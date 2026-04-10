"""
Processes a given web site and looks for FIDO2/WebAuthn usage through multiple heuristics.

It builds a dictionary, for a web site, containing the results of each heuristic and, finally,
infer potential FIDO2 usage.
"""

from import_data import *
from utils import *
import random as pyrand

__all__ = ["process_site"]

credentials_hook_script = r"""
(() => {
    window._skipCredentialCapture = false;
    window._forceCredentialCapture = false;
    window._lastUserInteraction = 0;

    // Track user interactions
    function updateInteractionTime() {
        try { window._lastUserInteraction = Date.now(); } catch(e) {}
    }
    window.addEventListener("click", updateInteractionTime, true);
    window.addEventListener("keydown", updateInteractionTime, true);
    window.addEventListener("pointerdown", updateInteractionTime, true);

    if (!navigator.credentials) return;

    window._credentialsCalled = false;
    window._credentialsParams = { get: [], create: [] };

    const origGet = navigator.credentials.get;
    const origCreate = navigator.credentials.create;

    const INTERACTION_WINDOW_MS = 3500; // 3s after user interaction

    navigator.credentials.get = function(...args) {
        try {
            if (window._skipCredentialCapture) return origGet.apply(this, args);

            const now = Date.now();
            const afterInteraction = (now - (window._lastUserInteraction || 0)) < INTERACTION_WINDOW_MS;

            if (afterInteraction || window._forceCredentialCapture) {
                window._credentialsCalled = true;
                const serializedArgs = JSON.parse(JSON.stringify(args[0], (k,v) => v instanceof Uint8Array ? Array.from(v) : v));
                window._credentialsParams.get.push({
                    args: serializedArgs,
                    ts: now,
                    afterInteraction: afterInteraction
                });
            }
        } catch(e){ /* swallow errors */ }
        return origGet.apply(this, args);
    };

    navigator.credentials.create = async function(...args) {
        try {
            if (window._skipCredentialCapture) return origCreate.apply(this, args);

            const now = Date.now();
            const afterInteraction = (now - (window._lastUserInteraction || 0)) < INTERACTION_WINDOW_MS;

            if (afterInteraction || window._forceCredentialCapture) {
                window._credentialsCalled = true;

                const serializedArgs = JSON.parse(JSON.stringify(args[0], (k,v) => v instanceof Uint8Array ? Array.from(v) : v));

                window._credentialsParams.create.push({
                    args: serializedArgs,
                    ts: now,
                    afterInteraction: afterInteraction
                });
            }

            if (args[0]?.publicKey && !args[0].publicKey.rp?.name) {
                const publicKey = args[0].publicKey;
                publicKey.rp = { name: location.hostname, id: location.hostname };
                return await origCreate.apply(this, [{ publicKey }]);
            }

        } catch(e){ /*swallow*/ }

        return origCreate.apply(this, args);
    };
})();
"""

async def process_site(site_url: str, browser: Browser, site_nb: int, len_df: int) -> Dict:
    """
    Applies heuristics on a given webpage inside a given browser.
    Integrates page classification (CMP, anti-bot, interstitial) before proceeding.

    Ensures deterministic collection of FIDO2, OTP, and password-based signals
    by stabilizing the login surface before performing any inference.

    Params:
        site_url: URL of the web site to scrape
        browser: the browser to run the web site

    Returns:
        dictionary representing heuristics results for the site
    """
    ########################################################################
    #                   STEP 0: Initialisation                             #
    ########################################################################
    logger.info(f"Début traitement site: {site_url}")
    try:
        results = {"site_url": site_url,}
        results["nb_clicks"] = 0

        auth_escalation_state = {
            "clicks": 0,
            "redirects": 0,
            "extra_time": 0.0,
        }

        primary_scope = await get_etld1(site_url)
        results["primary_auth_scope"] = primary_scope
        logger.info(f"Primary scope: {primary_scope}")
        context = None
        page = None

        try:
            context = await _create_context_with_credentials_hook(browser)
            page = await context.new_page()
            page._fidology_results = results
            page.on("console", lambda msg: logger.debug(f"PAGE LOG: {msg.text}"))
            ####################################################################
            #                 STEP 1: Jump to Web site URL                     #
            ####################################################################
            await page.goto(site_url, timeout=15000)

            ####################################################################
            #           STEP 2: manage cookies, language, locale popups        #
            ####################################################################
            logger.info("[Step 2] manage cookies, language, locale popups...")

            await safe_await(
                lambda: accept_cookie_banner(page),
                timeout=3, label="accept_cookie_banner"
            )
            await safe_await(
                lambda: handle_language_selector(page),
                timeout=2, label="handle_language_selector"
            )
            await safe_await(
                lambda: handle_locale_suggestion(page),
                timeout=2, label="handle_locale_suggestion"
            )

            logger.info("[Step 2] DONE")

            await page.wait_for_load_state("load", timeout=5000)

            ####################################################################
            #          STEP 3: manage consent banners inside iframes           #
            ####################################################################
            logger.info("[Step 3] manage consent banners inside iframes...")

            await safe_await(
                lambda: handle_consent_banners(page),
                timeout=3, label="handle_consent_banners"
            )

            logger.info("[Step 3] DONE")

            ####################################################################
            #            STEP 4: classify/stabilize the page context           #
            ####################################################################
            logger.info("[Step 4] Classify/stabilize the page content...")
            page_context = await safe_await(
                lambda: classify_page_context(page),
                timeout=3, default={}, label="stabilize page content"
            )

            # store classification in results
            page_type = page_context.get("page_type", "unknown")
            blocked = page_context.get("blocked", False)
            results["page_classification"] = page_type
            if blocked:
                results["reason"] = page_context.get("error", "blocked_page")
            logger.info("[Step 4] DONE")

            ####################################################################
            #                 STEP 5.a: proceed to login navigation            #
            ####################################################################
            logger.info("[Step 5] proceed to login navigation...")
            res = {"login": False, "cloudflare": False, "multistep": 0, "checks": {'password_input': False, 'email_input': False, 'passkey_btn': False}}
            login_navigated = await safe_await(
                lambda: navigate_to_login(page, site_url),
                timeout=30, default= res, label="navigate_to_login"
            )
            await asyncio.sleep(1)
            results["login_navigation_successful"] = login_navigated["login"]
            if not login_navigated["login"]:
                await asyncio.sleep(1)
                await page.goto(site_url, timeout=TIMEOUT_MS, wait_until="load")
                await page.wait_for_load_state()
                await asyncio.sleep(0.5)

                if login_navigated["cloudflare"]:
                    results["page_classification"] = 'antibot_challenge'

            else:
                results["page_classification"] = 'real_login_page'

            # Ensure we collect data on primary scope
            current_url = page.url
            current_scope = await get_etld1(current_url)
            results["login_url"] = current_url
            results["login_scope"] = current_scope
            results["cross_scope_login"] = current_scope != primary_scope

            # Force expose login UI always
            forced = await safe_await(
                lambda: force_expose_login_ui(page),
                timeout=2, label="force_expose_login_ui"
            )
            results["login_ui_forced"] = forced
            logger.info(f"Login UI forced exposure: {forced}")

            # Wait for authentication form to appear and stabilize
            if forced or login_navigated["login"]:
                form_result = await safe_await(
                    lambda: wait_for_auth_form_appearance(page, timeout=10.0, stabilization_delay=2.0),
                    timeout=10,
                    default={"appeared": False, "phase": "none", "elapsed_time": 0.0, "signals_detected": []},
                    label="wait_for_auth_form_appearance"
                )
                results["auth_form_appeared"] = form_result["appeared"]
                results["auth_form_phase"] = form_result["phase"]
                results["auth_form_detection_time"] = form_result["elapsed_time"]

                logger.info(
                    f"Auth form appearance: {form_result['appeared']} "
                    f"(phase: {form_result['phase']}, elapsed: {form_result['elapsed_time']:.2f}s)"
                )

                # Only proceed if form is fully stabilized
                if form_result["phase"] != "stabilized":
                    logger.warning(
                        "Auth form detected but not stabilized. Signals may be incomplete."
                    )
            else:
                results["auth_form_appeared"] = False
                results["auth_form_phase"] = "skipped"
                results["auth_form_detection_time"] = 0.0
                logger.info("Login UI not forced; skipping auth form wait")

            # Stabilize auth surface
            await safe_await(
                lambda: stabilize_auth_surface(page),
                timeout=3.0, label="stabilize_auth_surface"
            )

            # expose login popup and wait for auth surface
            login_frame = await safe_await(
                lambda: wait_for_login_popup(page, timeout=5.0),
                timeout=6.0, label="wait_for_login_popup"
            )

            if login_frame is None:
                login_frame = page.main_frame
                logger.info("Login popup not detected; fallback to main frame.")
            logger.info("[Step 5] DONE")

            ####################################################################
            #      Signal 1:detect UI keywords in stabilized frame             #
            #      Signal 2:detect shadow DOM keywords                         #
            #      Signal 3:detect password inputs (main frame and shadow dom) #
            #      Signal 4:detect potential iFrame cross-origin               #
            ########################################################################
            logger.info("[Signal 1-->4]")
            auth_signals = await collect_auth_signals(page, login_frame)

            results["password_input_present"] = auth_signals["password_input_present"] or login_navigated.get("checks").get("password_input", False)
            results["password_input_in_shadow_dom"] = auth_signals["password_input_in_shadow_dom"]
            results["ui_webauthn_keywords_present"] = auth_signals["ui_webauthn_keywords_present"] or login_navigated.get("checks").get("passkey_btn", False)
            results["shadow_dom_webauthn"] = auth_signals["shadow_dom_webauthn"]
            results["login_iframe_cross_origin"] = auth_signals["login_iframe_cross_origin"]
            results["login_iframe_src"] = auth_signals["login_iframe_src"]

            results["auth_surface_type"] = detect_auth_surface_type(
                login_navigation_successful=results.get("login_navigation_successful", False),
                login_ui_forced=results.get("login_ui_forced", False),
                login_iframe_cross_origin=auth_signals.get("login_iframe_cross_origin", False),
                login_frame=login_frame
            )

            logger.info("[Signal 1-->4] DONE")

            await asyncio.sleep(1)  # allow FedCM scripts to initialize

            ####################################################################
            #              STEP 5.b Authentication Escalation                  #
            ####################################################################
            if should_auth_escalate(results, auth_escalation_state):
                logger.info("[Step 5b] Authentication escalation...")
                results, auth_escalation_state, login_frame = await perform_auth_escalation(
                    page, results, auth_escalation_state, login_frame,
                )

                logger.info(f"[Step 5b] Escalation done. Clicks used: {auth_escalation_state['clicks']}, Extra time: {auth_escalation_state['extra_time']}")

            ####################################################################
            #              SIGNAL 5: double check for FEDCM usage              #
            ####################################################################
            logger.info("[Signal 5] Double check for FedCM usage...")
            try:
                fedcm_credentials_params = await safe_evaluate(
                    page,
                    "window._credentialsParams || {}",
                    default={}
                )

                if fedcm_credentials_params:
                    context._fedcm_credentials_params = fedcm_credentials_params
                    logger.debug(f"Stored FedCM credentials parameters: {fedcm_credentials_params}")

            except Exception as e:
                logger.warning(f"Unable to retrieve FedCM credentials hook data: {e}")
                context._fedcm_credentials_params = {}

            fedcm_result = await safe_await(
                lambda: detect_fedcm(page),
                timeout=6.0, label="detect_fedcm",
                default={
                            "fedcm_present": False,
                            "fedcm_provider": False,
                            "fido2_indirect_possible": False,
                            "fedcm_detected_via_api": False,
                        }
            )
            results.update(fedcm_result)
            logger.info("[Signal 5] DONE...")

        except Exception as e:
            logger.error(f"Erreur navigation vers {site_url}: {e}")
            results["error"] = str(e)
            results["fido2_usage"] = "error"
            await asyncio.sleep(1)
            if page is not None:
                await page.close()
            if context is not None:
                await context.close()
            return results

        try:
            ####################################################################
            #                     SIGNAL 6: Network Analysis                   #
            ####################################################################
            logger.info("[Signal 6] Network Analysis...")
            requests_list = []
            setup_network_logging(page, requests_list)
            await asyncio.sleep(2)
            network_results = analyze_network_requests(requests_list)
            results.update(network_results)

            # Detect active anti-bot challenges
            blocked, reason = await detect_active_antibot(requests_list)
            if blocked:
                results["analysis_blocked"] = True
                results["analysis_block_reason"] = reason
                results["fido2_usage"] = "error"
                results["confidence_score"] = 0.0
                results["fido2_confidence_diagnosis"] = "Active anti-bot challenge detected (Cloudflare Turnstile)."
                results["page_classification"] = "antibot_challenge"
                logger.info("Analysis aborted due to active anti-bot challenge.")
                await context.close()
                return results
            logger.info("[Signal 6] DONE")

            ####################################################################
            #              SIGNAL 7-8: Storage and cookies analysis            #
            ####################################################################
            logger.info("[Signal 7-8] Storage and cookies analysis...")
            storage_results = await analyze_storage_and_cookies(page, context)
            results.update(storage_results)
            logger.info("[Signal 7-8] DONE")

            ####################################################################
            #                  SIGNAL 9: Credentials API related               #
            ####################################################################
            logger.info("[Signal 9] Credentials API related...")
            called, params = await detect_credentials_api(page)
            results["credentials_api_used"] = called
            results["credentials_api_params"] = params
            results.update(await detect_passkey_js_support(page))
            logger.info("[Signal 9] DONE")

            ####################################################################
            #                  SIGNAL 10: iFrame dom detector                  #
            ####################################################################
            logger.info("[Signal 10] iFrame dom detector...")

            iframe_dom_results = await safe_await(
                lambda: apply_dom_detectors_to_frames(
                    page,
                    [
                        lambda frame, _det=detect_password_input: _det(frame),
                        lambda frame, _det=detect_credentials_api: _det(frame),
                        lambda frame, _det=detect_ui_keywords: _det(frame, UI_KEYWORDS),
                        lambda frame, _det=detect_webauthn_keywords_in_shadow_dom: _det(frame, FIDO_KEYWORDS),
                    ]
                ),
                timeout=4.0,
                default=[],
                label="apply_dom_detectors_to_frames"
            )

            results["iframe_dom_results"] = iframe_dom_results

            try:
                js_support = await detect_passkey_js_support(page)
                results["auth_js_supports_passkey"] = js_support.get(
                    "auth_js_supports_passkey", False
                )
            except Exception as e:
                logger.debug(f"detect_passkey_js_support failed: {e}")
                results["auth_js_supports_passkey"] = False

            logger.info("[Signal 10] DONE")

            ####################################################################
            #                  SIGNAL 11: Multistep login                      #
            ####################################################################
            logger.info("[Signal 11] Multistep login...")
            results["multistep_login"] = await safe_await(
                lambda: detect_multistep_login(page),
                timeout=2, default=False, label="detect_multistep_login"
            )
            if login_navigated["multistep"] != 0:
                results["multistep_login"] = True

            logger.info("[Signal 11] DONE")

            ####################################################################
            #                   SIGNAL 12: OTP Detection                       #
            ####################################################################
            logger.info("[Signal 12] OTP Detection")
            otp_results = await safe_await(
                lambda: detect_otp_indicators(page, requests_list),
                timeout=3, default={}, label="detect_otp_indicators"
            )
            results["otp_indicators_present"] = otp_results.get("otp_indicators_present", False)
            results["otp_sources"] = otp_results.get("otp_sources", [])
            results["otp_keywords_detected"] = otp_results.get("otp_keywords_detected", [])
            logger.info("[Signal 12] DONE")

            ####################################################################
            #   STEP 5c / FINAL: Authentication observability diagnosis        #
            ####################################################################
            results["fido2_usage"] = await infer_authentication(results)

            ####################################################################
            #                STEP 6: Freeze authentication inference           #
            ####################################################################
            logger.info("[Step 6] Freeze authentication inference...")

            results = await finalize_classification(results)
            await _apply_auth_scope_correction(results)
            finalize_auth_observability(results)

            logger.info("[Step 6] DONE")

            logger.info(f"Analyse terminée pour {site_url}")
            logger.info(f"DEBUG: fido2_usage = {results['fido2_usage']!r}")

            ####################################################################
            #                STEP 7: Trying to validage FIDO2                 #
            ####################################################################
            logger.info("[Step 7] Trying to validate FIDO2...")
            final_class = results.get("fido2_usage")
            if final_class in FIDO_CLASSES:
                try:
                    await page.goto(current_url, timeout=2500, wait_until="load")
                    await safe_evaluate(page, "window._forceCredentialCapture = true;")
                    cose_info = await safe_await(
                        lambda: validate_fido_classification(page),
                        timeout=15, default={}, label="validate_fido_classification"
                    )
                    await safe_evaluate(page, "window._forceCredentialCapture = false;")

                    results["validated"] = cose_info.get("passkey_button_clicked")
                    results["passkey_trigger_attempted"] = True
                    results["passkey_trigger_result"] = cose_info or {}
                    results["cose_algorithms"] = cose_info.get("cose_algorithms", [])
                    results["cose_algorithms_count"] = len(results["cose_algorithms"])
                except Exception as e:
                    logger.info(f"PasskeyTrigger Exception: {e}")
                    results["passkey_trigger_attempted"] = True
                    results["passkey_trigger_error"] = str(e)
                    results["validated"] = False
            else:
                results["passkey_trigger_attempted"] = False
                results["validated"] = False
            logger.info("[Step 7] DONE")

        except Exception as e:
            logger.error(f"Erreur analyse site {site_url}: {e}")
            results["error"] = str(e)
            results['fido2_usage'] = 'error'
            pass

    except Exception:
        pass

    finally:
        await asyncio.sleep(1)
        if page is not None:
            await page.close()
        if context is not None:
            await context.close()

    return results

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

async def _create_context_with_credentials_hook(browser: Browser) -> BrowserContext:
    """
    Creates a browser context with a robust hook injected to monitor any usage of
    navigator.credentials.get() and navigator.credentials.create(), including iframes.

    Features:
        - Captures only likely user-triggered calls (within 3s of click/keydown/pointerdown)
        - Safely serializes arguments (Uint8Array → Array)
        - Injects a dummy safe call for testing capture without breaking the site
        - Records timestamp and afterInteraction flag for downstream analysis
        - Prevents false positives with _skipCredentialCapture
    """
    browser_profile = pyrand.choice(USER_AGENTS_POOL)
    browser_profile = pyrand.choice(USER_AGENTS_POOL)

    context = await browser.new_context(
        user_agent=browser_profile["user_agent"],
        locale=browser_profile["locale"],
        viewport=browser_profile["viewport"],
        timezone_id=browser_profile["timezone"],
    )

    await context.add_init_script(credentials_hook_script)

    context.on("frameattached", lambda frame: frame.add_init_script(credentials_hook_script))

    return context

async def _apply_auth_scope_correction(results: dict) -> None:
    if (
        results.get("cross_scope_login")
        and results.get("fido2_usage") == "password_only"
    ):
        # Si on a vu des signaux FIDO ailleurs → ne pas dégrader
        fido_signals = any([
            results.get("credentials_api_used"),
            results.get("network_webauthn"),
            results.get("ui_webauthn_keywords_present"),
            results.get("shadow_dom_webauthn"),
            results.get("fedcm_present"),
        ])

        if fido_signals:
            results["fido2_usage"] = "password+fido"
            results["fido2_confidence_diagnosis"] += (
                " Password-only detected on secondary auth surface; "
                "primary site exposes FIDO2-capable login."
            )
