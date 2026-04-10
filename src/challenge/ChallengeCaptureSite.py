from import_data import *
from utils import *

__all__ = ["capture_fido_challenge"]

credentials_hook_script = r"""
(() => {

    if (window.__fidoHookInstalled)
        return;
    window.__fidoHookInstalled = true;

    window._skipCredentialCapture = false;
    window._forceCredentialCapture = false;
    window._lastUserInteraction = 0;
    window._credentialsCalled = false;

    window._credentialsParams = { get: [], create: [] };

    window._conditionalMediationChecked = false;

    function updateInteractionTime() {
        try { window._lastUserInteraction = Date.now(); } catch(e) {}
    }

    window.addEventListener("click", updateInteractionTime, true);
    window.addEventListener("keydown", updateInteractionTime, true);
    window.addEventListener("pointerdown", updateInteractionTime, true);

    if (!navigator.credentials)
        return;

    const INTERACTION_WINDOW_MS = 5000;

    const origGet = navigator.credentials.get.bind(navigator.credentials);
    const origCreate = navigator.credentials.create.bind(navigator.credentials);

    function deepClonePublicKey(obj) {

        if (!obj || typeof obj !== "object")
            return obj;

        if (obj instanceof ArrayBuffer)
            return Array.from(new Uint8Array(obj));

        if (ArrayBuffer.isView(obj))
            return Array.from(obj);

        const clone = Array.isArray(obj) ? [] : {};

        for (const key of Object.getOwnPropertyNames(obj)) {

            try {
                const value = obj[key];
                clone[key] = deepClonePublicKey(value);
            } catch (e) {
                clone[key] = null;
            }

        }

        return clone;
    }

    navigator.credentials.get = async function(...args) {

        const now = Date.now();

        const afterInteraction =
            (now - (window._lastUserInteraction || 0)) < INTERACTION_WINDOW_MS;

        try {

            if (!window._skipCredentialCapture) {

                window._credentialsCalled = true;

                const challengeBytes = args?.[0]?.publicKey?.challenge;
                console.log('[HOOK] credentials.get called, challenge:',
                    challengeBytes ? Array.from(new Uint8Array(challengeBytes instanceof ArrayBuffer ? challengeBytes : challengeBytes.buffer)) : 'none',
                    'afterInteraction:', afterInteraction
                );

                const serializedArgs = deepClonePublicKey(args);

                window._credentialsParams.get.push({
                    args: serializedArgs,
                    ts: now,
                    afterInteraction: afterInteraction
                });

                if (window._abortWebAuthn) {
                    throw new DOMException("User cancelled", "NotAllowedError");
                }

            }
        } catch(e){}

        return origGet(...args);

    };

    navigator.credentials.create = async function(...args) {

        const now = Date.now();

        const afterInteraction =
            (now - (window._lastUserInteraction || 0)) < INTERACTION_WINDOW_MS;

        try {

            if (!window._skipCredentialCapture) {

                window._credentialsCalled = true;

                const serializedArgs = deepClonePublicKey(args);

                window._credentialsParams.create.push({
                    args: serializedArgs,
                    ts: now,
                    afterInteraction: afterInteraction
                });

                if (window._abortWebAuthn) {
                    throw new DOMException("User cancelled", "NotAllowedError");
                }

            }
        } catch(e){}

        return origCreate(...args);

    };

    /* ------------------------------------------------ */
    /* Conditional mediation detection                  */
    /* ------------------------------------------------ */

    try {

        if (window.PublicKeyCredential &&
            PublicKeyCredential.isConditionalMediationAvailable) {

            const origConditional =
                PublicKeyCredential.isConditionalMediationAvailable;

            PublicKeyCredential.isConditionalMediationAvailable =
                async function(...args) {

                    try {
                        window._conditionalMediationChecked = true;
                    } catch(e){}

                    return origConditional.apply(this, args);
                };

        }

    } catch(e){}

    /* ------------------------------------------------ */
    /* Hide hook modifications                          */
    /* ------------------------------------------------ */

    try {

        navigator.credentials.get.toString = () =>
            "function get() { [native code] }";

        navigator.credentials.create.toString = () =>
            "function create() { [native code] }";

    } catch(e){}

    /* ------------------------------------------------ */
    /* Prevent override by page scripts                 */
    /* ------------------------------------------------ */

    try {

        Object.defineProperty(navigator.credentials, "get", {
            configurable: false,
            writable: false,
            value: navigator.credentials.get
        });

        Object.defineProperty(navigator.credentials, "create", {
            configurable: false,
            writable: false,
            value: navigator.credentials.create
        });

    } catch(e){}

})();
"""

async def capture_fido_challenge(
    site_url: str,
    browser: Browser,
    challenge_probes: int = NB_ATTEMPTS_CAPTURE  # number of attempts per site
) -> Dict[str, Any]:
    logger.info(f"Début traitement site: {site_url}")

    results: Dict[str, Any] = {
        "site_url": site_url,
        "capture_successful": False,
        "nb_clicks": 0,
        "webauthn_triggered": False,
        "captures_count": 0,
        "captures": [],
        "challenge_probe_count": challenge_probes,
        "cose_algorithms": [],
        "challenge_lengths": [],
        "challenge_entropy": [],
        "user_verification": [],
        "attestation_modes": [],
        "rp_ids": [],
    }

    stealth = Stealth()
    context = await _create_context_with_credentials_hook(browser)
    page: Page = await context.new_page()
    await stealth.apply_stealth_async(page)

    antibot_detected = {"value": False}

    def console_listener(msg):
        text = msg.text.lower()
        if (
            "turnstile" in text or
            "private access token" in text or
            "verify you are human" in text or
            "cloudflare" in text
        ):
            antibot_detected["value"] = True

        logger.debug(f"[JS console.{msg.type}] {msg.text}")

    page.on("console", console_listener)

    def _handle_console_message(msg):
        text = msg.text.strip()
        try:
            obj = json.loads(text)
            one_liner = json.dumps(obj, separators=(",", ":"))
            logger.debug(f"[JS console.{msg.type}] {one_liner}")
        except json.JSONDecodeError:
            compact = " ".join(text.split())
            logger.debug(f"[JS console.{msg.type}] {compact}")

    #page.on("console", _handle_console)
    page.on("console", lambda msg: _handle_console_message(msg))

    try:
        ####################################################################
        # Step 1: Navigation
        ####################################################################
        try:
            await page.goto(site_url, timeout=15000, wait_until="commit")
            await page.wait_for_timeout(2000)  # stabilisation
        except Exception as e:
            if "ERR_ABORTED" in str(e):
                logger.debug("Navigation aborted (likely redirect chain).")
            else:
                logger.error(f"Step 1: {e}")
                results["error"] = f"navigation_error: {e}"
                return results

        await page.wait_for_timeout(3000)  # laisser les scripts antibot se déclencher

        if antibot_detected["value"]:
            logger.info("Anti-bot protection detected via console signals.")
            results["error"] = "blocked by antibot"
            results["security_level"] = "unobservable"
            return results

        ####################################################################
        # Step 2: Stabilisation
        ####################################################################
        await safe_await(lambda: accept_cookie_banner(page), timeout=3)

        #await page.wait_for_load_state("networkidle")
        await page.wait_for_load_state("domcontentloaded")
        await page.wait_for_timeout(1500)

        await safe_await(lambda: navigate_to_login(page, site_url), timeout=5)
        await asyncio.sleep(2)

        ####################################################################
        # Step 3 + 4: Multi-challenge probing
        ####################################################################
        await page.wait_for_timeout(
            random.randint(1200, 2500)
        )

        all_captures = []

        for probe_index in range(challenge_probes):

            if probe_index > 0:
                await page.reload(timeout=10000)
                await page.wait_for_load_state("domcontentloaded")
                await asyncio.sleep(1)

            await page.wait_for_timeout(500)

            trigger_result = None

            try:
                trigger_result = await validate_fido_classification(
                    page, timeout_ms=4000
                )

                if trigger_result and trigger_result.get("error"):
                    results["error"] = trigger_result["error"]
                    return results

            except Exception as e:
                logger.debug(f"Trigger failed but continuing capture: {e}")

            if isinstance(trigger_result, dict):
                # Seulement au premier probe
                if probe_index == 0:
                    results["nb_clicks"] = 1 if trigger_result.get("passkey_button_clicked") else 0
                    results["webauthn_triggered"] = trigger_result.get("webauthn_called", False)
                    results["cose_algorithms"] = trigger_result.get("cose_algorithms", [])

                # À CHAQUE probe
                raw_data = await page.evaluate("""
                    () => {
                        if (!window._credentialsParams) return [];
                        const flatten = [];
                        for (const item of window._credentialsParams.get || []) {
                            // Ignorer les appels FedCM (identity) et conditional mediation (pas de publicKey)
                            if (!item.args?.[0]?.publicKey) continue;
                            flatten.push({ type: "get", ...item.args?.[0]?.publicKey });
                        }
                        for (const item of window._credentialsParams.create || []) {
                            flatten.push({ type: "create", ...item.args?.[0]?.publicKey });
                        }
                        window._credentialsParams = { get: [], create: [] };
                        return flatten;
                    }
                """)
                await page.wait_for_timeout(2000)
                if isinstance(raw_data, list):
                    all_captures.extend(raw_data)

        # Store aggregated captures
        results["captures"] = all_captures
        results["captures_count"] = len(all_captures)
        results["webauthn_triggered"] = (
            results.get("webauthn_triggered", False)
            or results["captures_count"] > 0
        )

        ####################################################################
        # Step 5: Extract statistics
        ####################################################################
        try:
            captures = results.get("captures", [])

            # If captures accidentally serialized to string, fix it
            if isinstance(captures, str):
                try:
                    captures = json.loads(captures.replace("'", '"'))
                except Exception:
                    captures = []

            if captures:
                stats = await extract_challenge_statistics(captures)

                if isinstance(stats, dict):
                    results["challenge_lengths"] = stats.get("challenge_lengths", [])
                    results["challenge_entropy"] = stats.get("challenge_entropy", [])

                for cap in captures:
                    if not isinstance(cap, dict):
                        continue

                    if cap.get("userVerification"):
                        results["user_verification"].append(
                            cap["userVerification"]
                        )

                    if cap.get("attestation"):
                        results["attestation_modes"].append(
                            cap["attestation"]
                        )

                    if cap.get("rpId"):
                        results["rp_ids"].append(cap["rpId"])

        except Exception as e:
            logger.error(f"Step 5: {e}")
            results["error"] = f"stats_error: {e}"

        ####################################################################
        # Step 6: Deduplicate safely
        ####################################################################
        results["cose_algorithms"] = sorted(
            set(results["cose_algorithms"] or [])
        )
        results["user_verification"] = sorted(
            set(results["user_verification"] or [])
        )
        results["attestation_modes"] = sorted(
            set(results["attestation_modes"] or [])
        )
        results["rp_ids"] = sorted(set(results["rp_ids"] or []))

        results["capture_successful"] = results["captures_count"] > 0

        uniqueness_metrics = analyze_challenge_uniqueness(results["captures"])
        results.update(uniqueness_metrics)

        decoded = []
        for cap in results["captures"]:
            ch = cap.get("challenge")
            if isinstance(ch, list):
                decoded.append(bytes(ch))

        replay_metrics = analyze_replay_and_timestamp_risk(decoded)
        results.update(replay_metrics)

        ####################################################################
        # Step 7: Scoring
        ####################################################################
        if results["captures_count"] > 0:
            score_metrics = compute_fido_security_score(
                challenge_lengths=results["challenge_lengths"],
                challenge_entropy=results["challenge_entropy"],
                user_verification=results["user_verification"],
                attestation_modes=results["attestation_modes"],
                challenge_uniqueness_score=results.get("challenge_uniqueness_score", 1.0)
            )

            results.update(score_metrics)
            results["security_level"] = classify_security_level(score_metrics["overall_score"])
        else:
            results["security_level"] = "no_data"

    except Exception as e:
        # Catch-all safety net (should rarely trigger now)
        results["error"] = f"unexpected_error: {e}"
        logger.error(f"Catch all: {e}")

    finally:
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

    browser_profile = random.choice(USER_AGENTS_POOL)

    context = await browser.new_context(
        user_agent=browser_profile["user_agent"],
        locale=browser_profile["locale"],
        viewport=browser_profile["viewport"],
        timezone_id=browser_profile["timezone"],
        java_script_enabled=True,
    )

    await context.add_init_script(credentials_hook_script)

    return context
