"""
Analyzes visible Document Object Models (DOM).

It checks for the presence of the password field, calls to JavaScript
navigator.credentials, ...

It also detects calls to Credentials API.  A Credentials API enables a website
to create, store, and retrieve credentials. A credential is an item which
enables a system to make an authentication decision: for example, to decide
whether to sign a user into an account.

It looks for particular keywords (see configs/) in user interface.

It navigates towards dedicated login pages or attemtps to discover login
through clicks.
"""

from import_data import *
from utils import *

__all__ = ["detect_password_input", "detect_credentials_api", "detect_ui_keywords", "navigate_to_login", "expose_login_popup", "force_expose_login_ui", "stabilize_auth_surface", "wait_for_login_popup", "detect_passkey_js_support", "wait_for_auth_form_appearance"]

# regex to avoid compile each time
cloudflare_patterns = re.compile(r"performing security verification|cloudflare|not.*bot", re.I)
search_patterns = re.compile(r"help|research|search|bar", re.I)
passkey_patterns = re.compile(r"log\s*in.*passkey|sign\s*in.*passkey|continue.*passkey|log\s*in.*security device", re.I)
login_patterns = re.compile(r"log\s*in|sign\s*in|passkey|account|customer", re.I)
login_keywords = re.compile(r"""\b(log.*?in|sign.*?in|sign.*?up|logon|anmelden|einloggen|connexion|se\s+connecter|password|
                            s['’]inscrire|inscription|iniciar\s+sesión|registrarse|continuar|authenticate|min\s+(konto|sida))\b""", re.I)

async def detect_passkey_js_support(page: Page) -> Dict[str, bool]:
    return {
        "auth_js_supports_passkey": await _detect_passkey_js_support(page)
    }

async def stabilize_auth_surface(page: Page, timeout: float = 4.0) -> None:
    """
    Waits until the authentication surface (login form or modal) is stable.
    Prevents non-deterministic inference caused by late DOM injections.
    Uses safe_evaluate to handle cases where document.body might be null.
    """
    end = asyncio.get_event_loop().time() + timeout
    last_snapshot = None

    js_fn = """
        () => {
            const body = document.body;
            if (!body) return "";
            return body.innerText.slice(0, 2000);
        }
    """

    while asyncio.get_event_loop().time() < end:
        snapshot = await safe_evaluate(page, js_fn, default="")

        # If the snapshot didn't change and is non-empty, assume stable
        if snapshot == last_snapshot and snapshot.strip():
            return

        last_snapshot = snapshot
        await asyncio.sleep(0.4)

async def wait_for_auth_form_appearance(
    page: Page,
    timeout: float = 10.0,
    check_interval: float = 0.3,
    stabilization_delay: float = 2.0
) -> dict:
    """
    Waits for authentication form elements to appear and stabilize in the DOM after a login action.

    This function uses a two-phase detection strategy to handle progressive rendering:

    Phase 1 - Initial Detection (fast):
        - Monitors for the first signs of authentication UI appearing
        - Checks for containers, keywords, or partial form structure
        - Returns as soon as any authentication element is detected

    Phase 2 - Stabilization & Deep Verification (thorough):
        - Waits for the form to finish rendering completely
        - Verifies presence of actual input fields (password, email, username)
        - Ensures the form is interactive and ready for signal collection

    This two-phase approach addresses the common issue where authentication
    forms are detected initially but their interactive elements (input fields,
    buttons) are loaded progressively via JavaScript frameworks (React, Vue,
    Angular, etc.)

    Params:
        page: Playwright Page object to monitor
        timeout: Maximum time to wait for auth elements (default: 10.0 seconds)
        check_interval: Time between DOM checks (default: 0.3 seconds)
        stabilization_delay: Additional wait after initial detection (default: 2.0 seconds)

    Returns:
        Dictionary containing:
            - appeared (bool): True if authentication form was detected
            - phase (str): Detection phase reached ("none", "initial", "stabilized")
            - elapsed_time (float): Time taken to detect (seconds)
            - signals_detected (list): Types of signals found
    """
    start_time = asyncio.get_event_loop().time()

    # Prepare keyword lists for JavaScript injection
    ui_keywords_js = json.dumps([kw.lower() for kw in UI_KEYWORDS])
    login_keywords_js = json.dumps([kw.lower() for kw in LOGIN_KEYWORDS])

    # Prepare password patterns from configs/patterns.py
    # Filter out API endpoints and keep only attribute/field patterns
    password_attr_patterns = [
        p.lower() for p in PASSWORD_PATTERNS
        if not p.startswith('/') and len(p) <= 30  # Exclude endpoints, keep short patterns
    ]
    password_patterns_js = json.dumps(password_attr_patterns)

    # Prepare auth container patterns from configs/patterns.py
    auth_container_selectors = ", ".join(AUTH_CONTAINER_PATTERNS)

    # Phase 1: Initial detection script (lightweight)
    js_initial_detection = f"""
    () => {{
        try {{
            const bodyText = (document.body?.innerText || "").toLowerCase();
            if (bodyText.length < 20) return false;

            // Check 1: Quick keyword scan
            const uiKeywords = {ui_keywords_js};
            const loginKeywords = {login_keywords_js};
            const hasKeywords =
                uiKeywords.some(kw => bodyText.includes(kw)) ||
                loginKeywords.some(kw => bodyText.includes(kw));
            if (hasKeywords) return true;

            // Check 2: Auth container presence (patterns from AUTH_CONTAINER_PATTERNS)
            const authContainers = document.querySelectorAll("{auth_container_selectors}");
            if (authContainers.length > 0) return true;

            // Check 3: Any form element appeared
            const forms = document.querySelectorAll("form");
            if (forms.length > 0) return true;

            return false;
        }} catch (e) {{
            return false;
        }}
    }}
    """

    # Phase 2: Deep verification script (comprehensive)
    js_deep_verification = f"""
    () => {{
        try {{
            const passwordPatterns = {password_patterns_js};

            // Check 1: Password input field (explicit)
            const hasPasswordInput = !!document.querySelector("input[type='password']");
            if (hasPasswordInput) return true;

            // Check 2: Password field by name/id/class/placeholder attributes
            const inputs = document.querySelectorAll("input");
            for (const input of inputs) {{
                const name = (input.name || "").toLowerCase();
                const id = (input.id || "").toLowerCase();
                const className = (input.className || "").toLowerCase();
                const placeholder = (input.placeholder || "").toLowerCase();

                const allAttrs = name + " " + id + " " + className + " " + placeholder;

                // Match against password patterns from configs/patterns.py
                if (passwordPatterns.some(pattern => allAttrs.includes(pattern))) {{
                    return true;
                }}
            }}

            // Check 3: Form with login-related inputs (email, text, password)
            const forms = document.querySelectorAll("form");
            for (const form of forms) {{
                const formInputs = form.querySelectorAll(
                    "input[type='text'], input[type='email'], input[type='password']"
                );
                if (formInputs.length > 0) return true;
            }}

            // Check 4: Submit buttons (common login button patterns)
            const submitButtons = document.querySelectorAll(
                "button[type='submit'], " +
                "input[type='submit']"
            );
            if (submitButtons.length > 0) {{
                // Verify button is in a form or auth context
                for (const btn of submitButtons) {{
                    const parent = btn.closest('form, [class*="login"], [class*="signin"], [class*="auth"]');
                    if (parent) return true;
                }}
            }}

            return false;
        }} catch (e) {{
            return false;
        }}
    }}
    """

    result = {
        "appeared": False,
        "phase": "none",
        "elapsed_time": 0.0,
        "signals_detected": []
    }

    logger.debug("Starting wait_for_auth_form_appearance (two-phase detection)...")

    # ========== PHASE 1: Initial Detection ==========
    phase1_timeout = timeout * 0.6  # 60% of total timeout for phase 1
    phase1_start = asyncio.get_event_loop().time()

    while (asyncio.get_event_loop().time() - phase1_start) < phase1_timeout:
        initial_detected = await safe_evaluate(
            page, js_initial_detection, default=False
        )

        if initial_detected:
            elapsed = asyncio.get_event_loop().time() - start_time
            logger.info(f"[Phase 1] Auth form indicators detected after {elapsed:.2f}s")
            result["phase"] = "initial"
            result["signals_detected"].append("initial_indicators")
            break

        await asyncio.sleep(check_interval)

    # If phase 1 failed, return early
    if result["phase"] == "none":
        result["elapsed_time"] = asyncio.get_event_loop().time() - start_time
        logger.info(f"[Phase 1] No auth indicators detected within {phase1_timeout:.1f}s")
        return result

    # ========== STABILIZATION: Wait for form to finish rendering ==========
    logger.debug(f"[Stabilization] Waiting {stabilization_delay}s for form to complete rendering...")
    await asyncio.sleep(stabilization_delay)

    # ========== PHASE 2: Deep Verification ==========
    phase2_timeout = timeout - (asyncio.get_event_loop().time() - start_time)
    phase2_start = asyncio.get_event_loop().time()

    logger.debug("[Phase 2] Starting deep verification...")

    while (asyncio.get_event_loop().time() - phase2_start) < phase2_timeout:
        deep_verified = await safe_evaluate(
            page,
            js_deep_verification,
            default=False
        )

        if deep_verified:
            elapsed = asyncio.get_event_loop().time() - start_time
            logger.info(f"[Phase 2] Auth form fully verified after {elapsed:.2f}s total")
            result["appeared"] = True
            result["phase"] = "stabilized"
            result["elapsed_time"] = elapsed
            result["signals_detected"].append("password_inputs")
            return result

        await asyncio.sleep(check_interval)

    # Phase 2 timeout: initial indicators found but form didn't stabilize
    result["elapsed_time"] = asyncio.get_event_loop().time() - start_time
    logger.warning(
        f"[Phase 2] Form indicators detected but verification failed "
        f"(elapsed: {result['elapsed_time']:.2f}s)"
    )

    return result

async def wait_for_login_popup(page: Page, timeout: float = 5.0) -> Optional[Frame]:
    """
    Waits for a login popup/frame to appear, up to `timeout` seconds.
    Returns the Frame if found, otherwise None.
    """
    start_time = asyncio.get_event_loop().time()
    while (asyncio.get_event_loop().time() - start_time) < timeout:
        popup_frame = await expose_login_popup(page)
        if popup_frame:
            return popup_frame
        await asyncio.sleep(0.2)
    return None



async def force_expose_login_ui(page: Page) -> bool:
    """
    Attempts to expose login UI by triggering click events via JS
    when normal Playwright click fails.
    Uses safe_evaluate to prevent exceptions if elements are missing.
    """
    await page.evaluate("window._fidology_click_count = 0")

    script = """
    (() => {
        try {
            const candidates = Array.from(document.querySelectorAll("a, button, div"))
                .filter(el => el && el.innerText && /log\\s*in|sign\\s*in|account|passkey/i.test(el.innerText));

            for (const el of candidates) {
                try {
                    el.scrollIntoView({block: "center"});
                    el.click();
                    if (window._fidology_click_count !== undefined) {
                        window._fidology_click_count++;
                    }
                    return true;
                } catch (e) {}
            }
        } catch (e) {}
        return false;
    })();
    """
    # Use safe_evaluate to avoid unhandled exceptions
    result = await safe_evaluate(page, script, default=False)

    # Sync JS clicks to results
    if hasattr(page, '_fidology_results'):
        js_clicks = await safe_evaluate(page, "() => window._fidology_click_count || 0", default=0)
        page._fidology_results["nb_clicks"] = page._fidology_results.get("nb_clicks", 0) + js_clicks

    return result

async def expose_login_popup(page: Page) -> Optional[Frame]:
    """
    Tries to expose the main login popup or modal.

    Returns the frame containing the login UI, if found.
    """
    for selector in LOGIN_ICON_SELECTORS:
        try:
            btn = await page.query_selector(selector)
            if btn:
                await btn.click()
                if hasattr(page, '_fidology_results'):
                    page._fidology_results["nb_clicks"] = page._fidology_results.get("nb_clicks", 0) + 1
                await page.wait_for_timeout(1000)  # wait 1s for popup to appear
                logger.info(f"Login popup triggered via {selector}")
                break
        except Exception as e:
            logger.debug(f"Failed clicking login icon {selector}: {e}")

    # 2. Return the frame of the popup/modal if it exists
    # Usually modals are first child frame of body or shadow DOM
    for frame in page.frames:
        text = await frame.evaluate("() => document.body.innerText || ''")
        if any(kw.lower() in text.lower() for kw in UI_KEYWORDS):
            logger.info(f"Login popup frame detected for UI keyword scanning")
            return frame

    # fallback: use main page
    return page.main_frame

async def detect_password_input(page: Page) -> bool:
    """
    Detects if a standard password input exists in the visible DOM.

    Params:
        page: Playwright Page object to inspect

    Returns:
        True if an <input type="password"> exists, False otherwise.
    """
    script = """
    () => {
        try {
            return !!document.querySelector("input[type='password']");
        } catch (e) {
            return false;
        }
    }
    """
    result = await safe_evaluate(page, script, default=False)
    logger.debug("detect_password_input: %s", result)
    return result

async def detect_credentials_api(page: Page) -> Tuple[bool, Dict[str, List[str]]]:
    """
    Detects usage of navigator.credentials API and extracts argument traces safely.

    Returns:
        Tuple:
            - True if any call was made
            - Dict with keys 'get' and 'create' containing argument traces
    """
    # Allow some time for the API to be called by scripts
    await asyncio.sleep(3)

    # Safe evaluation for API usage
    called = await safe_evaluate(
        page,
        "() => window._credentialsCalled === true",
        default=False,
    )

    # Safe evaluation for API parameters
    params = await safe_evaluate(
        page,
        """
        () => {
            try {
                return window._credentialsParams || {get: [], create: []};
            } catch (e) {
                return {get: [], create: []};
            }
        }
        """,
        default={"get": [], "create": []},
    )

    logger.debug("detect_credentials_api: %s", called)
    return called, params

async def detect_ui_keywords(page: Page, keywords: List[str]) -> bool:
    """
    Safely looks for keywords related to WebAuthn/FIDO2 (UI_KEYWORDS)
    in the visible DOM of a given page.

    Params:
        page: the Playwright Page object to investigate
        keywords: list of keywords to search for

    Returns:
        True if any keyword is found, False otherwise
    """
    js_code = """
    () => {
        try {
            const body = document.body;
            return body ? body.innerText || "" : "";
        } catch (e) {
            return "";
        }
    }
    """

    text_content = await safe_evaluate(
        page, js_code, default=""
    )

    if not text_content:
        return False

    text_lower = text_content.lower()
    found = any(keyword.lower() in text_lower for keyword in keywords)
    logger.debug("detect_ui_keywords: %s", found)
    return found

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

async def _click_element(el_handle, page) -> str | bool:
    """
    Safely click an element, using JS fallback if needed.
    """
    try:
        page._fidology_results["nb_clicks"] = page._fidology_results.get("nb_clicks", 0) + 1
        await el_handle.scroll_into_view_if_needed(timeout=1500)
        await el_handle.click(timeout=2000)

        return True
    except Exception as e:
        try:
            await page.evaluate(
                "(el) => el.dispatchEvent(new MouseEvent('click', {bubbles:true}))",
                el_handle
            )
            if hasattr(page, '_fidology_results'):
                page._fidology_results["nb_clicks"] = page._fidology_results.get("nb_clicks", 0) + 1
            return True
        except Exception:
            return False

async def _detect_passkey_js_support(page: Page) -> bool:
    """
    Detects whether the frontend JavaScript suggests support for Passkeys/WebAuthn.

    Strategy:
      - Inspect loaded <script> tags
      - Analyze script src URLs
      - Analyze inline script content
      - Match against known passkey / WebAuthn keywords

    Returns:
        True if passkey-related JS support is likely present.
    """
    # Combine UI_KEYWORDS and FIDO_KEYWORDS, convert to lowercase, remove duplicates
    combined_keywords = list(set(
        [kw.lower() for kw in UI_KEYWORDS] +
        [kw.lower() for kw in FIDO_KEYWORDS]
    ))

    # Inject keywords into JavaScript
    keywords_js = json.dumps(combined_keywords)

    # Inject keywords into JavaScript
    keywords_js = json.dumps(combined_keywords)

    js_fn = f"""
    () => {{
        const keywords = {keywords_js};

        const scripts = Array.from(document.scripts || []);
        for (const script of scripts) {{
            // Check script src
            if (script.src) {{
                const src = script.src.toLowerCase();
                if (keywords.some(k => src.includes(k))) {{
                    return true;
                }}
            }}

            // Check inline script content (limited size)
            if (script.textContent) {{
                const content = script.textContent.toLowerCase();
                if (keywords.some(k => content.includes(k))) {{
                    return true;
                }}
            }}
        }}
        return false;
    }}
    """
    return await safe_evaluate(page, js_fn, default=False)

async def _is_search_form(form):
    """
    Checks a form to see if it is a search form

    Params:
        form: the element <form> to inspect

    Returns:
        True if it is a search form, False otherwise
    """
    formId = (await form.get_attribute("id") or "").lower()
    if search_patterns.search(formId):
        return True

    formFor = (await form.get_attribute("for") or "").lower()
    if search_patterns.search(formFor):
        return True

    text = (await form.inner_text() or "").strip().lower()
    if search_patterns.search(text):
        return True

    return False

async def _login_eval(page) -> dict:
    """
    Evalute a page or a frame to see if it's a login page

    Params:
        page: the page or frame to inspect
        page: the page or frame to inspect

    Returns:
        A dict: { "password_input": bool, "email_input": bool, "passkey_btn": bool }
    """
    login_dict = { "password_input": False, "email_input": False, "passkey_btn": False }

    # passwords: input needs to be visible
    passwordFields = await page.query_selector_all("form input[type='password']")
    if len(passwordFields):
        for passwordField in passwordFields:
            if (await passwordField.is_visible()):
                logger.info("Found a visible password input.")
                login_dict['password_input'] = True
                break

     # if log in with passkey button
    try:
        buttons = await page.query_selector_all(
        "form button, form [role='button'], form a, main button, main [role='button'], main a"
        )

        for button in buttons:
            text = (await button.inner_text() or "").strip().lower()
            if passkey_patterns.search(text):
                logger.info("Found a passkey use button.")
                login_dict['passkey_btn'] = True
                break
    except Exception:
        pass

    try:
        # if a form is not a search for and contains login clues, then ok
        forms = await page.query_selector_all("form input[type='email'], form input[type='text']")

        for el in forms:
            # get form from el
            form = await el.evaluate_handle("el => el.closest('form')")
            # skip form if search form
            if await _is_search_form(form):
                continue
            text = (await form.inner_text() or "").strip().lower()
            if login_keywords.search(text):
                logger.info("Found a valid login form.")
                login_dict['email_input'] = True
                break

    except Exception:
        pass

    return login_dict

async def _is_login_visible(page: Page) -> dict:
    """
    Iterate over the page and frames and evaluates login page

    Params:
        page: the page to inspect

    Returns:
        The dict returned from _login_eval
    """
    # check first main page
    try:
        return await _login_eval(page)
    except Exception:
        result = await _login_eval(page)
        if result:
            return result
    except Exception:
        pass

    main_origin = urlparse(page.url).netloc

    # if several frames to check
    for frame in page.frames:
        if frame == page.main_frame:
            continue

        # Ignore third-party frames (ads, trackers, etc.)
        try:
            frame_origin = urlparse(frame.url).netloc
            if frame_origin != main_origin:
                continue
        except Exception:
            continue

        try:
            return await _login_eval(frame)
        except Exception:
            pass

    return {"password_input": False, "email_input": False, "passkey_btn": False }

async def _click_login_candidate(page: Page) -> bool:
    """
    Last-resort JS-only login click.
    Used when Playwright interactions fail (shadow DOM, overlays, JS handlers).
    """
    clicked = await safe_evaluate(
        page,
        """
        (() => {
            if (!document || !document.body) return false;

            const matches = [];
            const walk = (root) => {
                const els = root.querySelectorAll('a, button');
                const els = root.querySelectorAll('a, button');
                for (const el of els) {
                    const text = (el.innerText || "").trim();
                    if (/log\\s*in|sign\\s*in|account|passkey/i.test(text)) {
                        matches.push({ text, el });
                    }
                }
                const all = root.querySelectorAll('*');
                for (const el of all) if (el.shadowRoot) walk(el.shadowRoot);
            };
            walk(document);

            for (const m of matches) {
                try {
                    m.el.scrollIntoView({ block: 'center' });
                    m.el.click();
                    return true;
                } catch (e) {}
            }
            return false;
        })();
        """,
        default=False,
    )

    if clicked:
        await asyncio.sleep(1)
        return True

    return False

async def _try_avatar_selectors(page: Page) -> bool:
    """
    Attempts to click avatar/icon-based login buttons.

    Many modern sites use icon-only buttons (no text) for login, typically
    showing a user avatar or account icon in the header.

    This function tries all AVATAR_LOGIN_SELECTORS with fast timeouts to
    avoid slowing down the overall login detection process.

    Args:
        page: Playwright Page object

    Returns:
        True if an avatar/icon was successfully clicked, False otherwise
    """
    url = page.url
    for selector in AVATAR_LOGIN_SELECTORS:
        try:
            # Fast check with short timeout
            element = page.locator(selector).first

            # Check if element exists (with minimal timeout)
            count = await element.count()
            if count > 0:
                # Check visibility (short timeout to avoid delays)
                is_visible = await element.is_visible(timeout=500)
                if is_visible:
                    # Click the element
                    await element.click(timeout=1000)
                    logger.info(f"Clicked avatar/icon login: {selector}")
                    logger.info(f"Clicked avatar/icon login: {selector}")

                    # Track click if results attached to page
                    if hasattr(page, '_fidology_results'):
                        page._fidology_results["nb_clicks"] = page._fidology_results.get("nb_clicks", 0) + 1

                    res = await _is_login_visible(page)
                    if any(res.values()):
                        await save_screenshot(page, page.url)
                        return {"login": True, "cloudflare": False,"multistep": 0, "checks": res}
                    else:
                        await page.goto(url, timeout=3000, wait_until="load")

        except Exception as e:
            # Continue with next selector on any error
            # (timeout, element not found, not visible, etc.)
            logger.debug(f"Avatar selector failed: {selector} - {e}")
            continue

    # No avatar/icon found or clicked
    return False

async def _checking_for_cloudflare(page):
    """
    Function to try detecting Cloudflare challenges when trying to go to login page
    """
    try:
        elements = await page.query_selector_all("h2")
        for element in elements:
            html = (await element.inner_text() or "").lower()
            if cloudflare_patterns.search(html):
                return True
            else:
                return False
    except Exception:
        return False

    elements = await page.query_selector_all("h2")
    for element in elements:
        html = (await element.inner_text() or "").lower()
        if cloudflare_patterns.search(html):
            return True
        else:
            return False

async def _detect_login_or_multistep(page: Page, site_url: str, depth: int, previous_text: str) -> dict:
    """
    Search the login page by trying href or buttons, detecting multistep when existing

    Params:
        page: the page to inspect
        site_url: the initial url of the page
        depth: the depth of the multistep login process
        previous_text: the previously clicked element in case of multistep

    Retuns:
        A dict with login sucess and the depth of multistep login process: {"login": bool, "multistep": int}
    """
    # Stabilize dynamic frontend rendering (React/Tailwind sites)
    try:
        await page.wait_for_load_state("networkidle", timeout=3000)
        await asyncio.sleep(1.2)
    except:
        pass


    if depth >= 2:
        return {"login": False, "cloudflare": False, "multistep": depth, "checks": {'password_input': False, 'email_input': False, 'passkey_btn': False}}

    initial_dom = await page.content()
    before_dom = initial_dom
    site_url = page.url
    i = -1
    navigated = False

    try:
        while(True):
            try:
                # loop initiation
                i += 1
                if navigated:
                    await page.goto(site_url, timeout=3000, wait_until="load")
                    initial_dom = await page.content()
                    before_dom = initial_dom

                navigated = False

                # querying elements
                locator = page.locator("a, button, [role='button']")
                count = await locator.count()

                # if nothing, then impossible to do something here
                if count == 0:
                    logger.info("Website is not happy with scraping.")
                    break
                # check if we passed over all elements
                if i >= count:
                    break
                el = locator.nth(i)

                text = (await el.inner_text() or "").strip().lower()
                class_attr = (await el.get_attribute("class") or "").lower()
                href = await el.get_attribute("href") or ""

                # for avoiding clicking on same element when multistep
                if previous_text == text:
                    continue

                # for next call
                previous_text = text

                # if some info has login pattern
                if login_patterns.search(text) or login_patterns.search(class_attr) or login_patterns.search(href):

                    # href -> navigation -> check page
                    if href:
                        if href.startswith("https"):
                            full_url = href
                        else:
                            full_url = urljoin(site_url, href)

                        navigated = True
                        try:
                            await page.goto(full_url, timeout=3000, wait_until="load")
                        except Exception:
                            continue

                        res = await _is_login_visible(page)
                        if any(res.values()):
                            logger.info(f"Navigated to login page with href element in main DOM: '{text}'")
                            await save_screenshot(page, page.url)
                            return {"login": True, "cloudflare": False, "multistep": depth, "checks": res}

                        elif await _checking_for_cloudflare(page):
                            logger.info("Cloudflare challenge detected, nothing more to do.")
                            return {"login": False, "cloudflare": True, "multistep": depth, "checks": {'password_input': False, 'email_input': False, 'passkey_btn': False}}
                    else:
                        try:
                            await el.click(timeout=1000)
                            page._fidology_results["nb_clicks"] = page._fidology_results.get("nb_clicks", 0) + 1
                        except playwright.async_api.TimeoutError:
                            continue
                        except Exception:
                            continue

                        await asyncio.sleep(1)
                        current_dom = await page.content()

                        # got navigation
                        if page.url != site_url :
                            navigated = True
                            res = await _is_login_visible(page)
                            if any(res.values()):
                                logger.info(f"Navigated to login page with button click in main DOM: '{text}'")
                                await save_screenshot(page, page.url)
                                return {"login": True, "cloudflare": False, "multistep": depth, "checks": res}

                            elif await _checking_for_cloudflare(page):
                                logger.info("Cloudflare challenge detected, nothing more to do.")
                                return {"login": False, "cloudflare": True, "multistep": depth, "checks": {'password_input': False, 'email_input': False, 'passkey_btn': False}}
                            else:
                                logger.info(f"Navigated to another page, trying multistep login.")
                                res = await _detect_login_or_multistep(page, page.url, depth + 1, previous_text)
                                depth = res["multistep"]
                                if res["login"]:
                                    return res

                        elif current_dom != before_dom:
                            # modal or popup
                            res = await _is_login_visible(page)

                            if any(res.values()):
                                logger.info(f"Navigated to login page with button click in main DOM: '{text}'")
                                await save_screenshot(page, page.url)
                                return {"login": True, "cloudflare": False, "multistep": depth, "checks": res}
                            elif await _checking_for_cloudflare(page):
                                logger.info("Cloudflare challenge detected, nothing more to do.")
                                return {"login": False, "cloudflare": True, "multistep": depth, "checks": {'password_input': False, 'email_input': False, 'passkey_btn': False}}
                            # dropdown with options
                            else:
                                logger.info("Got maybe a dropdown, trying multistep login.")
                                res = await _detect_login_or_multistep(page, page.url, depth + 1, previous_text)
                                depth = res["multistep"]
                                if res["login"]:
                                    return res
            except Exception:
                continue

    except Exception:
        pass

    return {"login": False, "cloudflare": False, "multistep": depth, "checks": {'password_input': False, 'email_input': False, 'passkey_btn': False}}

async def navigate_to_login(page: Page, site_url: str, timeout: float = 15.0) -> bool:
    """
    Adaptive login navigation for dynamic sites with Shadow DOM/iframes.

    New strategy:
    0. Try see if we are directly on login page
    1. Searching for login buttons/href in DOM
    2. Searching for login by URL
    3. Avatar based (less frequent or should be detected earlier)
    4. JS last resort or Shadow dom inspection

    To confirm that the page is a login page, check with function '_is_login_visible'

    Returns True if login page is reached or login UI is exposed.
    """
    depth = 0

    ############################
    #   Step 0: Direct login   #
    ############################
    res = await _is_login_visible(page)
    if any(res.values()):
        await save_screenshot(page, page.url)
        logger.info(f"Home page is the login page.")
        return {"login": True, "cloudflare": False, "multistep": depth, "checks": res}

    ############################
    #   Step 1: Buttons/href   #
    ############################
    logger.info("Trying <a>/<button> for login page detection.")

    try:
        result = await _detect_login_or_multistep(page, site_url, 0, None)
        if result["login"] or result['cloudflare']:
            return result
    except:
        pass

    elements = await page.query_selector_all("a, button,[role='button'],span")

    for el in elements:
        try:
            href = await el.get_attribute("href") or ""
            #text = (await el.inner_text() or "").lower()
            text = (
                (await el.inner_text() or "")
                or (await el.text_content() or "")
                or (await el.get_attribute("aria-label") or "")
            ).lower()

            if ("/app/login" in href or "/login" in href or "/user/signin" in href or login_keywords.search(text)):
                # navigation directe si href présent
                if href:
                    full_url = urljoin(page.url, href)
                    await page.goto(full_url, wait_until="domcontentloaded", timeout=3000)
                else:
                    parent = await el.evaluate_handle("el => el.closest('a')")
                    if parent:
                        el = parent

                    if not await _click_element(el):
                        continue

                await asyncio.sleep(0.8)

                return {"login": True, "cloudflare": False,
                    "multistep": depth, "checks": await _is_login_visible(page)}

        except:
            pass

    logger.info("Failed <a>/<button> for login page detection.")

    #############################
    #     Step 2: URL login     #
    #############################
    logger.info("Trying URL paths for login page detection.")

    for path in COMMON_LOGIN_PATHS:

        base_url = site_url.rstrip()
        if base_url[-1] == "/":
            login_url = base_url[0:-1] + path
        else:
            login_url = base_url + path
        try:
            logger.info("trying URL")
            await page.goto(login_url, timeout=3000, wait_until="load")
            res = await _is_login_visible(page)
            if any(res.values()):
                logger.info(f"Found login page with URL path: {login_url}")
                await save_screenshot(page, page.url)
                return {"login": True, "cloudflare": False, "multistep": depth, "checks": res}

        except Exception:
            await page.wait_for_load_state("load", timeout=1000)
            continue

    logger.info("Failed URL paths for login page detection.")

    ############################
    #   Step 3: Avatar login   #
    ############################
    logger.info("Trying avatar/icon-based login selectors for login page detection.")

    avatar_clicked = await _try_avatar_selectors(page)

    if avatar_clicked:
        # Wait for potential dropdown menu or login modal to appear
        await asyncio.sleep(1)

        # Check if login UI is now visible
        res = await _is_login_visible(page)
        if any(res.values()):
            logger.info("Login UI exposed via avatar/icon click")
            await save_screenshot(page, page.url)
            return {"login": True, "cloudflare": False, "multistep": depth, "checks": res}

        # Avatar clicked but no login visible yet - continue with other methods
        logger.debug("Avatar clicked but login UI not immediately visible")

    logger.info("Failed avatar/icon-based login selectors for login page detection.")

   ############################
    #   Step 4: JS/shadow dom  #
    ############################
    # Shadow DOM
    await page.goto(site_url, timeout=2500, wait_until="domcontentloaded")

    shadow_candidates = await safe_evaluate(
            page,
            """
            () => {
                if (!document || !document.body) return [];

                const results = [];
                const walk = (root) => {
                    const els = root.querySelectorAll('a, button, [role="button"]');
                    for (const el of els) {
                        const text = (el.innerText || "").trim();
                        if (text) results.push(text);
                    }
                    const all = root.querySelectorAll('*');
                    for (const el of all) if (el.shadowRoot) walk(el.shadowRoot);
                };
                walk(document);
                return results;
            }
            """,
            default=[]
        )

    for text in shadow_candidates:
        if not login_patterns.search(text):
            continue

        try:
            elements = await page.query_selector_all("a, button, [role='button']")
            for el in elements:
                el_text = (await el.inner_text() or "").strip()
                if el_text == text:
                    if await _click_element(el):
                        await asyncio.sleep(0.8)
                        res = await _is_login_visible(page)
                        if any(res.values()):
                            logger.info(f"Clicked login element in shadow DOM: '{text}'")
                            await save_screenshot(page, page.url)
                            return {"login": True, "cloudflare": False, "multistep": depth, "checks": res}
        except Exception:
            pass

    await page.goto(site_url, timeout=2500, wait_until="domcontentloaded")

    # 3c. Iframes
    try:
        for frame in page.frames:
            elements = await frame.query_selector_all("a, button")
            for el in elements:
                text = (await el.inner_text() or "").strip()
                if login_patterns.search(text):
                    if await _click_element(el):
                        await asyncio.sleep(0.8)
                        res = await _is_login_visible(page)
                        if any(res.values()):
                            logger.info(f"Clicked login element in iframe: '{text}'")
                            await save_screenshot(page, page.url)
                            return {"login": True, "cloudflare": False, "multistep": depth, "checks": res}
    except Exception:
        pass

    # JS-only fallback (last resort)
    clicked = await safe_await(
        lambda: _click_login_candidate(page),
        timeout=2, label="_click_login_candidate",
        default=False
    )
    if clicked:
        await asyncio.sleep(0.8)
        res = await _is_login_visible(page)
        if any(res.values()):
            logger.info("Login reached via JS-only fallback click")
            await save_screenshot(page, page.url)
            return {"login": True, "cloudflare": False, "multistep": depth, "checks": res}

    logger.info("Login navigation failed (no element or URL found)")

    return {"login": False, "cloudflare": False, "multistep": depth, "checks": {'password_input': False, 'email_input': False, 'passkey_btn': False}}
