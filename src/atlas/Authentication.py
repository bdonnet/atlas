from import_data import *
from utils import *

__all__ = ["collect_auth_signals", "detect_auth_surface_type", "finalize_auth_observability"]

def finalize_auth_observability(results: dict) -> None:
    """
    Determines whether the authentication surface was effectively unobservable,
    after all reasonable collection steps have been attempted.
    """

    observable_signals = [
        results.get("password_input_present"),
        results.get("password_input_in_shadow_dom"),
        results.get("ui_webauthn_keywords_present"),
        results.get("shadow_dom_webauthn"),
        results.get("credentials_api_used"),
        results.get("network_password"),
        results.get("network_webauthn"),
        results.get("fedcm_detected"),
        results.get("passkey_setup_endpoint_present"),
        results.get("auth_js_supports_passkey"),
        results.get("auth_form_appeared"),
    ]

    # Any strong auth-related signal = observable
    if any(observable_signals):
        results["auth_surface_unobservable"] = False
        return

    # Cross-origin iframe with no DOM access
    if results.get("login_iframe_cross_origin"):
        results["auth_surface_unobservable"] = True
        results["auth_surface_unobservable_reason"] = "cross_origin_iframe"
        return

    # Login navigation succeeded but no observable auth signals
    if (
        results.get("login_navigation_successful")
        and results.get("login_ui_forced")
    ):
        results["auth_surface_unobservable"] = True
        results["auth_surface_unobservable_reason"] = "js_orchestrated_or_native_auth"
        return

    results["auth_surface_unobservable"] = False
    return

def detect_auth_surface_type(*, login_navigation_successful: bool,
    login_ui_forced: bool, login_iframe_cross_origin: bool,
    login_frame) -> str:
    """
    Classifies the technical shape of the authentication surface.

    This function does NOT infer the authentication mechanism (password, FIDO2, OTP).
    It only describes *how* the login UI is presented from a structural standpoint.

    Possible return values:
        - iframe_cross_origin : login form hosted in a cross-origin iframe
        - iframe_same_origin  : login form hosted in a same-origin iframe
        - popup               : login surface exposed dynamically (modal / JS popup)
        - redirect            : full-page navigation to a login page
        - unknown              : unable to determine the auth surface type
    """

    # Highest priority: cross-origin iframe
    if login_iframe_cross_origin:
        return "iframe_cross_origin"

    # Same-origin iframe
    if login_frame is not None and hasattr(login_frame, "url"):
        # Frame detected and used as auth surface
        return "iframe_same_origin"

    # Dynamic popup / modal
    if login_ui_forced:
        return "popup"

    # Full-page redirect
    if login_navigation_successful:
        return "redirect"

    # Fallback
    return "unknown"

async def collect_auth_signals(page: Page, login_frame: Frame | Page) -> Dict[str, bool | str]:
    """
    Collects authentication-related signals from the main DOM or login frame.

    Handles cross-origin iframes by collecting indirect signals (iframe presence & src).

    Signals:
        - password_input_present (main DOM)
        - password_input_in_shadow_dom
        - ui_webauthn_keywords_present (main DOM)
        - shadow_dom_webauthn
        - login_iframe_cross_origin: True if login frame is cross-origin

    Params:
        page: Playwright Page
        login_frame: Frame or Page to inspect

    Returns:
        Dictionary with signals.
    """
    signals: Dict[str, bool | str] = {
        "password_input_present": False,
        "password_input_in_shadow_dom": False,
        "ui_webauthn_keywords_present": False,
        "shadow_dom_webauthn": False,
        "login_iframe_cross_origin": False,
        "login_iframe_src": "",
    }

    try:
        # Determine if login_frame is a cross-origin iframe
        frame_to_check = login_frame if isinstance(login_frame, Frame) else page.main_frame

        page_origin = _get_origin(page.url)
        frame_url = None

        try:
            frame_url = frame_to_check.url
        except Exception:
            frame_url = None

        frame_origin = _get_origin(frame_url)

        # about:blank / srcdoc / no url → SAME origin
        cross_origin = False
        if frame_origin and page_origin:
            cross_origin = frame_origin != page_origin

        signals["login_iframe_cross_origin"] = cross_origin
        signals["login_iframe_src"] = frame_url or ""

        # If not cross-origin, proceed with normal detection
        if not cross_origin:
            # Password input in DOM (page AND frame)
            # Check both page and login_frame to catch modal/popup/iframe forms
            page_to_check = login_frame.page if isinstance(login_frame, Frame) else page

            password_in_page = await safe_await(
                lambda: detect_password_input(page),
                timeout=1, default=False,
                label="detect_password_input (page)"
            )

            password_in_frame = await safe_await(
                lambda: detect_password_input(page_to_check),
                timeout=1, default=False,
                label="detect_password_input (frame)"
            )

            signals["password_input_present"] = password_in_page or password_in_frame

            # Password input in shadow DOM
            signals["password_input_in_shadow_dom"] = await safe_await(
                lambda: detect_password_inputs_in_shadow_dom(frame_to_check),
                timeout=5, default=False,
                label="detect_password_inputs_in_shadow_dom"
            )

            # WebAuthn keywords in main DOM
            page_to_check = login_frame.page if isinstance(login_frame, Frame) else page
            signals["ui_webauthn_keywords_present"] = await safe_await(
                lambda: detect_ui_keywords(page_to_check, UI_KEYWORDS),
                timeout=2, default=False,
                label="detect_ui_keywords"
            )

            # WebAuthn keywords in shadow DOM
            signals["shadow_dom_webauthn"] = await safe_await(
                lambda: detect_webauthn_keywords_in_shadow_dom(frame_to_check, FIDO_KEYWORDS),
                timeout=2, default=False,
                label="detect_webauthn_keywords_in_shadow_dom"
            )

    except Exception as e:
        logger.warning(f"Erreur collect_auth_signals: {e}")

    logger.debug(f"Collected auth signals: {signals}")
    return signals

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _get_origin(url: str | None) -> str | None:
    if not url or url in ("about:blank", ""):
        return None
    try:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return None
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return None
