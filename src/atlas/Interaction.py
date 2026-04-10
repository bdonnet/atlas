"""
Potential page escalation (i.e., clicks) under a maximum budget.

May better expose login page.
"""

from import_data import *
from utils import *

__all__ = ["should_auth_escalate", "perform_auth_escalation"]

AUTH_ESCALATION_LIMITS = {
    "max_clicks": 3,
    "max_redirects": 2,
    "max_extra_time": 12.0,  # seconds
}

def should_auth_escalate(results, state):
    """
    Checks whether authentication escalation makes sense or is allowed by
    the budget.
    """
    return (
        # clear login intention
        results.get("login_navigation_successful", False)
        and results.get("login_ui_forced", False)

        # no auth signal after Signals 1 –-> 4
        and not results.get("password_input_present", False)
        and not results.get("password_input_in_shadow_dom", False)
        and not results.get("ui_webauthn_keywords_present", False)
        and not results.get("shadow_dom_webauthn", False)

        # Particular case where opacity is plausible
        and results.get("auth_surface_type") in (
            "popup",
            "iframe_same_origin",
            "redirect",
        )

        # Budget OK
        and _can_click(state)
    )

async def perform_auth_escalation(page, results: dict, state: dict, login_frame) -> tuple[dict, dict, any]:
    """
    Performs a light authentication escalation to try to expose login UI or hidden inputs.

    Params:
        page         : Playwright Page object
        results      : dict, collected auth signals so far
        state        : dict, auth escalation state (clicks, redirects, extra_time)
        login_frame  : current login frame (main_frame if popup not detected)

    Returns:
        results     : updated signals dict
        state       : updated auth_escalation_state
        login_frame : updated login_frame after escalation
    """

    # 1. Attempt to force expose login UI if clicks budget allows
    if _can_click(state):
        try:
            forced = await safe_await(
                lambda: force_expose_login_ui(page),
                timeout=2, label="force_expose_login_ui (escalation)"
            )
            if forced:
                _register_click(state)
                state["extra_time"] += 1.0  # small time penalty
                results["login_ui_forced"] = results.get("login_ui_forced", False) or forced
        except Exception:
            pass

    # 2. Retry waiting for login popup if redirects budget allows
    if _can_redirect(state):
        try:
            frame = await safe_await(
                lambda: wait_for_login_popup(page, timeout=5.0),
                timeout=6.0, label="wait_for_login_popup_escalation"
            )
            login_frame = frame if frame else page.main_frame
            if frame:
                _register_redirect(state)
        except Exception:
            login_frame = page.main_frame

    # 3. Re-collect signals 1→4 in the (possibly) new login_frame
    try:
        auth_signals = await collect_auth_signals(page, login_frame)

        results["password_input_present"] = results.get("password_input_present", False) or auth_signals.get("password_input_present", False)
        results["password_input_in_shadow_dom"] = results.get("password_input_in_shadow_dom", False) or auth_signals.get("password_input_in_shadow_dom", False)
        results["ui_webauthn_keywords_present"] = results.get("ui_webauthn_keywords_present", False) or auth_signals.get("ui_webauthn_keywords_present", False)
        results["shadow_dom_webauthn"] = results.get("shadow_dom_webauthn", False) or auth_signals.get("shadow_dom_webauthn", False)
        results["login_iframe_cross_origin"] = auth_signals.get("login_iframe_cross_origin", False) #results.get("login_iframe_cross_origin", False) or
        results["login_iframe_src"] = results.get("login_iframe_src") or auth_signals.get("login_iframe_src")
    except Exception:
        pass

    # 4. Optional small delay to allow potential scripts / FedCM
    await asyncio.sleep(1.0)
    state["extra_time"] += 1.0

    return results, state, login_frame

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _can_click(state):
    """
    Checks click budget
    """
    return state["clicks"] < AUTH_ESCALATION_LIMITS["max_clicks"]

def _register_click(state):
    """
    Registers click in the budget
    """
    state["clicks"] += 1

def _can_redirect(state):
    """
    Checks redirection budget
    """
    return state["redirects"] < AUTH_ESCALATION_LIMITS["max_redirects"]

def _register_redirect(state):
    """
    Registers redirection in the budget
    """
    state["redirects"] += 1
