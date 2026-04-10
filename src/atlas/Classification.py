"""
Performs the final classification by combining observed signals.
"""

from import_data import *

__all__ = ["infer_authentication", "finalize_classification"]

async def infer_authentication(result: Dict[str, Any]) -> str:
    """
    Infers the way FIDO2, OTP, or password-based authentication is used
    with respect to site analysis.

    Usages:
        - 'none': no clues detected.
        - 'error': analysis error or navigation failure.
        - 'password_only': authentication relies only on classic password.
        - 'password+otp': password plus one-time code / OTP / 2FA.
        - 'password+fido': password plus FIDO2 (2FA or optional FIDO2).
        - 'mixed':  hybrid cases or multiple mechanisms detected (FIDO + OTP + password)
        - 'webauthn': clear usage of WebAuthn API without any other elements.
        - 'storage': clues about FIDO2 in local storage only.
        - 'fido_only_ui': keywords for FIDO only in UI.
        - 'full_fido2': full or passwordless FIDO2 authentication.
        - 'latent_support': indirect or potential FIDO2 support (e.g., FedCM).
        - 'latent_usage':  Evidence of potential or inactive FIDO2 support
        - 'unknown': ambiguous or mixed cases.
    """
    ############################################################################
    #                           Error shortcut                                 #
    ############################################################################
    if "error" in result:
        return "error"

    ############################################################################
    #                           Preparing Signals                              #
    ############################################################################
    auth_unobservable = result.get("auth_surface_unobservable", False)
    auth_form_appeared = result.get("auth_form_appeared", False)

    # Core signals
    pw_explicit = (
        result.get("password_input_present", False)
        or result.get("password_input_in_shadow_dom", False)
    )

    pw_network = (
        result.get("network_password", False)
        and not pw_explicit
    )

    pw_any = (
        result.get("password_input_present", False)
        or result.get("password_input_in_shadow_dom", False)
    )

    # Weak / supporting signals
    storage = any([
        result.get("local_storage_contains_fido", False),
        result.get("session_storage_contains_fido", False),
        result.get("cookies_contain_fido", False),
    ])

    shadow = result.get("shadow_dom_webauthn", False)
    ui_keywords = result.get("ui_webauthn_keywords_present", False)

    weak_fido = storage or shadow or ui_keywords

    # Strong WebAuthn / FIDO2 signals
    passkey_ui_present = result.get("ui_webauthn_keywords_present", False)
    passkey_triggered = result.get("webauthn_triggered", False)
    net = result.get("network_webauthn", False)
    credentials = result.get("credentials_api_used", False)
    credentials_summary = bool(result.get("credentials_create_summary"))

    strong_fido = net or credentials or credentials_summary

    passkey_flow_available = strong_fido and ui_keywords

    # OTP indicators
    otp_present = result.get("otp_indicators_present", False)

    # FedCM / latent signals
    fedcm_present = result.get("fedcm_present", False)
    fedcm_provider = result.get("fedcm_provider", False)
    fido2_indirect = result.get("fido2_indirect_possible", False)
    fedcm_detected_via_api = result.get("fedcm_detected_via_api", False)

    fedcm_signal = (
        fido2_indirect or fedcm_detected_via_api
        or (fedcm_present and fedcm_provider in KNOWN_FEDCM_IDPS)
    )

    latent_support = result.get("latent_support", False)

    auth_js_supports_passkey = result.get("auth_js_supports_passkey", False)

    # iframe DOM reinforcement
    iframe_results = result.get("iframe_dom_results", [])

    if isinstance(iframe_results, list):
        for r in iframe_results:
            if not isinstance(r, dict):
                continue

            # Reinforce password detection
            if r.get("password_input_present", False):
                pw_explicit = True
                pw_any = True

            # Reinforce credentials API
            if r.get("credentials_api_used", False):
                strong_fido = True

            # Reinforce UI / shadow hints
            if r.get("ui_webauthn_keywords_present", False) or r.get("shadow_dom_webauthn", False):
                weak_fido = True

    ############################################################################
    #                               Decision tree                              #
    ############################################################################

    # 1. No signal at all
    if not any([
        pw_explicit, pw_network, otp_present, strong_fido, weak_fido,
        fedcm_signal, latent_support
    ]):
        # 1.a can't observe authentication surface
        if auth_unobservable and not auth_form_appeared:
            return "auth_surface_unobservable"

        # 1.b authentication through cross-origin
        if result.get("auth_surface_type") == "iframe_cross_origin":
            return "unknown_cross_origin"

        # 1.c cannot observe any signal
        # Notice: if auth_surface_observable==True and none => closed shadow DOM
        return "none"

    # 2. JavaScript Passkey Support (Latent)
    if auth_js_supports_passkey and not strong_fido:
        # Even if password is present, the JS support indicates latent capability
        if pw_any and not otp_present:
            # Password + JS passkey support (but not active) = latent_support
            # This prevents misclassification as "password_only"
            return "latent_support"

        # If no password but JS support = also latent
        if not pw_any:
            return "latent_support"

    # 2. Password only (basic case)
    if pw_any and not any([
        otp_present, strong_fido, weak_fido, fedcm_signal, latent_support, auth_js_supports_passkey
    ]):
        return "password_only"

    # 2. Password only (opaque / network inferred)
    if pw_network and not any([
        otp_present, strong_fido, weak_fido, fedcm_signal, latent_support, auth_js_supports_passkey
    ]):
        return "password_only"

    # 3. Password + OTP (classic 2FA)
    if (pw_explicit or pw_network) and otp_present and not any([
        strong_fido, weak_fido, fedcm_signal, auth_js_supports_passkey
    ]):
        return "password+otp"

    # 4. Password + FIDO2 (distinguish MFA vs alternative login)
    if (pw_explicit or pw_network) and (strong_fido or fedcm_signal):
        # detect passwordless alternative flow
        if strong_fido and ui_keywords:
            return "full_fido2"

        return "password+fido"

    # 5. WebAuthn only (API-level, no password, no UI/storage)
    if strong_fido and not any([
        pw_any, weak_fido, fedcm_signal
    ]):
        return "webauthn"

    # 6. FIDO UI only (no API, no password)
    if (shadow or ui_keywords) and not any([
        pw_any, strong_fido, storage, fedcm_signal
    ]):
        return "fido_only_ui"

    # 7. Storage only (persistent traces, nothing else)
    if storage and not any([
        pw_any, strong_fido, shadow, ui_keywords, fedcm_signal
    ]):
        return "storage"

    # 8. Full / passwordless FIDO2
    if strong_fido and (weak_fido or fedcm_signal):
        return "full_fido2"

    # 9. Latent support explicitly detected
    if latent_support or fedcm_signal:
        return "latent_support"

    # 10. Latent usage (artefacts without activation)
    if not pw_any and not strong_fido and (weak_fido or storage):
        return "latent_usage"

    # 11. Guard rail: indirect FIDO signals must not result in 'unknown'
    if any([weak_fido, storage, fedcm_signal, auth_js_supports_passkey]):
        return "latent_support"

    # 12. Ambiguous or mixed
    return "unknown"

async def finalize_classification(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Finalizes authentication inference and computes confidence score

    Params:
        dictionay of signals captured

    Results:
        dictionary updated with inference and confidence score
    """
    # 1. Opaque pwd inference + network signal update
    await _infer_opaque_password_usage(results)

    # 2. Confidence score + explanation
    eval_ret = compute_score(results, results["fido2_usage"])

    # Possibly normalize returned values
    score = 0.0
    explanation = None

    if isinstance(eval_ret, (tuple, list)):
        # trying to interpret what has been returned
        try:
            score = float(eval_ret[0])
        except Exception:
            score = 0.0
        if len(eval_ret) > 1 and eval_ret[1] is not None:
            explanation = str(eval_ret[1])
    else:
        # only got the score
        try:
            score = float(eval_ret)
        except Exception:
            score = 0.0

    # Clamp and round up
    score = max(0.0, min(score, 1.0))
    results["fido2_confidence"] = round(score, 3)

    # 3. Automatic diagnosis in case of low confidence
    diag = diagnose_low_confidence_case(results)

    # If comments provided by confidence calculcation, prioritizing/concataining
    results["fido2_confidence_diagnosis"] = ""
    if diag and explanation:
        results["fido2_confidence_diagnosis"] = f"{explanation} | {diag}"
    elif diag:
        results["fido2_confidence_diagnosis"] = diag
    elif explanation:
        results["fido2_confidence_diagnosis"] = explanation
    #otherwise empty

    # 4. Likely 2FA?
    usage = results.get("fido2_usage", "unknown")
    results["likely_2fa"] = usage in ("password+otp", "password+fido", "mixed", "full_fido2")

    return results

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

async def _infer_opaque_password_usage(results: dict) -> None:
    """
    If no strong FIDO2/FedCM detected but login navigation succeeded
    or network password seen, infer password-based authentication.

    Sets:
        results['fido2_usage']
        results['fido2_confidence']
        results['fido2_confidence_diagnosis']
        results['latent_support'] if latent support inferred
    """
    # Already detected strong FIDO2? Skip
    if results.get("fido2_usage") not in [None, "none", "password_based_opaque", "password_based_network"]:
        return

    # Conditions for password-based detection
    login_visible = (
        results.get("login_navigation_successful", False)
        and results.get("login_ui_forced", False)
        and results.get("auth_surface_type") in ["redirect", "popup", "iframe_same_origin"]
    )

    network_password_signal = results.get("network_webauthn") == False and results.get("network_password", False)

    # Detect latent FIDO2 support via backend/frontend JS
    passkey_detected = (
        results.get("passkey_setup_endpoint_present", False)
        or results.get("auth_js_supports_passkey", False)
    )

    if (login_visible or network_password_signal) and passkey_detected:
        results["fido2_usage"] = "latent_support"
        results["latent_support"] = True
        results["fido2_confidence"] = OBSERVABILITY_PENALTIES.get("latent_support", 0.5)
        results["fido2_confidence_diagnosis"] = (
            "Password-based authentication detected. "
            "Passkey/FIDO2 support present in backend or frontend code "
            "but not activated during observed session."
        )

async def _update_from_network_signals(results: dict) -> None:
    """
    If network requests indicate password usage, promote confidence.
    """
    if results.get("fido2_usage") in [None, "none"]:
        if results.get("network_password", False):
            results["fido2_usage"] = "password_based_network"
            results["fido2_confidence"] = OBSERVABILITY_PENALTIES["password_based_network"]
