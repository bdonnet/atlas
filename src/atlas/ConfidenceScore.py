"""
Provides a confidence score for authentication mechanism classification.
The main objective is to quantify the reliability of heuristic classification results.

It works by weighting the presence of specific FIDO2-related signals:
    - WebAuthn network requests:               +0.25
    - API `navigator.credentials.create()`     +0.2
    - API `navigator.credentials.get()`        +0.3
    - Shadow DOM with FIDO2 keywords:          +0.08
    - FIDO in local storage:                   +0.1
    - FIDO in session storage:                 +0.05
    - FIDO in cookies:                         +0.02
    - multisteps login                         +0.03
    - password field in Domain                 +0.02
    - FedCM API fedcm_present                  +0.05
    - FedCM detected through API  calls        +0.1
    - Strong signal FIDO2 with FedCM           +0.12
    - OTP                                      +0.08

Interpretation of the confidence score (subjective scale):
    - ≥ 0.8: highly reliable classification
    - [0.5, 0.8]: some serious indicators present
    - < 0.5: weak or conflicting signals; classification uncertain
"""

from import_data import *

__all__ = ["compute_score", "diagnose_low_confidence_case"]

def _apply_observability_penalties(confidence: float, result: Dict[str, Any]) -> float:
    """
    Applies penalties to confidence score when authentication surface
    cannot be reliably observed.
    """
    for signal, penalty in OBSERVABILITY_PENALTIES.items():
        if result.get(signal, False):
            confidence = min(confidence, 1.0 - penalty)
    return confidence

def compute_score(results: Dict[str, Any], auth_classif: str) -> tuple[float, str]:
    """
    Computes a confidence score (0.0–1.0) for the inferred authentication mode.

    This version enforces:
      - A MINIMUM score for each fido_usage category (based on the reference table).
      - A MAXIMUM score (cap) for each category.
      - Preservation of the existing signal-based weighting logic.

    The typical score intervals come directly from the specification table provided:

        | Usage                     | Range         |
        |---------------------------|---------------|
        | none                      | 0.00 – 0.05   |
        | password_only             | 0.05 – 0.20   |
        | password+otp              | 0.25 – 0.45   |
        | password+fido             | 0.45 – 0.70   |
        | mixed                     | 0.40 – 0.65   |
        | webauthn                  | 0.60 – 0.80   |
        | storage                   | 0.40 – 0.55   |
        | fido_only_ui              | 0.25 – 0.35   |
        | latent_support            | 0.25 – 0.40   |
        | latent_usage              | 0.35 – 0.50   |
        | full_fido2                | 0.80 – 1.00   |
        | unknown                   | 0.20 – 0.40   |
        | error                     | 0.00          |
    """
    # 1. Score computation from raw weighted signals
    score = 0.0
    for signal, weight in SIGNAL_WEIGHTS.items():
        if results.get(signal, False):
            score += weight

    score = min(score, 1.0)

    # Additional signals used in some logic paths
    otp_present = results.get("otp_indicators_present", False)
    fedcm_hint = results.get("fedcm_fido2_hint", False)
    latent = results.get("latent_support", False)

    min_score, max_score = SIGNAL_WEIGHTS_RANGES.get(auth_classif, (0.0, 0.4))

    diagnosis = []

    # 2. Usage-specific logic
    if auth_classif == "password_only":
        diagnosis.append("Password-only authentication detected (no FIDO2 or OTP).")

        # Preserve original behavior: cap at 0.15 but enforce table minimum 0.05
        score = min(score, 0.15)
        if results.get("password_input_present", False):
            score = max(score, min_score)

    elif auth_classif == "password+otp":
        diagnosis.append("Password + OTP (two-factor) detected.")
        # Original logic: baseline + bonus if otp detected
        score = 0.25 + (0.2 if otp_present else 0.0)

    elif auth_classif == "password+fido":
        diagnosis.append("Password + FIDO2 authentication detected (hybrid).")
        score = 0.45 + min(0.25, score)

    elif auth_classif == "webauthn":
        diagnosis.append("Direct use of WebAuthn API detected.")
        score = max(score, 0.6)

    elif auth_classif == "fido_only_ui":
        diagnosis.append("FIDO/passkey keywords visible in UI only.")
        score = min(score, 0.3)

    elif auth_classif == "storage":
        diagnosis.append("FIDO2 data detected in browser storage.")
        score = max(score, 0.4)

    elif auth_classif == "full_fido2":
        diagnosis.append("Full FIDO2 authentication flow detected.")
        score = max(score, 0.85)

    elif auth_classif == "latent_support":
        diagnosis.append(
            "Password-based authentication detected. "
            "Passkey/FIDO2 support present in backend or frontend code but not activated during observed session."
        )

        score = 0.25  # table baseline

        # FedCM / indirect hints
        if fedcm_hint:
            score += 0.05

        # Explicit latent flag from classifier
        if latent:
            score += 0.05

        # concrete passkey support signals
        if results.get("passkey_setup_endpoint_present", False):
            score += 0.05

        if results.get("auth_js_supports_passkey", False):
            score += 0.05

        if results.get("auth_surface_unobservable", False):
            score = min(score, 0.35)

    elif auth_classif == "latent_usage":
        diagnosis.append("FIDO2 present in storage/config but inactive.")
        score = max(score, 0.35)

    elif auth_classif == "none":
        diagnosis.append("No authentication clues detected.")
        score = 0.0

    elif auth_classif == "unknown":
        diagnosis.append("Ambiguous or mixed signals detected.")
        score = 0.2 + (score * 0.3)

    elif auth_classif == "error":
        if results['auth_form_appeared']:
            diagnosis.append("Likely closed Shadow DOM.")
        else:
            diagnosis.append("Error during navigation or analysis.")
        score = 0.0

    elif auth_classif == "unknown_cross_origin":
        diagnosis.append("Authentication surface is cross-origin; signals cannot be fully captured.")

    # --- Password usage penalty (anti false-positive for passwordless flows)
    if results.get("network_password", False):
        if auth_classif in ("webauthn", "full_fido2"):
            score -= 0.10
        elif auth_classif in ("password+fido", "mixed"):
            score -= 0.05

    # 3. Reinforcement from direct API evidence (kept identical)
    if auth_classif in ("password+fido", "full_fido2", "webauthn"):
        if results.get("credentials_api_used", False) or results.get("network_webauthn", False):
            score += 0.05

    # 4. Apply observability penalties (cross-origin auth surfaces, etc.)
    score = _apply_observability_penalties(score, results)

    # 5. Final enforcement of min/max interval
    score = max(min_score, min(score, max_score))
    score = min(round(score, 3), 1.0)
    return score, " ".join(diagnosis)

def diagnose_low_confidence_case(results: Dict[str, Any], threshold: float = THRESHOLD_SIGNAL_CONFIDENCE) -> Optional[str]:
    """
    Diagnoses cases where the confidence in inferring FIDO2 usage is low while significant signals were detected.

    Params:
        results: dictionary representing heuristics results for a given site (mandatory)
        threshold: threshold below which the score is considered as low (default = THRESHOLD_SIGNAL_CONFIDENCE)

    Returns:
        A textual explanation if a potential inconsistency or low-confidence case is detected, else None.
    """
    score = results.get("fido2_confidence", 1.0)
    usage = results.get("fido2_usage", "unknown")

    # 1. Normal low-confidence cases
    if score >= threshold:
        return None

    # 2. Ignore normal password-only cases with no extra signal
    if usage == "password_only":
        signals_present = any(results.get(key, False) for key in [
            "network_webauthn",
            "local_storage_contains_fido",
            "session_storage_contains_fido",
            "cookies_contain_fido",
            "shadow_dom_webauthn",
            "credentials_api_used",
            "ui_webauthn_keywords_present",
            "fedcm_present",
            "fedcm_fido2_hint",
            "fedcm_detected_via_api",
            "otp_indicators_present",
        ]) or bool(results.get("credentials_create_summary"))

        if not signals_present:
            return None

    # 3. Handle latent or indirect support cases
    if usage in ("latent_support", "latent_usage"):
        if score < threshold:
            return (
                f"Low confidence ({score}) despite detection of latent or indirect FIDO2 signals "
                f"(FedCM/UI/storage but no active WebAuthn)."
            )
        return None

    if usage == "password_based_low_confidence":
        return "No FIDO2 signals, login UI detected, fallback to low-confidence password."

    if usage == "password_based_network":
        return "Network request indicates password usage."

    if usage == "password_based_opaque":
        return "Login UI detected but no DOM password input. Assuming password-based."

    # 4. Build list of active signals
    signals_present_list = [
        key for key in [
            "network_webauthn",
            "local_storage_contains_fido",
            "session_storage_contains_fido",
            "cookies_contain_fido",
            "shadow_dom_webauthn",
            "credentials_api_used",
            "ui_webauthn_keywords_present",
            "fedcm_present",
            "fedcm_fido2_hint",
            "otp_indicators_present",
        ]
        if results.get(key, False)
    ]

    if results.get("credentials_create_summary"):
        signals_present_list.append("credentials_create_summary")

    # 5. Tailored diagnostics per category
    if not signals_present_list:
        return None

    if usage in ("password+fido", "password+otp", "mixed"):
        return (
            f"Low confidence ({score}) for usage '{usage}' "
            f"despite active signals suggesting partial multi-factor or hybrid flow: "
            f"{', '.join(signals_present_list)}"
        )

    return (
        f"Low confidence ({score}) for usage '{usage}' "
        f"despite active signals detected: {', '.join(signals_present_list)}"
    )
