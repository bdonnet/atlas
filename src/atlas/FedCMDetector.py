"""
FedCM (Federated Crediential Management) provides a standard mechanism for
identity providers (IdPs) to make identity federation services available on the
web in a privacy-preserving way, without the need for third-party cookies and
 edirects.

This includes a JavaScript API that enables the use of federated authentication
for activities such as signing in or signing up on a website.
"""
from import_data import *

__all__ = ["detect_fedcm"]

async def detect_fedcm(page) -> Dict[str, Any]:
    """
    Detects possible usage of FedCM (Federated Credential Management) on a given Playwright page.
    Combines:
      1. Console message analysis (heuristic)
      2. Intercepted navigator.credentials.get() API calls (technical evidence)
    """

    fedcm_detected = False
    fedcm_provider = None
    fido2_hint = False
    detected_via_api = False

    # 1. Check console messages
    console_logs = []
    page.on("console", lambda msg: console_logs.append(msg.text))

    for msg in console_logs:
        msg_lower = msg.lower()
        if "fedcm" in msg_lower or "identity" in msg_lower:
            fedcm_detected = True
            for idp in KNOWN_FEDCM_IDPS:
                if idp in msg_lower:
                    fedcm_provider = idp.capitalize()
                    if idp in ["google", "apple", "microsoft"]:
                        fido2_hint = True
                    break

    # 2. Analysis through navigator.credentials.get() (hook JS)
    try:
        credentials_params = getattr(page.context, "_fedcm_credentials_params", {})
        get_calls = credentials_params.get("get", [])

        for call in get_calls:
            # Call might be a str (JSON) or a dictionary
            if isinstance(call, str):
                try:
                    call = json.loads(call)
                except Exception:
                    continue

            if not isinstance(call, dict):
                continue

            # Detecting "identity" block
            if "identity" in call:
                fedcm_detected = True
                detected_via_api = True

                providers = call["identity"].get("providers", [])
                for provider in providers:
                    config_url = provider.get("configURL", "").lower()
                    for idp in KNOWN_FEDCM_IDPS:
                        if idp in config_url:
                            fedcm_provider = idp.capitalize()
                            if idp in ["google", "apple", "microsoft"]:
                                fido2_hint = True
                            break
    except Exception as e:
        logger.warning(f"FedCM API detection failed: {e}")

    # Sum up results
    result = {
        "fedcm_present": fedcm_detected,
        "fedcm_provider": fedcm_provider,
        "fido2_indirect_possible": fido2_hint,
        "fedcm_detected_via_api": detected_via_api,
    }

    logger.debug(f"FedCM detection result: {result}")
    return result
