"""
Analyses captured requests to detect WebAuthn/FIDO2 through patterns in URLs/headers.
"""

from import_data import *

__all__ = ["setup_network_logging", "analyze_network_requests"]

def setup_network_logging(page: Page, requests_list: List[Dict]) -> None:
    """
    Attaches a listener to a given page to capture all network requests.

    Params:
        page: the page to investigate
        requests_list: list of dictionaries representing requests.
    """
    def on_request(request):
        try:
            post_data_raw = request.post_data
            # Tries to decode in UTF-8 (if possible)
            if post_data_raw:
                try:
                    post_data_text = post_data_raw.encode('utf-8').decode('utf-8')
                except UnicodeDecodeError:
                    # In case of failure, encode in base64 for log
                    post_data_text = f"<binary data: {len(post_data_raw)} bytes>"
            else:
                post_data_text = ""
        except Exception as e:
            post_data_text = f"<error reading post_data: {e}>"

        req_info = {
            "url": request.url,
            "method": request.method,
            "headers": dict(request.headers),
            "post_data": post_data_text,
        }
        requests_list.append(req_info)
        logger.debug(f"Requête capturée: {request.method} {request.url}")

    page.on("request", on_request)
    logger.info("Listener réseau attaché à la page")

def analyze_network_requests(requests_list: List[Dict]) -> Dict[str, bool]:
    """
    Analyze captured network requests to detect authentication-related mechanisms.

    Detects:
      - Explicit WebAuthn/FIDO2 usage
      - Password-based authentication endpoints
      - Passkey setup / registration capability (latent support)

    Params:
        requests_list: list of captured network requests
            Each request is expected to contain:
              - "url": str
              - "headers": Dict[str, str]

    Returns:
        Dictionary of boolean signals:
        {
            "network_webauthn": bool,
            "network_password": bool,
            "passkey_setup_endpoint_present": bool,
        }
    """
    logger.info(f"Analyse de {len(requests_list)} requêtes réseau")

    network_webauthn = False
    network_password = False
    passkey_setup_endpoint_present = False

    for req in requests_list:
        url_lower = req.get("url", "").lower()
        headers = req.get("headers", {})
        headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}

        # 1. WebAuthn / FIDO2 usage (explicit)
        if any(pat in url_lower for pat in WEBAUTHN_ENDPOINT_PATTERNS):
            network_webauthn = True
            logger.debug(f"WebAuthn detected in URL: {req['url']}")

        if any(
            pat in value
            for value in headers_lower.values()
            for pat in WEBAUTHN_ENDPOINT_PATTERNS
        ):
            network_webauthn = True
            logger.debug(f"WebAuthn detected in request header to {req['url']}")

        # 2. Password-based authentication
        if any(pat in url_lower for pat in PASSWORD_ENDPOINT_PATTERNS):
            network_password = True
            logger.debug(f"Endpoint password detected: {req['url']}")

        # 3. Passkey setup / registration (latent support) 
        if any(pat in url_lower for pat in PASSKEY_SETUP_PATTERNS):
            passkey_setup_endpoint_present = True
            logger.debug(f"Endpoint passkey detected: {req['url']}")

        # --- Early exit if all signals are found ---
        if (
            network_webauthn
            and network_password
            and passkey_setup_endpoint_present
        ):
            logger.info(
                "All network signals detected (password, webauthn, passkey setup)"
            )
            break

    result = {
        "network_webauthn": network_webauthn,
        "network_password": network_password,
        "passkey_setup_endpoint_present": passkey_setup_endpoint_present,
    }

    logger.info(f"Network analysis results: {result}")
    return result
