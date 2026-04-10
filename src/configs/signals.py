"""
Configuration file for signals captured used during ATLAS scrapping
"""

"""
Weights associated to each signal.  Useful for assigning confidence score to authentication
usage.

Values are based on expertise and not considered in the paper.
"""
SIGNAL_WEIGHTS = {
    # Strong technical signals (direct WebAuthn/FIDO2 evidence)
    "credentials_api_used": 0.30,                  # Explicit usage of navigator.credentials
    "network_webauthn": 0.25,                      # Network request compatible with WebAuthn
    "credentials_create_summary": 0.20,            # Detailed params for credentials.create()

    # Persistent indicators (storage)
    "local_storage_contains_fido": 0.10,
    "session_storage_contains_fido": 0.05,
    "cookies_contain_fido": 0.02,

    # Presence of password field (important to detect password-only flows)
    "password_input_present": 0.02,
    "password_input_in_shadow_dom": 0.02,
    "network_password": 0.06,

    # Structural / UI indicators (latent or indirect)
    "shadow_dom_webauthn": 0.08,                   # Structural element suggesting WebAuthn code
    "ui_webauthn_keywords_present": 0.02,          # Visible text, weak but relevant
    'passkey_setup_endpoint_present':0.07,
    'auth_js_supports_passkey':0.05,

    # FedCM (Federated Credential Management)
    "fedcm_present": 0.05,                         # Presence of FedCM in logs or code
    "fedcm_fido2_hint": 0.12,                      # FedCM with known FIDO2-capable IdP (Google, Apple)
    "fedcm_detected_via_api": 0.10,
    "fedcm_provider": 0.05,

    # OTP-related indicators (new)
    "otp_indicators_present": 0.08,                # UI elements mentioning OTP, SMS, verification code, etc.

    # Complementary contextual signal
    "multistep_login": 0.03,                        # Optional: common on secure modern flows

    "fido2_indirect_possible": 0.05,
    "auth_surface_type": 0.25,
}

THRESHOLD_SIGNAL_CONFIDENCE = 0.4

"""
Confidence score intervals for each classification usage
"""
SIGNAL_WEIGHTS_RANGES = {
    "none":            (0.00, 0.05),
    "password_only":   (0.05, 0.20),
    "password+otp":    (0.25, 0.45),
    "password+fido":   (0.45, 0.70),
    "webauthn":        (0.60, 0.80),
    "storage":         (0.40, 0.55),
    "fido_only_ui":    (0.25, 0.35),
    "latent_support":  (0.25, 0.40),
    "latent_usage":    (0.35, 0.50),
    "full_fido2":      (0.80, 1.00),
    "unknown":         (0.20, 0.40),
    "error":           (0.00, 0.00),
}

"""
Classification usage associated to FIDO.
"""
FIDO_CLASSES = {
    "password+fido",
    "webauthn",
    "storage",
    "fido_only_ui",
    "latent_support",
    "latent_usage",
    "full_fido2",
}

"""
Signals that affect confidence/observability, not authentication likelihood
"""
OBSERVABILITY_PENALTIES = {
    "login_iframe_cross_origin": 0.40,   # Severe loss of DOM / JS visibility
    "password_based_network":0.4,
    "password_based_opaque":0.3,
    "password_based_low_confidence":0.2,
    "latent_support": 0.5,               # Password + passkey detected but not active
    "auth_surface_unobservable": 0.35,
}

"""
All the signals for data analysis
"""
SIGNALS = {
    'password_input_present',
    'password_input_in_shadow_dom',
    'credentials_api_used',
    'network_webauthn',
    'fedcm_present',
    'fedcm_detected_via_api',
    'multistep_login',
    'local_storage_contains_fido',
    'session_storage_contains_fido',
    'cookies_contain_fido',
    'shadow_dom_webauthn',
    'ui_webauthn_keywords_present',
    'fedcm_provider',
    'otp_indicators_present',
    'fido2_indirect_possible'
}
