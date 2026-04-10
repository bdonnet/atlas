"""
Configuration file for output CSV file
"""

"""
Columns for the FIDO2 challenge capture CSV file.
"""
CHALLENGE_CSV_COLUMNS = [
    # =====================================================
    # Site metadata
    # =====================================================
    "site_url",
    "domain",
    "fido2_usage",

    # =====================================================
    # Ethics / Execution context
    # =====================================================
    "capture_successful",
    "nb_clicks",
    "processing_time",
    "webauthn_triggered",

    # =====================================================
    # Data Capture
    # =====================================================
    "captures_count",
    "captures",
    "challenge_probe_count",          # number of WebAuthn attempts performed
    "cose_algorithms",

    # =====================================================
    # Challenge Analysis
    # =====================================================
    "challenge_lengths",
    "challenge_entropy",

    # advanced analysis
    "challenge_unique",
    "challenge_reuse_detected",
    "unique_challenge_count",
    "average_hamming_distance",
    "min_hamming_distance",

    # Timestamp / Replay detection
    "timestamp_pattern_detected",
    "timestamp_position",
    "timestamp_monotonic",
    "replay_vulnerability",
    "replay_risk_level",

    # =====================================================
    # WebAuthn Policy Analysis
    # =====================================================
    "user_verification",
    "attestation_modes",
    "rp_ids",

    # =====================================================
    # Security Scoring
    # =====================================================
    "average_challenge_length",
    "average_entropy_per_byte",
    "average_effective_entropy_bits",

    "user_verification_score",
    "attestation_score",
    "challenge_uniqueness_score",      # scoring dimension
    "overall_score",
    "security_level",

    # =====================================================
    # Error (if any)
    # =====================================================
    "error",
]

"""
Columns for the raw ATLAS output CSV file.
Each column corresponds to a signal, result, or metadata captured during site analysis.
"""
RAW_OUTPUT_CSV_COLUMNS = [
    # =====================================================
    # Site metadata
    # =====================================================
    'site_url',                   # Full URL of the site analyzed
    'domain',                     # Extracted ETLD+1
    'category',                   # Site category (banking, ecommerce, etc.)
    'country',                    # Country code
    'primary_auth_scope',          # Primary authentication scope (ETLD+1)

    # =====================================================
    # Errors / blocking
    # =====================================================
    'error',                       # Error message if analysis failed
    'analysis_blocked',            # True if analysis was blocked
    'analysis_block_reason',       # Reason for blocking
    'diagnosis',                   # High-level diagnostic (non-scoring)


    # =====================================================
    # Login navigation & surface
    # =====================================================
    'login_navigation_successful',
    'login_url',
    'login_scope',
    'cross_scope_login',
    'login_ui_forced',
    'login_iframe_cross_origin',
    'login_iframe_src',
    'auth_surface_type',           # inline, popup, redirect, iframe_*
    'auth_surface_unobservable',   # True if surface could not be reliably inspected
    'auth_form_appeared',          # bool: True si formulaire détecté
    'auth_form_phase',             # str: "none", "initial", "stabilized"
    'auth_form_detection_time',    # float: temps de détection en secondes

    # =====================================================
    # Password signals
    # =====================================================
    'password_input_present',
    'password_input_in_shadow_dom',
    'network_password',

    # =====================================================
    # FIDO2 / WebAuthn signals (direct)
    # =====================================================
    'network_webauthn',
    'credentials_api_used',
    'credentials_get_summary',
    'credentials_create_summary',
    'credentials_api_params',

    # =====================================================
    # FIDO2 / Passkey support (latent / indirect)
    # =====================================================
    'passkey_setup_endpoint_present',
    'auth_js_supports_passkey',

    # =====================================================
    # UI / DOM signals
    # =====================================================
    'ui_webauthn_keywords_present',
    'shadow_dom_webauthn',
    'iframe_dom_results',          # Aggregated iframe DOM detections

    # =====================================================
    # Storage & cookies
    # =====================================================
    'local_storage_contains_fido',
    'session_storage_contains_fido',
    'cookies_contain_fido',
    'raw_local_storage',
    'raw_session_storage',
    'raw_cookies',

    # =====================================================
    # FedCM / federated identity
    # =====================================================
    'fedcm_present',
    'fedcm_provider',
    'fido2_indirect_possible',
    'fedcm_detected_via_api',

    # =====================================================
    # OTP / multistep login
    # =====================================================
    'multistep_login',
    'otp_indicators_present',
    'otp_sources',
    'otp_keywords_detected',

    # =====================================================
    # Inference & confidence
    # =====================================================
    'fido2_usage',
    'latent_support',
    'latent_support_comment',
    'fido2_confidence',
    'fido2_confidence_diagnosis',
    'likely_2fa',

    # =====================================================
    # Page classification
    # =====================================================
    'page_classification',

    # =====================================================
    # Validation / passkey trigger
    # =====================================================
    'passkey_trigger_attempted',
    'passkey_trigger_result',
    'passkey_trigger_error',
    'validated',
    'cose_algorithms',
    'cose_algorithms_count',

    # =====================================================
    # Ethics
    # =====================================================
    "nb_clicks",              # Total number of clicks performed during analysis
    "processing_time",
]

"""
Columns for the filtered ATLAS output CSV file (raw results might be too large)
"""
FILTERED_OUTPUT_CSV_COLUMNS = [
    # =====================================================
    # Site
    # =====================================================
    'site_url',
    'domain',
    'category',
    'country',

    # =====================================================
    # Login navigation
    # =====================================================
    'login_navigation_successful',
    'login_url',
    'login_scope',
    'cross_scope_login',
    'login_ui_forced',
    'login_iframe_cross_origin',
    'auth_surface_type',
    'auth_surface_unobservable',
    'auth_form_appeared',          # bool: True si formulaire détecté
    'auth_form_phase',             # str: "none", "initial", "stabilized"
    'auth_form_detection_time',    # float: temps de détection en secondes

    # =====================================================
    # Password authentication
    # =====================================================
    'password_input_present',
    'password_input_in_shadow_dom',
    'network_password',

    # =====================================================
    # FIDO2 / WebAuthn signals
    # =====================================================
    'network_webauthn',
    'credentials_api_used',
    'passkey_setup_endpoint_present',
    'auth_js_supports_passkey',

    # =====================================================
    # UI / storage hints
    # =====================================================
    'ui_webauthn_keywords_present',
    'shadow_dom_webauthn',
    'local_storage_contains_fido',

    # =====================================================
    # FedCM
    # =====================================================
    'fedcm_present',
    'fedcm_provider',
    'fido2_indirect_possible',

    # =====================================================
    # OTP / flow complexity
    # =====================================================
    'multistep_login',
    'otp_indicators_present',

    # =====================================================
    # Final inference
    # =====================================================
    'fido2_usage',
    'fido2_confidence',
    'fido2_confidence_diagnosis',

    # =====================================================
    # Validation
    # =====================================================
    'validated',
    'cose_algorithms',

    # =====================================================
    # Page context
    # =====================================================
    'page_classification',

    # =====================================================
    # Ethics
    # =====================================================
    "nb_clicks",
    "processing_time",
]
