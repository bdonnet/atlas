"""
Applies filtering to dataframes.

Cas "closed shadow dom":
- Surface d’authentification visible pour l’utilisateur mais structurellement opaque à l’observateur
- Formulaire injecté dynamiquement dans un composant non inspectable
- Web Component encapsulant totalement la logique d’authentification
- Iframe same-origin dont le contenu réel est masqué par orchestration JavaScript
- UI d’authentification rendue mais jamais stabilisée dans le DOM observable
- Formulaire minimal exposé, logique métier entièrement déportée
- Architecture d’authentification conçue pour résister à l’inspection automatisée
"""

from import_data import *

__all__ = ["filter_closed_shadow_dom", "filter_headless_blocked_sites", "filter_antibot_challenge_sites", "none_fp_quantification"]

def filter_antibot_challenge_sites(df: pd.DataFrame) -> tuple[int, pd.DataFrame]:
    """
    Filters out sites that trigger anti-bot challenges during scraping (e.g., Cloudflare Turnstile).

    A site is considered to have triggered an anti-bot challenge if ALL of the following conditions are met:
    1. fido2_usage == 'error' or 'none'
    2. AND one of the following:
       - page_classification == 'antibot_challenge'
       - fido2_confidence_diagnosis contains 'anti-bot' (case-insensitive)

    Params:
        df: DataFrame containing scraping results with columns from FILTERED_OUTPUT_CSV_COLUMNS

    Returns:
        tuple containing:
            - count (int): Number of sites with anti-bot challenges
            - filtered_df (pd.DataFrame): DataFrame without the anti-bot challenge sites (copy)
    """
    # Normalize input dataframe
    df_normalized = _normalize_scraping_types(df)
    df_normalized.columns = df_normalized.columns.str.strip().str.lower()

    # Condition 1: fido2_usage == 'error' or 'none'
    condition_1a = (df_normalized['fido2_usage'] == 'error')
    condition_1b = (df_normalized['fido2_usage'] == 'none')

    # Condition 2a: page_classification == 'antibot_challenge'
    condition_2a = False
    if 'page_classification' in df_normalized.columns:
        condition_2a = (df_normalized['page_classification'] == 'antibot_challenge')

    # Condition 2b: fido2_confidence_diagnosis contains 'anti-bot' (case-insensitive)
    condition_2b = False
    if 'fido2_confidence_diagnosis' in df_normalized.columns:
        # Handle NaN/None values safely
        try:
            condition_2b = (df_normalized['fido2_confidence_diagnosis']).fillna('').str.lower().str.contains('anti-bot', na=False)
        except:
            condition_2b = False
    # Combine: fido2_usage='error' AND (page_classification OR diagnosis contains anti-bot)
    mask = (condition_1a | condition_1b) & (condition_2a | condition_2b)

    # Count anti-bot challenge sites
    count = int(mask.sum())

    # Filter DataFrame (using original, not normalized)
    filtered_df = df[~mask].copy()

    return count, filtered_df

def filter_headless_blocked_sites(df: pd.DataFrame) -> tuple[int, pd.DataFrame]:
    """
    Filters out sites that likely block headless browsers.

    A site is considered blocked if:
        fido2_usage == 'none'
        AND (
            all signals are truthy
            OR all signals are NaN (empty)
            OR all signals are 0
        )
    """
    # Normalize input dataframe
    #df_normalized = _normalize_scraping_types(df)
    df_normalized = df.copy()
    df_normalized.columns = df_normalized.columns.str.strip().str.lower()

    fields_to_check = [
        'login_navigation_successful', 'login_url', 'login_scope',
        'cross_scope_login', 'login_ui_forced', 'auth_surface_type',
        'auth_surface_unobservable', 'auth_form_appeared', 'auth_form_phase',
        'auth_form_detection_time', 'password_input_present',
        'password_input_in_shadow_dom', 'network_password', 'network_webauthn',
        'credentials_api_used', 'passkey_setup_endpoint_present',
        'auth_js_supports_passkey', 'ui_webauthn_keywords_present',
        'shadow_dom_webauthn', 'local_storage_contains_fido', 'fedcm_present',
        'fedcm_provider', 'fido2_indirect_possible', 'multistep_login',
        'otp_indicators_present', 'fido2_confidence',
        'fido2_confidence_diagnosis', 'validated', 'cose_algorithms',
        'page_classification'
    ]

    # --- Classification condition ---
    condition_class = (df_normalized['fido2_usage'] == 'error')

    # --- Initialize masks ---
    condition_all_truthy = pd.Series(True, index=df_normalized.index)
    condition_all_empty = pd.Series(True, index=df_normalized.index)
    condition_all_zero = pd.Series(True, index=df_normalized.index)

    for field in fields_to_check:
        if field not in df_normalized.columns:
            condition_all_truthy &= False
            condition_all_empty &= False
            condition_all_zero &= False
            continue

        col = df_normalized[field]

        # Truthy = not NaN and not 0 and not False
        condition_all_truthy &= (
            col.notna() &
            (col != 0) &
            (col != False)
        )

        # Empty = NaN
        condition_all_empty &= col.isna()

        # Zero = numeric zero only (and not NaN)
        condition_all_zero &= (
            col.notna() &
            (col == 0)
        )

    # --- Final mask ---
    mask = condition_class & (
        condition_all_truthy |
        condition_all_empty |
        condition_all_zero
    )

    count = int(mask.sum())
    filtered_df = df[~mask].copy()

    return count, filtered_df

def filter_closed_shadow_dom(df_scraping: pd.DataFrame) -> tuple[int, dict, pd.DataFrame, pd.DataFrame]:
    """
    Filters out suspected closed Shadow DOM cases from scraping results only.

    A case is considered a suspected closed Shadow DOM if ALL of the following conditions are met:
    - login_navigation_successful == True
    - cross_scope_login == False
    - login_ui_forced == True
    - auth_form_appeared == True
    - fido2_usage == 'none'

    Params:
        df_scraping: DataFrame containing scraping results with columns from FILTERED_OUTPUT_CSV_COLUMNS

    Returns:
        tuple containing:
            - total_closed_shadow (int): Number of total suspected closed Shadow DOM cases
            - counts (dictionary): splits total_closed_shadow in multiple cases
            - filtered_scraping (pd.DataFrame): Scraping DataFrame without suspected cases (copy)
            - df_closed_shadow (pd.DataFrame): DataFrame with suspected cases (copy)
    """
    df_normalized = _normalize_scraping_types(df_scraping)
    #df_normalized = df_scraping.copy()
    df_normalized.columns = df_normalized.columns.str.strip().str.lower()


    df_normalized['auth_form_detection_time'] = pd.to_numeric(
        df_normalized['auth_form_detection_time'],
        errors='coerce'
    )

    # --- NEW: unified condition ---
    surface_unobservable_or_nan = (
        (df_normalized['auth_surface_unobservable'] == True) |
        (df_normalized['auth_surface_unobservable'].isna())
    )

    # 1. Canonical closed shadow DOM
    base_closed_shadow = (
        (df_normalized['login_navigation_successful'] == True) &
        (df_normalized['cross_scope_login'] == False) &
        (df_normalized['login_ui_forced'] == True) &
        (df_normalized['auth_form_appeared'] == True) &
        surface_unobservable_or_nan &
        (df_normalized['fido2_usage'] == 'none')
    )

    # 2. JS-orchestrated / native auth UI (non-DOM)
    js_orchestrated_auth = (
        (df_normalized['login_navigation_successful'] == True) &
        (df_normalized['login_ui_forced'] == True) &
        (df_normalized['auth_form_appeared'] == False) &
        surface_unobservable_or_nan &
        (df_normalized['fido2_usage'] == 'none')
    )

    # 3. Same-origin iframe but opaque surface
    iframe_same_origin_opaque = (
        (df_normalized['login_navigation_successful'] == True) &
        (df_normalized['auth_surface_type'] == 'iframe_same_origin') &
        surface_unobservable_or_nan &
        (df_normalized['auth_form_appeared'] == True) &
        (df_normalized['fido2_usage'] == 'none')
    )

    # 4. UI present but never stabilizes
    stalled_auth_ui = (
        (df_normalized['login_navigation_successful'] == True) &
        (df_normalized['login_ui_forced'] == True) &
        (df_normalized['auth_form_appeared'] == True) &
        surface_unobservable_or_nan &
        (df_normalized['auth_form_phase'].isin(['initial', 'none'])) &
        (df_normalized['auth_form_detection_time'] >= 8.0) &
        (df_normalized['fido2_usage'] == 'none')
    )

    # 5. Password input without observable surface
    password_without_observability = (
        (df_normalized['password_input_present'] == True) &
        surface_unobservable_or_nan &
        (df_normalized['network_password'] == False) &
        (df_normalized['fido2_usage'] == 'none')
    )

    mask = (
        base_closed_shadow |
        js_orchestrated_auth |
        iframe_same_origin_opaque |
        stalled_auth_ui |
        password_without_observability
    )

    counts = {
        "canonical_closed_shadow_dom": int(base_closed_shadow.sum()),
        "js_orchestrated_auth_ui": int(js_orchestrated_auth.sum()),
        "iframe_same_origin_opaque": int(iframe_same_origin_opaque.sum()),
        "stalled_auth_ui": int(stalled_auth_ui.sum()),
        "password_without_observability": int(password_without_observability.sum()),
    }

    total_closed_shadow = int(mask.sum())
    #print(df_scraping.loc[[103]].dtypes)
    #closed_shadow_df = df_scraping[mask].copy()
    closed_shadow_df = df_scraping[base_closed_shadow].copy()
    filtered_scraping = df_scraping[~mask].copy()

    return total_closed_shadow, counts, filtered_scraping, closed_shadow_df
    #return total_closed_shadow, counts, filtered_scraping

def none_fp_quantification(df: pd.DataFrame) -> tuple[dict, dict]:
    """
    Quantifies false negatives for class 'none' / 'error'.

    Returns:
        - approach_a: multi-label quantification (non-exclusive)
        - approach_b: exclusive root-cause attribution
    """
    # Normalize input dataframe
    df_normalized = _normalize_scraping_types(df)
    df.columns = df.columns.str.strip().str.lower()

    if 'auth_form_detection_time' in df.columns:
        df['auth_form_detection_time'] = pd.to_numeric(
            df['auth_form_detection_time'], errors='coerce'
        )

    # ---------------------------
    # Define FN masks
    # ---------------------------

    fn_errors = (
        df['fido2_usage'] == 'error'
    )

    fn_no_login_surface = (
        (df['login_navigation_successful'] == False) &
        (df['fido2_usage'] == 'none')
    )

    fn_non_interactive_ui = (
        (df['login_ui_forced'] == True) &
        (df['auth_form_appeared'] == False) &
        (df['auth_surface_unobservable'] == True)
    )

    fn_closed_shadow_residual = (
        (df['auth_form_appeared'] == True) &
        (df['auth_surface_unobservable'] == True) &
        (df['password_input_present'] == False) &
        (df['password_input_in_shadow_dom'] == False)
    )

    fn_cross_scope = (
        (df['cross_scope_login'] == True) &
        (df['login_navigation_successful'] == True)
    )

    fn_not_auth_page = (
        df['page_classification'].isin([
            'content_page',
            'interstitial',
            'cmp_blocking',
        ])
    )

    fn_silent_block = (
        (df['login_navigation_successful'] == True) &
        (df['auth_form_phase'].isin(['none', 'skipped'])) &
        (df['auth_form_appeared'] == False)
    )

    masks = {
        "no_login_surface": fn_no_login_surface,
        "third_party_redirect": fn_cross_scope,
        "not_an_auth_page": fn_not_auth_page,
        "silent_antibot_block": fn_silent_block,
        "non_interactive_ui": fn_non_interactive_ui,
        "closed_shadow_dom_residual": fn_closed_shadow_residual,
        "error": fn_errors
    }

    # Approach A — multi-label (diagnostic)
    approach_a = {
        name: int(mask.sum())
        for name, mask in masks.items()
    }
    approach_a["total_rows"] = len(df)

    # Approach B — exclusive attribution (explanatory)
    approach_b = {name: 0 for name in masks.keys()}
    approach_b["unexplained_residual"] = 0

    assigned = pd.Series(False, index=df.index)

    for name, mask in masks.items():
        eligible = mask & (~assigned)
        count = int(eligible.sum())
        approach_b[name] += count
        assigned |= eligible

    # Remaining unexplained cases
    approach_b["unexplained_residual"] = int((~assigned).sum())
    approach_b["total_rows"] = len(df)

    return approach_a, approach_b

def _normalize_scraping_types(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalizes column names and converts column types for scraping results.

    - Boolean-like columns -> bool (True/False/NaN)
    - Numeric columns -> numeric
    - Categorical columns -> stripped lowercase strings
    """
    df = df.copy()

    # --- Normalize column names ---
    df.columns = df.columns.str.strip().str.lower()

    # --- Boolean columns ---
    bool_cols = [
        'login_navigation_successful',
        'cross_scope_login',
        'login_ui_forced',
        'login_iframe_cross_origin',
        'auth_form_appeared',
        'password_input_present',
        'password_input_in_shadow_dom',
        'network_password',
        'network_webauthn',
        'credentials_api_used',
        'passkey_setup_endpoint_present',
        'auth_js_supports_passkey',
        'ui_webauthn_keywords_present',
        'shadow_dom_webauthn',
        'local_storage_contains_fido',
        'fedcm_present',
        'fido2_indirect_possible',
        'multistep_login',
        'otp_indicators_present',
        'validated'
    ]

    for col in bool_cols:
        if col in df.columns:
            df[col] = (
                df[col]
                .astype(str)
                .str.strip()
                .str.lower()
                .map({
                    'true': True,
                    'false': False,
                    '1': True,
                    '0': False
                })
            )

    # --- Special case: auth_surface_unobservable (float 1.0 / 0.0 / NaN) ---
    if 'auth_surface_unobservable' in df.columns:
        df['auth_surface_unobservable'] = df['auth_surface_unobservable'].map({
            1.0: True,
            0.0: False
        })

    # --- Numeric columns ---
    numeric_cols = [
        'auth_form_detection_time',
        'fido2_confidence',
        'nb_clicks',
        'processing_time'
    ]

    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    # --- Categorical columns (strip + lowercase) ---
    categorical_cols = [
        'auth_surface_type',
        'auth_form_phase',
        'fido2_usage',
        'fedcm_provider',
        'fido2_confidence_diagnosis',
        'page_classification',
        'cose_algorithms'
    ]

    for col in categorical_cols:
        if col in df.columns:
            df[col] = (
                df[col]
                .astype(str)
                .str.strip()
                .str.lower()
            )

    return df
