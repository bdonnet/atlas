"""
Prints statistics about scraped data to the analysis/outputs folder
"""

from import_data import *

__all__ = ["scraping_analysis"]

def scraping_analysis(scraped_file):
    """
    Main function for writing scraping analysis to output file
    """
    # Load file
    df = pd.read_csv(scraped_file)
    f = open(SCRAPING_PLOT+"results.txt", 'w')

    with open(SCRAPING_PLOT + "results.txt", "w") as f:
        f.write(f"ANALYSIS RESULTS FROM FILE: {scraped_file}")
        f.write(f"\n\n{'='*70}\n")
        f.write("BEFORE FILTERING")
        f.write(f"\n{'='*70}\n")

        # WRITE: Login and authentication
        _login_analysis(df, f)

        # WRITE: classes and categories repartition
        f.write(f"\n{'='*40}\n")
        f.write("CLASSES, CATEGORIES AND PAGE REPARTITION")
        f.write(f"\n{'='*40}\n")
        _fido_class_and_categories_repartition(df, f)
        # WRITE: page classification repartition
        _handles_page_classification(df, f)

        # Filtering on shadow dom, anti bot, etc
        f.write(f"\n{'='*40}\n")
        f.write("FILTERING STEP")
        f.write(f"\n{'='*40}\n")
        df_filtered = _filtering_step(df, f)
        df_filtered.to_csv(SCRAPING_DIR+"FILTERED/1M_filtered_scraping.csv",index=False)

        f.write(f"\n{'='*70}\n")
        f.write("AFTER FILTERING")
        f.write(f"\n{'='*70}\n")
        f.write("\n")
        f.write(f"Analysis for the {len(df_filtered)} filtered websites.\n")

        # WRITE: Login and authentication
        _login_analysis(df_filtered, f)

        # WRITE
        _clicks_processing_time_avg(df_filtered, f)

        # WRITE: signals frequency tables and graphs
        _signals_frequencies(df_filtered, f)

        # WRITE: classes and categories repartition
        f.write(f"\n{'='*40}\n")
        f.write("CLASSES, CATEGORIES AND PAGE REPARTITION")
        f.write(f"\n{'='*40}\n")
        _fido_class_and_categories_repartition(df_filtered, f,)
        # WRITE: page classification repartition
        _handles_page_classification(df_filtered, f)

    print("Successful writing to output file: results.txt")

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _write_stats_table(stats: dict, title: str, normalizer: float, f) -> None:
    """
    Writes a dict like a table in the output file

    Params:
        stats (dict): dict  {metric: value}
        title (str): table title
        normalizer (float): value used to compute proportions
    """
    if not stats:
        f.write(f"{title}\n(empty)\n")
        return

    # Avoiding division by 0
    if normalizer == 0:
        raise ValueError("Le normalizer ne peut pas être égal à 0.")

    # Dynamic column width
    metric_width = max(len("Metric"), max(len(str(k)) for k in stats))
    raw_width = max(len("Raw Value"), max(len(str(v)) for v in stats.values()))
    prop_width = len("Proportion")

    # Table header
    f.write(f"\n{title}")
    f.write("\n")
    f.write(f"-" * (metric_width + raw_width + prop_width + 6))
    f.write("\n")

    header = (
        f"{'Metric':<{metric_width}} | "
        f"{'Raw Value':>{raw_width}} | "
        f"{'Proportion':>10}"
    )
    f.write(header)
    f.write("\n")

    f.write("-" * len(header))
    f.write("\n")

    # Rows
    for metric, value in stats.items():
        proportion = value / normalizer
        f.write(
            f"{metric:<{metric_width}} | "
            f"{value:>{raw_width}} | "
            f"{proportion:>10.2%}"
        )
        f.write("\n")
    f.write("\n")

def _login_analysis(df, f):
    """
    Writes in opened file login information: login success rate, authentication surface type and phase repartition
    """
    login_dict = {}

    # filter df on login success
    df_login = df[df['login_navigation_successful'].fillna(False)].copy()
    login_dict['login_successful'] = df['login_navigation_successful'].sum()
    login_dict['cross_scope'] = df_login['cross_scope_login'].sum()
    login_dict['login_ui_forced'] = df_login['login_ui_forced'].sum()

    # converting objects into numbers
    df_login["auth_form_detection_time"] = round(pd.to_numeric(df_login["auth_form_detection_time"], errors="coerce"), 2)

    auth_surfaces = (
        df_login.groupby("auth_surface_type")
        .agg(total=("auth_surface_type", "size"),
             auth_surface_unobservable=("auth_surface_unobservable", "sum"),
             auth_form_appeared=("auth_form_appeared", "sum"),
             auth_form_detection_time=("auth_form_detection_time", "mean"),)
    )

    auth_surfaces["auth_form_detection_time"] = auth_surfaces["auth_form_detection_time"].round(2)
    df_auth = df[df['auth_form_appeared'].fillna(False)]

    auth_phase = df_auth.groupby('auth_form_phase').size().to_dict()

    # login stats
    f.write(f"\n{'='*40}\n")
    f.write("LOGIN NAVIGATION")
    f.write(f"\n{'='*40}\n")

    # total length
    f.write(f"TOTAL number of websites: {len(df)}\n")

    _write_stats_table(login_dict, "LOGIN success and information", len(df), f)
    _write_stats_table(auth_phase, "Authentication PHASE stats", len(df),f)

def _filtering_step(df, f):

    dict_filtering = {}
    # 1 Headless browser blocking
    headless_blocking_count, df_after_headless = filter_headless_blocked_sites(df)
    dict_filtering["headless_browser_blocking"] = headless_blocking_count

    # 2 Anti-bot challenge blocking
    count_antibot, df_after_antibot = filter_antibot_challenge_sites(
        df_after_headless
    )
    dict_filtering["anti_bot_challenge_blocking"] = count_antibot

    # 3 Closed Shadow DOM
    closed_shadow_count, split_cases, df_final_filtered, df_closed_shadow = filter_closed_shadow_dom(
        df_after_antibot
    )

    # Add detailed closed shadow split
    dict_filtering.update(split_cases)

    # Total filtering count
    dict_filtering["total"] = sum(dict_filtering.values())

    _write_stats_table(
        stats      = dict_filtering,
        title      = "Filtering step statistics",
        normalizer = len(df),
        f = f
    )

    return df_final_filtered

def _clicks_processing_time_avg(df, f):
    df['nb_clicks'] = df['nb_clicks'].replace('True', 0)
    df['nb_clicks'] = df['nb_clicks'].replace('False', 0)
    df["nb_clicks"] = df["nb_clicks"].astype(int)
    click_mean = df['nb_clicks'].mean().round(2)
    process_time = df['processing_time'].mean().round(2)

    f.write(f"\n{'='*40}\n")
    f.write("ETHIC ANALYSIS")
    f.write(f"\n{'='*40}\n")

    f.write(f"Mean number of clicks: {click_mean}\n")

    f.write(f"Mean time processing: {process_time} seconds\n")
    f.write("Plus see plotted CDFs.\n\n")

def _handles_signals(df, f, signals, title):
    """
    Writes signals repartition for a specified set of signals
    """
    signals_dict = {}

    for signal in signals:
        signals_dict[signal] = (df[signal].fillna(False).sum()).round(2)

    _write_stats_table(
        stats      = signals_dict,
        title      = title,
        normalizer = len(df),
        f = f
    )
def _signals_frequencies(df, f):
    """
    Handles the different categories of signals
    """

    f.write(f"\n{'='*40}\n")
    f.write("SIGNALS ANALYSIS (grouped per category)")
    f.write(f"\n{'='*40}\n")

    # Password authentication
    signals = 'password_input_present', 'password_input_in_shadow_dom', 'network_password'
    _handles_signals(df, f, signals, "PASSWORD AUTHENTICATION signals frequency")

    # FIDO2 / WebAuthn signals
    signals = ['network_webauthn', 'credentials_api_used', 'passkey_setup_endpoint_present', 'auth_js_supports_passkey']
    _handles_signals(df, f, signals, "FIDO2 / WEBAUTHN signals frequency")

    # UI / storage hints
    signals = ['ui_webauthn_keywords_present', 'shadow_dom_webauthn', 'local_storage_contains_fido']
    _handles_signals(df, f, signals, "UI / STORAGE hints frequency")

    # FedCM
    signals = ['fedcm_present', 'fedcm_provider', 'fido2_indirect_possible']
    _handles_signals(df, f, signals, "FEDCM signals frequency")

    # OTP / flow complexity
    signals = ['multistep_login', 'otp_indicators_present']
    _handles_signals(df, f, signals, "OTP / FLOW COMPLEXITY signals frequency")


def _handles_page_classification(df, f):
    """
    Computes and writes the page classification repartition
    """
    dict_page = df.groupby('page_classification').size().to_dict()

    _write_stats_table(
            stats      = dict_page,
            title      = "PAGE CLASSIFICATION repartition",
            normalizer = len(df),
            f = f
    )

def _compute_frequencies(series: pd.Series):
    """
    Compute frequencies from a pandas Series.

    Returns:
        dict: {value: count}
    """
    return series.value_counts(dropna=False).to_dict()

def _fido_class_and_categories_repartition(df, f):
    """
    Computes and writes the repartition for authentication classes (11) and categories (5)
    """
    # per classes
    usage_stats = _compute_frequencies(df['fido2_usage'])

    _write_stats_table(
        stats       = usage_stats,
        title       = "Authentication class frequency",
        normalizer  = len(df),
        f = f
    )

    # per category
    df['category'] = df['fido2_usage'].map(USAGE_TO_CATEGORY)
    usage_stats = _compute_frequencies(
        df['category'].fillna('Unknown')
    )

    _write_stats_table(
        stats       = usage_stats,
        title       = "Authentication categories frequency",
        normalizer  = len(df),
        f = f
    )
