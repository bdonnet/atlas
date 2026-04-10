"""
Confusion matrix analysis for groundtruth data as collected by FIDOLOGY.
"""

from import_data import *
from scipy.stats import fisher_exact

__all__ = ["groundtruth_analysis"]

"""
Each of the 5 authentication categories
"""
CATEGORIES = [
    "None/Error",
    "Password-Based",
    "Password-Extended",
    "Fido2-Native",
    "Unknown"
]

"""
Order of priority for the different categories for the groundtruth
"""
GT_PRIORITY = [
    "Fido2-Native",
    "Password-Extended",
    "Password-Based",
    "None/Error",
    "Unknown",
]

COLOR_TO_CATEGORY = {
    "Green": "Fido2-Native",
    "Yellow": "Password-Extended",
    "Orange": "Password-Based",
    "Red": "None/Error",
    "Grey": "Unknown"
}

"""
Mapping between the usages to the 5 authentication categories
"""
USAGE_TO_CATEGORY = {
    "none": "None/Error",
    "error": "None/Error",

    "password_only": "Password-Based",
    "password_based_network":"Password-Based",
    "password_based_opaque":"Password-Based",

    "password+otp": "Password-Extended",
    "password+fido": "Password-Extended",

    "unknown": "Unknown",

    "fido_only_ui": "Fido2-Native",
    "latent_support": "Fido2-Native",
    "latent_usage": "Fido2-Native",
    "storage": "Fido2-Native",
    "webauthn": "Fido2-Native",
    "full_fido2": "Fido2-Native",
}

def groundtruth_analysis(groundtruth, fidology, shadow_dom_validation=False):
    # Load the scraping and groundtruth
    df_fidology     = pd.read_csv(fidology)
    df_groundtruth  = pd.read_csv(groundtruth)
    total_fidology  = len(df_fidology)

    ############################################################################
    #                    Confusion matrix BEFORE filtering                     #
    ############################################################################
    confusion_raw, confusion_weighted, metric, df = _evaluate_with_confusion(
        df_fidology,
        df_groundtruth
    )

    print(f"Confusion Matrix BEFORE filtering")
    print(f"{'='*87}")
    print(confusion_raw)
    print(confusion_weighted)
    print(metric)

    confusion_raw.to_csv(GROUNDTRUTH_PLOT+"heatmap_confusion_before_filtering.csv")

    ############################################################################
    #                               Filtering                                  #
    ############################################################################
    dict_filtering = {}

    # 0 filtering only on websites that are not correctly categorized
    df = _merge_scraping_and_groundtruth(df_fidology, df_groundtruth)

    # map the columns
    df['fido2_mapped'] = df['fido2_usage'].map(USAGE_TO_CATEGORY)
    df['color_mapped'] = df['color'].map(COLOR_TO_CATEGORY)

    df_fidology_correct = df[df['fido2_mapped'] == df['color_mapped']]
    df_fidology_correct = df_fidology_correct.drop(columns=['fido2_mapped', 'color_mapped','site',
       'category_gt', 'country_gt', 'fido2_usage_gt', 'label_source',
       'source_number', 'date', 'comment', 'color'])
    df_fidology_not_correct = df[df['fido2_mapped'] != df['color_mapped']]
    df_fidology_not_correct = df_fidology_not_correct.drop(columns=['fido2_mapped', 'color_mapped','site',
       'category_gt', 'country_gt', 'fido2_usage_gt', 'label_source',
       'source_number', 'date', 'comment', 'color'])

    # 1 Headless browser blocking
    headless_blocking_count, df_after_headless = filter_headless_blocked_sites(
        df_fidology_not_correct
    )
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

    _print_stats_table(
        stats      = dict_filtering,
        title      = "Filtering Step",
        normalizer = total_fidology
    )

    df_combined = pd.concat([df_final_filtered, df_fidology_correct], ignore_index=True)
    df_combined.to_csv(
        GROUNDTRUTH_DIR + "filtered_groundtruth.csv",
        index=False
    )

    ############################################################################
    #                    Confusion matrix AFTER filtering                      #
    ############################################################################
    print(f"Confusion Matrix AFTER filtering")
    print(f"{'='*87}")
    confusion_raw, confusion_weighted, metric, df, df_false_negatives_none, df_false_negatives_fido, df_false_negatives_pwd, df_true_positives_pwd, df_true_positives_fido, df_true, df_false  = _evaluate_with_confusion(
        df_combined,
        df_groundtruth,
        return_false_negatives_none=True
    )

    print(confusion_raw)
    print(confusion_weighted)

    confusion_raw.to_csv(
        GROUNDTRUTH_PLOT+"heatmap_confusion_after_filtering.csv"
    )

    print(metric)
    print(len(confusion_raw))

    df_false_negatives_fido.to_csv(GROUNDTRUTH_PLOT+'false_negative_fido.csv')
    df_false_negatives_pwd.to_csv(GROUNDTRUTH_PLOT+'false_negative_pwd.csv')
    df_true_positives_pwd.to_csv(GROUNDTRUTH_PLOT+'true_positives_pwd.csv')
    df_true_positives_fido.to_csv(GROUNDTRUTH_PLOT+'true_positives_fido.csv')
    df_false_negatives_none.to_csv(GROUNDTRUTH_PLOT+'false_negatives_none.csv')
    df_true.to_csv(GROUNDTRUTH_PLOT+'correct_class.csv')
    df_false.to_csv(GROUNDTRUTH_PLOT+'incorrect_class.csv')

    ############################################################################
    #                    'none' wrong classification                           #
    ############################################################################
    none_fp_dict_a, none_fp_dict_b = none_fp_quantification(
        df_false_negatives_none
    )

    _print_stats_table(
        stats      = none_fp_dict_b,
        title      = "NONE false negative analysis (Exclusive)",
        normalizer = total_fidology
    )

    _print_stats_table(
        stats      = none_fp_dict_a,
        title      = "NONE false negative analysis (Inclusive)",
        normalizer = total_fidology
    )

    ############################################################################
    #                        Closed Shadow DOM validation                      #
    ############################################################################
    if(shadow_dom_validation):
        df_suspects =df_closed_shadow['site_url']
        sites_to_validate = df_suspects.tolist()

        df_validation, stats_csd_validation = asyncio.run(
            validate_batch(sites_to_validate, max_concurrent=10)
        )

        confirmed = (df_validation['is_closed_shadow_dom'] == True).sum()
        total_validated = len(df_validation)
        precision = confirmed / total_validated

        print(f"Filter precision: {precision:.1%}")
        _print_stats_table(
            stats      = stats_csd_validation,
            title      = "Validation Summary",
            normalizer = stats_csd_validation["total_sites"]
        )

    ############################################################################
    #              ForestPlot Analysis for FIDO2 True Positives                #
    ############################################################################
    df_odd_ratios = _compute_fido2_odds_ratios(df_true_positives_fido)

    df_odd_ratios.to_csv(GROUNDTRUTH_PLOT+"groundtruth_forest_fido.csv")

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _merge_scraping_and_groundtruth(df_pred, df_gt):
    """
    Merges scraping results (predictions) with groundtruth data, keeping only common sites.

    Params:
        df_pred: DataFrame with scraping results (may be filtered)
        df_gt: DataFrame with groundtruth data (original, unfiltered)

    Returns:
        pd.DataFrame: Merged DataFrame with only common sites
    """
    # Normalize column names (case-insensitive, strip whitespace)
    df_pred_normalized = df_pred.copy()
    df_pred_normalized.columns = df_pred_normalized.columns.str.strip().str.lower()

    df_gt_normalized = df_gt.copy()
    df_gt_normalized.columns = df_gt_normalized.columns.str.strip().str.lower()

    # Merge on site_url (scraping) and site (groundtruth)
    # how='inner' keeps only sites present in BOTH DataFrames
    df_merged = df_pred_normalized.merge(
        df_gt_normalized,
        left_on="site_url",
        right_on="site",
        how="inner",
        suffixes=("_pred", "_gt")
    )

    # Log merge statistics for debugging
    n_pred = len(df_pred_normalized)
    n_gt = len(df_gt_normalized)
    n_merged = len(df_merged)

    if n_merged < n_pred:
        print(
            f"Merge: {n_pred} scraping results, {n_gt} groundtruth entries, "
            f"{n_merged} common sites ({n_pred - n_merged} sites in scraping not found in groundtruth)"
        )

    return df_merged

def _safe_float(value, default=0.0):
    """
    Convertit une valeur en float si possible, sinon renvoie la valeur par
    défaut.
    Gère les chaînes 'True', 'False', None, NaN, etc.
    """
    if value is None:
        return default
    if isinstance(value, (float, int)):
        return float(value)
    if isinstance(value, str):
        v_lower = value.strip().lower()
        if v_lower in ("true", "false"):
            return default  # bool invalid for float => default
        try:
            return float(value)
        except ValueError:
            return default
    return default

def _usage_to_category(usage: str) -> str:
    return USAGE_TO_CATEGORY.get(usage, "Unknown")

def _gt_usage_to_category(usage: str) -> str:
    return COLOR_TO_CATEGORY.get(usage, "Unknown")

def _parse_gt_usages(value):
    """
    GT may be:
      - Python list as string
      - comma-separated string
    """
    if pd.isna(value):
        return []
    if isinstance(value, list):
        return value
    try:
        parsed = ast.literal_eval(value)
        if isinstance(parsed, list):
            return parsed
    except Exception:
        pass
    return [x.strip() for x in str(value).split(",")]

def _dominant_category(categories: set[str]) -> str:
    """
    Pick a single GT category for confusion matrix display,
    following a fixed priority.
    """
    for c in GT_PRIORITY:
        if c in categories:
            return c
    return "Unknown"

def _evaluate_with_confusion(df_pred, df_gt, return_false_negatives_none=False):
    """
    Builds two confusion matrices:
        - with raw values
        - with values weighted with confidence score

    Params:
        df_pred: dataframe for the prediction (i.e., scraping)
        df_gt: dataframe for the groundtruth
        return_false_negatives_none: if True, returns an additional DataFrame
                                     containing a subset of df_pred with mispredicted sites
                                     where fido2_usage='none'

    Returns:
        If return_false_negatives_none=False (default):
            (confusion_raw, confusion_weighted, metrics, detailed_df)

        If return_false_negatives_none=True:
            (confusion_raw, confusion_weighted, metrics, detailed_df, false_negatives_none_df)

            where false_negatives_none_df is a subset of df_pred (original columns)
            containing only the rows where:
                - fido2_usage = 'none' (prediction)
                - groundtruth != 'none' (misprediction)
    """
    # Merge scraping and groundtruth on common sites only
    df = _merge_scraping_and_groundtruth(df_pred, df_gt)

    # If no common sites, return empty confusion matrices
    if len(df) == 0:
        logger.warning("No common sites found between scraping results and groundtruth!")
        confusion_raw = pd.DataFrame(0, index=CATEGORIES, columns=CATEGORIES)
        confusion_weighted = pd.DataFrame(0.0, index=CATEGORIES, columns=CATEGORIES)
        metrics = {"total_sites": 0, "category_accuracy": 0.0}

        if return_false_negatives_none:
            return (confusion_raw, confusion_weighted, metrics, pd.DataFrame(), pd.DataFrame())
        else:
            return (confusion_raw, confusion_weighted, metrics, pd.DataFrame())

    # Confusion matrices
    confusion_raw = pd.DataFrame(0, index=CATEGORIES, columns=CATEGORIES)
    confusion_weighted = pd.DataFrame(0.0, index=CATEGORIES, columns=CATEGORIES)

    total = len(df)
    category_hits = 0

    detailed = []
    false_negatives_none_urls       = []  # List 'none' false negatives
    false_negatives_fido_urls       = []  # List of 'FIDO2' false negatives
    false_negatives_pwd_urls        = []  # List of 'Pwd-Based' false negatives
    true_positives_pwd_urls         = []  # List of "Pwd-Based" true positives
    true_positives_fido_urls        = []  # List of "FIDO2" true positives
    correct_urls                    = []  # just the correct ones
    incorrect_urls                  = []  # just the incorrect ones

    for _, row in df.iterrows():
        pred_usage = row["fido2_usage"]
        confidence = _safe_float(row.get("fido2_confidence", 0.0))

        pred_category = _usage_to_category(pred_usage)
        gt_usages = _parse_gt_usages(row["color"])
        gt_categories = {_gt_usage_to_category(u) for u in gt_usages}

        # Success rule (core of your requirement)
        success = pred_category in gt_categories
        if success:
            category_hits += 1

        gt_cat_display = _dominant_category(gt_categories)

        # Update confusion matrices
        confusion_raw.loc[gt_cat_display, pred_category] += 1
        confusion_weighted.loc[gt_cat_display, pred_category] += confidence

        detailed.append({
            "site": row["site_url"],
            "pred_usage": pred_usage,
            "pred_category": pred_category,
            "gt_usages": gt_usages,
            "gt_categories": list(gt_categories),
            "category_match": success,
            "confidence": confidence,
        })

        #  Collect URLs of false negatives/true positives
        if not success and pred_usage == 'none':
            false_negatives_none_urls.append(row["site_url"])
        if not success and pred_usage == 'error':
            false_negatives_none_urls.append(row["site_url"])

        if not success and pred_category == 'Fido2-Native':
            false_negatives_fido_urls.append(row["site_url"])

        if not success and pred_category == 'Password-Based':
            false_negatives_pwd_urls.append(row['site_url'])

        if success and pred_category == 'Fido2-Native':
            true_positives_fido_urls.append(row['site_url'])

        if success and pred_category == 'Password-Based':
            true_positives_pwd_urls.append(row['site_url'])

        if success:
            correct_urls.append(row['site_url'])
        if not success:
            incorrect_urls.append(row['site_url'])

    metrics = {
        "total_sites": total,
        "category_accuracy": category_hits / total if total else 0.0,
    }

    # Extract subset of df_pred (original) for false negatives 'none'
    if return_false_negatives_none:
        # Normalize column names to find site_url column
        df_pred_normalized = df_pred.copy()
        df_pred_normalized.columns = df_pred_normalized.columns.str.strip().str.lower()

        # Create boolean mask for rows to keep
        mask_none = df_pred_normalized['site_url'].isin(false_negatives_none_urls)
        mask_fido = df_pred_normalized['site_url'].isin(false_negatives_fido_urls)
        mask_pwd = df_pred_normalized['site_url'].isin(false_negatives_pwd_urls)
        mask_tp_fido = df_pred_normalized['site_url'].isin(true_positives_fido_urls)
        mask_tp_pwd = df_pred_normalized['site_url'].isin(true_positives_pwd_urls)
        mask_true = df_pred_normalized['site_url'].isin(correct_urls)
        mask_false = df_pred_normalized['site_url'].isin(incorrect_urls)

        # Filter df_pred (ORIGINAL, not normalized) using the mask
        # This preserves all original column names and data
        df_false_negatives_none     = df_pred[mask_none].copy()
        df_false_negatives_fido     = df_pred[mask_fido].copy()
        df_false_negatives_pwd      = df_pred[mask_pwd].copy()
        df_true_positives_fido      = df_pred[mask_tp_fido].copy()
        df_true_positives_pwd       = df_pred[mask_tp_pwd].copy()
        df_correct                  = df_pred[mask_true].copy()
        df_incorrect                = df_pred[mask_false].copy()

        return (
            confusion_raw,
            confusion_weighted,
            metrics,
            pd.DataFrame(detailed),
            df_false_negatives_none,
            df_false_negatives_fido,
            df_false_negatives_pwd,
            df_true_positives_pwd,
            df_true_positives_fido,
            df_correct,
            df_incorrect
        )
    else:
        return (
            confusion_raw,
            confusion_weighted,
            metrics,
            pd.DataFrame(detailed)
        )

def _print_stats_table(stats: dict, title: str, normalizer: float) -> None:
    """
    Affiche un dictionnaire de statistiques sous forme de tableau.

    Params:
        stats (dict): dictionnaire {metric: value}
        title (str): titre du tableau
        normalizer (float): valeur utilisée pour calculer les proportions
    """
    if not stats:
        print(f"{title}\n(empty)\n")
        return

    # Avoiding division by 0
    if normalizer == 0:
        raise ValueError("Le normalizer ne peut pas être égal à 0.")

    # Dynamic column width
    metric_width = max(len("Metric"), max(len(str(k)) for k in stats))
    raw_width = max(len("Raw Value"), max(len(str(v)) for v in stats.values()))
    prop_width = len("Proportion")

    # Table header
    print(f"\n{title}")
    print(f"=" * (metric_width + raw_width + prop_width + 8))

    header = (
        f"{'Metric':<{metric_width}} | "
        f"{'Raw Value':>{raw_width}} | "
        f"{'Proportion':>10}"
    )
    print(header)
    print("-" * len(header))

    # Rows
    for metric, value in stats.items():
        proportion = value / normalizer
        print(
            f"{metric:<{metric_width}} | "
            f"{value:>{raw_width}} | "
            f"{proportion:>10.2%}"
        )

    print()

def _compute_fido2_odds_ratios(df):

    # --- Sécurité : colonnes manquantes → False
    expected_signals = [
        "credentials_api_used",
        "credentials_create_summary",
        "network_webauthn",
        "ui_webauthn_keywords_present",
        "shadow_dom_webauthn",
        "cookies_contain_fido",
        "local_storage_contains_fido",
        "session_storage_contains_fido",
        "fedcm_present",
        "fedcm_detected_via_api",
        "fido2_indirect_possible",
        "auth_js_supports_passkey"
    ]

    for col in expected_signals:
        if col not in df.columns:
            df[col] = False

    # --- Conversion en bool (au cas où 0/1 ou NaN)
    for col in expected_signals:
        df[col] = df[col].fillna(False).astype(bool)

    # --- Mapping catégories -> signaux
    category_signals = {
        "full_fido2": [
            "credentials_api_used",
            "credentials_create_summary",
            "network_webauthn",
            "ui_webauthn_keywords_present",
            "shadow_dom_webauthn",
            "cookies_contain_fido",
            "local_storage_contains_fido",
            "session_storage_contains_fido",
            "fedcm_present",
            "fedcm_detected_via_api",
            "fido2_indirect_possible",
        ],
        "webauthn": [
            "credentials_api_used",
            "credentials_create_summary",
            "network_webauthn",
        ],
        "storage": [
            "cookies_contain_fido",
            "local_storage_contains_fido",
            "session_storage_contains_fido",
        ],
        "latent_usage": [
            "ui_webauthn_keywords_present",
            "shadow_dom_webauthn",
            "cookies_contain_fido",
            "local_storage_contains_fido",
            "session_storage_contains_fido",
        ],
        "latent_support": [
            "fedcm_present",
            "fedcm_detected_via_api",
            "fido2_indirect_possible",
            "auth_js_supports_passkey",
        ],
        "fido_only_ui": [
            "ui_webauthn_keywords_present",
            "shadow_dom_webauthn",
        ],
    }

    category_order = [
        "full_fido2",
        "webauthn",
        "storage",
        "latent_usage",
        "latent_support",
        "fido_only_ui"
    ]

    results = []

    for category in category_order:
        y = (df["fido2_usage"] == category)

        N = y.sum()

        for signal in category_signals[category]:
            x = df[signal]

            # Table de contingence
            a = np.sum((y == 1) & (x == 1))
            b = np.sum((y == 1) & (x == 0))
            c = np.sum((y == 0) & (x == 1))
            d = np.sum((y == 0) & (x == 0))

            # Correction de continuité (évite division par 0)
            a_c, b_c, c_c, d_c = a, b, c, d
            if 0 in [a, b, c, d]:
                a_c += 0.5
                b_c += 0.5
                c_c += 0.5
                d_c += 0.5

            # Odds ratio
            or_value = (a_c * d_c) / (b_c * c_c)

            # IC 95% (log scale)
            se = np.sqrt(1/a_c + 1/b_c + 1/c_c + 1/d_c)
            log_or = np.log(or_value)
            ci_lower = np.exp(log_or - 1.96 * se)
            ci_upper = np.exp(log_or + 1.96 * se)

            # p-value Fisher exact
            _, p_value = fisher_exact([[a, b], [c, d]])

            results.append({
                "category": category,
                "signals": signal,
                "N": int(N),
                "odds_ratio": or_value,
                "ci_lower": ci_lower,
                "ci_upper": ci_upper,
                "p_value": p_value
            })

    result_df = pd.DataFrame(results)

    return result_df
