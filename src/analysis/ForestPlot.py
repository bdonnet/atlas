from import_data import *

__all__ = ["forest_plot"]

# fido classes in correct order
FIDO_CLASSES = [
    "full_fido2",
    "webauthn",
    "storage",
    "latent_support",
    "fido_only_ui",
]

# singals that need to be true for each classes
SIGNALS = {
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

def _compute_fido2_odds_ratios(df, filter_out_small_signal: bool = False):
    """
    Computes the odds ratios and the p-values for a given dataframe

    Params:
        df_filtered: df of interest
        filter_out_small_signal: boolean to filter insignifcant signals

    Returns:
        a DF with the columns: 
            {   'category', 
                'signals', 
                'N', 
                'odds_ratio', 
                'ci_lower', 
                'ci_upper', 
                'p_value'
            }
    """
    results = []

    # loading raw results and extracting interesting lines 
    df_raw = pd.read_csv("FIDOLOGY_raw_results_2026-03-23.csv")
    df = df_raw[df_raw['site_url'].isin(df['site_url'])]
    df.to_csv(ANALYSIS_OUTPUT+'positive_fido_raw.csv')

    for classe in FIDO_CLASSES:
        # need df with all lines that have 'classe' as fido2_usage
        df_classe = df[df['fido2_usage'] == classe]
        # need df with the rest (df - df_classe)
        df_rest = df[df['fido2_usage'] != classe]
        # nb of instances
        N = len(df_classe)

        for signal in SIGNALS.get(classe):
            
            # compute the 4 elements of the table
            a = df_classe[signal].fillna(False).sum()
            b = N - a
            c = df_rest[signal].fillna(False).sum()
            d = len(df_rest) - c

            # 0.5 correction if necessary
            if not a or not b or not c or not d:
                a = a + 0.5
                b = b + 0.5
                c = c + 0.5
                d = d + 0.5

            # compute odds ratio for the 4 elements
            odds_ratio = (a * d) / (b * c)

            # p-value with fisher_exact
            table = [[a, b],
                    [c, d]]
            _, p_value = fisher_exact(table)

            # confidence interval and bounds
            se = np.sqrt(1/a + 1/b + 1/c + 1/d)
            log_or = np.log(odds_ratio)
            ci_lower = np.exp(log_or - 1.96 * se)
            ci_upper = np.exp(log_or + 1.96 * se)

            # filter if wanted on 'useless' signals
            if filter_out_small_signal:
                if p_value == 1:
                    continue

            results.append({
                "category": classe,
                "signals": signal,
                "N": N,
                "odds_ratio": odds_ratio,
                "ci_lower": ci_lower,
                "ci_upper": ci_upper,
                "p_value": p_value
            })

    return pd.DataFrame(results)
    
def forest_plot(input_file):
    """
    Forest plot function, calculates odds ratios with CI and p values
    """
    df_true_positives_fido = pd.read_csv(input_file)
    df_odd_ratios = _compute_fido2_odds_ratios(df_true_positives_fido, False)
    print(df_odd_ratios)
    params = {
        "category_col" : "category",
        "signal_col"   : "signals",
        "estimate_col" : "odds_ratio",
        "lower_col"    : "ci_lower",
        "upper_col"    : "ci_upper",
        "pvalue_col"   : "p_value",
        "N_col"        : "N",

        "category_order": [
            "full_fido2",
            "webauthn",
            "storage",
            "latent_support",
            "fido_only_ui"
        ],

        "marker"      : "s",
        "marker_size" : 7,
        "linewidth"   : 1.5,

        "signal_title"   : "FIDO2-Native",
        "pvalue_title"   : "p-value",
        "estimate_title" : "Est.(95 C.I.)",
        "xlabel"         : "Odds Ratio",
        "N_title"        : "N",

        "x_lim":[0.0005,20000],
        "xlog": True,

        "show_pvalues"          : True,
        "show_estimate_text"    : True,
        "alternate_row_shading" : True,
        "show_N"                : True,

        "ref_line": 1,
        "ref_line_params": {
            "color": "black",
            "linestyle": "--",
            "linewidth": 1.2
        },
    }

    gp = GenericPlot()
    fig, ax, ax_left_sig, ax_left_est, ax_right_pval = gp.generic_plot(Plot.FOREST_PLOT, df_odd_ratios, params)

    fig.savefig("groundtruth_forest_fido.pdf", bbox_inches="tight")