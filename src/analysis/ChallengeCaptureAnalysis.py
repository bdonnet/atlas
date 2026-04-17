"""
Analysis of FIDO2 Challenge capture.
"""

from import_data import *
import seaborn as sns
import matplotlib.pyplot as plt

__all__ = ["challenge_capture_analysis"]

def challenge_capture_analysis(file):
    ############################################################################
    # Step 1: Pre-processing data
    ############################################################################
    logger.info("Loading file for challenge security analysis")
    df = pd.read_csv(file)

    logger.info("Data cleaning...")
    clean_df, stats = _clean_fido2_dataframe(df)
    df_prepared = _prepare_scatter_dataframe(clean_df)

    ############################################################################
    # Step 2: Dump cleaned dataframe to CSV file (jointplot)
    ############################################################################
    logger.info("Dump...")
    df_prepared.to_csv(CHALLENGE_PLOT+"df_challenge_fido.csv")

    ############################################################################
    # Step 3: Reuse of challenges (table + histogram)
    ###########################################################################
    # Population 1 : all succeeded capture
    N_all   = len(clean_df)
    _print_reuse_metrics(clean_df, "All successful captures", N_all)

    # Population 2 : at least 2 successfull captures
    multi_df = clean_df[clean_df['unique_challenge_count'] >= 2].copy()
    N_multi  = len(multi_df)
    _print_reuse_metrics(multi_df, "Sites with >= 2 unique challenges", N_multi)

    multi_df.to_csv(CHALLENGE_PLOT+"df_histogram_challenge_reuse.csv")

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _print_reuse_metrics(df, label, n):
    reuse   = df['challenge_reuse_detected'].sum()
    exact   = (df['min_hamming_distance'] == 0).sum()
    ts      = df['timestamp_pattern_detected'].sum()

    print(f"\n{'='*55}")
    print(f"  {label}  (N = {n})")
    print(f"{'='*55}")
    print(f"  Challenge reuse detected : {reuse:>4}  ({reuse/n*100:.2f}%)")
    print(f"  Exact reuse (Hamming=0)  : {exact:>4}  ({exact/n*100:.2f}%)")
    print(f"  Timestamp pattern        : {ts:>4}  ({ts/n*100:.2f}%)")

def _clean_fido2_dataframe(df, column_name="captures"):
    """
    Nettoie une dataframe contenant des challenges FIDO2.

    Args:
        df (pd.DataFrame): dataframe originale
        column_name (str): nom de la colonne contenant les challenges

    Returns:
        cleaned_df (pd.DataFrame): dataframe nettoyée
        stats (dict): statistiques sur les cas supprimés
    """

    empty_capture_count = 0
    empty_challenge_only_count = 0

    cleaned_rows = []

    for _, row in df.iterrows():
        raw_value = row[column_name]

        # Cas 1 : rien capté (NaN, vide, etc.)
        if pd.isna(raw_value) or raw_value == "" or raw_value == "[]":
            empty_capture_count += 1
            continue

        try:
            parsed = ast.literal_eval(raw_value)
        except Exception:
            # Si parsing impossible → considéré comme vide
            empty_capture_count += 1
            continue

        # Cas 2 : uniquement des challenges vides
        has_valid_challenge = False

        for item in parsed:
            challenge = item.get("challenge")

            if challenge and any(x != 0 for x in challenge):
                has_valid_challenge = True
                break

        if not has_valid_challenge:
            empty_challenge_only_count += 1
            continue

        # Sinon on garde la ligne
        cleaned_rows.append(row)

    cleaned_df = pd.DataFrame(cleaned_rows).reset_index(drop=True)

    stats = {
        "empty_capture_count": empty_capture_count,
        "empty_challenge_only_count": empty_challenge_only_count,
        "total_removed": empty_capture_count + empty_challenge_only_count,
        "remaining_rows": len(cleaned_df)
    }

    return cleaned_df, stats

def _prepare_scatter_dataframe(clean_df):
    """
    Prépare une dataframe prête pour le scatter plot entropie vs longueur.

    Colonnes produites :
        - x  : average_effective_entropy_bits  (float)
        - y  : average_challenge_length        (float)
        - hue: user_verification               (str, normalisée)
        - size: unique_challenge_count         (int)

    Args:
        clean_df (pd.DataFrame): dataframe nettoyée par _clean_fido2_dataframe()

    Returns:
        scatter_df (pd.DataFrame): dataframe avec les 4 colonnes ci-dessus
    """

    required_cols = [
        "average_effective_entropy_bits",
        "average_challenge_length",
        "user_verification",
        "unique_challenge_count",
    ]

    missing = [c for c in required_cols if c not in clean_df.columns]
    if missing:
        raise ValueError(f"Colonnes manquantes dans la dataframe : {missing}")

    scatter_df = clean_df[required_cols].copy()

    # Normalize user_verification : value extraction from stringified list
    # e.g. "['preferred']" -> "preferred"
    def _parse_uv(val):
        if pd.isna(val):
            return "unknown"
        if isinstance(val, list):
            return val[0] if val else "unknown"
        try:
            parsed = ast.literal_eval(str(val))
            if isinstance(parsed, list):
                return parsed[0] if parsed else "unknown"
        except Exception:
            pass
        return str(val).strip().lower()

    scatter_df["user_verification"] = scatter_df["user_verification"].apply(_parse_uv)

    # Force numerical values
    scatter_df["average_effective_entropy_bits"] = pd.to_numeric(
        scatter_df["average_effective_entropy_bits"], errors="coerce"
    )
    scatter_df["average_challenge_length"] = pd.to_numeric(
        scatter_df["average_challenge_length"], errors="coerce"
    )
    scatter_df["unique_challenge_count"] = pd.to_numeric(
        scatter_df["unique_challenge_count"], errors="coerce"
    ).fillna(1).astype(int)

    # Removes lines with missing data on x or y
    scatter_df = scatter_df.dropna(
        subset=["average_effective_entropy_bits", "average_challenge_length"]
    ).reset_index(drop=True)

    return scatter_df
