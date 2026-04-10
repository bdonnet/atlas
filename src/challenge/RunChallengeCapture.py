"""
"""

from import_data import *
from utils import *

__all__ = ["run_capture"]

async def _manage_args(input_file):
    """
    manages FIDOLOGY arguments
    """
    match input_file:
        case 'TEST':
            if os.path.exists(TEST_FIDO_FULL):
                return TEST_FIDO_FULL
            else:
                logger.info("Fichier "+TEST_FIDO_FULL+" n'existe pas dans "+TARGET_DIR)
                sys.exit(-1)

        case 'FIDO2':
            if os.path.exists(FIDO_CHALLENGE_FULL):
                return FIDO_CHALLENGE_FULL
            else:
                logger.info("Fichier "+FIDO_CHALLENGE_FULL+" n'existe pas dans "+CHALLENGE_DIR)
                sys.exit(-1)

        case _:
            logger.info("Fichier en entrée "+input_file+" non accepté")
            sys.exit(-1)

async def run_capture(args, resume: bool = False, dump_freq: int = DUMP_EVERY):
    """
    Runs FIDO2 challenge capture with periodic CSV dumps to save memory.

    Params:
        args: CLI arguments for input file (e.g., TEST, FIDO2)
        dump_freq: number of sites to process before dumping to CSV (default: DUMP_EVERY)
        resume: indicates whether check points must be taken into account (for safe resart after failure)
    """
    logger.info("Parsing des arguments")
    input_file = await _manage_args(args.input)

    logger.info("Chargement des targets dans une dataframe")
    df = pd.read_csv(input_file, sep=',', skipinitialspace=True)

    # Resume mode: skip already processed sites if CSV exists
    if resume and os.path.exists(CHALLENGE_OUTPUT_FILE):
        processed_df = pd.read_csv(CHALLENGE_OUTPUT_FILE)
        processed_sites = set(processed_df['site_url'].astype(str))
        logger.info(f"Resuming from previous run, {len(processed_sites)} sites already processed.")
    else:
        processed_sites = set()
        # Prepare CSV headers
        pd.DataFrame(columns=CHALLENGE_CSV_COLUMNS).to_csv(
            CHALLENGE_OUTPUT_FILE, index=False, header=True
        )

    logger.info(f"Début de l'analyse des sites ({len(df)} au total)")
    results_df = pd.DataFrame(columns=CHALLENGE_CSV_COLUMNS)
    dump_counter = 0

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=[
            '--disable-blink-features=AutomationControlled',
            '--disable-dev-shm-usage',
            '--no-sandbox',
            "--disable-features=IsolateOrigins,site-per-process",
            ]
        )

        with alive_bar(len(df), title="Analyse sites") as bar:
            for index, row in df.iterrows():
                site_url = row['Site']

                # Skip if already processed
                if site_url in processed_sites:
                    bar()
                    continue

                start_time = time.time()
                result = await capture_fido_challenge(site_url, browser)
                end_time = time.time()
                result['processing_time'] = round(end_time - start_time, 2)
                result['domain']   = extract_domain(site_url)
                result['fido2_usage'] = row['Usage']

                results_df.loc[len(results_df)] = result

                dump_counter += 1
                bar()

                # Dump logic
                if dump_counter >= dump_freq:
                    # Auto-convert all-bool object columns to proper bool dtype
                    bool_cols = [
                        c for c in results_df.columns
                        if results_df[c].dtype == object
                        and results_df[c].dropna().isin([True, False]).all()
                    ]

                    results_df[bool_cols] = results_df[bool_cols].astype('bool')

                    # Append to CSVs (no header, append mode)
                    results_df.to_csv(CHALLENGE_OUTPUT_FILE, index=False, header=False, mode='a')

                    logger.info(f"Dumped {dump_counter} sites to CSV. Continuing...")
                    results_df = pd.DataFrame(columns=CHALLENGE_CSV_COLUMNS) # reset raw df
                    dump_counter = 0  # reset counter

        await browser.close()

    # Final dump
    if not results_df.empty:
        # Auto-convert all-bool object columns to proper bool dtype
        bool_cols = [
            c for c in results_df.columns
            if results_df[c].dtype == object
            and results_df[c].dropna().isin([True, False]).all()
        ]

        results_df[bool_cols] = results_df[bool_cols].astype('bool')

        results_df.to_csv(CHALLENGE_OUTPUT_FILE, index=False, header=False, mode='a')
        logger.info(f"Final dump of {len(results_df)} sites completed.")

    logger.info(f"Export terminé : {CHALLENGE_OUTPUT_FILE}")
