"""
Scrapper for investigating authentication mechansims by websites.
"""

from import_data import *
from utils import *

__all__ = ["parallel_run_atlas", "non_parallel_run_atlas"]

async def non_parallel_run_atlas(args, resume: bool = False, dump_freq: int = DUMP_EVERY):
    """
    Runs ATLAS scraping with periodic CSV dumps to save memory.

    Params:
        args: CLI arguments for input file (e.g., TEST, TRANCO, UMBRELLA, CRUX)
        dump_freq: number of sites to process before dumping to CSV (default: DUMP_EVERY)
        resume: indicates whether check points must be taken into account (for safe resart after failure)
    """
    logger.info("Parsing des arguments")
    input_file = await _manage_args(args.input)

    logger.info("Chargement des targets dans une dataframe")
    df = pd.read_csv(input_file, sep=',', skipinitialspace=True)

    # Resume mode: skip already processed sites if CSV exists
    if resume and os.path.exists(FILTERED_OUTPUT_FILE):
        processed_df = pd.read_csv(FILTERED_OUTPUT_FILE)
        processed_sites = set(processed_df['site_url'].astype(str))
        logger.info(f"Resuming from previous run, {len(processed_sites)} sites already processed.")
    else:
        processed_sites = set()
        # Prepare CSV headers
        pd.DataFrame(columns=RAW_OUTPUT_CSV_COLUMNS).to_csv(
            RAW_OUTPUT_FILE, index=False, header=True, compression="gzip"
        )
        pd.DataFrame(columns=FILTERED_OUTPUT_CSV_COLUMNS).to_csv(
            FILTERED_OUTPUT_FILE, index=False, header=True
        )

    logger.info(f"Début de l'analyse des sites ({len(df)} au total)")
    raw_results_df = pd.DataFrame(columns=RAW_OUTPUT_CSV_COLUMNS)
    dump_counter = 0

    async with async_playwright() as playwright:
        browser = await playwright.firefox.launch(
            headless=True,
            args=[
            '--disable-blink-features=AutomationControlled',
            '--disable-dev-shm-usage',
            '--no-sandbox',
            ]
        )
        with alive_bar(len(df), title="Analyse sites") as bar:
            for index, row in df.iterrows():
                site_url = row['Site']

                # Skip if already processed
                if site_url in processed_sites:
                    bar()
                    continue

                # Skip if bullshit website
                if _looks_like_cdn(site_url):
                    bar()
                    logger.info(f"Bullshit URL {site_url} Skipping...")
                    continue

                start_time = time.time()
                default_result = dict.fromkeys(RAW_OUTPUT_CSV_COLUMNS, None)
                default_result['site_url'] = site_url
                default_result['fido2_usage'] = "error"
                default_result['nb_clicks'] = 0

                result = await safe_await(
                    lambda: process_site(site_url, browser, index, len(df)),
                    timeout=135, default=default_result, label="process site"
                )
                end_time = time.time()
                result['processing_time'] = round(end_time - start_time, 2)
                result['category'] = row['Category']
                result['country']  = row['Country']
                result['domain']   = extract_domain(site_url)

                raw_results_df.loc[len(raw_results_df)] = result

                dump_counter += 1
                bar()

                # Dump logic
                if dump_counter >= dump_freq:
                    filtered_df = raw_results_df[FILTERED_OUTPUT_CSV_COLUMNS]

                    # Append to CSVs (no header, append mode)
                    raw_results_df.to_csv(RAW_OUTPUT_FILE, index=False, header=False, mode='a', compression="gzip")
                    filtered_df.to_csv(FILTERED_OUTPUT_FILE, index=False, header=False, mode='a')

                    logger.info(f"Dumped {dump_counter} sites to CSV. Continuing...")
                    raw_results_df = pd.DataFrame(columns=RAW_OUTPUT_CSV_COLUMNS) # reset raw df
                    dump_counter = 0  # reset counter

        try:
            if browser.is_connected():
                await browser.close()
        except Exception as e:
            logger.warning(f"Browser already closed or driver crashed: {e}")

    # Final dump
    if not raw_results_df.empty:
        # Auto-convert all-bool object columns to proper bool dtype
        bool_cols = [
            c for c in raw_results_df.columns
            if raw_results_df[c].dtype == object
            and raw_results_df[c].dropna().isin([True, False]).all()
        ]

        # raw_results_df[bool_cols] = raw_results_df[bool_cols].fillna(False).astype('bool')
        raw_results_df[bool_cols] = raw_results_df[bool_cols].fillna(False).astype('bool')

        filtered_df = raw_results_df[FILTERED_OUTPUT_CSV_COLUMNS]
        raw_results_df.to_csv(RAW_OUTPUT_FILE, index=False, header=False, mode='a', compression="gzip")
        filtered_df.to_csv(FILTERED_OUTPUT_FILE, index=False, header=False, mode='a')
        logger.info(f"Final dump of {len(raw_results_df)} sites completed.")

    logger.info(f"Export terminé : {FILTERED_OUTPUT_FILE}")


async def _parallelized_atlas(df, resume, dump_freq, output_file, raw_file, i):
    # Resume mode: skip already processed sites if CSV exists
    if resume and os.path.exists(output_file):
        processed_df = pd.read_csv(output_file)
        processed_sites = set(processed_df['site_url'].astype(str))
        logger.info(f"Resuming from previous run, {len(processed_sites)} sites already processed.")
    else:
        processed_sites = set()
        # Prepare CSV headers
        pd.DataFrame(columns=RAW_OUTPUT_CSV_COLUMNS).to_csv(
            raw_file, index=False, header=True, compression="gzip"
        )
        pd.DataFrame(columns=FILTERED_OUTPUT_CSV_COLUMNS).to_csv(
            output_file, index=False, header=True
        )

    logger.info(f"Début de l'analyse des sites ({len(df)} au total)")
    raw_results_df = pd.DataFrame(columns=RAW_OUTPUT_CSV_COLUMNS)
    raw_results_buffer = []
    dump_counter = 0

    async with async_playwright() as playwright:
        try:
            browser = await playwright.chromium.launch(
                headless=True,
                args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
                ]
            )

            site_nb = 0
            for _, row in df.iterrows():
                site_url = row['Site']
                site_nb += 1

                # Skip if already processed
                if site_url in processed_sites:
                    continue

                if _looks_like_cdn(site_url):
                    logger.info(f"Bullshit URL {site_url} Skipping...")
                    continue

                default_res = dict.fromkeys(RAW_OUTPUT_CSV_COLUMNS, None)
                default_res['site_url'] = site_url
                default_res['fido2_usage'] = "error"
                default_res['nb_clicks'] = 0
                try:
                    start_time = time.time()
                    result = await process_site(site_url, browser, site_nb, len(df))

                # should not happen since all exception are handled in process_site
                except Exception as e:
                    logger.error(f"Scraping error for {site_url}: {e}")
                    result = default_res

                end_time = time.time()
                result['processing_time'] = round(end_time - start_time, 2)
                result['category'] = False
                result['country']  = row['Country']
                result['domain']   = extract_domain(site_url)

                raw_results_buffer.append(normalize_result(result))

                dump_counter += 1

                # ---- DUMP LOGIC ----
                if dump_counter >= dump_freq:
                    raw_results_df = pd.DataFrame(raw_results_buffer)

                    filtered_df = raw_results_df[FILTERED_OUTPUT_CSV_COLUMNS]

                    raw_results_df.to_csv(raw_file, index=False, header=False, mode='a', compression="gzip")
                    filtered_df.to_csv(output_file, index=False, header=False, mode='a')

                    logger.info(f"Dumped {dump_counter} sites to CSV. Continuing...")
                    raw_results_buffer.clear()
                    dump_counter = 0

                # restarting with fresh browser
                if site_nb % 200 == 0:
                    await browser.close()
                    browser = await playwright.chromium.launch(
                        headless=True,
                        args=[
                        '--disable-blink-features=AutomationControlled',
                        '--disable-dev-shm-usage',
                        '--no-sandbox',
                        ]
                    )

        except Exception as e:
            pass

        finally:
            await browser.close()

    # ---- Final dump ----
    if raw_results_buffer:
        raw_results_df = pd.DataFrame(raw_results_buffer)

        # Auto-convert all-bool object columns to proper bool dtype
        bool_cols = [
            c for c in raw_results_df.columns
            if raw_results_df[c].dtype == object
            and raw_results_df[c].dropna().isin([True, False]).all()
        ]

        raw_results_df[bool_cols] = raw_results_df[bool_cols].astype('bool')

        filtered_df = raw_results_df[FILTERED_OUTPUT_CSV_COLUMNS]
        raw_results_df.to_csv(raw_file, index=False, header=False, mode='a', compression="gzip")
        filtered_df.to_csv(output_file, index=False, header=False, mode='a')
        logger.info(f"Final dump of {len(raw_results_df)} sites completed.")

    logger.info(f"Export terminé : {output_file}")

async def parallel_run_atlas(args, resume: bool = True, dump_freq: int = DUMP_EVERY, df_split: int = 10):
    """
    Runs ATLAS scraping with a process pool to parallelize the scraping processus.

    Params:
        args: CLI arguments for input file (e.g., TEST, GROUNDTRUTH_DIR)
        dump_freq: number of sites to process before dumping to CSV (default: DUMP_EVERY)
        resume: indicates whether check points must be taken into account (for safe resart after failure)
    """
    zip_old_logs_file()

    logger.info("Parsing des arguments")
    input_file = await _manage_args(args.input)

    logger.info("Chargement des targets dans une dataframe")
    df = pd.read_csv(input_file, sep=',', skipinitialspace=True)

    # splitting dataframes into n processes
    dataframes = np.array_split(df, df_split)
    processes = []
    try:
        for index, chunk in enumerate(dataframes):
            p = Process(target=_asyncio_atlas,
                        args=(chunk, resume, dump_freq, f'results/results_{index}.csv', f'raw_results/raw_results_{index}.csv.gz',index))
            p.start()
            processes.append(p)

        for p in processes:
            p.join()

        if p.exitcode != 0:
            print(f"Process {p.pid} failed with exit code {p.exitcode}")

    except KeyboardInterrupt:
        print("KeyboardInterrupt received, terminating workers...")
        for p in processes:
            p.terminate()
            p.join()
        if p.exitcode != 0:
            print(f"Process {p.pid} failed with exit code {p.exitcode}")
        sys.exit()

    # concatenating the results
    dfs = []
    for i in range(df_split):
        file_name = f"results/results_{i}.csv"
        if os.path.exists(file_name):
            dfs.append(pd.read_csv(file_name))
    pd.concat(dfs).to_csv(FILTERED_OUTPUT_FILE, index=False)

    dfs = []
    for i in range(df_split):
        file_name = f"raw_results/raw_results_{i}.csv.gz"
        if os.path.exists(file_name):
            dfs.append(pd.read_csv(file_name))
    pd.concat(dfs).to_csv(RAW_OUTPUT_FILE, index=False)

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _setup_logger(log_file: str):

    logger = logging.getLogger("ATLAS")
    logger.setLevel(logging.INFO)

    # enlever ce qui est hérité du parent
    logger.handlers.clear()

    formatter = logging.Formatter(
    '%(asctime)s - %(filename)s - %(lineno)d - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )

    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.propagate = False

    return logger

def _asyncio_atlas(df, resume, dump_freq, output_file, raw_file, i):
    """
    Launched each process with the needed arguments with asyncio to handle the async functions
    """
    log_file = f"../CSV/Scraping/logs_parallel/worker_{i}_{datetime.now().strftime('%Y-%m-%d')}.log"
    logger = setup_logger(log_file)
    logger.info("Worker Started")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_parallelized_atlas(df, resume, dump_freq, output_file, raw_file, i))
    except Exception as e:
        logger.error(f"Worker {i} failed: {e}", exc_info=True)
        raise
    finally:
        loop.close()

async def _manage_args(input_file):
    """
    manages ATLAS arguments
    """
    match input_file:
        case 'GROUNDTRUTH':
            if os.path.exists(GROUNDTRUTH_FULL):
                return GROUNDTRUTH_FULL
            else:
                logger.info("Fichier "+GROUNDTRUTH_FULL+" n'existe pas dans "+GROUNDTRUTH_DIR)
                sys.exit(-1)
        case 'TEST':
            if os.path.exists(TEST_FULL):
                return TEST_FULL
            else:
                logger.info("Fichier "+TEST_FULL+" n'existe pas dans "+TARGET_DIR)
                sys.exit(-1)

        case 'DATASET_0':
            if os.path.exists(DATASET_0):
                return DATASET_0
            else:
                logger.info("Fichier "+DATASET_0+" n'existe pas dans "+TARGET_DIR)
                sys.exit(-1)

        case 'DATASET_1':
            if os.path.exists(DATASET_1):
                return DATASET_1
            else:
                logger.info("Fichier "+DATASET_1+" n'existe pas dans "+TARGET_DIR)
                sys.exit(-1)

        case 'DATASET_2':
            if os.path.exists(DATASET_2):
                return DATASET_2
            else:
                logger.info("Fichier "+DATASET_2+" n'existe pas dans "+TARGET_DIR)
                sys.exit(-1)
        case 'DATASET_3':
            if os.path.exists(DATASET_3):
                return DATASET_3
            else:
                logger.info("Fichier "+DATASET_3+" n'existe pas dans "+TARGET_DIR)
                sys.exit(-1)

        case _:
            logger.info("Fichier en entrée "+input_file+" non accepté")
            sys.exit(-1)

# --- Regex de base ---
RR_PREFIX = re.compile(r"^rr\d+(-{2,})?")
SN_SEGMENT = re.compile(r"sn-[a-z0-9-]{6,}")
PUNYCODE = re.compile(r"xn--")

# --- Domains racine infra connus ---
CDN_BASE_DOMAINS = {
    "googlevideo.com",
    "gvt1.com",
    "drive.google.com",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "info", "click", "site", "online", "buzz"
}

def _base_domain(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname

def _looks_high_entropy(label: str) -> bool:
    if len(label) < 10:
        return False

    alnum_ratio = sum(c.isalnum() for c in label) / len(label)
    vowel_ratio = sum(c in "aeiou" for c in label) / len(label)

    return alnum_ratio > 0.8 and vowel_ratio < 0.2

def _looks_like_cdn(url: str) -> bool:
    try:
        hostname = urlparse(url).hostname or ""
    except Exception:
        return False

    hostname = hostname.lower()
    labels = hostname.split(".")

    # --- Heuristique Punycode ---
    if any(PUNYCODE.search(l) for l in labels):
        return True

    # --- TLD ---
    tld = labels[-1] if labels else ""
    base = _base_domain(hostname)

    # --- CDN Google ---
    if base in CDN_BASE_DOMAINS:
        for label in labels:
            if RR_PREFIX.match(label):
                return True
            if SN_SEGMENT.search(label):
                return True
            if _looks_high_entropy(label):
                return True

    # --- Domain jetable / DGA ---
    if tld in SUSPICIOUS_TLDS:
        entropy_labels = [l for l in labels[:-1] if _looks_high_entropy(l)]
        if len(entropy_labels) >= 1:
            return True

    # --- Fallback général ---
    if sum(_looks_high_entropy(l) for l in labels) >= 2:
        return True

    return False
