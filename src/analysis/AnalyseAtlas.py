"""
Entry point for ATLAS data analysis.
"""

from import_data import *
from utils import *

__all__ = ["run_data_analysis"]

def run_data_analysis(args):
    """
    Entry point for ATLAS data analysis

    Params:
        args: CLI arguments
    """
    _manage_args_metric(args.metric)

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _manage_args_metric(input_file):
    """
    manages ATLAS data analysis arguments
    """
    match input_file:
        case 'CHALLENGE':
            if os.path.exists(SCRAPING_FIDO_CHALLENGE_FULL):
                challenge_capture_analysis(SCRAPING_FIDO_CHALLENGE_FULL)
            else:
                logger.info("Fichier "+SCRAPING_FIDO_CHALLENGE_FULL+" n'existe pas dans "+CHALLENGE_DIR)
                sys.exit(-1)

        case 'GROUNDTRUTH':
            if os.path.exists(GROUNDTRUTH_FULL):
                groundtruth_analysis(GROUNDTRUTH_FULL, SCRAPED_GROUNDTRUTH, shadow_dom_validation=True)
            else:
                logger.info("Fichier "+GROUNDTRUTH_FULL+" n'existe pas dans "+GROUNDTRUTH_DIR)
                sys.exit(-1)

        case 'SCRAPING':
            if os.path.exists(SCRAPED_FILE):
                scraping_analysis(SCRAPED_FILE)
            else:
                logger.info("Fichier " + SCRAPED_FILE + " n'existe pas dans ../CSV/Scraping/FILTERED/.")

        case 'ETHICS':
            ethics_analysis(SCRAPED_GROUNDTRUTH, SCRAPED_FILE)

        case _:
            logger.info("Fichier en entrée "+input_file+" non accepté")
            sys.exit(-1)
