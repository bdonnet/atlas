"""
Configuration file for paths towards files
"""
from datetime import datetime

"""
Directories with data for this project
"""
CSV_DIR         = "../CSV/"
SCREENSHOT_DIR  = "../Screenshots/"
LOG_DIR         = "../Logs/"
TARGET_DIR      = CSV_DIR+"URLs/"
GROUNDTRUTH_DIR = CSV_DIR+"Groundtruth/"
ANALYSIS_DIR    = "./analysis/"
SCRAPING_DIR    = CSV_DIR+"Scraping/"
CHALLENGE_DIR   = CSV_DIR+"Challenge/"
PLOT_DIR        = "../Plots/"

"""
File for testing FIDOLOGY scraping.
"""
TEST_FULL      = TARGET_DIR+"Test_Scraping.csv"
TEST_FIDO_FULL = TARGET_DIR+"Test_Fido2_Challenge_Capture.csv"

"""
File for scraping the groundtruth
"""
GROUNDTRUTH_FULL   = GROUNDTRUTH_DIR+"groundtruth.csv"

"""
Files to launch the Atlas scraping for the Top 1M websites.

Each file is the input for a given vantage point.
"""
DATASET_0 = TARGET_DIR+"dataset_0.csv"
DATASET_1 = TARGET_DIR+"dataset_1.csv"
DATASET_2 = TARGET_DIR+"dataset_2.csv"
DATASET_3 = TARGET_DIR+"dataset_3.csv"

"""
Output file for ATLAS scraping.

The CSV file is organized according to OUTPUT_CSV_COLUMNS
"""
RAW_OUTPUT_FILE      = SCRAPING_DIR + f"RAW/ATLAS_raw_results_{datetime.now().strftime('%Y-%m-%d')}.csv.gz"
FILTERED_OUTPUT_FILE = SCRAPING_DIR + f"FILTERED/ATLAS_filtered_results_{datetime.now().strftime('%Y-%m-%d')}.csv"
SCREENSHOTS_ZIP      = SCREENSHOT_DIR + f"ATLAS_screenshots_{datetime.now().strftime('%Y-%m-%d')}.zip"

"""
Plotting and analysis directories
"""
GROUNDTRUTH_PLOT = PLOT_DIR+"Groundtruth/"
ETHICS_PLOT      = PLOT_DIR+"Ethics/"
SCRAPING_PLOT    = PLOT_DIR+"Scraping/"
CHALLENGE_PLOT   = PLOT_DIR+"Challenge/"

"""
Scraped file that wants to be analysed
"""
SCRAPED_FILE =  SCRAPING_DIR+"FILTERED/1M_filtered_scraping_03-27.csv"
SCRAPED_GROUNDTRUTH = GROUNDTRUTH_DIR+"groundtruth_results_2026-03-23.csv"
SCRAPED_GROUNDTRUTH_RAW = GROUNDTRUTH_DIR+"raw_results_2026-03-23.csv"

"""
Output file for capturing FIDO2 challenges
"""
CHALLENGE_OUTPUT_FILE = CHALLENGE_DIR + f"ATLAS_challenge_capture_results_{datetime.now().strftime('%Y-%m-%d')}.csv"
SCRAPING_FIDO_CHALLENGE_FULL = CHALLENGE_DIR+"ATLAS_challenge_capture_results_2026-04-01.csv"
FIDO_CHALLENGE_FULL = CHALLENGE_DIR+"FIDO2_challenge_dataset.csv"
