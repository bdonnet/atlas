
from import_data import *

__all__ = ["ethics_analysis"]

def ethics_analysis(groundtruth: str, scraping: str):
    df_gdt = pd.read_csv(groundtruth)
    df_scraping = pd.read_csv(scraping)

    # selecting columns
    df_result = pd.DataFrame({
        "nb_click_groundtruth": df_gdt["nb_clicks"],
        "nb_click_scraping": df_scraping["nb_clicks"],
        "processing_time_groundtruth": df_gdt["processing_time"],
        "processing_time_scraping": df_scraping["processing_time"]
    })

    df_result.to_csv(ETHICS_PLOT+"df_ethics.csv")
