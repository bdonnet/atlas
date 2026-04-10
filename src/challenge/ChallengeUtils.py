from import_data import *
from utils import *

def create_capture_dataset(input_file):
    """
    - Creates a dataset for FIDO capture
    - It takes the URLs that are classified in 'full_fido2' and 'webauthn' 
      and the other FIDO2-Native ('storage', 'latent_support', 'fido_only_ui', 'latent_usage') 
      that have a 'Validated' FIDO2 usage
    """
    df = pd.read_csv(input_file)
    # full fido and webauthn
    df_1 = df[df["fido2_usage"].isin(['full_fido2', 'webauthn'])]
    # other fido2 native that are validated
    df_2 = df[df["fido2_usage"].isin(['storage', 'latent_support', 'fido_only_ui', 'latent_usage']) & df["validated"]]
    df_out = pd.concat([df_1, df_2])
    # keeping only interesting columns
    df_out = df_out[['site_url', 'fido2_usage']]
    # renaming columns
    df_out.rename(columns={'site_url': 'Site', 'fido2_usage': 'Usage'}, inplace=True)
    df_out.to_csv(CSV_DIR+"Capture/capture_dataset.csv", index_label='Index')
