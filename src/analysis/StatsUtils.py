"""
Functions to get different statistics about the scraped data
"""

from import_data import *
from utils import *

def top_countries(input_file, n): 
    """
    Count the occurencies of each country in a URL <-> Country mapped list

    Params:
        input_file: the mapped list
        n: top n countries

    Returns:
        A sorted dictionnary with the number of occurencies for each country in decroissant order
    """
    # loading file
    df = pd.read_csv(input_file, sep=",", skipinitialspace=True)
    # df = df[df['fido2_usage'] == "full_fido2"]

    country_dict = df.groupby('country').size().to_dict()

    # sorting it
    country_dict = {k: v for k, v in sorted(country_dict.items(), key=lambda item: item[1], reverse=True)}

    return dict(islice(country_dict.items(), n)), len(df)

def top_categories(input_file): 
    """
    Count the occurencies of each category in a URL <-> Category mapped list

    Params:
        input_file: the mapped list
        n: top n categories

    Returns:
        A sorted dictionnary with the number of occurencies for each category in decroissant order
    """
    # loading file
    df = pd.read_csv(input_file, sep=",", skipinitialspace=True)

    category_dict = (df.groupby('category').size().to_dict())

    # sorting it
    category_dict = {k: v for k, v in sorted(category_dict.items(), key=lambda item: item[1], reverse=True)}

    return category_dict, len(df)

def adding_colors_to_file(file):
    """
    Adding the correct color to all the file
    """
    df = pd.read_csv(file, sep=",", skipinitialspace=True)
    df["category"] = df["fido2_usage"].apply(get_usage_color)
    df.to_csv(file, index=False)

def adding_score_to_groundtruth(file):
    """ 
    Adding confidence score to groundtruth
    """
    df = pd.read_csv(file, sep=",", skipinitialspace=True)
    rows = []
    for index, row in df.iterrows():
        for n in row['fido2_usage_gt']:
            row['score_confidence'] = get_usage_max_score(n)
        rows.append(row)
    new = pd.DataFrame(rows)
    new.to_csv(file,index=False)


def check_scraping_correctness(input_file):
    """
    Check for each row if the color corresponds to the one from the groundtruth

    Params:
        input_file: the scraper result file
    """
    # loading the 2 files
    result_df = pd.read_csv(input_file, sep=",", skipinitialspace=True)
    groundtruth = pd.read_csv(GROUNDTRUTH_FULL, sep=",", skipinitialspace=True)

    # variables for stats
    correct_usage = 0
    incorrect_usage = 0
    fp = 0 
    fn = 0
    total_dict_color = {'Green': 0, 'Yellow': 0, 'Orange': 0, 'Red': 0, 'Grey': 0}
    matching_dict_color = {'Green': 0, 'Yellow': 0, 'Orange': 0, 'Red': 0, 'Grey': 0}
    not_matching_dict_color = {'Green': 0, 'Yellow': 0, 'Orange': 0, 'Red': 0, 'Grey': 0}
    rows = []
    len_grdt = len(groundtruth)

    # checking for each row the colors
    for index,row in result_df.iterrows():

        # getting colors
        groundtruth_color = groundtruth.loc[index]['color']
        scraping_color = get_usage_color(row['fido2_usage'])
        # updating dict
        total_dict_color[scraping_color] += 1
        # adding to output
        row['scraping_color'] = scraping_color
        row['groundtruth_color'] = groundtruth_color
        rows.append(row)

        # if color is right
        if groundtruth_color == scraping_color:
            correct_usage += 1
            matching_dict_color[scraping_color] += 1

        # if color is wrong
        else:
            incorrect_usage += 1
            not_matching_dict_color[scraping_color] += 1
            # found a 'better' color
            if more_secure(groundtruth_color, scraping_color):
                fp += 1
            # found a 'less better' color
            else:
                fn += 1

    incorrect_df = pd.DataFrame(rows)
    incorrect_df.to_csv("../CSV/Scraping/comparisons/first_scraping_comp.csv",index=False)

    percentage_correct = (correct_usage/len_grdt)*100
    print(f'Percentage of matching colors: {math.floor(percentage_correct)}%')
    print(f'Percentage of not matching colors: {100 - math.floor(percentage_correct)}% :')
    print(f'    {math.floor((fn/len_grdt)*100)}% of less secure colors')
    print(f'    {math.floor((fp/len_grdt)*100)}% of more secure colors')
    print(f'Total colors dictionnary: {total_dict_color}')
    print(f'Matching colors dictionnary: {matching_dict_color}')
    print(f'Not matching colors dictionnary: {not_matching_dict_color}')

    return correct_usage/len_grdt, fp/len_grdt

def get_usage_color(fido_usage):
    """
    Returns the color depending on the fido usage 

    Params:
        fido_usage: usage of fido2 found by scraper 
    """
    usage_to_color_dict = {'none': 'None/Error', 'unknown': 'Unknown',
                           'password_only': 'Password-Based', 'password+otp': 'Password-Extended',
                           'password+fido': 'Password-Extended', 'full_fido2': 'FIDO2-Native',
                           'webauthn': 'FIDO2-Native', 'latent_support': 'FIDO2-Native', 'mixed': 'FIDO2-Native', 
                           'fido_only_ui': 'FIDO2-Native', 'error': 'None/Error', 'latent_usage': 'FIDO2-Native'}
    
    if usage_to_color_dict.get(fido_usage):
        return usage_to_color_dict.get(fido_usage) 
    else: 
        return 'None/Error'
    
def get_usage_max_score(fido_usage):
    usage_to_score_dict = {'none': 0.05, 'unknown': 0.4,
                           'password_only': 0.2, 'password+otp': 0.45,
                           'password+fido': 0.7, 'full_fido2': 1,
                           'webauthn': 0.8, 'latent_support': 0.4, 'mixed': 0.65, 
                           'fido_only_ui': 0.35, 'error': 0.0, 'latent_usage': 0.5}
     
    if usage_to_score_dict.get(fido_usage):
        return usage_to_score_dict.get(fido_usage) 
    else: 
        return 0.0
   
def more_secure(groudtruth_color, scraping_color):
    """
    Returns True if the color found by the scraper is more secure than the one of the groudntruth

    Params:
        groundtruth_color: fido usage color from the groundtruth
        scraping_color: fido usage color found by scraper
    """
    if scraping_color == "Yellow" and groudtruth_color == "Green":
        return False
    
    if scraping_color == "Orange" and (groudtruth_color == "Green" or groudtruth_color == "Yellow"):
        return False
    
    if scraping_color == "Red" and (groudtruth_color == "Green" or groudtruth_color == "Yellow" or groudtruth_color == "Orange"):
        return False
    
    if scraping_color == "Grey" and (groudtruth_color != "Grey"):
        return False
    
    return True
    
    
def signals_stats(input_file):
    """
    Creates a dictionnary with the most found signals

    Params:
        input_file: the scraper results to analyze
    """
    df = pd.read_csv(input_file)
    signals = ['password_input_present', 'password_input_in_shadow_dom', 
                'credentials_api_used', 'credentials_create_summary',
                'network_webauthn', 'network_password', 'passkey_setup_endpoint_present',
                'fedcm_present', 'fedcm_detected_via_api', 'local_storage_contains_fido', 
                'session_storage_contains_fido', 'cookies_contain_fido', 
                'shadow_dom_webauthn', 'ui_webauthn_keywords_present', 
                'otp_indicators_present', 'fedcm_provider', 'fedcm_fido2_hint', 'multistep_login',
                'auth_js_supports_passkey', 'fido2_indirect_possible']   
    # getting all True signals and summing them
    signals_dict = (df[signals]).sum().to_dict()
    return signals_dict, len(df)

# scraping
def signals_stats_per_country(input_file):
    """
    Creates a dictionnary with the most found signals per country

    Params:
        input_file: the scraper results to analyze
    """
    df = pd.read_csv(input_file)

    tld_df = pd.read_csv(TLD_CODE_DB, sep=";", skipinitialspace=True)
    tld_df =  tld_df.drop_duplicates(subset='country', keep='first')
    to_tld = dict(zip(tld_df['country'], tld_df['tld']))
    df['country'] = df['country'].map(to_tld)
    df['country'] = df['country'].str.lstrip('.')

    signals = ['password_input_present','password_input_in_shadow_dom',
               'network_password','network_webauthn',
               'credentials_api_used','passkey_setup_endpoint_present',
               'auth_js_supports_passkey','ui_webauthn_keywords_present',
               'shadow_dom_webauthn','local_storage_contains_fido',
               'fedcm_present','fedcm_provider',
               'fido2_indirect_possible','multistep_login',
               'otp_indicators_present']
    
    # getting all True signals and summing them
    signals_dict = (df[signals] == True).groupby(df["country"]).sum().to_dict()

    return signals_dict

def colors_per_country(input_file):
    """
    Builds a dictionnary with the color occurencies for each country

    {
        United States of Amercia: {Green: 19, Yellow: 3, ...},
        United Kingdom: {Green: 8, Yellow: 2, ...},
        ...
    }

    Params:
        input_file: the scraper result file
    """
    # loading countries
    df_countries = pd.read_csv(TLD_CODE_DB, sep=";", skipinitialspace=True)

    # loading scraping results
    df = pd.read_csv(input_file, sep=",", skipinitialspace=True)
    countries = {}

    # adding color to each row
    df['color'] = df['fido2_usage'].apply(get_usage_color)

    # grouping them by country and get color as columns to check after
    color_occurence = (df.groupby(['country', 'color']).size().unstack(fill_value=0)) 

    # checking if each color is present
    for col in ['FIDO2-Native', 'Password-Extended', 'Password-Based', 'None/Error', 'Unknown']:
        if col not in color_occurence.columns:
            color_occurence[col] = 0

    countries = color_occurence.to_dict(orient='index')

    return countries 

def countries_per_color(input_file):
    """
    Builds a dictionnary with the top countries for each color (inverting above dict)

    {
        Green: {America: 8, UK: 3, ...},
        Yellow: {America: 4, UK: ...},
        ...
    }

    Params:
        input_file: the scraper result file
    """

    dict = colors_per_country(input_file)
    colors_dict =  {'Green': {}, 'Yellow': {}, 'Orange': {}, 'Red': {}, 'Grey': {}}

    for country, val in dict.items():
        for color in colors_dict:
            colors_dict[color].update({country: val[color]})
            
    for key, val in colors_dict.items():
        colors_dict[key] = {k: v for k, v in sorted(val.items(), key=lambda item: item[1], reverse=True)}

    print(colors_dict)

    return colors_dict


def errors_per_option(input_file, option):
    """
    Creates a dict with the number of errors per country or per category

    Params:
        input_file: the scraper result file
        option: 'country' or 'category'
    """
    if not(option == 'country' or option == 'category'):
        print("usage: option is 'country' or 'category' ")
        return 
    
    df = pd.read_csv(input_file, sep=",", skipinitialspace=True)

    # changing countries into their tld
    tld_df = pd.read_csv(TLD_CODE_DB, sep=";", skipinitialspace=True)
    to_tld = dict(zip(tld_df['country'], tld_df['tld']))
    df['country'] = df['country'].map(to_tld)
    df['country'] = df['country'].str.lstrip('.')

    # total occ per country
    total_occurrence = df.groupby(option).size()

    # nb of errors per country
    errors_occurence = df[df['login_navigation_successful'] == False].groupby(option).size()

    # putting into one dict
    errors_dict = {}
    for country in total_occurrence.index:
        errors_dict[country] = {'analysis success': int(total_occurrence[country]-errors_occurence.get(country, 0)), 'errors': int(errors_occurence.get(country, 0))}
    return errors_dict


def categories_per_country(input_file):
    """
    Creates a dict with the different categories occurence per country 

    Params:
        input_file: the scraper result file
    """
    df = pd.read_csv(input_file, sep=",")

    dict = df.groupby(['Country', 'Category']).size().unstack(fill_value=0).astype(int).to_dict(orient='index')
    return dict

def country_per_categories(input_file):
    """
    Creates a dict with the different country occurencies per categories

    Params:
        input_file: the scraper result file
    """
    df = pd.read_csv(input_file, sep=",")

    dict = df.groupby(['Category', 'Country']).size().unstack(fill_value=0).astype(int).to_dict(orient='index')
    print(dict)
    return dict

def confidence_score_distribution(input_file, country=None, col='fido2_usage'):
    """
    Getting the confidence score for one country

    Params:
        input_file: the scraper result file
        country: the wanted country 
    """
    df = pd.read_csv(input_file, sep=",")

    if country is None:
        data = df
    else:
        data = df[df['country'] == country]

    data = data.dropna(subset=['fido2_confidence'])

    data['fido2_confidence'] = pd.to_numeric(
        data['fido2_confidence'], errors='coerce'
    )

    data = data.dropna(subset=['fido2_confidence'])

    data = (
        data[['fido2_confidence', col]]
        .sort_values(by='fido2_confidence', ascending=True)
    )
    return data


def comparing_two_scraping_file(file1, file2):
    """
    Comparing two scraping files to see the differences
    """
    df1 = adding_colors_to_file(file1)
    df1 = pd.read_csv(file1, sep=",")
    df1 = df1[['site_url', 'color']]

    df2 = adding_colors_to_file(file2)
    df2 = pd.read_csv(file2, sep=",")    
    df2 = df2[['site_url', 'color']]

    ne_stacked = (df1 != df2).stack()
    changed = ne_stacked[ne_stacked]

    difference_locations = np.where(df1 != df2)
    changed_from = df1.values[difference_locations]
    changed_to = df2.values[difference_locations]

    print(len(pd.DataFrame({'file_1': changed_from, 'file_2': changed_to}, index=changed.index)))

def define_dataset(dataset, n):
    """
    Return the top countries and the top categories associated
    """
    dataset = pd.read_csv(dataset)

    # country into tld
    tld_df = pd.read_csv(TLD_CODE_DB, sep=";", skipinitialspace=True)
    to_tld = dict(zip(tld_df['country'], tld_df['tld']))
    dataset['country'] = dataset['country'].map(to_tld)
    dataset['country'] = dataset['country'].str.lstrip('.')

    # iab label into code
    iab_df = pd.read_csv("../CSV/DomainCategory/iab_categories.csv")
    to_iab = dict(zip(iab_df['category'], iab_df['code']))
    dataset['category'] = dataset['category'].map(to_iab)

    top_N_countries = dataset['country'].value_counts().head(n).index
    top_categories = dataset[dataset['country'].isin(top_N_countries)]
    
    return top_categories, top_N_countries, len(dataset)

