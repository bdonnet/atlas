"""
Configuration file for timeouts used during ATLAS scrapping
"""

"""
Managing timeouts for loading pages.  Values might be adapted such that we have a balance
between scraping scalability and results relevance.

Quite long but ensure better FIDO2 detection for some corner cases.
"""
TIMEOUT_MS          = 5000
TIMEOUT_COOKIE      = 1000
TIMEOUT_FEDCM       = 2000
TIMEOUT_CLICK       = 2000
TIMEOUT_TRIGGER     = 3000
TIMEOUT_VISIBLE     = 3000
TIMEOUT_VALIDATION  = 4000
TIMEOUT_ENABLE      = 5000

"""
Default number of sites to process before dumping to CSV.

Might be modified by command-line argument
"""
DUMP_EVERY     = 10

"""
Number of attempts per site for capturing WebAuthn/FIDO2 data
"""
NB_ATTEMPTS_CAPTURE = 5
