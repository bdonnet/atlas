"""
Configuration file for keywords used during ATLAS analysis
"""

"""
Each of the 5 authentication categories
"""
CATEGORIES = [
    "None/Error",
    "Password-Based",
    "Password-Extended",
    "Unknown",
    "Fido2-Native",
]

"""
Order of priority for the different categories for the groundtruth
"""
GT_PRIORITY = [
    "Fido2-Native",
    "Password-Extended",
    "Password-Based",
    "None/Error",
    "Unknown",
]

"""
Mapping between the usages to the 5 authentication categories
"""
USAGE_TO_CATEGORY = {
    "none": "None/Error",
    "error": "None/Error",

    "password_only": "Password-Based",
    "password_based_network":"Password-Based",
    "password_based_opaque":"Password-Based",

    "password+otp": "Password-Extended",
    "password+fido": "Password-Extended",

    "unknown": "Unknown",

    "fido_only_ui": "Fido2-Native",
    "latent_support": "Fido2-Native",
    "latent_usage": "Fido2-Native",
    "storage": "Fido2-Native",
    "webauthn": "Fido2-Native",
    "full_fido2": "Fido2-Native",
}
