"""
Configuration file for common COSE algorithms
"""

"""
Common COSE algorithms

Source:
- https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/Algorithms.html
"""
COMMON_COSE_ALGOS = {
    -7,    # ES256
    -35,   # ES384
    -36,   # ES512
    -257,  # RS256
    -258,  # RS384
    -259,  # RS512
    -37,   # PS256? actually -37/-38 are ECDSA variants, keep them
    -38,
    -8,    # EdDSA
}
