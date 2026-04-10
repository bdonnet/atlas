"""
Analyses FIDO2 challenge that has been capture and provides a score describing the web site security level.

See Documentation/challenge_analysis.md for details
"""

from import_data import *
from utils import *

import math

__all__ = ["extract_challenge_statistics", "classify_security_level", "compute_fido_security_score", "analyze_challenge_uniqueness", "analyze_replay_and_timestamp_risk"]

async def extract_challenge_statistics(captures: List[Dict[str, Any]]) -> Dict[str, List]:
    lengths = []
    entropies = []

    for cap in captures:
        if not isinstance(cap, dict):
            continue

        challenge_value = cap.get("challenge")

        if isinstance(challenge_value, list):
            raw = bytes(challenge_value)
        elif isinstance(challenge_value, str):
            raw = await _decode_challenge(challenge_value)
        else:
            raw = None

        if not raw:
            continue

        lengths.append(len(raw))
        entropies.append(await _compute_shannon_entropy(raw))

    return {
        "challenge_lengths": lengths,
        "challenge_entropy": entropies
    }

def compute_fido_security_score(
    challenge_lengths: list[int],
    challenge_entropy: list[float],
    user_verification: list[str],
    attestation_modes: list[str],
    challenge_uniqueness_score: float = 1.0,
    replay_risk_level: float = 0.0
) -> dict:
    """
    Compute a per-site FIDO2 security score based on WebAuthn captures.
    """
    # Step 1: Challenge statistics
    avg_len = float(np.mean(challenge_lengths)) if challenge_lengths else 0.0
    avg_entropy = float(np.mean(challenge_entropy)) if challenge_entropy else 0.0
    avg_effective_entropy = avg_len * avg_entropy  # bits

    # Step 2: User Verification score
    uv_mapping = {"required": 1.0, "preferred": 0.5, "discouraged": 0.0}
    uv_scores = [uv_mapping.get(uv.lower(), 0.0) for uv in user_verification]
    uv_score = float(np.mean(uv_scores)) if uv_scores else 0.0

    # Step 3: Attestation score
    att_mapping = {"direct": 1.0, "indirect": 0.7, "none": 0.0}
    att_scores = [att_mapping.get(a.lower(), 0.0) for a in attestation_modes]
    att_score = float(np.mean(att_scores)) if att_scores else 0.0

    # Step 4: Overall score
    # New weighting:
    # 40% entropy
    # 25% user verification
    # 15% attestation
    # 20% challenge uniqueness
    entropy_component = min(avg_effective_entropy / 256, 1.0)

    overall_score = (
        entropy_component * 40
        + uv_score * 25
        + att_score * 15
        + challenge_uniqueness_score * 20
    )

    overall_score = overall_score * (1 - replay_risk_level)

    return {
        "average_challenge_length": round(avg_len, 2),
        "average_entropy_per_byte": round(avg_entropy, 2),
        "average_effective_entropy_bits": round(avg_effective_entropy, 2),
        "user_verification_score": round(uv_score, 2),
        "attestation_score": round(att_score, 2),
        "challenge_uniqueness_score": round(challenge_uniqueness_score, 2),
        "overall_score": round(overall_score, 2),
    }

def classify_security_level(overall_score: float) -> str:
    """
    Classify a FIDO2 site's security level based on its overall score.

    Parameters
    ----------
    overall_score : float
        Overall score returned by compute_fido_security_score (0-100).

    Returns
    -------
    str
        One of: 'very weak', 'weak', 'moderate', 'strong'
    """
    if overall_score >= 80:
        return "strong"
    elif overall_score >= 60:
        return "moderate"
    elif overall_score >= 40:
        return "weak"
    else:
        return "very weak"

def _hamming_distance_bytes(a: bytes, b: bytes) -> int:
    """Compute bit-level Hamming distance between two byte strings."""
    if len(a) != len(b):
        return 0

    distance = 0
    for x, y in zip(a, b):
        distance += bin(x ^ y).count("1")
    return distance


def analyze_challenge_uniqueness(
    captures: list[dict]
) -> dict:
    """
    Analyze multiple captured challenges for uniqueness and randomness.

    Returns:
        - challenge_unique (bool)
        - challenge_reuse_detected (bool)
        - unique_challenge_count (int)
        - average_hamming_distance (float)
        - min_hamming_distance (float)
        - challenge_uniqueness_score (float) [0-1]
    """

    decoded_challenges = []

    for cap in captures:
        challenge_value = cap.get("challenge")

        if isinstance(challenge_value, list):
            decoded_challenges.append(bytes(challenge_value))
        elif isinstance(challenge_value, str):
            try:
                padded = challenge_value + "=" * (-len(challenge_value) % 4)
                decoded_challenges.append(base64.urlsafe_b64decode(padded))
            except Exception:
                continue

    if len(decoded_challenges) < 2:
        return {
            "challenge_unique": True,
            "challenge_reuse_detected": False,
            "unique_challenge_count": len(decoded_challenges),
            "average_hamming_distance": 0.0,
            "min_hamming_distance": 0.0,
            "challenge_uniqueness_score": 1.0,
        }

    # Detect reuse
    unique_set = set(decoded_challenges)
    reuse_detected = len(unique_set) < len(decoded_challenges)

    # Compute Hamming distances
    distances = []
    for i in range(len(decoded_challenges)):
        for j in range(i + 1, len(decoded_challenges)):
            d = _hamming_distance_bytes(
                decoded_challenges[i],
                decoded_challenges[j]
            )
            distances.append(d)

    avg_distance = float(np.mean(distances)) if distances else 0.0
    min_distance = float(np.min(distances)) if distances else 0.0

    # Expected distance for 256-bit challenge ≈ 128
    # Normalize uniqueness score
    expected_half_bits = (len(decoded_challenges[0]) * 8) / 2
    normalized_distance = min(avg_distance / expected_half_bits, 1.0)

    if reuse_detected:
        uniqueness_score = 0.0
    else:
        uniqueness_score = normalized_distance

    return {
        "challenge_unique": not reuse_detected,
        "challenge_reuse_detected": reuse_detected,
        "unique_challenge_count": len(unique_set),
        "average_hamming_distance": round(avg_distance, 2),
        "min_hamming_distance": round(min_distance, 2),
        "challenge_uniqueness_score": round(uniqueness_score, 2),
    }

def analyze_replay_and_timestamp_risk(decoded_challenges: list[bytes]) -> dict:
    """
    Advanced academic-level replay & timestamp pattern analysis.
    """

    if len(decoded_challenges) < 2:
        return {
            "timestamp_pattern_detected": False,
            "timestamp_position": None,
            "timestamp_monotonic": False,
            "replay_vulnerability": False,
            "replay_risk_level": 0.0,
        }

    # 1. Exact reuse
    unique_count = len(set(decoded_challenges))
    exact_reuse = unique_count < len(decoded_challenges)

    # 2. Timestamp detection
    all_timestamp_candidates = []

    for ch in decoded_challenges:
        candidates = _extract_possible_timestamps(ch)
        all_timestamp_candidates.append(candidates)

    # Find common offset across probes
    offset_counter = {}

    for probe in all_timestamp_candidates:
        for (offset, val, size, mode) in probe:
            offset_counter[offset] = offset_counter.get(offset, 0) + 1

    timestamp_detected = False
    timestamp_position = None
    monotonic = False

    if offset_counter:
        # offset appearing in all probes
        for offset, count in offset_counter.items():
            if count == len(decoded_challenges):
                timestamp_detected = True
                timestamp_position = offset
                break

    # Monotonicity check
    if timestamp_detected:
        extracted_values = []
        for ch in decoded_challenges:
            chunk = ch[timestamp_position:timestamp_position + 8]
            try:
                val = struct.unpack(">Q", chunk[:8])[0]
            except:
                val = struct.unpack(">I", chunk[:4])[0]
            extracted_values.append(val)

        monotonic = all(
            extracted_values[i] <= extracted_values[i + 1]
            for i in range(len(extracted_values) - 1)
        )

    # 3. Structural similarity (Hamming analysis)
    distances = []

    for i in range(len(decoded_challenges)):
        for j in range(i + 1, len(decoded_challenges)):
            dist = sum(
                bin(a ^ b).count("1")
                for a, b in zip(decoded_challenges[i], decoded_challenges[j])
            )
            distances.append(dist)

    avg_distance = sum(distances) / len(distances) if distances else 0
    expected_half = len(decoded_challenges[0]) * 8 / 2

    similarity_ratio = 1 - min(avg_distance / expected_half, 1.0)

    # 4. Risk scoring (graduelle)
    risk = 0.0

    if exact_reuse:
        risk += 1.0

    if timestamp_detected and monotonic:
        risk += 0.8
    elif timestamp_detected:
        risk += 0.5

    if similarity_ratio > 0.4:
        risk += 0.4 * similarity_ratio

    risk = min(risk, 1.0)

    return {
        "timestamp_pattern_detected": timestamp_detected,
        "timestamp_position": timestamp_position,
        "timestamp_monotonic": monotonic,
        "replay_vulnerability": risk > 0.5,
        "replay_risk_level": round(risk, 2),
    }

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

async def _decode_challenge(challenge_b64: str) -> Optional[bytes]:
    """
    Safely decodes a Base64 or Base64URL WebAuthn challenge.

    Returns raw bytes or None if decoding fails.
    """
    if not challenge_b64 or not isinstance(challenge_b64, str):
        return None

    try:
        # First try standard base64
        return base64.b64decode(challenge_b64, validate=True)
    except Exception:
        try:
            # Try base64url fallback
            padded = challenge_b64 + "=" * (-len(challenge_b64) % 4)
            return base64.urlsafe_b64decode(padded)
        except Exception:
            return None

async def _compute_shannon_entropy(data: bytes) -> float:
    """
    Computes Shannon entropy in bits per byte.

    | Entropy   | Interpretation             |
    | --------- | -------------------------- |
    | 7.7 – 8.0 | Excellent (correct CSPRNG) |
    | 7.0 – 7.6 | Acceptable but suspect     |
    | 6.0 – 6.9 | Weak                       |
    | < 6.0     | Very bad                   |
    | < 5.0     | Probably deterministic     |
    """
    if not data:
        return 0.0

    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0.0
    length = len(data)

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)

def _extract_possible_timestamps(data: bytes):
    """
    Scan all possible 4 and 8 byte windows for plausible UNIX timestamps.
    Returns list of (offset, value, size).
    """
    candidates = []
    now = int(time.time())

    for size in (4, 8):
        for offset in range(0, len(data) - size + 1):
            chunk = data[offset:offset + size]

            try:
                if size == 4:
                    val_be = struct.unpack(">I", chunk)[0]
                    val_le = struct.unpack("<I", chunk)[0]
                    values = [val_be, val_le]
                else:
                    val_be = struct.unpack(">Q", chunk)[0]
                    val_le = struct.unpack("<Q", chunk)[0]
                    values = [val_be, val_le]

                for val in values:
                    # seconds
                    if abs(val - now) < 600:
                        candidates.append((offset, val, size, "seconds"))
                    # milliseconds
                    elif abs(val // 1000 - now) < 600:
                        candidates.append((offset, val, size, "milliseconds"))

            except Exception:
                continue

    return candidates
