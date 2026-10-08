"""
S.H.A.D.E. — Shannon Entropy Utility
Role: Member 3 — AI/ML + Anomaly Analysis
"""

import math


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    for x in set(text):
        p_x = float(text.count(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy
