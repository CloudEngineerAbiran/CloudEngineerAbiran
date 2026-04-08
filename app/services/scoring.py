from __future__ import annotations


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def cvss_like_score(exploitability: float, impact: float) -> float:
    score = (0.6 * impact) + (0.4 * exploitability)
    return max(0.0, min(10.0, round(score, 1)))
