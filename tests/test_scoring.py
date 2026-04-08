from app.services.scoring import cvss_like_score, score_to_severity


def test_cvss_like_score_bounds():
    assert cvss_like_score(20, 20) == 10.0
    assert cvss_like_score(-1, -1) == 0.0


def test_score_to_severity():
    assert score_to_severity(9.5) == "CRITICAL"
    assert score_to_severity(7.2) == "HIGH"
    assert score_to_severity(5.1) == "MEDIUM"
    assert score_to_severity(2.0) == "LOW"
