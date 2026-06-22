from app.scoring import compute, grade_for


def test_grade_bands():
    assert grade_for(100) == "A+"
    assert grade_for(92) == "A"
    assert grade_for(85) == "B"
    assert grade_for(72) == "C"
    assert grade_for(61) == "D"
    assert grade_for(40) == "F"


def test_all_pass_is_perfect():
    cats = [{"key": "tls", "label": "TLS", "findings": [
        {"title": "a", "status": "pass", "weight": 1.0},
        {"title": "b", "status": "pass", "weight": 2.0},
    ]}]
    out = compute(cats)
    assert out["score"] == 100.0
    assert out["grade"] == "A+"


def test_warning_is_half_credit():
    cats = [{"key": "tls", "label": "TLS", "findings": [
        {"title": "a", "status": "warn", "weight": 1.0},
    ]}]
    out = compute(cats)
    assert out["score"] == 50.0


def test_info_findings_do_not_affect_score():
    cats = [{"key": "tls", "label": "TLS", "findings": [
        {"title": "a", "status": "pass", "weight": 1.0},
        {"title": "note", "status": "info", "weight": 5.0},
    ]}]
    out = compute(cats)
    assert out["score"] == 100.0
    assert out["categories"][0]["max_score"] == 1.0  # info excluded from max


def test_category_weighting():
    # tls (weight 2.0) all fail, http_protocol (weight 0.5) all pass.
    cats = [
        {"key": "tls", "label": "TLS", "findings": [{"title": "a", "status": "fail", "weight": 1.0}]},
        {"key": "http_protocol", "label": "P", "findings": [{"title": "b", "status": "pass", "weight": 1.0}]},
    ]
    out = compute(cats)
    # weighted mean = (0*2.0 + 1*0.5) / 2.5 = 0.2 -> 20%
    assert out["score"] == 20.0
