from app.masking import mask_hostname


def test_benchmarks_are_not_masked():
    assert mask_hostname("github.com") == "github.com"
    assert mask_hostname("GitHub.com") == "github.com"


def test_subdomain_is_masked():
    masked = mask_hostname("internal-admin.corp.example.com")
    assert "internal-admin" not in masked
    assert masked.endswith("example.com")
    assert masked.startswith("i***")


def test_apex_is_masked():
    masked = mask_hostname("mysecretstartup.com")
    assert masked.startswith("m***")
    assert "secret" not in masked
