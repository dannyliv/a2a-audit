from __future__ import annotations

import pytest

from a2a_audit.fetch import FetchError, assert_safe_url


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://localhost/x",
        "https://127.0.0.1/x",
        "http://10.0.0.1/x",
        "http://192.168.1.1/x",
        "http://[::1]/x",
        "ftp://example.com/x",
        "file:///etc/passwd",
        "gopher://example.com",
    ],
)
def test_blocks_unsafe(url):
    with pytest.raises(FetchError):
        assert_safe_url(url)


def test_allows_public_https():
    # Public, resolvable host should not raise.
    assert_safe_url("https://example.com/.well-known/agent-card.json")


def test_allow_http_false_blocks_http():
    with pytest.raises(FetchError):
        assert_safe_url("http://example.com/x", allow_http=False)
