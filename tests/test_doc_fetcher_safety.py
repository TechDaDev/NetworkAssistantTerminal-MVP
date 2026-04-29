import pytest

from app.services.doc_fetcher import DocFetchError, validate_public_http_url


def test_doc_fetch_blocks_localhost():
    with pytest.raises(DocFetchError):
        validate_public_http_url("http://localhost/docs")


def test_doc_fetch_blocks_private_ip():
    with pytest.raises(DocFetchError):
        validate_public_http_url("http://192.168.88.1/docs")


def test_doc_fetch_blocks_non_http_scheme():
    with pytest.raises(DocFetchError):
        validate_public_http_url("file:///etc/passwd")
