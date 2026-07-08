"""Tests for the HTTPS callback server that captures the authorization code.

Uses trustme to issue real certificates so the server runs genuine TLS.
"""

import threading

import pytest
import requests
import trustme

from simpleoauth2token.callbackServer import CallbackServer
from simpleoauth2token.errors import OAuth2Error


@pytest.fixture
def tlsFiles(tmp_path):
    """Real localhost certificate, key, and CA bundle paths for TLS tests."""
    certificateAuthority = trustme.CA()
    serverCert = certificateAuthority.issue_cert("localhost", "127.0.0.1")
    certFile = tmp_path / "localhost.pem"
    keyFile = tmp_path / "localhost-key.pem"
    caFile = tmp_path / "ca.pem"
    serverCert.cert_chain_pems[0].write_to_path(str(certFile))
    serverCert.private_key_pem.write_to_path(str(keyFile))
    certificateAuthority.cert_pem.write_to_path(str(caFile))
    return certFile, keyFile, caFile


def sendCallbackRequest(url: str, caFile) -> None:
    """Fire a GET at the callback URL from a background thread."""
    def doRequest():
        requests.get(url, verify=str(caFile), timeout=10)
    thread = threading.Thread(target=doRequest, daemon=True)
    thread.start()


def test_capturesCodeAndStateOverHttps(tlsFiles):
    certFile, keyFile, caFile = tlsFiles
    server = CallbackServer(port=0, certFile=certFile, keyFile=keyFile)
    server.start()
    try:
        url = f"{server.redirectUri}?code=abc123&state=xyz789"
        sendCallbackRequest(url, caFile)
        result = server.waitForCallback(timeoutSeconds=10)
        assert result == {"code": "abc123", "state": "xyz789"}
    finally:
        server.stop()


def test_redirectUriUsesHttpsLocalhostAndCallbackPath(tlsFiles):
    certFile, keyFile, _ = tlsFiles
    server = CallbackServer(port=0, certFile=certFile, keyFile=keyFile)
    server.start()
    try:
        assert server.redirectUri.startswith("https://localhost:")
        assert server.redirectUri.endswith("/callback")
    finally:
        server.stop()


def test_providerErrorRaisesOAuth2Error(tlsFiles):
    certFile, keyFile, caFile = tlsFiles
    server = CallbackServer(port=0, certFile=certFile, keyFile=keyFile)
    server.start()
    try:
        url = f"{server.redirectUri}?error=access_denied&error_description=User+declined"
        sendCallbackRequest(url, caFile)
        with pytest.raises(OAuth2Error, match="access_denied"):
            server.waitForCallback(timeoutSeconds=10)
    finally:
        server.stop()


def test_timeoutRaisesOAuth2Error(tlsFiles):
    certFile, keyFile, _ = tlsFiles
    server = CallbackServer(port=0, certFile=certFile, keyFile=keyFile)
    server.start()
    try:
        with pytest.raises(OAuth2Error, match="[Tt]imed out"):
            server.waitForCallback(timeoutSeconds=0.2)
    finally:
        server.stop()
