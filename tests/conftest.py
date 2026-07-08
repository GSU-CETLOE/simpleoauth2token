"""Shared test fixtures.

Provides a real local HTTP server that behaves like an OAuth2 token endpoint,
so client tests exercise genuine HTTP request/response handling with no mocks.
"""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


class FakeTokenEndpointHandler(BaseHTTPRequestHandler):
    """Handles POSTs the way a standard OAuth2 token endpoint would."""

    def do_POST(self) -> None:
        contentLength = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(contentLength).decode("utf-8")
        params = dict(urllib.parse.parse_qsl(body))
        self.server.recordedRequests.append(params)  # type: ignore[attr-defined]

        grantType = params.get("grant_type")
        clientAuthenticated = params.get("client_secret") == "testClientSecret"
        if grantType in ("refresh_token", "client_credentials") and not clientAuthenticated:
            self.sendJson(400, {
                "error": "invalid_client",
                "error_description": "client authentication failed",
            })
        elif grantType == "authorization_code" and params.get("code") == "goodCode":
            self.sendJson(200, {
                "access_token": "initialAccessToken",
                "refresh_token": "initialRefreshToken",
                "expires_in": 3600,
                "token_type": "Bearer",
            })
        elif grantType == "refresh_token" and params.get("refresh_token") == "initialRefreshToken":
            self.sendJson(200, {
                "access_token": "refreshedAccessToken",
                "expires_in": 3600,
                "token_type": "Bearer",
            })
        elif grantType == "client_credentials":
            self.sendJson(200, {
                "access_token": "serviceAccessToken",
                "expires_in": 3600,
                "token_type": "Bearer",
            })
        else:
            self.sendJson(400, {"error": "invalid_grant"})

    def sendJson(self, status: int, payload: dict) -> None:
        """Write a JSON response with the given HTTP status."""
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        """Silence request logging to keep test output pristine."""


class FakeTokenEndpoint:
    """A live localhost OAuth2 token endpoint for tests."""

    def __init__(self) -> None:
        self.httpServer = HTTPServer(("127.0.0.1", 0), FakeTokenEndpointHandler)
        self.httpServer.recordedRequests = []  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpServer.serve_forever, daemon=True)
        self.thread.start()

    @property
    def tokenUrl(self) -> str:
        """URL clients should POST token requests to."""
        return f"http://127.0.0.1:{self.httpServer.server_address[1]}/token"

    @property
    def recordedRequests(self) -> list[dict]:
        """Every form-decoded request body received, in order."""
        return self.httpServer.recordedRequests  # type: ignore[attr-defined]

    def shutdown(self) -> None:
        """Stop the server and release the port."""
        self.httpServer.shutdown()
        self.httpServer.server_close()


@pytest.fixture
def tokenEndpoint():
    """A running fake OAuth2 token endpoint, torn down after the test."""
    endpoint = FakeTokenEndpoint()
    yield endpoint
    endpoint.shutdown()
