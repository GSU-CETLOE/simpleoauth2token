"""Shared test fixtures.

Provides a real local HTTP server that behaves like an OAuth2 token endpoint,
so client tests exercise genuine HTTP request/response handling with no mocks.
"""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class FakeTokenEndpointHandler(BaseHTTPRequestHandler):
    """Handles POSTs the way a standard OAuth2 token endpoint would."""

    def do_POST(self) -> None:
        contentLength = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(contentLength).decode("utf-8")
        params = dict(urllib.parse.parse_qsl(body))
        self.server.recordedRequests.append(params)  # type: ignore[attr-defined]

        grantType = params.get("grant_type")
        clientAuthenticated = (
            params.get("client_secret") == "testClientSecret"
            or self.clientAssertionValid(params)
        )
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

    def clientAssertionValid(self, params: dict) -> bool:
        """Verify a JWT client assertion the way a real provider would.

        The signature is checked against the JWK registered on the endpoint
        (see FakeTokenEndpoint.registerAssertionJwk), along with the audience,
        issuer/subject, and required claims from RFC 7523.
        """
        registeredJwk = getattr(self.server, "assertionJwk", None)
        assertion = params.get("client_assertion")
        if registeredJwk is None or not assertion:
            return False
        if params.get("client_assertion_type") != CLIENT_ASSERTION_TYPE:
            return False
        tokenUrl = self.server.tokenUrl  # type: ignore[attr-defined]
        try:
            header = jwt.get_unverified_header(assertion)
            claims = jwt.decode(
                assertion,
                jwt.PyJWK(registeredJwk).key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                audience=tokenUrl,
                issuer="testClientId",
                options={"require": ["exp", "iat", "jti"]},
            )
        except jwt.exceptions.PyJWTError:
            return False
        return header.get("kid") == registeredJwk.get("kid") and claims.get("sub") == "testClientId"

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
        self.httpServer.assertionJwk = None  # type: ignore[attr-defined]
        # The handler validates assertion audiences against this URL.
        self.httpServer.tokenUrl = self.tokenUrl  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpServer.serve_forever, daemon=True)
        self.thread.start()

    def registerAssertionJwk(self, jwk: dict) -> None:
        """Trust this public JWK for client assertions, as a provider does
        when an administrator registers the application's JWKS URL."""
        self.httpServer.assertionJwk = jwk  # type: ignore[attr-defined]

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
