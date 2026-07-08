"""Local HTTPS server that captures the OAuth2 authorization callback.

Providers redirect the browser to https://localhost:<port>/callback after the
user approves access; this server catches that single request and hands the
authorization code back to the client.
"""

import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import cast

from .errors import OAuth2Error

SUCCESS_PAGE = (
    b"<html><body><h1>Authorization complete</h1>"
    b"<p>You may close this window and return to the terminal.</p></body></html>"
)
ERROR_PAGE = (
    b"<html><body><h1>Authorization failed</h1>"
    b"<p>Return to the terminal for details.</p></body></html>"
)


class CallbackHTTPServer(HTTPServer):
    """HTTPServer that stores the query parameters of the callback request."""

    def __init__(self, serverAddress: tuple[str, int], callbackPath: str) -> None:
        super().__init__(serverAddress, CallbackRequestHandler)
        self.callbackPath = callbackPath
        self.callbackParams: dict[str, str] | None = None
        self.callbackReceived = threading.Event()


class CallbackRequestHandler(BaseHTTPRequestHandler):
    """Handles the single redirect the OAuth2 provider sends to localhost."""

    def do_GET(self) -> None:
        server = cast(CallbackHTTPServer, self.server)
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != server.callbackPath:
            self.send_response(404)
            self.end_headers()
            return

        params = dict(urllib.parse.parse_qsl(parsed.query))
        page = ERROR_PAGE if "error" in params else SUCCESS_PAGE
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

        server.callbackParams = params
        server.callbackReceived.set()

    def log_message(self, format: str, *args) -> None:
        """Silence per-request logging; the client logs the outcome instead."""


class CallbackServer:
    """Runs the HTTPS callback listener on a background thread."""

    def __init__(
        self,
        port: int,
        certFile: str | Path,
        keyFile: str | Path,
        callbackPath: str = "/callback",
    ) -> None:
        self.callbackPath = callbackPath
        self.httpServer = CallbackHTTPServer(("127.0.0.1", port), callbackPath)
        tlsContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tlsContext.load_cert_chain(certfile=str(certFile), keyfile=str(keyFile))
        self.httpServer.socket = tlsContext.wrap_socket(self.httpServer.socket, server_side=True)
        self.serverThread: threading.Thread | None = None

    @property
    def port(self) -> int:
        """The port actually bound (useful when constructed with port 0)."""
        return self.httpServer.server_address[1]

    @property
    def redirectUri(self) -> str:
        """The redirect URI to register with the OAuth2 provider."""
        return f"https://localhost:{self.port}{self.callbackPath}"

    def start(self) -> None:
        """Begin serving on a background thread."""
        self.serverThread = threading.Thread(target=self.httpServer.serve_forever, daemon=True)
        self.serverThread.start()

    def stop(self) -> None:
        """Stop serving and release the port."""
        self.httpServer.shutdown()
        self.httpServer.server_close()

    def waitForCallback(self, timeoutSeconds: float = 300) -> dict[str, str | None]:
        """Block until the provider redirects back, then return code and state.

        Raises OAuth2Error if the provider reports an error or nothing arrives
        within timeoutSeconds.
        """
        received = self.httpServer.callbackReceived.wait(timeout=timeoutSeconds)
        if not received:
            raise OAuth2Error(
                f"Timed out after {timeoutSeconds}s waiting for the OAuth2 callback"
            )
        params = self.httpServer.callbackParams or {}
        if "error" in params:
            description = params.get("error_description", "no description provided")
            raise OAuth2Error(f"Provider returned {params['error']}: {description}")
        return {"code": params.get("code"), "state": params.get("state")}
