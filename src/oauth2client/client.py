"""The OAuth2 client other projects import.

Handles the manual first-time authorization (browser consent captured over an
mkcert-secured HTTPS callback), token persistence, and automatic refresh.
"""

import secrets
import time
import urllib.parse
import webbrowser
from collections.abc import Callable
from pathlib import Path
from typing import Any

import requests

from .callbackServer import CallbackServer
from .certs import ensureCertificates
from .errors import OAuth2Error
from .loggingService import getLogger
from .providers import ProviderConfig, getProvider
from .tokenStore import TokenStore, isExpired

DEFAULT_CALLBACK_PORT = 8400
REQUEST_TIMEOUT_SECONDS = 30

MANUAL_AUTHORIZATION_INSTRUCTIONS = """\
Open this URL in a browser on any device and approve access:

  {authorizationUrl}

The browser will then be redirected to {redirectUri} and show a
connection error -- that is expected. Copy the full URL from the browser's
address bar (it contains the authorization code) and paste it below.
"""


def parseCallbackInput(callbackInput: str) -> dict[str, str]:
    """Interpret pasted manual-authorization input.

    Accepts the full redirect URL, just its query string, or a bare
    authorization code, and returns the callback parameters.
    """
    if callbackInput.startswith(("http://", "https://")):
        query = urllib.parse.urlparse(callbackInput).query
        return dict(urllib.parse.parse_qsl(query))
    if "=" in callbackInput:
        return dict(urllib.parse.parse_qsl(callbackInput))
    return {"code": callbackInput}


class OAuth2Client:
    """OAuth2 authorization-code client for Google, Microsoft, D2L Brightspace,
    or any provider described by a ProviderConfig.

    Typical use in another project::

        client = OAuth2Client(
            provider="google",
            clientId="...",
            clientSecret="...",
            scopes="openid email",
            tokenName="myGoogle",
        )
        accessToken = client.getAccessToken()   # refreshes automatically

    The first token must be obtained manually once, via client.authorize() or
    the `oauth2 authorize` command.
    """

    def __init__(
        self,
        provider: ProviderConfig | str,
        clientId: str,
        clientSecret: str,
        scopes: list[str] | str,
        tokenName: str,
        workingDir: str | Path = "working",
        redirectPort: int = DEFAULT_CALLBACK_PORT,
        tenant: str = "common",
        extraAuthParams: dict[str, str] | None = None,
    ) -> None:
        if isinstance(provider, str):
            provider = getProvider(provider, tenant=tenant)
        self.provider = provider
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.scopes = scopes.split() if isinstance(scopes, str) else list(scopes)
        self.tokenName = tokenName
        self.workingDir = Path(workingDir)
        self.redirectPort = redirectPort
        self.extraAuthParams = dict(extraAuthParams or {})
        self.tokenStore = TokenStore(workingDir=self.workingDir)
        self.logger = getLogger(workingDir=self.workingDir)

    def buildAuthorizationUrl(self, state: str, redirectUri: str | None = None) -> str:
        """Return the provider URL the user must visit to grant access."""
        if redirectUri is None:
            redirectUri = f"https://localhost:{self.redirectPort}/callback"
        params = {
            "response_type": "code",
            "client_id": self.clientId,
            "redirect_uri": redirectUri,
            "scope": " ".join(self.scopes),
            "state": state,
            **self.extraAuthParams,
        }
        return f"{self.provider.authorizationUrl}?{urllib.parse.urlencode(params)}"

    def authorize(self, openBrowser: bool = True, timeoutSeconds: float = 300) -> dict[str, Any]:
        """Run the manual first-time authorization and save the token.

        Starts the mkcert-secured HTTPS callback server, sends the user to the
        provider's consent page, waits for the redirect, and exchanges the
        authorization code for a token.
        """
        certFile, keyFile = ensureCertificates(workingDir=self.workingDir)
        server = CallbackServer(port=self.redirectPort, certFile=certFile, keyFile=keyFile)
        server.start()
        try:
            state = secrets.token_urlsafe(32)
            authorizationUrl = self.buildAuthorizationUrl(state=state, redirectUri=server.redirectUri)
            self.logger.info(
                "authorization started for provider '%s' (token '%s'), listening on %s",
                self.provider.name, self.tokenName, server.redirectUri,
            )
            print(f"Open this URL in your browser to authorize:\n\n  {authorizationUrl}\n")
            if openBrowser:
                webbrowser.open(authorizationUrl)
            callback = server.waitForCallback(timeoutSeconds=timeoutSeconds)
            if callback.get("state") != state:
                self.logger.error("state mismatch in OAuth2 callback; aborting")
                raise OAuth2Error("State mismatch in OAuth2 callback; aborting")
            code = callback.get("code")
            if not code:
                raise OAuth2Error("Provider callback did not include an authorization code")
            return self.exchangeCodeForToken(code, redirectUri=server.redirectUri)
        finally:
            server.stop()

    def authorizeManual(self, promptInput: Callable[[str], str] = input) -> dict[str, Any]:
        """Manual first-time authorization for headless servers.

        Prints the authorization URL to open in a browser on any other
        device, then reads the pasted redirect URL (or bare code) from the
        terminal. Needs no local browser, callback server, or mkcert.
        """
        state = secrets.token_urlsafe(32)
        redirectUri = f"https://localhost:{self.redirectPort}/callback"
        authorizationUrl = self.buildAuthorizationUrl(state=state, redirectUri=redirectUri)
        self.logger.info(
            "manual authorization started for provider '%s' (token '%s')",
            self.provider.name, self.tokenName,
        )
        print(MANUAL_AUTHORIZATION_INSTRUCTIONS.format(
            authorizationUrl=authorizationUrl, redirectUri=redirectUri,
        ))
        pasted = promptInput("Paste the redirect URL or authorization code: ").strip()
        if not pasted:
            raise OAuth2Error("Nothing was entered; paste the redirect URL or code")
        return self.completeManualAuthorization(pasted, expectedState=state, redirectUri=redirectUri)

    def completeManualAuthorization(
        self, callbackInput: str, expectedState: str, redirectUri: str
    ) -> dict[str, Any]:
        """Finish a manual authorization from the pasted redirect URL or code.

        The state parameter is validated when the pasted input carries one;
        a bare code has no state to check.
        """
        params = parseCallbackInput(callbackInput)
        if "error" in params:
            description = params.get("error_description", "no description provided")
            self.logger.error("manual authorization failed: %s: %s", params["error"], description)
            raise OAuth2Error(f"Provider returned {params['error']}: {description}")
        code = params.get("code")
        if not code:
            raise OAuth2Error("The pasted input did not include an authorization code")
        if "state" in params and params["state"] != expectedState:
            self.logger.error("state mismatch in manual authorization; aborting")
            raise OAuth2Error("State mismatch in pasted redirect URL; aborting")
        return self.exchangeCodeForToken(code, redirectUri=redirectUri)

    def exchangeCodeForToken(self, code: str, redirectUri: str) -> dict[str, Any]:
        """Exchange an authorization code for a token and save it."""
        response = self.postTokenRequest({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirectUri,
            "client_id": self.clientId,
            "client_secret": self.clientSecret,
        })
        token = self.normalizeToken(response)
        self.tokenStore.save(self.tokenName, token)
        self.logger.info(
            "token '%s' obtained from provider '%s' and saved",
            self.tokenName, self.provider.name,
        )
        return token

    def refreshToken(self) -> dict[str, Any]:
        """Use the stored refresh token to obtain and save a new access token."""
        stored = self.tokenStore.load(self.tokenName)
        if stored is None:
            self.logger.error("no stored token named '%s' to refresh", self.tokenName)
            raise OAuth2Error(
                f"No stored token named '{self.tokenName}'; run authorize() first"
            )
        refreshTokenValue = stored.get("refreshToken")
        if not refreshTokenValue:
            raise OAuth2Error(
                f"Stored token '{self.tokenName}' has no refresh token; re-run authorize()"
            )
        response = self.postTokenRequest({
            "grant_type": "refresh_token",
            "refresh_token": refreshTokenValue,
            "client_id": self.clientId,
            "client_secret": self.clientSecret,
        })
        token = self.normalizeToken(response, fallbackRefreshToken=refreshTokenValue)
        self.tokenStore.save(self.tokenName, token)
        self.logger.info("token '%s' refreshed", self.tokenName)
        return token

    def getAccessToken(self) -> str:
        """Return a valid access token, refreshing automatically if expired.

        This is the everyday entry point for importing projects.
        """
        stored = self.tokenStore.load(self.tokenName)
        if stored is None:
            self.logger.error("no stored token named '%s'", self.tokenName)
            raise OAuth2Error(
                f"No stored token named '{self.tokenName}'; run authorize() or "
                f"'oauth2 authorize' once to obtain the initial token"
            )
        if isExpired(stored):
            self.logger.info("token '%s' is expired; refreshing", self.tokenName)
            stored = self.refreshToken()
        return stored["accessToken"]

    def postTokenRequest(self, payload: dict[str, str]) -> dict[str, Any]:
        """POST to the provider's token endpoint and return the JSON response."""
        try:
            response = requests.post(
                self.provider.tokenUrl,
                data=payload,
                headers={"Accept": "application/json"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.RequestException as error:
            self.logger.error("token request to %s failed: %s", self.provider.tokenUrl, error)
            raise OAuth2Error(f"Token request to {self.provider.tokenUrl} failed: {error}") from error

        if response.status_code != 200:
            detail = self.describeErrorResponse(response)
            self.logger.error(
                "token endpoint %s returned %s: %s",
                self.provider.tokenUrl, response.status_code, detail,
            )
            raise OAuth2Error(f"Token endpoint returned {response.status_code}: {detail}")
        return response.json()

    @staticmethod
    def describeErrorResponse(response: requests.Response) -> str:
        """Extract the most useful error detail from a failed token response."""
        try:
            body = response.json()
            error = body.get("error", "unknown_error")
            description = body.get("error_description")
            return f"{error}: {description}" if description else str(error)
        except ValueError:
            return response.text.strip() or "no response body"

    def normalizeToken(
        self, response: dict[str, Any], fallbackRefreshToken: str | None = None
    ) -> dict[str, Any]:
        """Convert a provider token response into the stored token format.

        Client credentials are kept alongside the token so the CLI can refresh
        without re-prompting; the file is saved owner-read-only.
        """
        if "access_token" not in response:
            raise OAuth2Error(f"Token response contained no access_token: {response}")
        expiresIn = response.get("expires_in")
        now = time.time()
        return {
            "accessToken": response["access_token"],
            "refreshToken": response.get("refresh_token", fallbackRefreshToken),
            "tokenType": response.get("token_type", "Bearer"),
            "expiresAt": now + float(expiresIn) if expiresIn is not None else None,
            "obtainedAt": now,
            "scopes": self.scopes,
            "provider": self.provider.name,
            "authorizationUrl": self.provider.authorizationUrl,
            "tokenUrl": self.provider.tokenUrl,
            "clientId": self.clientId,
            "clientSecret": self.clientSecret,
            "raw": response,
        }
