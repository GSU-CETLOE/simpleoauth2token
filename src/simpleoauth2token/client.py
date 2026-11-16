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
from .clientAssertion import CLIENT_ASSERTION_TYPE, buildClientAssertion
from .errors import OAuth2Error
from .loggingService import getLogger
from .providers import ProviderConfig, getProvider
from .tokenStore import TokenStore, isExpired

DEFAULT_CALLBACK_PORT = 8400
REQUEST_TIMEOUT_SECONDS = 30
SUPPORTED_GRANT_TYPES = ("authorization_code", "client_credentials")

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


def callbackListenerAddress(redirectUri: str) -> tuple[int, str]:
    """Return the (port, path) the local callback server must listen on.

    The browser flow can only catch a redirect sent to https://localhost,
    so any other redirect URI is rejected with a pointer to --manual.
    """
    parsed = urllib.parse.urlparse(redirectUri)
    if parsed.scheme != "https" or parsed.hostname != "localhost":
        raise OAuth2Error(
            f"The browser flow can only receive a redirect to https://localhost, "
            f"not {redirectUri}. Use the manual flow (--manual) for this redirect URI."
        )
    return parsed.port or 443, parsed.path or "/"


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
    the `simpleoauth2token authorize` command.

    For service-to-service calls with no user, pass
    grantType="client_credentials" — then getAccessToken() obtains and renews
    tokens entirely on its own and no manual step is ever needed. Providers
    that authenticate with JWT client assertions instead of a secret
    (Brightspace service users) take privateKeyFile and keyId in place of
    clientSecret.

    The redirect URI defaults to https://localhost:<redirectPort>/callback.
    When the provider's app registration uses a different one, pass it as
    redirectUri exactly as registered.
    """

    def __init__(
        self,
        provider: ProviderConfig | str,
        clientId: str,
        clientSecret: str = "",
        scopes: list[str] | str = "",
        tokenName: str = "",
        workingDir: str | Path = "working",
        redirectPort: int = DEFAULT_CALLBACK_PORT,
        tenant: str = "common",
        extraAuthParams: dict[str, str] | None = None,
        grantType: str = "authorization_code",
        privateKeyFile: str | Path | None = None,
        keyId: str | None = None,
        assertionAlgorithm: str = "ES256",
        redirectUri: str | None = None,
    ) -> None:
        if grantType not in SUPPORTED_GRANT_TYPES:
            raise OAuth2Error(
                f"Unknown grant type '{grantType}'. "
                f"Supported grant types: {', '.join(SUPPORTED_GRANT_TYPES)}"
            )
        if privateKeyFile is not None and not keyId:
            raise OAuth2Error(
                "privateKeyFile requires keyId — the 'kid' of this key in the "
                "JWKS registered with the provider"
            )
        if grantType == "client_credentials" and not clientSecret and privateKeyFile is None:
            raise OAuth2Error(
                "The client credentials grant needs clientSecret or privateKeyFile "
                "(plus keyId) to authenticate"
            )
        if isinstance(provider, str):
            provider = getProvider(provider, tenant=tenant)
        self.provider = provider
        self.grantType = grantType
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.scopes = scopes.split() if isinstance(scopes, str) else list(scopes)
        self.tokenName = tokenName
        self.workingDir = Path(workingDir)
        self.redirectUri = redirectUri or f"https://localhost:{redirectPort}/callback"
        self.extraAuthParams = dict(extraAuthParams or {})
        self.privateKeyFile = privateKeyFile
        self.keyId = keyId
        self.assertionAlgorithm = assertionAlgorithm
        self.tokenStore = TokenStore(workingDir=self.workingDir)
        self.logger = getLogger(workingDir=self.workingDir)

    def buildAuthorizationUrl(self, state: str, redirectUri: str | None = None) -> str:
        """Return the provider URL the user must visit to grant access."""
        if redirectUri is None:
            redirectUri = self.redirectUri
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
        port, callbackPath = callbackListenerAddress(self.redirectUri)
        certFile, keyFile = ensureCertificates(workingDir=self.workingDir)
        server = CallbackServer(port=port, certFile=certFile, keyFile=keyFile, callbackPath=callbackPath)
        server.start()
        try:
            state = secrets.token_urlsafe(32)
            authorizationUrl = self.buildAuthorizationUrl(state=state)
            self.logger.info(
                "authorization started for provider '%s' (token '%s'), listening on %s",
                self.provider.name, self.tokenName, self.redirectUri,
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
            return self.exchangeCodeForToken(code, redirectUri=self.redirectUri)
        finally:
            server.stop()

    def authorizeManual(self, promptInput: Callable[[str], str] = input) -> dict[str, Any]:
        """Manual first-time authorization for headless servers.

        Prints the authorization URL to open in a browser on any other
        device, then reads the pasted redirect URL (or bare code) from the
        terminal. Needs no local browser, callback server, or mkcert.
        """
        state = secrets.token_urlsafe(32)
        redirectUri = self.redirectUri
        authorizationUrl = self.buildAuthorizationUrl(state=state)
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

    def fetchClientCredentialsToken(self) -> dict[str, Any]:
        """Obtain and save a token with the client credentials grant (no user).

        For service-to-service calls where no human signs in. The client
        authenticates with its secret, or — when privateKeyFile is set — with
        a signed JWT client assertion (RFC 7523), which is how Brightspace
        service users work. The provider issues no refresh token — renewing
        simply re-runs this grant. (Google service accounts use a different
        JWT flow that this library does not implement.)
        """
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.clientId,
        }
        if self.privateKeyFile is not None:
            assert self.keyId is not None  # enforced in __init__
            payload["client_assertion_type"] = CLIENT_ASSERTION_TYPE
            payload["client_assertion"] = buildClientAssertion(
                clientId=self.clientId,
                tokenUrl=self.provider.tokenUrl,
                privateKeyFile=self.privateKeyFile,
                keyId=self.keyId,
                algorithm=self.assertionAlgorithm,
            )
        else:
            payload["client_secret"] = self.clientSecret
        if self.scopes:
            payload["scope"] = " ".join(self.scopes)
        try:
            response = self.postTokenRequest(payload)
        except OAuth2Error as error:
            # invalid_client here means the credential itself was rejected —
            # point at the likely fix instead of the bare provider error.
            if "invalid_client" in str(error):
                if self.privateKeyFile is not None:
                    raise OAuth2Error(
                        f"{error} (the provider rejected the client assertion; "
                        f"check that the registered JWKS is reachable and still "
                        f"contains key '{self.keyId}')"
                    ) from error
                raise OAuth2Error(
                    f"{error} (the client secret may have been rotated or "
                    f"expired; re-run authorize with current credentials)"
                ) from error
            raise
        token = self.normalizeToken(response, grantType="client_credentials")
        self.tokenStore.save(self.tokenName, token)
        self.logger.info(
            "token '%s' obtained from provider '%s' with client credentials and saved",
            self.tokenName, self.provider.name,
        )
        return token

    def refreshToken(self) -> dict[str, Any]:
        """Obtain and save a new access token for the stored token.

        Authorization-code tokens are renewed with their refresh token;
        client-credentials tokens are renewed by re-running their grant.
        """
        stored = self.tokenStore.load(self.tokenName)
        if stored is None:
            self.logger.error("no stored token named '%s' to refresh", self.tokenName)
            raise OAuth2Error(
                f"No stored token named '{self.tokenName}'; run authorize() first"
            )
        if stored.get("grantType") == "client_credentials":
            # Re-running the grant renews it; credential hints are added there.
            return self.fetchClientCredentialsToken()
        refreshTokenValue = stored.get("refreshToken")
        if not refreshTokenValue:
            raise OAuth2Error(
                f"Stored token '{self.tokenName}' has no refresh token; re-run authorize()"
            )
        try:
            response = self.postTokenRequest({
                "grant_type": "refresh_token",
                "refresh_token": refreshTokenValue,
                "client_id": self.clientId,
                "client_secret": self.clientSecret,
            })
        except OAuth2Error as error:
            # Client secrets expire (Azure enforces this), and a renewal that
            # ran fine for months then fails with invalid_client is almost
            # always that — point at the fix instead of the bare provider error.
            if "invalid_client" in str(error):
                raise OAuth2Error(
                    f"{error} (the client secret may have been rotated or "
                    f"expired; re-run authorize with current credentials)"
                ) from error
            raise
        token = self.normalizeToken(response, fallbackRefreshToken=refreshTokenValue)
        self.tokenStore.save(self.tokenName, token)
        self.logger.info("token '%s' refreshed", self.tokenName)
        return token

    def getAccessToken(self, forceRefresh: bool = False) -> str:
        """Return a valid access token, refreshing automatically if expired.

        This is the everyday entry point for importing projects. Pass
        forceRefresh=True to renew even an unexpired token — e.g. after an
        API answered 401 because the token was revoked before its expiry.
        """
        stored = self.tokenStore.load(self.tokenName)
        if stored is None:
            if self.grantType == "client_credentials":
                self.logger.info(
                    "no stored token named '%s'; fetching with client credentials",
                    self.tokenName,
                )
                return self.fetchClientCredentialsToken()["accessToken"]
            self.logger.error("no stored token named '%s'", self.tokenName)
            raise OAuth2Error(
                f"No stored token named '{self.tokenName}'; run authorize() or "
                f"'simpleoauth2token authorize' once to obtain the initial token"
            )
        if forceRefresh or isExpired(stored):
            reason = "renewal forced" if forceRefresh else "is expired"
            self.logger.info("token '%s' %s; refreshing", self.tokenName, reason)
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
        self,
        response: dict[str, Any],
        fallbackRefreshToken: str | None = None,
        grantType: str = "authorization_code",
    ) -> dict[str, Any]:
        """Convert a provider token response into the stored token format.

        The grant that produced the token is recorded so refreshToken() knows
        how to renew it. The client id and its credential — the secret, or for
        assertion-authenticated clients the private key *path*, key id, and
        algorithm (never the key material) — are kept alongside the token so
        the CLI can refresh without re-prompting; the file is saved
        owner-read-only.
        """
        if "access_token" not in response:
            raise OAuth2Error(f"Token response contained no access_token: {response}")
        expiresIn = response.get("expires_in")
        now = time.time()
        return {
            "accessToken": response["access_token"],
            "refreshToken": response.get("refresh_token", fallbackRefreshToken),
            "tokenType": response.get("token_type", "Bearer"),
            "grantType": grantType,
            "expiresAt": now + float(expiresIn) if expiresIn is not None else None,
            "obtainedAt": now,
            "scopes": self.scopes,
            "provider": self.provider.name,
            "authorizationUrl": self.provider.authorizationUrl,
            "tokenUrl": self.provider.tokenUrl,
            "clientId": self.clientId,
            "clientSecret": self.clientSecret,
            "privateKeyFile": str(self.privateKeyFile) if self.privateKeyFile is not None else None,
            "keyId": self.keyId,
            "assertionAlgorithm": self.assertionAlgorithm if self.privateKeyFile is not None else None,
            "raw": response,
        }
