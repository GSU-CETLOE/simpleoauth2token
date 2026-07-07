"""Tests for OAuth2Client against a real local token endpoint (no mocks)."""

import re
import time
import urllib.parse

import pytest

from oauth2client.client import OAuth2Client
from oauth2client.errors import OAuth2Error
from oauth2client.providers import ProviderConfig
from oauth2client.tokenStore import TokenStore


def makeClient(tokenEndpoint, tmp_path, **overrides) -> OAuth2Client:
    """An OAuth2Client wired to the local fake token endpoint."""
    provider = ProviderConfig(
        name="testProvider",
        authorizationUrl="https://example.com/auth",
        tokenUrl=tokenEndpoint.tokenUrl,
    )
    settings = {
        "provider": provider,
        "clientId": "testClientId",
        "clientSecret": "testClientSecret",
        "scopes": ["openid", "email"],
        "tokenName": "testToken",
        "workingDir": tmp_path / "working",
    }
    settings.update(overrides)
    return OAuth2Client(**settings)


def seedStoredToken(tmp_path, tokenEndpoint, **overrides) -> dict:
    """Persist a token as if a prior authorize() had saved it."""
    token = {
        "accessToken": "storedAccessToken",
        "refreshToken": "initialRefreshToken",
        "tokenType": "Bearer",
        "expiresAt": time.time() + 3600,
        "obtainedAt": time.time(),
        "scopes": ["openid", "email"],
        "provider": "testProvider",
        "tokenUrl": tokenEndpoint.tokenUrl,
        "clientId": "testClientId",
        "clientSecret": "testClientSecret",
    }
    token.update(overrides)
    TokenStore(workingDir=tmp_path / "working").save("testToken", token)
    return token


def test_buildAuthorizationUrlContainsStandardParams(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path)
    url = client.buildAuthorizationUrl(state="expectedState")
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    assert url.startswith("https://example.com/auth?")
    assert params["response_type"] == "code"
    assert params["client_id"] == "testClientId"
    assert params["state"] == "expectedState"
    assert params["scope"] == "openid email"
    assert params["redirect_uri"].startswith("https://localhost:")


def test_buildAuthorizationUrlIncludesExtraAuthParams(tokenEndpoint, tmp_path):
    client = makeClient(
        tokenEndpoint, tmp_path,
        extraAuthParams={"access_type": "offline", "prompt": "consent"},
    )
    url = client.buildAuthorizationUrl(state="s")
    params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
    assert params["access_type"] == "offline"
    assert params["prompt"] == "consent"


def test_exchangeCodeForTokenNormalizesAndStoresToken(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path)
    token = client.exchangeCodeForToken("goodCode", redirectUri="https://localhost:8400/callback")

    assert token["accessToken"] == "initialAccessToken"
    assert token["refreshToken"] == "initialRefreshToken"
    assert token["tokenType"] == "Bearer"
    assert token["expiresAt"] > time.time()

    stored = TokenStore(workingDir=tmp_path / "working").load("testToken")
    assert stored is not None
    assert stored["accessToken"] == "initialAccessToken"

    request = tokenEndpoint.recordedRequests[-1]
    assert request["grant_type"] == "authorization_code"
    assert request["code"] == "goodCode"
    assert request["client_id"] == "testClientId"
    assert request["client_secret"] == "testClientSecret"
    assert request["redirect_uri"] == "https://localhost:8400/callback"


def test_exchangeCodeForTokenRaisesOnProviderError(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path)
    with pytest.raises(OAuth2Error, match="invalid_grant"):
        client.exchangeCodeForToken("badCode", redirectUri="https://localhost:8400/callback")


def test_refreshTokenUpdatesAccessToken(tokenEndpoint, tmp_path):
    seedStoredToken(tmp_path, tokenEndpoint, expiresAt=time.time() - 10)
    client = makeClient(tokenEndpoint, tmp_path)
    token = client.refreshToken()

    assert token["accessToken"] == "refreshedAccessToken"
    request = tokenEndpoint.recordedRequests[-1]
    assert request["grant_type"] == "refresh_token"
    assert request["refresh_token"] == "initialRefreshToken"


def test_refreshTokenKeepsRefreshTokenWhenResponseOmitsIt(tokenEndpoint, tmp_path):
    seedStoredToken(tmp_path, tokenEndpoint)
    client = makeClient(tokenEndpoint, tmp_path)
    token = client.refreshToken()
    assert token["refreshToken"] == "initialRefreshToken"


def test_refreshTokenWithoutStoredTokenRaises(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path)
    with pytest.raises(OAuth2Error, match="[Nn]o stored token"):
        client.refreshToken()


def test_getAccessTokenReturnsValidStoredTokenWithoutNetworkCall(tokenEndpoint, tmp_path):
    seedStoredToken(tmp_path, tokenEndpoint)
    client = makeClient(tokenEndpoint, tmp_path)
    accessToken = client.getAccessToken()
    assert accessToken == "storedAccessToken"
    assert tokenEndpoint.recordedRequests == []


def test_getAccessTokenRefreshesExpiredToken(tokenEndpoint, tmp_path):
    seedStoredToken(tmp_path, tokenEndpoint, expiresAt=time.time() - 10)
    client = makeClient(tokenEndpoint, tmp_path)
    accessToken = client.getAccessToken()
    assert accessToken == "refreshedAccessToken"
    assert tokenEndpoint.recordedRequests[-1]["grant_type"] == "refresh_token"


def test_getAccessTokenWithoutStoredTokenRaises(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path)
    with pytest.raises(OAuth2Error, match="authorize"):
        client.getAccessToken()


def test_completeManualAuthorizationWithFullRedirectUrl(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path)
    pastedUrl = "https://localhost:8400/callback?code=goodCode&state=expectedState"
    token = client.completeManualAuthorization(
        pastedUrl, expectedState="expectedState", redirectUri="https://localhost:8400/callback"
    )

    assert token["accessToken"] == "initialAccessToken"
    stored = TokenStore(workingDir=tmp_path / "working").load("testToken")
    assert stored is not None
    assert stored["accessToken"] == "initialAccessToken"

    request = tokenEndpoint.recordedRequests[-1]
    assert request["grant_type"] == "authorization_code"
    assert request["code"] == "goodCode"
    assert request["redirect_uri"] == "https://localhost:8400/callback"


def test_completeManualAuthorizationRejectsStateMismatch(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path)
    pastedUrl = "https://localhost:8400/callback?code=goodCode&state=wrongState"
    with pytest.raises(OAuth2Error, match="[Ss]tate mismatch"):
        client.completeManualAuthorization(
            pastedUrl, expectedState="expectedState", redirectUri="https://localhost:8400/callback"
        )
    assert tokenEndpoint.recordedRequests == []


def test_completeManualAuthorizationAcceptsBareCode(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path)
    token = client.completeManualAuthorization(
        "goodCode", expectedState="unusedState", redirectUri="https://localhost:8400/callback"
    )
    assert token["accessToken"] == "initialAccessToken"


def test_completeManualAuthorizationAcceptsBareQueryString(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path)
    token = client.completeManualAuthorization(
        "code=goodCode&state=expectedState",
        expectedState="expectedState",
        redirectUri="https://localhost:8400/callback",
    )
    assert token["accessToken"] == "initialAccessToken"


def test_completeManualAuthorizationRejectsProviderError(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path)
    pastedUrl = "https://localhost:8400/callback?error=access_denied&error_description=User+declined"
    with pytest.raises(OAuth2Error, match="access_denied"):
        client.completeManualAuthorization(
            pastedUrl, expectedState="expectedState", redirectUri="https://localhost:8400/callback"
        )


def test_completeManualAuthorizationRejectsUrlWithoutCode(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path)
    with pytest.raises(OAuth2Error, match="code"):
        client.completeManualAuthorization(
            "https://localhost:8400/callback",
            expectedState="expectedState",
            redirectUri="https://localhost:8400/callback",
        )


def test_authorizeManualFullFlow(tokenEndpoint, tmp_path, capsys):
    client = makeClient(tokenEndpoint, tmp_path)

    def pasteRedirect(prompt: str) -> str:
        printed = capsys.readouterr().out
        stateMatch = re.search(r"state=([\w-]+)", printed)
        assert stateMatch is not None, "authorization URL with state was not printed"
        return f"https://localhost:8400/callback?code=goodCode&state={stateMatch.group(1)}"

    token = client.authorizeManual(promptInput=pasteRedirect)
    assert token["accessToken"] == "initialAccessToken"
    stored = TokenStore(workingDir=tmp_path / "working").load("testToken")
    assert stored is not None
    assert stored["refreshToken"] == "initialRefreshToken"


def test_authorizeManualRejectsEmptyInput(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path)
    with pytest.raises(OAuth2Error, match="[Nn]othing was entered"):
        client.authorizeManual(promptInput=lambda prompt: "   ")


def test_clientAcceptsProviderPresetName(tmp_path):
    client = OAuth2Client(
        provider="google",
        clientId="id",
        clientSecret="secret",
        scopes="openid email",
        tokenName="googleToken",
        workingDir=tmp_path / "working",
    )
    url = client.buildAuthorizationUrl(state="s")
    assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")


def test_clientAcceptsScopesAsString(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path, scopes="openid email")
    url = client.buildAuthorizationUrl(state="s")
    params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
    assert params["scope"] == "openid email"
