"""Tests for OAuth2Client against a real local token endpoint (no mocks)."""

import json
import re
import time
import urllib.parse

import jwt
import pytest

from simpleoauth2token.client import OAuth2Client
from simpleoauth2token.clientAssertion import CLIENT_ASSERTION_TYPE, generateSigningKey
from simpleoauth2token.errors import OAuth2Error
from simpleoauth2token.providers import ProviderConfig
from simpleoauth2token.tokenStore import TokenStore


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
    assert token["grantType"] == "authorization_code"
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


def test_fetchClientCredentialsTokenStoresTokenWithoutRefreshToken(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path, grantType="client_credentials")
    token = client.fetchClientCredentialsToken()

    assert token["accessToken"] == "serviceAccessToken"
    assert token["refreshToken"] is None
    assert token["grantType"] == "client_credentials"

    stored = TokenStore(workingDir=tmp_path / "working").load("testToken")
    assert stored is not None
    assert stored["accessToken"] == "serviceAccessToken"
    assert stored["grantType"] == "client_credentials"

    request = tokenEndpoint.recordedRequests[-1]
    assert request["grant_type"] == "client_credentials"
    assert request["client_id"] == "testClientId"
    assert request["client_secret"] == "testClientSecret"
    assert request["scope"] == "openid email"


def test_fetchClientCredentialsTokenRaisesOnProviderError(tokenEndpoint, tmp_path):
    client = makeClient(
        tokenEndpoint, tmp_path, grantType="client_credentials", clientSecret="wrongSecret"
    )
    with pytest.raises(OAuth2Error, match="invalid_client"):
        client.fetchClientCredentialsToken()


def test_refreshTokenHintsAtRotatedSecretForClientCredentials(tokenEndpoint, tmp_path):
    seedStoredToken(tmp_path, tokenEndpoint, refreshToken=None, grantType="client_credentials")
    client = makeClient(tokenEndpoint, tmp_path, clientSecret="rotatedAwaySecret")
    with pytest.raises(OAuth2Error, match="invalid_client.*rotated or expired"):
        client.refreshToken()


def test_refreshTokenHintsAtRotatedSecretForAuthorizationCode(tokenEndpoint, tmp_path):
    seedStoredToken(tmp_path, tokenEndpoint)
    client = makeClient(tokenEndpoint, tmp_path, clientSecret="rotatedAwaySecret")
    with pytest.raises(OAuth2Error, match="invalid_client.*rotated or expired"):
        client.refreshToken()


def test_getAccessTokenForceRefreshRenewsValidToken(tokenEndpoint, tmp_path):
    seedStoredToken(tmp_path, tokenEndpoint)
    client = makeClient(tokenEndpoint, tmp_path)
    accessToken = client.getAccessToken(forceRefresh=True)
    assert accessToken == "refreshedAccessToken"
    assert tokenEndpoint.recordedRequests[-1]["grant_type"] == "refresh_token"


def test_getAccessTokenForceRefreshRenewsValidClientCredentialsToken(tokenEndpoint, tmp_path):
    seedStoredToken(
        tmp_path, tokenEndpoint, refreshToken=None, grantType="client_credentials",
    )
    client = makeClient(tokenEndpoint, tmp_path, grantType="client_credentials")
    accessToken = client.getAccessToken(forceRefresh=True)
    assert accessToken == "serviceAccessToken"
    assert tokenEndpoint.recordedRequests[-1]["grant_type"] == "client_credentials"


def test_getAccessTokenFetchesClientCredentialsTokenWhenNoneStored(tokenEndpoint, tmp_path):
    client = makeClient(tokenEndpoint, tmp_path, grantType="client_credentials")
    accessToken = client.getAccessToken()
    assert accessToken == "serviceAccessToken"
    assert tokenEndpoint.recordedRequests[-1]["grant_type"] == "client_credentials"


def test_getAccessTokenRenewsExpiredClientCredentialsToken(tokenEndpoint, tmp_path):
    seedStoredToken(
        tmp_path, tokenEndpoint,
        expiresAt=time.time() - 10, refreshToken=None, grantType="client_credentials",
    )
    client = makeClient(tokenEndpoint, tmp_path, grantType="client_credentials")
    accessToken = client.getAccessToken()
    assert accessToken == "serviceAccessToken"
    assert tokenEndpoint.recordedRequests[-1]["grant_type"] == "client_credentials"


def test_refreshTokenRerunsClientCredentialsGrant(tokenEndpoint, tmp_path):
    # A client built with the default grant (as `simpleoauth2token refresh` does) must
    # still renew a stored client-credentials token by re-running its grant.
    seedStoredToken(
        tmp_path, tokenEndpoint, refreshToken=None, grantType="client_credentials",
    )
    client = makeClient(tokenEndpoint, tmp_path)
    token = client.refreshToken()
    assert token["accessToken"] == "serviceAccessToken"
    assert token["grantType"] == "client_credentials"
    assert tokenEndpoint.recordedRequests[-1]["grant_type"] == "client_credentials"


def test_clientRejectsUnknownGrantType(tmp_path):
    with pytest.raises(OAuth2Error, match="[Gg]rant"):
        OAuth2Client(
            provider="google",
            clientId="id",
            clientSecret="secret",
            scopes="openid",
            tokenName="badGrant",
            workingDir=tmp_path / "working",
            grantType="password",
        )


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


def registerSigningKey(tokenEndpoint, tmp_path, keyId="testKey"):
    """Generate a signing key and register its public JWK with the endpoint,
    mirroring how an admin registers a JWKS URL with a real provider."""
    privateKeyPath, jwksPath = generateSigningKey(
        keyId=keyId, algorithm="ES256", outputDir=tmp_path / "keys",
    )
    jwk = json.loads(jwksPath.read_text())["keys"][0]
    tokenEndpoint.registerAssertionJwk(jwk)
    return privateKeyPath, jwk


def makeAssertionClient(tokenEndpoint, tmp_path, privateKeyPath, **overrides) -> OAuth2Client:
    """A client-credentials client that authenticates with a JWT assertion."""
    settings = {
        "clientSecret": "",
        "grantType": "client_credentials",
        "privateKeyFile": privateKeyPath,
        "keyId": "testKey",
    }
    settings.update(overrides)
    return makeClient(tokenEndpoint, tmp_path, **settings)


def test_fetchClientCredentialsTokenWithClientAssertion(tokenEndpoint, tmp_path):
    privateKeyPath, jwk = registerSigningKey(tokenEndpoint, tmp_path)
    client = makeAssertionClient(tokenEndpoint, tmp_path, privateKeyPath)
    token = client.fetchClientCredentialsToken()
    assert token["accessToken"] == "serviceAccessToken"
    request = tokenEndpoint.recordedRequests[-1]
    assert request["client_assertion_type"] == CLIENT_ASSERTION_TYPE
    assert "client_secret" not in request
    claims = jwt.decode(
        request["client_assertion"], jwt.PyJWK(jwk).key,
        algorithms=["ES256"], audience=tokenEndpoint.tokenUrl,
    )
    assert claims["iss"] == "testClientId"
    assert claims["sub"] == "testClientId"


def test_assertionTokenStoresKeyPathForRenewal(tokenEndpoint, tmp_path):
    privateKeyPath, _ = registerSigningKey(tokenEndpoint, tmp_path)
    client = makeAssertionClient(tokenEndpoint, tmp_path, privateKeyPath)
    client.fetchClientCredentialsToken()
    stored = TokenStore(workingDir=tmp_path / "working").load("testToken")
    assert stored is not None
    assert stored["privateKeyFile"] == str(privateKeyPath)
    assert stored["keyId"] == "testKey"
    assert stored["assertionAlgorithm"] == "ES256"
    assert stored["clientSecret"] == ""


def test_assertionSignedByUnregisteredKeyIsRejected(tokenEndpoint, tmp_path):
    registerSigningKey(tokenEndpoint, tmp_path, keyId="registeredKey")
    rogueKeyPath, _ = generateSigningKey(
        keyId="testKey", algorithm="ES256", outputDir=tmp_path / "rogueKeys",
    )
    client = makeAssertionClient(tokenEndpoint, tmp_path, rogueKeyPath)
    with pytest.raises(OAuth2Error, match="JWKS"):
        client.fetchClientCredentialsToken()


def test_refreshTokenRerunsAssertionGrantFromStoredKeyPath(tokenEndpoint, tmp_path):
    privateKeyPath, _ = registerSigningKey(tokenEndpoint, tmp_path)
    seedStoredToken(
        tmp_path, tokenEndpoint, refreshToken=None, grantType="client_credentials",
        clientSecret="", privateKeyFile=str(privateKeyPath),
        keyId="testKey", assertionAlgorithm="ES256",
    )
    client = makeAssertionClient(tokenEndpoint, tmp_path, privateKeyPath)
    token = client.refreshToken()
    assert token["accessToken"] == "serviceAccessToken"
    request = tokenEndpoint.recordedRequests[-1]
    assert request["grant_type"] == "client_credentials"
    assert "client_assertion" in request


def test_getAccessTokenFetchesAssertionTokenWhenNoneStored(tokenEndpoint, tmp_path):
    privateKeyPath, _ = registerSigningKey(tokenEndpoint, tmp_path)
    client = makeAssertionClient(tokenEndpoint, tmp_path, privateKeyPath)
    assert client.getAccessToken() == "serviceAccessToken"
    assert "client_assertion" in tokenEndpoint.recordedRequests[-1]


def test_clientRequiresKeyIdWithPrivateKey(tmp_path):
    with pytest.raises(OAuth2Error, match="keyId"):
        OAuth2Client(
            provider="brightspace",
            clientId="id",
            scopes="core:*:*",
            tokenName="assertionToken",
            workingDir=tmp_path / "working",
            grantType="client_credentials",
            privateKeyFile=tmp_path / "key.pem",
        )


def test_clientCredentialsRequiresSecretOrPrivateKey(tmp_path):
    with pytest.raises(OAuth2Error, match="clientSecret or privateKeyFile"):
        OAuth2Client(
            provider="brightspace",
            clientId="id",
            scopes="core:*:*",
            tokenName="assertionToken",
            workingDir=tmp_path / "working",
            grantType="client_credentials",
        )
