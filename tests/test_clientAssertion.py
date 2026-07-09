"""Tests for JWT client assertions and signing-key generation (real keys and
signatures throughout — assertions are verified cryptographically, no mocks)."""

import json
import stat

import jwt
import pytest

from simpleoauth2token.clientAssertion import (
    ASSERTION_LIFETIME_SECONDS,
    CLIENT_ASSERTION_TYPE,
    buildClientAssertion,
    generateSigningKey,
)
from simpleoauth2token.errors import OAuth2Error

TOKEN_URL = "https://auth.example.com/core/connect/token"


def verificationKeyFromJwks(jwksPath):
    """Reconstruct the public verification key exactly as a provider would."""
    jwks = json.loads(jwksPath.read_text())
    return jwt.PyJWK(jwks["keys"][0]).key


def test_generateSigningKeyWritesPrivateKeyOwnerReadOnly(tmp_path):
    privateKeyPath, jwksPath = generateSigningKey(
        keyId="testKey", algorithm="ES256", outputDir=tmp_path / "keys",
    )
    assert privateKeyPath.exists()
    assert jwksPath.exists()
    mode = stat.S_IMODE(privateKeyPath.stat().st_mode)
    assert mode == 0o600
    assert "PRIVATE KEY" in privateKeyPath.read_text()


def test_generateSigningKeyWritesJwksWithKeyMetadata(tmp_path):
    _, jwksPath = generateSigningKey(
        keyId="testKey", algorithm="ES256", outputDir=tmp_path / "keys",
    )
    jwks = json.loads(jwksPath.read_text())
    assert len(jwks["keys"]) == 1
    key = jwks["keys"][0]
    assert key["kty"] == "EC"
    assert key["crv"] == "P-256"
    assert key["kid"] == "testKey"
    assert key["use"] == "sig"
    assert key["alg"] == "ES256"
    assert "d" not in key  # the JWKS must never leak the private key


def test_generateSigningKeySupportsRsa(tmp_path):
    _, jwksPath = generateSigningKey(
        keyId="rsaKey", algorithm="RS256", outputDir=tmp_path / "keys",
    )
    key = json.loads(jwksPath.read_text())["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert "d" not in key


def test_generateSigningKeyRefusesToOverwriteExistingKey(tmp_path):
    generateSigningKey(keyId="testKey", algorithm="ES256", outputDir=tmp_path / "keys")
    with pytest.raises(OAuth2Error, match="already exists"):
        generateSigningKey(keyId="testKey", algorithm="ES256", outputDir=tmp_path / "keys")


def test_generateSigningKeyRejectsUnknownAlgorithm(tmp_path):
    with pytest.raises(OAuth2Error, match="HS256"):
        generateSigningKey(keyId="testKey", algorithm="HS256", outputDir=tmp_path / "keys")


def test_buildClientAssertionVerifiesAgainstItsJwks(tmp_path):
    privateKeyPath, jwksPath = generateSigningKey(
        keyId="testKey", algorithm="ES256", outputDir=tmp_path / "keys",
    )
    assertion = buildClientAssertion(
        clientId="myClientId", tokenUrl=TOKEN_URL,
        privateKeyFile=privateKeyPath, keyId="testKey", algorithm="ES256",
    )
    header = jwt.get_unverified_header(assertion)
    assert header["alg"] == "ES256"
    assert header["kid"] == "testKey"
    claims = jwt.decode(
        assertion, verificationKeyFromJwks(jwksPath),
        algorithms=["ES256"], audience=TOKEN_URL,
    )
    assert claims["iss"] == "myClientId"
    assert claims["sub"] == "myClientId"


def test_buildClientAssertionUsesShortLifetimeAndUniqueJti(tmp_path):
    privateKeyPath, jwksPath = generateSigningKey(
        keyId="testKey", algorithm="ES256", outputDir=tmp_path / "keys",
    )
    def claimsOfFreshAssertion() -> dict:
        assertion = buildClientAssertion(
            clientId="myClientId", tokenUrl=TOKEN_URL,
            privateKeyFile=privateKeyPath, keyId="testKey", algorithm="ES256",
        )
        return jwt.decode(
            assertion, verificationKeyFromJwks(jwksPath),
            algorithms=["ES256"], audience=TOKEN_URL,
        )
    first = claimsOfFreshAssertion()
    second = claimsOfFreshAssertion()
    assert first["exp"] - first["iat"] == ASSERTION_LIFETIME_SECONDS
    assert first["jti"] != second["jti"]


def test_buildClientAssertionWithRsaKey(tmp_path):
    privateKeyPath, jwksPath = generateSigningKey(
        keyId="rsaKey", algorithm="RS256", outputDir=tmp_path / "keys",
    )
    assertion = buildClientAssertion(
        clientId="myClientId", tokenUrl=TOKEN_URL,
        privateKeyFile=privateKeyPath, keyId="rsaKey", algorithm="RS256",
    )
    claims = jwt.decode(
        assertion, verificationKeyFromJwks(jwksPath),
        algorithms=["RS256"], audience=TOKEN_URL,
    )
    assert claims["iss"] == "myClientId"


def test_buildClientAssertionRejectsMissingKeyFile(tmp_path):
    with pytest.raises(OAuth2Error, match="missing.pem"):
        buildClientAssertion(
            clientId="myClientId", tokenUrl=TOKEN_URL,
            privateKeyFile=tmp_path / "missing.pem", keyId="testKey", algorithm="ES256",
        )


def test_buildClientAssertionRejectsAlgorithmKeyMismatch(tmp_path):
    privateKeyPath, _ = generateSigningKey(
        keyId="testKey", algorithm="ES256", outputDir=tmp_path / "keys",
    )
    with pytest.raises(OAuth2Error):
        buildClientAssertion(
            clientId="myClientId", tokenUrl=TOKEN_URL,
            privateKeyFile=privateKeyPath, keyId="testKey", algorithm="RS256",
        )


def test_buildClientAssertionRejectsUnknownAlgorithm(tmp_path):
    privateKeyPath, _ = generateSigningKey(
        keyId="testKey", algorithm="ES256", outputDir=tmp_path / "keys",
    )
    with pytest.raises(OAuth2Error, match="none"):
        buildClientAssertion(
            clientId="myClientId", tokenUrl=TOKEN_URL,
            privateKeyFile=privateKeyPath, keyId="testKey", algorithm="none",
        )


def test_clientAssertionTypeIsTheRfc7523Urn():
    assert CLIENT_ASSERTION_TYPE == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
