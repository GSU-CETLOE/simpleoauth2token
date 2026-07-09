"""JWT client assertions (RFC 7523) and the signing keys behind them.

Some providers authenticate client-credentials applications with a signed JWT
instead of a shared secret — D2L Brightspace service users require this. The
application signs a short-lived assertion with its private key; the provider
validates it against a public JWKS hosted at an HTTPS URL the administrator
registered with the application.
"""

import json
import os
import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from .errors import OAuth2Error

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
# Providers want assertions short-lived; Brightspace recommends <= 60 seconds.
ASSERTION_LIFETIME_SECONDS = 60
# ES512 pairs with the P-521 curve — the 521 is not a typo.
ELLIPTIC_CURVES: dict[str, type[ec.EllipticCurve]] = {
    "ES256": ec.SECP256R1,
    "ES384": ec.SECP384R1,
    "ES512": ec.SECP521R1,
}
RSA_ALGORITHMS = ("RS256", "RS384", "RS512")
SUPPORTED_ASSERTION_ALGORITHMS = ("ES256", "ES384", "ES512", *RSA_ALGORITHMS)


def requireSupportedAlgorithm(algorithm: str) -> None:
    """Reject signing algorithms providers do not accept for client assertions."""
    if algorithm not in SUPPORTED_ASSERTION_ALGORITHMS:
        raise OAuth2Error(
            f"Unsupported assertion algorithm '{algorithm}'. "
            f"Supported: {', '.join(SUPPORTED_ASSERTION_ALGORITHMS)}"
        )


def buildClientAssertion(
    clientId: str,
    tokenUrl: str,
    privateKeyFile: str | Path,
    keyId: str,
    algorithm: str = "ES256",
) -> str:
    """Sign a short-lived JWT proving this client's identity to the token endpoint.

    The claims follow RFC 7523 as providers such as Brightspace require them:
    iss and sub carry the client id, aud is the token endpoint URL, and jti is
    unique per assertion so it cannot be replayed. The keyId lands in the JWT
    header as 'kid' and must match a key in the JWKS registered with the
    provider.
    """
    requireSupportedAlgorithm(algorithm)
    try:
        privateKeyPem = Path(privateKeyFile).read_text()
    except OSError as error:
        raise OAuth2Error(f"Could not read private key '{privateKeyFile}': {error}") from error
    now = int(time.time())
    claims = {
        "iss": clientId,
        "sub": clientId,
        "aud": tokenUrl,
        "iat": now,
        "exp": now + ASSERTION_LIFETIME_SECONDS,
        "jti": str(uuid.uuid4()),
    }
    try:
        return jwt.encode(claims, privateKeyPem, algorithm=algorithm, headers={"kid": keyId})
    except (jwt.exceptions.PyJWTError, ValueError, TypeError) as error:
        raise OAuth2Error(
            f"Could not sign the client assertion with '{privateKeyFile}' "
            f"using {algorithm}: {error}"
        ) from error


def generateSigningKey(
    keyId: str,
    algorithm: str = "ES256",
    outputDir: str | Path = "working/keys",
) -> tuple[Path, Path]:
    """Create a signing keypair and the JWKS a provider validates it with.

    Writes <keyId>.pem (the private key, owner-read-only) and
    <keyId>.jwks.json (the public key set to host at the HTTPS URL you
    register with the provider) into outputDir, and returns both paths.
    Refuses to overwrite an existing key: regenerating a registered key would
    break every deployment still signing with it.
    """
    requireSupportedAlgorithm(algorithm)
    outputPath = Path(outputDir)
    outputPath.mkdir(parents=True, exist_ok=True)
    privateKeyPath = outputPath / f"{keyId}.pem"
    jwksPath = outputPath / f"{keyId}.jwks.json"
    if privateKeyPath.exists():
        raise OAuth2Error(
            f"Key file '{privateKeyPath}' already exists; "
            f"pick a different key id or delete the old key first"
        )
    if algorithm in ELLIPTIC_CURVES:
        ecKey = ec.generate_private_key(ELLIPTIC_CURVES[algorithm]())
        jwk = ECAlgorithm.to_jwk(ecKey.public_key(), as_dict=True)
        privateKeyPem = serializePrivateKey(ecKey)
    else:
        rsaKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = RSAAlgorithm.to_jwk(rsaKey.public_key(), as_dict=True)
        privateKeyPem = serializePrivateKey(rsaKey)
    fileDescriptor = os.open(privateKeyPath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fileDescriptor, "wb") as keyFile:
        keyFile.write(privateKeyPem)
    jwk.update({"kid": keyId, "use": "sig", "alg": algorithm})
    jwksPath.write_text(json.dumps({"keys": [jwk]}, indent=2))
    return privateKeyPath, jwksPath


def serializePrivateKey(
    privateKey: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
) -> bytes:
    """Render a private key as unencrypted PKCS#8 PEM bytes."""
    return privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
