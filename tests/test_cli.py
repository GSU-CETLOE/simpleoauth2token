"""Tests for the simpleoauth2token CLI (non-interactive commands and the manual
headless authorization, which reads its input from stdin)."""

import io
import json
import time

from simpleoauth2token.cli import main
from simpleoauth2token.tokenStore import TokenStore


def seedToken(workingDir, name="myGoogle", **overrides) -> dict:
    """Save a token the CLI commands can operate on."""
    token = {
        "accessToken": "accessToken123",
        "refreshToken": "refreshToken123",
        "tokenType": "Bearer",
        "expiresAt": time.time() + 3600,
        "obtainedAt": time.time(),
        "scopes": ["openid"],
        "provider": "google",
    }
    token.update(overrides)
    TokenStore(workingDir=workingDir).save(name, token)
    return token


def test_providersCommandListsPresets(capsys):
    exitCode = main(["providers"])
    output = capsys.readouterr().out
    assert exitCode == 0
    for name in ("google", "microsoft", "brightspace", "generic"):
        assert name in output


def test_listCommandShowsSavedTokens(tmp_path, capsys):
    seedToken(tmp_path / "working")
    exitCode = main(["list", "--working-dir", str(tmp_path / "working")])
    assert exitCode == 0
    assert "myGoogle" in capsys.readouterr().out


def test_listCommandWithNoTokens(tmp_path, capsys):
    exitCode = main(["list", "--working-dir", str(tmp_path / "working")])
    assert exitCode == 0
    assert "No tokens" in capsys.readouterr().out


def test_statusCommandShowsTokenDetails(tmp_path, capsys):
    seedToken(tmp_path / "working")
    exitCode = main(["status", "--name", "myGoogle", "--working-dir", str(tmp_path / "working")])
    output = capsys.readouterr().out
    assert exitCode == 0
    assert "google" in output
    assert "valid" in output.lower()


def test_statusCommandReportsExpiredToken(tmp_path, capsys):
    seedToken(tmp_path / "working", expiresAt=time.time() - 10)
    exitCode = main(["status", "--name", "myGoogle", "--working-dir", str(tmp_path / "working")])
    assert exitCode == 0
    assert "expired" in capsys.readouterr().out.lower()


def test_statusCommandShowsGrantType(tmp_path, capsys):
    seedToken(tmp_path / "working", grantType="client_credentials", refreshToken=None)
    exitCode = main(["status", "--name", "myGoogle", "--working-dir", str(tmp_path / "working")])
    output = capsys.readouterr().out
    assert exitCode == 0
    assert "client_credentials" in output


def test_statusCommandFailsForMissingToken(tmp_path, capsys):
    exitCode = main(["status", "--name", "missing", "--working-dir", str(tmp_path / "working")])
    assert exitCode == 1
    assert "missing" in capsys.readouterr().err


def test_deleteCommandRemovesToken(tmp_path, capsys):
    seedToken(tmp_path / "working")
    exitCode = main(["delete", "--name", "myGoogle", "--working-dir", str(tmp_path / "working")])
    assert exitCode == 0
    assert TokenStore(workingDir=tmp_path / "working").load("myGoogle") is None


def test_deleteCommandFailsForMissingToken(tmp_path, capsys):
    exitCode = main(["delete", "--name", "missing", "--working-dir", str(tmp_path / "working")])
    assert exitCode == 1
    assert "missing" in capsys.readouterr().err


def manualAuthorizeArgs(tokenEndpoint, tmp_path) -> list[str]:
    """CLI arguments for a headless manual authorization against the fake endpoint."""
    return [
        "authorize", "--manual",
        "--provider", "generic",
        "--auth-url", "https://example.invalid/auth",
        "--token-url", tokenEndpoint.tokenUrl,
        "--client-id", "id",
        "--client-secret", "secret",
        "--scopes", "openid",
        "--name", "headlessToken",
        "--working-dir", str(tmp_path / "working"),
    ]


def test_manualAuthorizeWithBareCodeFromStdin(tokenEndpoint, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("goodCode\n"))
    exitCode = main(manualAuthorizeArgs(tokenEndpoint, tmp_path))
    output = capsys.readouterr().out
    assert exitCode == 0
    assert "headlessToken" in output
    stored = TokenStore(workingDir=tmp_path / "working").load("headlessToken")
    assert stored is not None
    assert stored["accessToken"] == "initialAccessToken"


def test_manualAuthorizePrintsUrlInsteadOfOpeningBrowser(tokenEndpoint, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("goodCode\n"))
    main(manualAuthorizeArgs(tokenEndpoint, tmp_path))
    output = capsys.readouterr().out
    assert "https://example.invalid/auth?" in output


def test_manualAuthorizeRejectsWrongState(tokenEndpoint, tmp_path, capsys, monkeypatch):
    pastedUrl = "https://localhost:8400/callback?code=goodCode&state=wrongState\n"
    monkeypatch.setattr("sys.stdin", io.StringIO(pastedUrl))
    exitCode = main(manualAuthorizeArgs(tokenEndpoint, tmp_path))
    assert exitCode == 1
    assert "state mismatch" in capsys.readouterr().err.lower()
    assert TokenStore(workingDir=tmp_path / "working").load("headlessToken") is None


def test_manualAuthorizeUsesRedirectUriOption(tokenEndpoint, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("goodCode\n"))
    args = manualAuthorizeArgs(tokenEndpoint, tmp_path) + [
        "--redirect-uri", "https://localhost:9443/oauth/return",
    ]
    exitCode = main(args)
    assert exitCode == 0
    assert "https://localhost:9443/oauth/return" in capsys.readouterr().out
    assert tokenEndpoint.recordedRequests[-1]["redirect_uri"] == "https://localhost:9443/oauth/return"


def clientCredentialsArgs(tokenEndpoint, tmp_path) -> list[str]:
    """CLI arguments for a client-credentials (no user) authorization.

    Deliberately omits --auth-url: the client credentials grant never visits
    an authorization endpoint, so the generic provider must not require one.
    """
    return [
        "authorize", "--client-credentials",
        "--provider", "generic",
        "--token-url", tokenEndpoint.tokenUrl,
        "--client-id", "testClientId",
        "--client-secret", "testClientSecret",
        "--scopes", "core:*:*",
        "--name", "serviceToken",
        "--working-dir", str(tmp_path / "working"),
    ]


def test_clientCredentialsAuthorizeSavesToken(tokenEndpoint, tmp_path, capsys):
    exitCode = main(clientCredentialsArgs(tokenEndpoint, tmp_path))
    output = capsys.readouterr().out
    assert exitCode == 0
    assert "serviceToken" in output
    stored = TokenStore(workingDir=tmp_path / "working").load("serviceToken")
    assert stored is not None
    assert stored["accessToken"] == "serviceAccessToken"
    assert stored["grantType"] == "client_credentials"
    assert tokenEndpoint.recordedRequests[-1]["grant_type"] == "client_credentials"


def test_refreshCommandRenewsClientCredentialsToken(tokenEndpoint, tmp_path, capsys):
    main(clientCredentialsArgs(tokenEndpoint, tmp_path))
    capsys.readouterr()
    exitCode = main(["refresh", "--name", "serviceToken", "--working-dir", str(tmp_path / "working")])
    assert exitCode == 0
    assert "refreshed" in capsys.readouterr().out
    assert tokenEndpoint.recordedRequests[-1]["grant_type"] == "client_credentials"


def test_keygenCommandWritesKeyAndPrintsJwks(tmp_path, capsys):
    workingDir = str(tmp_path / "working")
    exitCode = main(["keygen", "--kid", "serviceKey", "--working-dir", workingDir])
    output = capsys.readouterr().out
    assert exitCode == 0
    privateKeyPath = tmp_path / "working" / "keys" / "serviceKey.pem"
    jwksPath = tmp_path / "working" / "keys" / "serviceKey.jwks.json"
    assert privateKeyPath.exists()
    assert jwksPath.exists()
    assert str(privateKeyPath) in output
    assert '"keys"' in output          # the JWKS to host is printed
    assert "https" in output.lower()   # ...with the hosting instruction


def test_keygenCommandRefusesToOverwrite(tmp_path, capsys):
    workingDir = str(tmp_path / "working")
    main(["keygen", "--kid", "serviceKey", "--working-dir", workingDir])
    capsys.readouterr()
    exitCode = main(["keygen", "--kid", "serviceKey", "--working-dir", workingDir])
    assert exitCode == 1
    assert "already exists" in capsys.readouterr().err


def assertionAuthorizeArgs(tokenEndpoint, tmp_path, privateKeyPath) -> list[str]:
    """CLI arguments for client-credentials authorization with a JWT assertion
    instead of a client secret (as Brightspace service users require)."""
    return [
        "authorize", "--client-credentials",
        "--provider", "generic",
        "--token-url", tokenEndpoint.tokenUrl,
        "--client-id", "testClientId",
        "--private-key", str(privateKeyPath),
        "--kid", "serviceKey",
        "--scopes", "core:*:*",
        "--name", "assertionToken",
        "--working-dir", str(tmp_path / "working"),
    ]


def generateCliSigningKey(tokenEndpoint, tmp_path, capsys):
    """Run keygen and register the resulting public JWK with the endpoint."""
    main(["keygen", "--kid", "serviceKey", "--working-dir", str(tmp_path / "working")])
    capsys.readouterr()
    jwksPath = tmp_path / "working" / "keys" / "serviceKey.jwks.json"
    tokenEndpoint.registerAssertionJwk(json.loads(jwksPath.read_text())["keys"][0])
    return tmp_path / "working" / "keys" / "serviceKey.pem"


def test_clientCredentialsAuthorizeWithPrivateKey(tokenEndpoint, tmp_path, capsys):
    privateKeyPath = generateCliSigningKey(tokenEndpoint, tmp_path, capsys)
    exitCode = main(assertionAuthorizeArgs(tokenEndpoint, tmp_path, privateKeyPath))
    output = capsys.readouterr().out
    assert exitCode == 0
    assert "assertionToken" in output
    stored = TokenStore(workingDir=tmp_path / "working").load("assertionToken")
    assert stored is not None
    assert stored["privateKeyFile"] == str(privateKeyPath)
    request = tokenEndpoint.recordedRequests[-1]
    assert "client_assertion" in request
    assert "client_secret" not in request


def test_refreshCommandRenewsAssertionTokenFromStoredKeyPath(tokenEndpoint, tmp_path, capsys):
    privateKeyPath = generateCliSigningKey(tokenEndpoint, tmp_path, capsys)
    main(assertionAuthorizeArgs(tokenEndpoint, tmp_path, privateKeyPath))
    capsys.readouterr()
    exitCode = main(["refresh", "--name", "assertionToken", "--working-dir", str(tmp_path / "working")])
    assert exitCode == 0
    assert "refreshed" in capsys.readouterr().out
    assert "client_assertion" in tokenEndpoint.recordedRequests[-1]


def test_authorizeRequiresSecretOrPrivateKey(tokenEndpoint, tmp_path, capsys):
    args = clientCredentialsArgs(tokenEndpoint, tmp_path)
    secretIndex = args.index("--client-secret")
    del args[secretIndex:secretIndex + 2]
    exitCode = main(args)
    assert exitCode == 1
    assert "--client-secret" in capsys.readouterr().err


def test_privateKeyRequiresClientCredentials(tokenEndpoint, tmp_path, capsys):
    args = manualAuthorizeArgs(tokenEndpoint, tmp_path)
    args += ["--private-key", str(tmp_path / "key.pem"), "--kid", "serviceKey"]
    exitCode = main(args)
    assert exitCode == 1
    assert "--client-credentials" in capsys.readouterr().err


def test_privateKeyRequiresKid(tokenEndpoint, tmp_path, capsys):
    privateKeyPath = generateCliSigningKey(tokenEndpoint, tmp_path, capsys)
    args = assertionAuthorizeArgs(tokenEndpoint, tmp_path, privateKeyPath)
    kidIndex = args.index("--kid")
    del args[kidIndex:kidIndex + 2]
    exitCode = main(args)
    assert exitCode == 1
    assert "--kid" in capsys.readouterr().err


def test_statusCommandShowsSigningKey(tmp_path, capsys):
    seedToken(
        tmp_path / "working", grantType="client_credentials", refreshToken=None,
        privateKeyFile="/keys/serviceKey.pem", keyId="serviceKey",
    )
    exitCode = main(["status", "--name", "myGoogle", "--working-dir", str(tmp_path / "working")])
    output = capsys.readouterr().out
    assert exitCode == 0
    assert "/keys/serviceKey.pem" in output
    assert "serviceKey" in output
