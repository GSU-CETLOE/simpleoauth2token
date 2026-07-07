"""Tests for the oauth2 CLI (non-interactive commands and the manual
headless authorization, which reads its input from stdin)."""

import io
import time

from oauth2client.cli import main
from oauth2client.tokenStore import TokenStore


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
