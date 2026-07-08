"""Token persistence under <workingDir>/tokens, one JSON file per token."""

import json
import time
from pathlib import Path
from typing import Any

TOKEN_FILE_MODE = 0o600


class TokenStore:
    """Saves, loads, lists, and deletes named OAuth2 tokens on disk."""

    def __init__(self, workingDir: str | Path = "working") -> None:
        self.tokensDir = Path(workingDir) / "tokens"

    def tokenPath(self, name: str) -> Path:
        """Return the path where the named token is stored."""
        return self.tokensDir / f"{name}.json"

    def save(self, name: str, token: dict[str, Any]) -> Path:
        """Write the token as owner-read-only JSON and return its path."""
        self.tokensDir.mkdir(parents=True, exist_ok=True)
        path = self.tokenPath(name)
        path.write_text(json.dumps(token, indent=2), encoding="utf-8")
        path.chmod(TOKEN_FILE_MODE)
        return path

    def load(self, name: str) -> dict[str, Any] | None:
        """Return the named token, or None if it has never been saved."""
        path = self.tokenPath(name)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def delete(self, name: str) -> bool:
        """Remove the named token. Returns False if it did not exist."""
        path = self.tokenPath(name)
        if not path.exists():
            return False
        path.unlink()
        return True

    def listTokens(self) -> list[str]:
        """Return the names of every saved token, sorted."""
        if not self.tokensDir.exists():
            return []
        return sorted(path.stem for path in self.tokensDir.glob("*.json"))


def isExpired(token: dict[str, Any], skewSeconds: int = 60) -> bool:
    """True when the token's expiry (minus a safety skew) has passed.

    Tokens with no known expiry are treated as still valid.
    """
    expiresAt = token.get("expiresAt")
    if expiresAt is None:
        return False
    return time.time() >= (float(expiresAt) - skewSeconds)
