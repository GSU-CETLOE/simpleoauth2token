"""mkcert-backed TLS certificates for the local HTTPS callback server.

Certificates live under <workingDir>/certs and are generated once with mkcert,
which most OAuth2 providers trust because the redirect URI must be HTTPS.
"""

import shutil
import subprocess
from pathlib import Path

from .errors import OAuth2Error
from .loggingService import getLogger

MKCERT_INSTALL_HELP = (
    "mkcert is not installed. Install it and set up its local CA first "
    "(macOS: 'brew install mkcert && mkcert -install'). "
    "See https://github.com/FiloSottile/mkcert"
)


def isMkcertInstalled() -> bool:
    """True when the mkcert binary is available on PATH."""
    return shutil.which("mkcert") is not None


def ensureCertificates(
    workingDir: str | Path = "working", hostname: str = "localhost"
) -> tuple[Path, Path]:
    """Return (certFile, keyFile) for the callback server, generating them
    with mkcert on first use and reusing them afterwards."""
    certsDir = Path(workingDir) / "certs"
    certFile = certsDir / f"{hostname}.pem"
    keyFile = certsDir / f"{hostname}-key.pem"
    if certFile.exists() and keyFile.exists():
        return certFile, keyFile

    if not isMkcertInstalled():
        raise OAuth2Error(MKCERT_INSTALL_HELP)

    certsDir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            "mkcert",
            "-cert-file", str(certFile),
            "-key-file", str(keyFile),
            hostname, "127.0.0.1", "::1",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise OAuth2Error(f"mkcert failed to generate certificates: {result.stderr.strip()}")

    getLogger(workingDir=workingDir).info(
        "generated TLS certificate for %s at %s", hostname, certFile
    )
    return certFile, keyFile
