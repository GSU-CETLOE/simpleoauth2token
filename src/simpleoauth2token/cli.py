"""The simpleoauth2token command-line interface.

Commands:
    authorize   Run the manual first-time authorization for a provider
    refresh     Refresh a saved token using its stored credentials
    status      Show a saved token's provider, scopes, and expiry
    list        List all saved tokens
    delete      Delete a saved token
    providers   List the supported provider presets
    keygen      Generate a signing key and JWKS for JWT client assertions

Run `simpleoauth2token <command> --help` for the options of each command.
"""

import argparse
import sys
import time
from pathlib import Path
from typing import Any

from .client import DEFAULT_CALLBACK_PORT, OAuth2Client
from .clientAssertion import SUPPORTED_ASSERTION_ALGORITHMS, generateSigningKey
from .errors import OAuth2Error
from .providers import ProviderConfig, listProviders
from .tokenStore import TokenStore, isExpired


def formatTimestamp(epochSeconds: float) -> str:
    """Render an epoch time as a local human-readable timestamp."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epochSeconds))


def parseExtraAuthParams(pairs: list[str]) -> dict[str, str]:
    """Turn repeated KEY=VALUE arguments into a dict."""
    params: dict[str, str] = {}
    for pair in pairs:
        key, separator, value = pair.partition("=")
        if not separator or not key:
            raise OAuth2Error(f"--extra-auth-param must be KEY=VALUE, got '{pair}'")
        params[key] = value
    return params


def runAuthorize(args: argparse.Namespace) -> int:
    """Handle `simpleoauth2token authorize`: obtain and save the initial token."""
    grantType = "client_credentials" if args.clientCredentials else "authorization_code"
    if args.privateKeyFile and not args.clientCredentials:
        raise OAuth2Error(
            "--private-key authenticates the client credentials grant; "
            "add --client-credentials"
        )
    if args.privateKeyFile and not args.keyId:
        raise OAuth2Error(
            "--private-key requires --kid, the key id of this key in the "
            "JWKS registered with the provider"
        )
    if not args.clientSecret and not args.privateKeyFile:
        raise OAuth2Error(
            "authorize requires --client-secret (or, for --client-credentials, "
            "--private-key with --kid)"
        )
    if args.provider != "generic":
        provider: ProviderConfig | str = args.provider
    else:
        # The client credentials grant never visits an authorization endpoint,
        # so --auth-url is only required for the browser-based grant.
        provider = ProviderConfig(
            name="generic",
            authorizationUrl=(args.authUrl or "") if args.clientCredentials
                             else requireUrlArgument(args.authUrl, "--auth-url"),
            tokenUrl=requireUrlArgument(args.tokenUrl, "--token-url"),
        )
    client = OAuth2Client(
        provider=provider,
        clientId=args.clientId,
        clientSecret=args.clientSecret,
        scopes=args.scopes,
        tokenName=args.name,
        workingDir=args.workingDir,
        redirectPort=args.port,
        redirectUri=args.redirectUri,
        tenant=args.tenant,
        extraAuthParams=parseExtraAuthParams(args.extraAuthParams),
        grantType=grantType,
        privateKeyFile=args.privateKeyFile,
        keyId=args.keyId,
        assertionAlgorithm=args.assertionAlgorithm,
    )
    if args.clientCredentials:
        token = client.fetchClientCredentialsToken()
    elif args.manual:
        token = client.authorizeManual()
    else:
        token = client.authorize(openBrowser=not args.noBrowser, timeoutSeconds=args.timeout)
    print(f"Token '{args.name}' saved.")
    printExpiry(token)
    return 0


def requireUrlArgument(value: str | None, flag: str) -> str:
    """Fail clearly when a URL flag required by the generic provider is missing."""
    if not value:
        raise OAuth2Error(f"The generic provider requires {flag}")
    return value


def runRefresh(args: argparse.Namespace) -> int:
    """Handle `simpleoauth2token refresh`: renew a saved token with its stored credentials."""
    stored = TokenStore(workingDir=args.workingDir).load(args.name)
    if stored is None:
        print(f"Error: no token named '{args.name}'", file=sys.stderr)
        return 1
    client = OAuth2Client(
        provider=ProviderConfig(
            name=stored.get("provider", "generic"),
            authorizationUrl=stored.get("authorizationUrl", ""),
            tokenUrl=stored["tokenUrl"],
        ),
        clientId=stored["clientId"],
        clientSecret=stored.get("clientSecret", ""),
        scopes=stored.get("scopes", []),
        tokenName=args.name,
        workingDir=args.workingDir,
        privateKeyFile=stored.get("privateKeyFile"),
        keyId=stored.get("keyId"),
        assertionAlgorithm=stored.get("assertionAlgorithm") or "ES256",
    )
    token = client.refreshToken()
    print(f"Token '{args.name}' refreshed.")
    printExpiry(token)
    return 0


def runStatus(args: argparse.Namespace) -> int:
    """Handle `simpleoauth2token status`: report a saved token's details and validity."""
    stored = TokenStore(workingDir=args.workingDir).load(args.name)
    if stored is None:
        print(f"Error: no token named '{args.name}'", file=sys.stderr)
        return 1
    print(f"Token:         {args.name}")
    print(f"Provider:      {stored.get('provider', 'unknown')}")
    print(f"Grant:         {stored.get('grantType', 'authorization_code')}")
    print(f"Scopes:        {' '.join(stored.get('scopes', []))}")
    print(f"Refresh token: {'present' if stored.get('refreshToken') else 'absent'}")
    if stored.get("privateKeyFile"):
        print(f"Signing key:   {stored['privateKeyFile']} (kid {stored.get('keyId')})")
    expiresAt = stored.get("expiresAt")
    if expiresAt is None:
        print("Status:        valid (provider reported no expiry)")
    elif isExpired(stored):
        print(f"Status:        expired at {formatTimestamp(expiresAt)}")
    else:
        print(f"Status:        valid until {formatTimestamp(expiresAt)}")
    return 0


def runList(args: argparse.Namespace) -> int:
    """Handle `simpleoauth2token list`: show every saved token name."""
    names = TokenStore(workingDir=args.workingDir).listTokens()
    if not names:
        print("No tokens saved yet.")
        return 0
    for name in names:
        print(name)
    return 0


def runDelete(args: argparse.Namespace) -> int:
    """Handle `simpleoauth2token delete`: remove a saved token."""
    if TokenStore(workingDir=args.workingDir).delete(args.name):
        print(f"Token '{args.name}' deleted.")
        return 0
    print(f"Error: no token named '{args.name}'", file=sys.stderr)
    return 1


def runProviders(args: argparse.Namespace) -> int:
    """Handle `simpleoauth2token providers`: list the supported provider presets."""
    for name in listProviders():
        print(name)
    return 0


def runKeygen(args: argparse.Namespace) -> int:
    """Handle `simpleoauth2token keygen`: create a signing key and its JWKS."""
    outputDir = args.outputDir or Path(args.workingDir) / "keys"
    privateKeyPath, jwksPath = generateSigningKey(
        keyId=args.keyId, algorithm=args.algorithm, outputDir=outputDir,
    )
    print(f"Private key (keep secret):  {privateKeyPath}")
    print(f"Public JWKS:                {jwksPath}")
    print()
    print("Host the JWKS below at an HTTPS URL and register that URL with your")
    print("provider (for Brightspace: the JWKS URL of the client-credentials app).")
    print()
    print(jwksPath.read_text())
    return 0


def printExpiry(token: dict[str, Any]) -> None:
    """Print when the given token expires, if known."""
    expiresAt = token.get("expiresAt")
    if expiresAt is not None:
        print(f"Expires at {formatTimestamp(expiresAt)}.")


def buildParser() -> argparse.ArgumentParser:
    """Construct the simpleoauth2token argument parser with all subcommands."""
    commonArgs = argparse.ArgumentParser(add_help=False)
    commonArgs.add_argument(
        "--working-dir", dest="workingDir", default="working",
        help="Directory for tokens, certs, and logs (default: ./working)",
    )

    parser = argparse.ArgumentParser(
        prog="simpleoauth2token",
        description="Obtain and manage OAuth2 tokens for Google, Microsoft, "
                    "D2L Brightspace, or any OAuth2 provider.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    authorize = subparsers.add_parser(
        "authorize", parents=[commonArgs],
        help="Run the manual first-time authorization in your browser",
    )
    authorize.add_argument("--provider", required=True,
                           help=f"Provider preset: {', '.join(listProviders())}")
    authorize.add_argument("--client-id", dest="clientId", required=True,
                           help="OAuth2 client id from your provider's app registration")
    authorize.add_argument("--client-secret", dest="clientSecret", default="",
                           help="OAuth2 client secret from your provider's app "
                                "registration (not needed with --private-key)")
    authorize.add_argument("--scopes", required=True,
                           help="Space-separated scopes, quoted (e.g. \"openid email\")")
    authorize.add_argument("--name", required=True,
                           help="Name to store the token under")
    authorize.add_argument("--tenant", default="common",
                           help="Microsoft tenant id (microsoft provider only)")
    authorize.add_argument("--auth-url", dest="authUrl",
                           help="Authorization endpoint (generic provider only)")
    authorize.add_argument("--token-url", dest="tokenUrl",
                           help="Token endpoint (generic provider only)")
    authorize.add_argument("--port", type=int, default=DEFAULT_CALLBACK_PORT,
                           help=f"Local HTTPS callback port (default: {DEFAULT_CALLBACK_PORT})")
    authorize.add_argument("--redirect-uri", dest="redirectUri",
                           help="Redirect URI exactly as registered with the provider, "
                                "when it is not https://localhost:<port>/callback "
                                "(overrides --port; a host other than localhost needs --manual)")
    authorize.add_argument("--timeout", type=float, default=300,
                           help="Seconds to wait for the browser callback (default: 300)")
    authorize.add_argument("--no-browser", dest="noBrowser", action="store_true",
                           help="Print the authorization URL instead of opening a browser")
    authorize.add_argument("--manual", action="store_true",
                           help="Headless mode: print the URL to open on another "
                                "device, then paste the redirect URL back here "
                                "(no local browser, callback server, or mkcert needed)")
    authorize.add_argument("--client-credentials", dest="clientCredentials",
                           action="store_true",
                           help="Use the client credentials grant for "
                                "service-to-service calls where no user signs in "
                                "(Microsoft and Brightspace support it; no browser "
                                "or callback server involved)")
    authorize.add_argument("--extra-auth-param", dest="extraAuthParams", action="append",
                           default=[], metavar="KEY=VALUE",
                           help="Extra authorization query parameter; repeatable "
                                "(e.g. access_type=offline for Google refresh tokens)")
    authorize.add_argument("--private-key", dest="privateKeyFile",
                           help="PEM private key for JWT client-assertion "
                                "authentication instead of a client secret "
                                "(Brightspace service users; requires "
                                "--client-credentials and --kid)")
    authorize.add_argument("--kid", dest="keyId",
                           help="Key id of the private key in the JWKS "
                                "registered with the provider")
    authorize.add_argument("--assertion-algorithm", dest="assertionAlgorithm",
                           default="ES256", choices=SUPPORTED_ASSERTION_ALGORITHMS,
                           help="JWT signing algorithm for client assertions "
                                "(default: ES256)")
    authorize.set_defaults(handler=runAuthorize)

    refresh = subparsers.add_parser(
        "refresh", parents=[commonArgs],
        help="Refresh a saved token using its stored credentials",
    )
    refresh.add_argument("--name", required=True, help="Name of the saved token")
    refresh.set_defaults(handler=runRefresh)

    status = subparsers.add_parser(
        "status", parents=[commonArgs],
        help="Show a saved token's provider, scopes, and expiry",
    )
    status.add_argument("--name", required=True, help="Name of the saved token")
    status.set_defaults(handler=runStatus)

    listCommand = subparsers.add_parser(
        "list", parents=[commonArgs], help="List all saved tokens",
    )
    listCommand.set_defaults(handler=runList)

    delete = subparsers.add_parser(
        "delete", parents=[commonArgs], help="Delete a saved token",
    )
    delete.add_argument("--name", required=True, help="Name of the saved token")
    delete.set_defaults(handler=runDelete)

    providers = subparsers.add_parser(
        "providers", parents=[commonArgs], help="List supported provider presets",
    )
    providers.set_defaults(handler=runProviders)

    keygen = subparsers.add_parser(
        "keygen", parents=[commonArgs],
        help="Generate a signing key and JWKS for providers that require "
             "JWT client assertions (e.g. Brightspace service users)",
    )
    keygen.add_argument("--kid", dest="keyId", required=True,
                        help="Key id to stamp into the key and JWKS")
    keygen.add_argument("--algorithm", default="ES256",
                        choices=SUPPORTED_ASSERTION_ALGORITHMS,
                        help="Signing algorithm the key will be used with "
                             "(default: ES256)")
    keygen.add_argument("--out", dest="outputDir",
                        help="Output directory (default: <working-dir>/keys)")
    keygen.set_defaults(handler=runKeygen)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    args = buildParser().parse_args(argv)
    try:
        return args.handler(args)
    except OAuth2Error as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
