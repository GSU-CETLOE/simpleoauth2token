"""OAuth2 provider presets: Google, Microsoft, D2L Brightspace, and generic."""

from dataclasses import dataclass

from .errors import OAuth2Error


@dataclass(frozen=True)
class ProviderConfig:
    """The endpoints an OAuth2 provider exposes for the authorization code flow."""

    name: str
    authorizationUrl: str
    tokenUrl: str


MICROSOFT_AUTHORIZATION_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
MICROSOFT_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

PROVIDER_PRESETS = {
    "google": ProviderConfig(
        name="google",
        authorizationUrl="https://accounts.google.com/o/oauth2/v2/auth",
        tokenUrl="https://oauth2.googleapis.com/token",
    ),
    "brightspace": ProviderConfig(
        name="brightspace",
        authorizationUrl="https://auth.brightspace.com/oauth2/auth",
        tokenUrl="https://auth.brightspace.com/core/connect/token",
    ),
}


def listProviders() -> list[str]:
    """Return the names of every supported provider preset."""
    return sorted([*PROVIDER_PRESETS, "microsoft", "generic"])


def getProvider(
    name: str,
    tenant: str = "common",
    authorizationUrl: str | None = None,
    tokenUrl: str | None = None,
) -> ProviderConfig:
    """Return the ProviderConfig for a preset name.

    "microsoft" substitutes the given tenant into its endpoints. "generic"
    requires both authorizationUrl and tokenUrl so any OAuth2 provider works.
    """
    if name == "microsoft":
        return ProviderConfig(
            name="microsoft",
            authorizationUrl=MICROSOFT_AUTHORIZATION_URL.format(tenant=tenant),
            tokenUrl=MICROSOFT_TOKEN_URL.format(tenant=tenant),
        )
    if name == "generic":
        if not authorizationUrl or not tokenUrl:
            raise OAuth2Error(
                "The generic provider requires both authorizationUrl and tokenUrl"
            )
        return ProviderConfig(name="generic", authorizationUrl=authorizationUrl, tokenUrl=tokenUrl)
    if name in PROVIDER_PRESETS:
        return PROVIDER_PRESETS[name]
    raise OAuth2Error(
        f"Unknown provider '{name}'. Supported providers: {', '.join(listProviders())}"
    )
