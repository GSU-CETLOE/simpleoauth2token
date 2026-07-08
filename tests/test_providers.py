"""Tests for provider preset configuration."""

import pytest

from simpleoauth2token.errors import OAuth2Error
from simpleoauth2token.providers import ProviderConfig, getProvider, listProviders


def test_googleProviderHasCorrectEndpoints():
    provider = getProvider("google")
    assert provider.authorizationUrl == "https://accounts.google.com/o/oauth2/v2/auth"
    assert provider.tokenUrl == "https://oauth2.googleapis.com/token"


def test_microsoftProviderDefaultsToCommonTenant():
    provider = getProvider("microsoft")
    assert provider.authorizationUrl == "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    assert provider.tokenUrl == "https://login.microsoftonline.com/common/oauth2/v2.0/token"


def test_microsoftProviderSubstitutesTenant():
    provider = getProvider("microsoft", tenant="contoso.onmicrosoft.com")
    assert "contoso.onmicrosoft.com" in provider.authorizationUrl
    assert "contoso.onmicrosoft.com" in provider.tokenUrl


def test_brightspaceProviderHasCorrectEndpoints():
    provider = getProvider("brightspace")
    assert provider.authorizationUrl == "https://auth.brightspace.com/oauth2/auth"
    assert provider.tokenUrl == "https://auth.brightspace.com/core/connect/token"


def test_genericProviderRequiresBothUrls():
    with pytest.raises(OAuth2Error):
        getProvider("generic")
    with pytest.raises(OAuth2Error):
        getProvider("generic", authorizationUrl="https://example.com/auth")


def test_genericProviderUsesSuppliedUrls():
    provider = getProvider(
        "generic",
        authorizationUrl="https://example.com/auth",
        tokenUrl="https://example.com/token",
    )
    assert provider.authorizationUrl == "https://example.com/auth"
    assert provider.tokenUrl == "https://example.com/token"


def test_unknownProviderRaises():
    with pytest.raises(OAuth2Error):
        getProvider("notARealProvider")


def test_listProvidersIncludesAllPresets():
    names = listProviders()
    for expected in ("google", "microsoft", "brightspace", "generic"):
        assert expected in names


def test_providerConfigIsPlainDataHolder():
    provider = ProviderConfig(
        name="custom",
        authorizationUrl="https://example.com/auth",
        tokenUrl="https://example.com/token",
    )
    assert provider.name == "custom"
