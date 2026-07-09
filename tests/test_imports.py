"""The public API other projects import must be exposed at package level."""


def test_publicApiIsImportableFromPackageRoot():
    from simpleoauth2token import (
        CallbackServer,
        OAuth2Client,
        OAuth2Error,
        ProviderConfig,
        TokenStore,
        buildClientAssertion,
        ensureCertificates,
        generateSigningKey,
        getLogger,
        getProvider,
    )

    assert OAuth2Client is not None
    assert OAuth2Error is not None
    assert ProviderConfig is not None
    assert TokenStore is not None
    assert CallbackServer is not None
    assert buildClientAssertion is not None
    assert ensureCertificates is not None
    assert generateSigningKey is not None
    assert getLogger is not None
    assert getProvider is not None
