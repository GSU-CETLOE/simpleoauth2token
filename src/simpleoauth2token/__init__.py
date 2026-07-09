"""simpleoauth2token: an importable OAuth2 client with an mkcert-secured local
callback server. Works with Google, Microsoft, D2L Brightspace, and any
standard OAuth2 provider.

Quick start::

    from simpleoauth2token import OAuth2Client

    client = OAuth2Client(
        provider="google",
        clientId="...",
        clientSecret="...",
        scopes="openid email",
        tokenName="myGoogle",
    )
    client.authorize()                 # manual, first time only
    accessToken = client.getAccessToken()  # refreshes automatically after that
"""

from .callbackServer import CallbackServer
from .certs import ensureCertificates, isMkcertInstalled
from .client import OAuth2Client
from .clientAssertion import buildClientAssertion, generateSigningKey
from .errors import OAuth2Error
from .loggingService import getLogger
from .providers import ProviderConfig, getProvider, listProviders
from .tokenStore import TokenStore, isExpired

__all__ = [
    "CallbackServer",
    "OAuth2Client",
    "OAuth2Error",
    "ProviderConfig",
    "TokenStore",
    "buildClientAssertion",
    "ensureCertificates",
    "generateSigningKey",
    "getLogger",
    "getProvider",
    "isExpired",
    "isMkcertInstalled",
    "listProviders",
]
