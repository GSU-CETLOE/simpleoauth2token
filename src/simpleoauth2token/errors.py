"""Exception types raised by simpleoauth2token."""


class OAuth2Error(Exception):
    """Raised for any OAuth2 failure: provider errors, missing tokens,
    misconfiguration, or callback problems."""
