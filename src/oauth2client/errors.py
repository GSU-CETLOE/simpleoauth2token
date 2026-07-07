"""Exception types raised by oauth2client."""


class OAuth2Error(Exception):
    """Raised for any OAuth2 failure: provider errors, missing tokens,
    misconfiguration, or callback problems."""
