"""Tests for token persistence under the working directory."""

import stat
import threading
import time

from simpleoauth2token.tokenStore import TokenStore, isExpired


def makeToken(**overrides) -> dict:
    """A valid normalized token dict, with fields overridable per test."""
    token = {
        "accessToken": "accessToken123",
        "refreshToken": "refreshToken123",
        "tokenType": "Bearer",
        "expiresAt": time.time() + 3600,
        "obtainedAt": time.time(),
        "scopes": ["openid", "email"],
        "provider": "google",
    }
    token.update(overrides)
    return token


def test_saveAndLoadRoundtrip(tmp_path):
    store = TokenStore(workingDir=tmp_path / "working")
    token = makeToken()
    store.save("myGoogle", token)
    assert store.load("myGoogle") == token


def test_saveCreatesFileUnderWorkingTokens(tmp_path):
    store = TokenStore(workingDir=tmp_path / "working")
    savedPath = store.save("myGoogle", makeToken())
    assert savedPath == tmp_path / "working" / "tokens" / "myGoogle.json"
    assert savedPath.exists()


def test_savedFileIsOwnerReadWriteOnly(tmp_path):
    store = TokenStore(workingDir=tmp_path / "working")
    savedPath = store.save("myGoogle", makeToken())
    mode = stat.S_IMODE(savedPath.stat().st_mode)
    assert mode == 0o600


def test_saveLeavesNoTemporaryFiles(tmp_path):
    store = TokenStore(workingDir=tmp_path / "working")
    store.save("myGoogle", makeToken())
    store.save("myGoogle", makeToken(accessToken="overwritten"))
    assert [path.name for path in store.tokensDir.iterdir()] == ["myGoogle.json"]


def test_concurrentSaveAndLoadNeverObservesPartialToken(tmp_path):
    """A reader racing a writer must always see a complete token.

    Service tokens are renewed by unattended jobs, so two processes sharing a
    working directory is the normal case, not the exception.
    """
    store = TokenStore(workingDir=tmp_path / "working")
    store.save("myGoogle", makeToken())
    stopReading = threading.Event()
    failures = []

    def loadRepeatedly() -> None:
        while not stopReading.is_set():
            try:
                loaded = store.load("myGoogle")
            except Exception as error:  # noqa: BLE001 - any reader error is the failure
                failures.append(repr(error))
                return
            if loaded is None or "accessToken" not in loaded:
                failures.append(f"partial token observed: {loaded!r}")
                return

    reader = threading.Thread(target=loadRepeatedly)
    reader.start()
    for iteration in range(500):
        store.save("myGoogle", makeToken(accessToken=f"accessToken{iteration}"))
    stopReading.set()
    reader.join()
    assert failures == []


def test_loadMissingTokenReturnsNone(tmp_path):
    store = TokenStore(workingDir=tmp_path / "working")
    assert store.load("doesNotExist") is None


def test_deleteRemovesToken(tmp_path):
    store = TokenStore(workingDir=tmp_path / "working")
    store.save("myGoogle", makeToken())
    assert store.delete("myGoogle") is True
    assert store.load("myGoogle") is None


def test_deleteMissingTokenReturnsFalse(tmp_path):
    store = TokenStore(workingDir=tmp_path / "working")
    assert store.delete("doesNotExist") is False


def test_listTokensReturnsSavedNames(tmp_path):
    store = TokenStore(workingDir=tmp_path / "working")
    store.save("myGoogle", makeToken())
    store.save("myBrightspace", makeToken(provider="brightspace"))
    assert sorted(store.listTokens()) == ["myBrightspace", "myGoogle"]


def test_listTokensEmptyWhenNoTokens(tmp_path):
    store = TokenStore(workingDir=tmp_path / "working")
    assert store.listTokens() == []


def test_isExpiredFalseForFutureExpiry():
    assert isExpired(makeToken(expiresAt=time.time() + 3600)) is False


def test_isExpiredTrueForPastExpiry():
    assert isExpired(makeToken(expiresAt=time.time() - 10)) is True


def test_isExpiredTrueWithinSkewWindow():
    assert isExpired(makeToken(expiresAt=time.time() + 30), skewSeconds=60) is True


def test_isExpiredFalseWhenNoExpiryKnown():
    assert isExpired(makeToken(expiresAt=None)) is False
