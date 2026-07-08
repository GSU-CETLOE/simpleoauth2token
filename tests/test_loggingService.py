"""Tests for the logging service writing under working/logs."""

from simpleoauth2token.loggingService import getLogger


def test_loggerWritesInfoEventsToWorkingLogs(tmp_path):
    logger = getLogger(name="testLoggerInfo", workingDir=tmp_path / "working")
    logger.info("token refreshed for %s", "myGoogle")
    logFile = tmp_path / "working" / "logs" / "oauth2.log"
    assert logFile.exists()
    contents = logFile.read_text()
    assert "token refreshed for myGoogle" in contents
    assert "INFO" in contents


def test_loggerWritesErrorEvents(tmp_path):
    logger = getLogger(name="testLoggerError", workingDir=tmp_path / "working")
    logger.error("refresh failed: %s", "invalid_grant")
    contents = (tmp_path / "working" / "logs" / "oauth2.log").read_text()
    assert "refresh failed: invalid_grant" in contents
    assert "ERROR" in contents


def test_repeatCallsDoNotDuplicateHandlers(tmp_path):
    first = getLogger(name="testLoggerDupes", workingDir=tmp_path / "working")
    handlerCount = len(first.handlers)
    second = getLogger(name="testLoggerDupes", workingDir=tmp_path / "working")
    assert second is first
    assert len(second.handlers) == handlerCount
