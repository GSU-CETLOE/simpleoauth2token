"""Tests for mkcert certificate management under working/certs."""

import pytest

from simpleoauth2token.certs import ensureCertificates, isMkcertInstalled

requiresMkcert = pytest.mark.skipif(
    not isMkcertInstalled(), reason="mkcert is not installed on this machine"
)


@requiresMkcert
def test_ensureCertificatesCreatesCertAndKey(tmp_path):
    certFile, keyFile = ensureCertificates(workingDir=tmp_path / "working")
    assert certFile.exists()
    assert keyFile.exists()
    assert certFile.parent == tmp_path / "working" / "certs"
    assert certFile.read_text().startswith("-----BEGIN CERTIFICATE-----")


@requiresMkcert
def test_ensureCertificatesReusesExistingFiles(tmp_path):
    firstCert, firstKey = ensureCertificates(workingDir=tmp_path / "working")
    firstCertMtime = firstCert.stat().st_mtime_ns
    secondCert, secondKey = ensureCertificates(workingDir=tmp_path / "working")
    assert secondCert == firstCert
    assert secondKey == firstKey
    assert secondCert.stat().st_mtime_ns == firstCertMtime
