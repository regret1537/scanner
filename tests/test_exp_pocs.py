import os
import pytest

from scanners.plugins.exp.scan_exp import scan_exp


class DummyResp:
    def __init__(self, text='<html>OK</html>'):
        self.text = text


@pytest.fixture(autouse=True)
def patch_requests(monkeypatch, tmp_path):
    """
    Patch requests.Session to prevent real HTTP calls and return dummy responses.
    """
    import requests

    class DummySession:
        def get(self, url, timeout=None, **kwargs):
            return DummyResp()
        def post(self, url, timeout=None, **kwargs):
            return DummyResp()

    # Override Session class
    monkeypatch.setattr(requests, 'Session', lambda *args, **kwargs: DummySession())
    # Also override global requests.get/post if used
    monkeypatch.setattr(requests, 'get', lambda url, timeout=None, **kwargs: DummyResp())
    monkeypatch.setattr(requests, 'post', lambda url, timeout=None, **kwargs: DummyResp())
    return


def get_poc_list():
    # Locate the pocs directory under scanners/plugins/exp/pocs
    base = os.path.dirname(os.path.dirname(__file__))
    poc_dir = os.path.join(base, 'scanners', 'plugins', 'exp', 'pocs')
    return [f[:-3] for f in os.listdir(poc_dir) if f.endswith('.py')]


@pytest.mark.parametrize('poc_name', get_poc_list())
def test_poc_loading_and_execution(poc_name):
    """
    Test that each EXP PoC module loads and runs without raising import errors,
    and returns a list of findings (possibly empty) with expected keys.
    """
    # Execute scan_exp with single poc
    results = scan_exp('http://example.com', pocs=[poc_name])
    assert isinstance(results, list), f"Expected list for poc {poc_name}, got {type(results)}"
    for entry in results:
        assert isinstance(entry, dict)
        # Each finding should have 'poc' key matching filename
        assert 'poc' in entry, f"Missing 'poc' key in entry {entry}"
        assert entry['poc'].startswith(poc_name)
        # And either an 'info' or 'error' key
        assert 'info' in entry or 'error' in entry