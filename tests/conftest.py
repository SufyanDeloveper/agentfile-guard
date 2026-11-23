
import pytest


@pytest.fixture(autouse=True)
def _disable_update_check(monkeypatch):
    monkeypatch.setenv("AGENTFILE_GUARD_NO_UPDATE", "1")
