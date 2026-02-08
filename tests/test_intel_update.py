from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skillscan.intel import config_path, intel_dir, load_store
from skillscan.intel_update import sync_managed


class _FakeResponse:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: Any) -> None:
        return None


def test_sync_managed_updates_sources(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SKILLSCAN_HOME", str(tmp_path / ".skillscan"))

    def fake_load_sources() -> list[dict[str, str]]:
        return [
            {
                "name": "test_urls",
                "kind": "ioc",
                "format": "url_text",
                "url": "https://intel.example/urls.txt",
            }
        ]

    def fake_urlopen(*_args: Any, **_kwargs: Any) -> _FakeResponse:
        payload = b"# feed\nhttps://bad.example/x.sh\n"
        return _FakeResponse(payload)

    monkeypatch.setattr("skillscan.intel_update._load_sources", fake_load_sources)
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    stats = sync_managed(max_age_seconds=1, force=True)
    assert stats["updated"] == 1
    target = intel_dir() / "managed_test_urls.json"
    assert target.exists()

    parsed = json.loads(target.read_text(encoding="utf-8"))
    assert "https://bad.example/x.sh" in parsed["urls"]

    store = load_store()
    assert any(s.name == "managed:test_urls" for s in store.sources)
    assert config_path().exists()


def test_sync_managed_skips_fresh(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SKILLSCAN_HOME", str(tmp_path / ".skillscan"))

    target = intel_dir() / "managed_test_ips.json"
    target.write_text('{"domains": [], "ips": ["1.2.3.4"], "urls": []}', encoding="utf-8")

    def fake_load_sources() -> list[dict[str, str]]:
        return [
            {
                "name": "test_ips",
                "kind": "ioc",
                "format": "ip_text",
                "url": "https://intel.example/ips.txt",
            }
        ]

    monkeypatch.setattr("skillscan.intel_update._load_sources", fake_load_sources)

    stats = sync_managed(max_age_seconds=3600, force=False)
    assert stats["skipped"] == 1
