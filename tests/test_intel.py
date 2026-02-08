from __future__ import annotations

import json
from pathlib import Path

from skillscan.intel import (
    IntelSource,
    IntelStore,
    add_source,
    clear_runtime,
    config_path,
    data_dir,
    intel_dir,
    load_store,
    remove_source,
    reports_dir,
    save_store,
    set_enabled,
    upsert_source,
)


def test_data_dirs_and_store_roundtrip(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SKILLSCAN_HOME", str(tmp_path / ".skillscan"))
    assert data_dir().name == ".skillscan"
    assert intel_dir().exists()
    assert reports_dir().exists()

    store = IntelStore(sources=[IntelSource(name="a", kind="ioc", path="/tmp/a.json", enabled=True)])
    save_store(store)
    loaded = load_store()
    assert len(loaded.sources) == 1
    assert config_path().exists()


def test_add_remove_enable_disable(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SKILLSCAN_HOME", str(tmp_path / ".skillscan"))
    src = tmp_path / "ioc.json"
    src.write_text(json.dumps({"domains": ["x.com"], "ips": [], "urls": []}), encoding="utf-8")

    added = add_source(name="team", kind="ioc", source_path=src)
    assert added.name == "team"
    assert Path(added.path).exists()

    assert set_enabled("team", False)
    assert load_store().sources[0].enabled is False
    assert set_enabled("team", True)
    assert load_store().sources[0].enabled is True

    assert remove_source("team")
    assert not remove_source("team")


def test_add_source_validation(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SKILLSCAN_HOME", str(tmp_path / ".skillscan"))
    missing = tmp_path / "missing.json"

    try:
        add_source("x", "bad", missing)
        assert False, "expected ValueError for invalid kind"
    except ValueError:
        pass

    try:
        add_source("x", "ioc", missing)
        assert False, "expected ValueError for missing path"
    except ValueError:
        pass


def test_upsert_and_clear_runtime(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SKILLSCAN_HOME", str(tmp_path / ".skillscan"))
    p = intel_dir() / "m.json"
    p.write_text("{}", encoding="utf-8")
    upsert_source("managed", "ioc", p, enabled=True)
    assert any(s.name == "managed" for s in load_store().sources)

    cache = data_dir() / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "x").write_text("1", encoding="utf-8")
    clear_runtime(keep_data=True)
    assert data_dir().exists()
    assert not cache.exists()

    clear_runtime(keep_data=False)
    assert not data_dir().exists()
