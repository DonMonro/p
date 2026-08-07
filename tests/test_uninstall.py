"""Tests for panel.uninstall — cleanup of 3x-ui entries on uninstall.

Phase 27 (item 3): the uninstaller must delete ONLY the inbounds, outbounds,
and routing rules this panel created, leaving everything else in 3x-ui intact.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import Session

from panel.db import get_engine, init_db
from panel.models import CloneRecord, Country, XuiLink


def _isolated_env(tmp_path, monkeypatch) -> None:
    """Isolate the DB per test. Mirrors tests/test_dashboard.py."""
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    from panel import config, db
    config.get_settings.cache_clear()
    config.load_countries.cache_clear()
    db._engine = None  # noqa: SLF001
    db._session_factory = None  # noqa: SLF001


def _seed_clone(*, country_code: str, inbound_id: int) -> None:
    init_db()
    with Session(get_engine()) as s:
        s.add(
            CloneRecord(
                inbound_id=inbound_id,
                country_code=country_code,
                public_port=30000 + inbound_id,
                socks_port=11000 + inbound_id,
                healthy=True,
            )
        )
        s.commit()


def _seed_country(*, code: str) -> None:
    init_db()
    with Session(get_engine()) as s:
        s.add(Country(code=code, name=f"{code} Test", enabled=True))
        s.commit()


def _seed_xui_link() -> None:
    from panel.auth import encrypt_creds

    init_db()
    token = encrypt_creds({"password": "xui-pass"})
    with Session(get_engine()) as s:
        existing = s.get(XuiLink, {"id": 1})
        if existing is not None:
            s.delete(existing)
            s.flush()
        s.add(
            XuiLink(
                id=1,
                base_url="http://127.0.0.1:2053",
                username="xui-admin",
                password_enc=token,
            )
        )
        s.commit()


# Fake XuiClient that records what was deleted + the final template write.
class FakeUninstallClient:
    deleted_inbounds: list[int] = []
    xray_template: dict | None = None
    xray_update_payload: str | None = None
    login_raises: Exception | None = None
    delete_raises: dict[int, Exception] = {}
    get_xray_raises: Exception | None = None
    update_xray_raises: Exception | None = None

    def __init__(self, base_url: str, username: str, password: str, **kwargs) -> None:  # noqa: ARG002
        self.base_url = base_url
        self.username = username
        self.password = password

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # noqa: ARG002
        pass

    async def login(self) -> None:
        if FakeUninstallClient.login_raises:
            raise FakeUninstallClient.login_raises

    async def aclose(self) -> None:
        pass

    async def delete_inbound(self, inbound_id: int) -> dict:
        if inbound_id in FakeUninstallClient.delete_raises:
            raise FakeUninstallClient.delete_raises[inbound_id]
        FakeUninstallClient.deleted_inbounds.append(inbound_id)
        return {"obj": ""}

    async def get_xray_setting(self) -> dict:
        if FakeUninstallClient.get_xray_raises:
            raise FakeUninstallClient.get_xray_raises
        return {"xraySetting": FakeUninstallClient.xray_template or {}}

    async def update_xray_setting(self, xray_setting: str) -> dict:
        if FakeUninstallClient.update_xray_raises:
            raise FakeUninstallClient.update_xray_raises
        FakeUninstallClient.xray_update_payload = xray_setting
        FakeUninstallClient.xray_template = json.loads(xray_setting)
        return {"success": True}


@pytest.fixture(autouse=True)
def _patch_client(monkeypatch):
    FakeUninstallClient.deleted_inbounds = []
    FakeUninstallClient.xray_template = None
    FakeUninstallClient.xray_update_payload = None
    FakeUninstallClient.login_raises = None
    FakeUninstallClient.delete_raises = {}
    FakeUninstallClient.get_xray_raises = None
    FakeUninstallClient.update_xray_raises = None

    from panel.dashboard import xui_client

    monkeypatch.setattr(xui_client, "XuiClient", FakeUninstallClient)
    yield


@pytest.mark.asyncio
async def test_uninstall_deletes_cloned_inbounds(monkeypatch, tmp_path):
    """Every inbound ID recorded in CloneRecord is deleted."""
    _isolated_env(tmp_path, monkeypatch)
    _seed_country(code="US")
    _seed_country(code="DE")
    _seed_clone(country_code="US", inbound_id=42)
    _seed_clone(country_code="DE", inbound_id=99)
    _seed_xui_link()

    db_path = str(tmp_path / "panel.db")

    from panel import uninstall as uninstall_mod

    report = await uninstall_mod._cleanup(db_path, dry_run=False)
    assert report["skipped"] is None
    assert sorted(report["inbounds"]) == [42, 99]
    assert FakeUninstallClient.deleted_inbounds == [42, 99]


@pytest.mark.asyncio
async def test_uninstall_strips_country_outbounds_and_rules(monkeypatch, tmp_path):
    """The outbound + routing rules for each country are removed in one write."""
    _isolated_env(tmp_path, monkeypatch)
    from panel import uninstall as uninstall_mod

    _seed_country(code="US")
    _seed_country(code="JP")
    _seed_xui_link()

    # Populate a template with our outbounds + rules plus the user's own entries.
    FakeUninstallClient.xray_template = {
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "psiphon-out-US", "protocol": "socks"},  # ours
            {"tag": "psiphon-out-JP", "protocol": "socks"},  # ours
            {"tag": "user-custom", "protocol": "vmess"},  # theirs
        ],
        "routing": {
            "rules": [
                {"inboundTag": ["in-31001-tcp"], "outboundTag": "psiphon-out-US"},  # ours
                {"inboundTag": ["in-31002-tcp"], "outboundTag": "psiphon-out-JP"},  # ours
                {"protocol": ["bittorrent"], "outboundTag": "blocked"},  # theirs
            ]
        },
    }

    db_path = str(tmp_path / "panel.db")

    report = await uninstall_mod._cleanup(db_path, dry_run=False)
    assert report["skipped"] is None
    assert sorted(report["countries"]) == ["JP", "US"]

    final = json.loads(FakeUninstallClient.xray_update_payload)
    # Our two outbounds gone, user's custom one stays.
    assert len(final["outbounds"]) == 2
    assert {ob["tag"] for ob in final["outbounds"]} == {"direct", "user-custom"}
    # Our two rules gone, user's bittorrent rule stays.
    assert len(final["routing"]["rules"]) == 1
    assert final["routing"]["rules"][0]["protocol"] == ["bittorrent"]


@pytest.mark.asyncio
async def test_dry_run_reports_without_calling_xui(monkeypatch, tmp_path):
    """Dry-run returns what would be removed without any HTTP calls."""
    _isolated_env(tmp_path, monkeypatch)
    from panel import uninstall as uninstall_mod

    _seed_country(code="US")
    _seed_clone(country_code="US", inbound_id=42)
    _seed_xui_link()

    db_path = str(tmp_path / "panel.db")

    report = await uninstall_mod._cleanup(db_path, dry_run=True)
    assert report["skipped"] == "dry-run"
    assert report["inbounds"] == [42]
    assert report["countries"] == ["US"]
    assert FakeUninstallClient.deleted_inbounds == []
    assert FakeUninstallClient.xray_update_payload is None


@pytest.mark.asyncio
async def test_no_xui_link_skips_gracefully(monkeypatch, tmp_path):
    """When panel.db has no XuiLink row, cleanup is skipped."""
    _isolated_env(tmp_path, monkeypatch)
    from panel import uninstall as uninstall_mod

    _seed_country(code="US")
    # No _seed_xui_link()

    db_path = str(tmp_path / "panel.db")

    report = await uninstall_mod._cleanup(db_path, dry_run=False)
    assert "no 3x-ui link" in report["skipped"]
    assert report["inbounds"] == []
    assert report["countries"] == []


@pytest.mark.asyncio
async def test_login_failure_skips_gracefully(monkeypatch, tmp_path):
    """A 3x-ui panel that is down does not block the uninstall."""
    _isolated_env(tmp_path, monkeypatch)
    from panel import uninstall as uninstall_mod

    _seed_country(code="US")
    _seed_xui_link()
    FakeUninstallClient.login_raises = RuntimeError("panel unreachable")

    db_path = str(tmp_path / "panel.db")

    report = await uninstall_mod._cleanup(db_path, dry_run=False)
    assert "login failed" in report["skipped"]


@pytest.mark.asyncio
async def test_delete_failure_records_error_continues(monkeypatch, tmp_path):
    """A single delete_inbound failure is recorded; the rest still run."""
    _isolated_env(tmp_path, monkeypatch)
    from panel import uninstall as uninstall_mod

    _seed_country(code="US")
    _seed_country(code="DE")
    _seed_clone(country_code="US", inbound_id=42)
    _seed_clone(country_code="DE", inbound_id=99)
    _seed_xui_link()
    FakeUninstallClient.delete_raises = {42: RuntimeError("already gone")}

    db_path = str(tmp_path / "panel.db")

    report = await uninstall_mod._cleanup(db_path, dry_run=False)
    assert report["skipped"] is None
    # 42 errored, 99 succeeded.
    assert report["inbounds"] == [99]
    assert len(report["errors"]) == 1
    assert "delete_inbound(42)" in report["errors"][0]


@pytest.mark.asyncio
async def test_leaves_countries_with_no_outbound_unchanged(monkeypatch, tmp_path):
    """A country that never had an outbound (e.g. never enabled) skips the write."""
    _isolated_env(tmp_path, monkeypatch)
    from panel import uninstall as uninstall_mod

    _seed_country(code="US")
    _seed_xui_link()
    # Template has NO psiphon-out-US — the country was never enabled.
    FakeUninstallClient.xray_template = {
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": []},
    }

    db_path = str(tmp_path / "panel.db")

    report = await uninstall_mod._cleanup(db_path, dry_run=False)
    assert report["skipped"] is None
    assert report["countries"] == []
    assert FakeUninstallClient.xray_update_payload is None


# ===========================================================================
# Phase 29 (item 4) — "I uninstalled the script, but it didn't delete anything"
# ---------------------------------------------------------------------------
# XuiLink.password_enc is signed with PSIPHON3XUI_SESSION_SECRET, which lives
# only in /opt/psiphon-3x-ui/panel.env (systemd hands it to the panel via
# EnvironmentFile=). install.sh ran this module from a plain root shell, so the
# secret was absent, panel.config fell back to its built-in default,
# decrypt_creds() failed the signature check, and cleanup returned early having
# deleted nothing — exit 0, one easily-missed line of output.
# ===========================================================================
class TestPhase29UninstallCredentialDecryption:
    @pytest.mark.asyncio
    async def test_wrong_session_secret_reports_a_decrypt_failure(
        self, monkeypatch, tmp_path
    ):
        """A row that exists but won't decrypt must say WHY, not "no creds".

        This is the exact production failure: the row was fine, the secret was
        missing. Reporting it as "no cached credentials" sent operators looking
        for a DB problem that did not exist.
        """
        _isolated_env(tmp_path, monkeypatch)
        from panel import config
        from panel import uninstall as uninstall_mod

        monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "the-real-install-secret")
        config.get_settings.cache_clear()

        _seed_country(code="US")
        _seed_clone(country_code="US", inbound_id=42)
        _seed_xui_link()  # encrypted under the real secret

        # Now simulate install.sh's bare invocation: the env var is gone, so
        # panel.config falls back to its default.
        monkeypatch.delenv("PSIPHON3XUI_SESSION_SECRET", raising=False)
        config.get_settings.cache_clear()

        report = await uninstall_mod._cleanup(str(tmp_path / "panel.db"), dry_run=False)

        assert report["skipped"] is not None
        assert "decrypt" in report["skipped"].lower(), (
            "a signature failure must be reported as a decrypt failure, not as "
            f"a missing row; got: {report['skipped']!r}"
        )
        assert "PSIPHON3XUI_SESSION_SECRET" in report["skipped"], (
            "the skip message must name the env var an operator has to supply, "
            f"got: {report['skipped']!r}"
        )
        assert FakeUninstallClient.deleted_inbounds == []

    @pytest.mark.asyncio
    async def test_correct_session_secret_deletes_everything(
        self, monkeypatch, tmp_path
    ):
        """With the env var loaded, the same DB cleans up completely.

        The positive control for the test above: identical fixtures, only the
        secret differs, and now every inbound AND every outbound/rule goes.
        """
        _isolated_env(tmp_path, monkeypatch)
        from panel import config
        from panel import uninstall as uninstall_mod

        monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "the-real-install-secret")
        config.get_settings.cache_clear()

        _seed_country(code="US")
        _seed_clone(country_code="US", inbound_id=42)
        _seed_xui_link()
        FakeUninstallClient.xray_template = {
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "psiphon-out-US", "protocol": "socks"},
            ],
            "routing": {
                "rules": [
                    {"inboundTag": ["in-31001-tcp"], "outboundTag": "psiphon-out-US"}
                ]
            },
        }

        report = await uninstall_mod._cleanup(str(tmp_path / "panel.db"), dry_run=False)

        assert report["skipped"] is None
        assert report["inbounds"] == [42]
        assert report["countries"] == ["US"]
        final = json.loads(FakeUninstallClient.xray_update_payload)
        assert {ob["tag"] for ob in final["outbounds"]} == {"direct"}
        assert final["routing"]["rules"] == []

    @pytest.mark.asyncio
    async def test_empty_password_column_is_reported_separately(
        self, monkeypatch, tmp_path
    ):
        """An actually-empty password_enc keeps the "no cached credentials" text.

        The two failures need distinguishable messages or the diagnostic value
        of the one above is lost.
        """
        _isolated_env(tmp_path, monkeypatch)
        from panel import uninstall as uninstall_mod

        _seed_country(code="US")
        init_db()
        with Session(get_engine()) as s:
            s.add(
                XuiLink(
                    id=1,
                    base_url="http://127.0.0.1:2053",
                    username="xui-admin",
                    password_enc="",
                )
            )
            s.commit()

        report = await uninstall_mod._cleanup(str(tmp_path / "panel.db"), dry_run=False)

        assert report["skipped"] == "no cached 3x-ui credentials in panel.db"

    def test_skip_is_reported_on_stderr(self, monkeypatch, tmp_path, capsys):
        """A skip means debris is being left behind — it must be a warning.

        On stdout it was one quiet line lost among the rest of the uninstall
        output, which is why nobody noticed nothing had been deleted.
        """
        _isolated_env(tmp_path, monkeypatch)
        from panel import uninstall as uninstall_mod

        _seed_country(code="US")
        # No XuiLink at all → guaranteed skip.
        rc = uninstall_mod.main(["--db", str(tmp_path / "panel.db")])

        assert rc == 0, "a skip must never block the uninstall"
        captured = capsys.readouterr()
        assert "SKIPPED" in captured.err, (
            "the skip must go to stderr so it survives the uninstall output; "
            f"stdout={captured.out!r} stderr={captured.err!r}"
        )
        assert "3x-ui" in captured.err

