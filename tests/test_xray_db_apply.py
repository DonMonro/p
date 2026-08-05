"""Unit tests for installer/xray_db_apply.py — the 3x-ui SQLite DB patcher.

These tests mirror the structure of the existing xray_apply.py tests in
test_hardening.py, but use a temporary SQLite database with a ``settings``
table containing a ``xrayTemplateConfig`` row.

The script is imported as a module (not subprocess'd) so we get coverage
and can mock ``_db_path()`` to point at our temp DB.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

# ── Path setup ──────────────────────────────────────────────────────────────
# installer/ is not a package; add it to sys.path so we can import the script.
_INSTALLER_DIR = Path(__file__).resolve().parent.parent / "installer"
sys.path.insert(0, str(_INSTALLER_DIR))

import xray_db_apply  # noqa: E402  — stdlib-only script, no package


# ── Fixtures ────────────────────────────────────────────────────────────────

def _make_xui_db(db_path: Path, template: dict | None = None) -> None:
    """Create a minimal 3x-ui SQLite DB with a settings table."""
    if template is None:
        template = {
            "log": {"loglevel": "warning"},
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {
                "rules": [
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
                    {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
                ],
            },
        }
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
    conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("xrayTemplateConfig", json.dumps(template)))
    conn.commit()
    conn.close()


@pytest.fixture
def xui_db(tmp_path: Path) -> Path:
    """Create a temp 3x-ui DB and point the script at it via env var."""
    db_path = tmp_path / "x-ui.db"
    _make_xui_db(db_path)
    old_env = os.environ.get("PSIPHON_XUI_DB_PATH")
    os.environ["PSIPHON_XUI_DB_PATH"] = str(db_path)
    yield db_path
    if old_env is not None:
        os.environ["PSIPHON_XUI_DB_PATH"] = old_env
    else:
        os.environ.pop("PSIPHON_XUI_DB_PATH", None)


@pytest.fixture
def patch_file(tmp_path: Path) -> Path:
    """Create a valid apply patch file."""
    p = tmp_path / "US-apply-abc12345.json"
    p.write_text(json.dumps({
        "op": "apply",
        "country_code": "US",
        "socks_port": 11001,
        "public_port": 31001,
        "inbound_tag": "in-31001-tcp",
    }), encoding="utf-8")
    return p


@pytest.fixture
def remove_patch_file(tmp_path: Path) -> Path:
    """Create a valid remove patch file."""
    p = tmp_path / "US-remove-abc12345.json"
    p.write_text(json.dumps({
        "op": "remove",
        "country_code": "US",
        "public_port": 31001,
        "inbound_tag": "in-31001-tcp",
    }), encoding="utf-8")
    return p


def _read_template(db_path: Path) -> dict:
    """Read the xrayTemplateConfig back from the DB."""
    conn = sqlite3.connect(str(db_path))
    cur = conn.execute("SELECT value FROM settings WHERE key = ?", ("xrayTemplateConfig",))
    row = cur.fetchone()
    conn.close()
    assert row is not None, "xrayTemplateConfig row missing"
    return json.loads(row[0])


# ── Tests: apply op ─────────────────────────────────────────────────────────

class TestDbApply:
    """Tests for xray_db_apply._apply (outbound + routing upsert into DB)."""

    def test_apply_inserts_outbound_and_rule(self, xui_db: Path, patch_file: Path):
        """A fresh apply should add the socks outbound + routing rule to the DB."""
        patch = xray_db_apply._load_patch(patch_file)
        template, row_id = xray_db_apply._load_template(xui_db)

        mutated = xray_db_apply._apply(template, patch)

        assert mutated is True
        xray_db_apply._save_template(xui_db, template, row_id)

        result = _read_template(xui_db)
        # Outbound inserted
        out_tags = [ob.get("tag") for ob in result["outbounds"]]
        assert "psiphon-out-US" in out_tags
        # Routing rule inserted BEFORE bittorrent catch-all
        rules = result["routing"]["rules"]
        rule_tags = [(r.get("outboundTag"), r.get("inboundTag")) for r in rules]
        assert ("psiphon-out-US", ["in-31001-tcp"]) in rule_tags
        # Our rule should be before the bittorrent rule
        our_idx = next(i for i, r in enumerate(rules) if r.get("outboundTag") == "psiphon-out-US")
        bt_idx = next(i for i, r in enumerate(rules) if r.get("protocol") == ["bittorrent"])
        assert our_idx < bt_idx

    def test_apply_is_idempotent(self, xui_db: Path, patch_file: Path):
        """Applying the same patch twice should mutate only once."""
        patch = xray_db_apply._load_patch(patch_file)
        template, row_id = xray_db_apply._load_template(xui_db)

        # First apply — should mutate
        mutated1 = xray_db_apply._apply(template, patch)
        assert mutated1 is True
        xray_db_apply._save_template(xui_db, template, row_id)

        # Second apply — should be no-op
        template2, row_id2 = xray_db_apply._load_template(xui_db)
        mutated2 = xray_db_apply._apply(template2, patch)
        assert mutated2 is False

    def test_apply_replaces_stale_outbound(self, xui_db: Path, patch_file: Path):
        """If the outbound exists with a different socks_port, it should be replaced."""
        # Pre-insert an outbound with wrong port
        template, row_id = xray_db_apply._load_template(xui_db)
        template["outbounds"].append({
            "tag": "psiphon-out-US",
            "protocol": "socks",
            "settings": {"servers": [{"address": "127.0.0.1", "port": 99999, "users": []}]},
        })
        xray_db_apply._save_template(xui_db, template, row_id)

        patch = xray_db_apply._load_patch(patch_file)
        template2, row_id2 = xray_db_apply._load_template(xui_db)
        mutated = xray_db_apply._apply(template2, patch)
        assert mutated is True

        xray_db_apply._save_template(xui_db, template2, row_id2)
        result = _read_template(xui_db)
        ob = next(o for o in result["outbounds"] if o.get("tag") == "psiphon-out-US")
        assert ob["settings"]["servers"][0]["port"] == 11001

    def test_apply_multiple_countries(self, xui_db: Path, tmp_path: Path):
        """Multiple country patches should coexist in the same template."""
        for code, socks, public in [("US", 11001, 31001), ("DE", 11002, 31002), ("JP", 11003, 31003)]:
            p = tmp_path / f"{code}-apply-test.json"
            p.write_text(json.dumps({
                "op": "apply",
                "country_code": code,
                "socks_port": socks,
                "public_port": public,
                "inbound_tag": f"in-{public}-tcp",
            }), encoding="utf-8")
            patch = xray_db_apply._load_patch(p)
            template, row_id = xray_db_apply._load_template(xui_db)
            xray_db_apply._apply(template, patch)
            xray_db_apply._save_template(xui_db, template, row_id)

        result = _read_template(xui_db)
        out_tags = {ob.get("tag") for ob in result["outbounds"]}
        assert {"psiphon-out-US", "psiphon-out-DE", "psiphon-out-JP"}.issubset(out_tags)

        rule_keys = {
            (r.get("outboundTag"), tuple(r.get("inboundTag", [])))
            for r in result["routing"]["rules"]
        }
        assert ("psiphon-out-US", ("in-31001-tcp",)) in rule_keys
        assert ("psiphon-out-DE", ("in-31002-tcp",)) in rule_keys
        assert ("psiphon-out-JP", ("in-31003-tcp",)) in rule_keys


# ── Tests: remove op ────────────────────────────────────────────────────────

class TestDbRemove:
    """Tests for xray_db_apply._remove (outbound + routing strip from DB)."""

    def test_remove_strips_outbound_and_rule(self, xui_db: Path, patch_file: Path, remove_patch_file: Path):
        """Remove should strip both the outbound and the routing rule."""
        # First apply
        patch = xray_db_apply._load_patch(patch_file)
        template, row_id = xray_db_apply._load_template(xui_db)
        xray_db_apply._apply(template, patch)
        xray_db_apply._save_template(xui_db, template, row_id)

        # Then remove
        rm_patch = xray_db_apply._load_patch(remove_patch_file)
        template2, row_id2 = xray_db_apply._load_template(xui_db)
        mutated = xray_db_apply._remove(template2, rm_patch)
        assert mutated is True
        xray_db_apply._save_template(xui_db, template2, row_id2)

        result = _read_template(xui_db)
        out_tags = [ob.get("tag") for ob in result["outbounds"]]
        assert "psiphon-out-US" not in out_tags

        rule_tags = [r.get("outboundTag") for r in result["routing"]["rules"]]
        assert "psiphon-out-US" not in rule_tags

    def test_remove_is_idempotent(self, xui_db: Path, remove_patch_file: Path):
        """Removing a non-existent binding should be a no-op."""
        rm_patch = xray_db_apply._load_patch(remove_patch_file)
        template, _ = xray_db_apply._load_template(xui_db)
        mutated = xray_db_apply._remove(template, rm_patch)
        assert mutated is False

    def test_remove_preserves_sibling_countries(self, xui_db: Path, tmp_path: Path):
        """Removing one country should not affect others."""
        # Apply US and DE
        for code, socks, public in [("US", 11001, 31001), ("DE", 11002, 31002)]:
            p = tmp_path / f"{code}-apply-test.json"
            p.write_text(json.dumps({
                "op": "apply", "country_code": code, "socks_port": socks,
                "public_port": public, "inbound_tag": f"in-{public}-tcp",
            }), encoding="utf-8")
            patch = xray_db_apply._load_patch(p)
            template, row_id = xray_db_apply._load_template(xui_db)
            xray_db_apply._apply(template, patch)
            xray_db_apply._save_template(xui_db, template, row_id)

        # Remove US only
        rm = tmp_path / "US-remove-test.json"
        rm.write_text(json.dumps({
            "op": "remove", "country_code": "US",
            "public_port": 31001, "inbound_tag": "in-31001-tcp",
        }), encoding="utf-8")
        rm_patch = xray_db_apply._load_patch(rm)
        template, row_id = xray_db_apply._load_template(xui_db)
        xray_db_apply._remove(template, rm_patch)
        xray_db_apply._save_template(xui_db, template, row_id)

        result = _read_template(xui_db)
        out_tags = {ob.get("tag") for ob in result["outbounds"]}
        assert "psiphon-out-US" not in out_tags
        assert "psiphon-out-DE" in out_tags


# ── Tests: main / exit codes ────────────────────────────────────────────────

class TestDbMain:
    """Tests for xray_db_apply.main (exit codes, end-to-end)."""

    def test_main_apply_returns_0(self, xui_db: Path, patch_file: Path):
        """A successful apply should return exit code 0."""
        rc = xray_db_apply.main(["xray_db_apply.py", str(patch_file)])
        assert rc == xray_db_apply.EXIT_OK_MUTATED  # 0

    def test_main_idempotent_returns_10(self, xui_db: Path, patch_file: Path):
        """A no-op apply should return exit code 10."""
        # First apply
        xray_db_apply.main(["xray_db_apply.py", str(patch_file)])
        # Second apply — no-op. The patch file is still on disk because
        # main() deliberately does NOT unlink it (xray_apply.py does that,
        # and xray_applier.sh runs this helper first).
        rc = xray_db_apply.main(["xray_db_apply.py", str(patch_file)])
        assert rc == xray_db_apply.EXIT_OK_NO_OP  # 10

    def test_main_remove_returns_0(self, xui_db: Path, patch_file: Path, remove_patch_file: Path):
        """A successful remove should return exit code 0."""
        # Apply first
        xray_db_apply.main(["xray_db_apply.py", str(patch_file)])
        # Then remove
        rc = xray_db_apply.main(["xray_db_apply.py", str(remove_patch_file)])
        assert rc == xray_db_apply.EXIT_OK_MUTATED  # 0

    def test_main_bad_patch_returns_2(self, xui_db: Path, tmp_path: Path):
        """A malformed patch should return exit code 2."""
        bad = tmp_path / "bad.json"
        bad.write_text('{"op": "invalid"}', encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            xray_db_apply.main(["xray_db_apply.py", str(bad)])
        assert exc_info.value.code == xray_db_apply.EXIT_BAD_PATCH  # 2

    def test_main_missing_db_returns_3(self, tmp_path: Path, patch_file: Path):
        """A missing DB file should return exit code 3."""
        old_env = os.environ.get("PSIPHON_XUI_DB_PATH")
        os.environ["PSIPHON_XUI_DB_PATH"] = str(tmp_path / "nonexistent.db")
        try:
            rc = xray_db_apply.main(["xray_db_apply.py", str(patch_file)])
            assert rc == xray_db_apply.EXIT_DB_IO  # 3
        finally:
            if old_env is not None:
                os.environ["PSIPHON_XUI_DB_PATH"] = old_env
            else:
                os.environ.pop("PSIPHON_XUI_DB_PATH", None)


# ── Tests: DB missing xrayTemplateConfig key ────────────────────────────────

class TestDbMissingKey:
    """Tests for the case where xrayTemplateConfig doesn't exist in the DB."""

    def test_creates_key_if_missing(self, tmp_path: Path):
        """If xrayTemplateConfig doesn't exist, the script should create it."""
        db_path = tmp_path / "x-ui.db"
        # Create DB with settings table but no xrayTemplateConfig row
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
        conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("other_key", "other_value"))
        conn.commit()
        conn.close()

        old_env = os.environ.get("PSIPHON_XUI_DB_PATH")
        os.environ["PSIPHON_XUI_DB_PATH"] = str(db_path)
        try:
            patch = tmp_path / "US-apply-test.json"
            patch.write_text(json.dumps({
                "op": "apply", "country_code": "US", "socks_port": 11001,
                "public_port": 31001, "inbound_tag": "in-31001-tcp",
            }), encoding="utf-8")

            rc = xray_db_apply.main(["xray_db_apply.py", str(patch)])
            assert rc == xray_db_apply.EXIT_OK_MUTATED

            result = _read_template(db_path)
            out_tags = [ob.get("tag") for ob in result["outbounds"]]
            assert "psiphon-out-US" in out_tags
        finally:
            if old_env is not None:
                os.environ["PSIPHON_XUI_DB_PATH"] = old_env
            else:
                os.environ.pop("PSIPHON_XUI_DB_PATH", None)


# ── Tests: subprocess (smoke test) ──────────────────────────────────────────

class TestDbSubprocess:
    """Smoke test: run the script as a subprocess (as the applier does)."""

    def test_script_runs_as_subprocess(self, xui_db: Path, patch_file: Path):
        """The script should be runnable as ``python3 xray_db_apply.py <patch>``."""
        script = _INSTALLER_DIR / "xray_db_apply.py"
        env = os.environ.copy()
        env["PSIPHON_XUI_DB_PATH"] = str(xui_db)
        result = subprocess.run(
            [sys.executable, str(script), str(patch_file)],
            capture_output=True, text=True, env=env,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"