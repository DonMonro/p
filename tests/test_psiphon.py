"""pytest coverage for :mod:`panel.psiphon` (Phase 4 — step 4j).

Covers the three concerns in ``panel/psiphon/__init__.py``:

* :func:`render_config` — schema, upstream constants, validation.
* :func:`write_config` — file round-trip + ``config_dir`` override.
* :func:`start_unit` / :func:`stop_unit` / :func:`restart_unit` /
  :func:`is_unit_active` — thin wrappers around ``_systemctl``; we drive
  them by monkey-patching ``subprocess.run`` (the only external call).
* :func:`health_probe` — exercised through a fake ``_sock_factory`` that
  returns a stub socket supporting ``settimeout`` / ``connect`` / ``sendall``
  / ``recv`` / ``close``.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import FrozenInstanceError

import pytest

from panel.psiphon import (
    PSIPHON_PROPAGATION_CHANNEL_ID,
    PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY,
    PSIPHON_REMOTE_SERVER_LIST_URLS,
    HealthProbeResult,
    PsiphonUnitError,
    _unit_name,
    health_probe,
    is_unit_active,
    render_config,
    restart_unit,
    start_unit,
    stop_unit,
    write_config,
)


# ---------------------------------------------------------------------------
# render_config
# ---------------------------------------------------------------------------
class TestRenderConfig:
    def test_returns_six_required_keys(self):
        cfg = render_config("US", 1080)
        assert set(cfg) == {
            "PropagationChannelId",
            "RemoteServerListURLs",
            "RemoteServerListSignaturePublicKey",
            "EgressRegion",
            "LocalSocksProxyPort",
            "DisableLocalHTTPProxy",
        }

    def test_prescribes_constants(self):
        cfg = render_config("US", 1080)
        assert cfg["PropagationChannelId"] == PSIPHON_PROPAGATION_CHANNEL_ID
        assert cfg["RemoteServerListURLs"] == list(PSIPHON_REMOTE_SERVER_LIST_URLS)
        assert (
            cfg["RemoteServerListSignaturePublicKey"]
            == PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY
        )

    def test_egress_region_uppercased_and_port_int(self):
        cfg = render_config("de", 11080)
        assert cfg["EgressRegion"] == "DE"
        assert cfg["LocalSocksProxyPort"] == 11080
        assert isinstance(cfg["LocalSocksProxyPort"], int)

    def test_disable_local_http_proxy_true(self):
        # Spec: tunnels only expose SOCKS5; HTTP proxy is disabled.
        assert render_config("US", 1080)["DisableLocalHTTPProxy"] is True

    @pytest.mark.parametrize(
        ("code", "socks_port"),
        [
            ("US", 80),  # port below 1024
            ("US", 70000),  # port above 65535
            ("US1", 1080),  # non-alpha code
            ("U", 1080),  # too short
            ("USA", 1080),  # too long
            ("", 1080),  # empty
        ],
    )
    def test_invalid_inputs_raise_value_error(self, code, socks_port):
        with pytest.raises(ValueError):
            render_config(code, socks_port)

    def test_remote_server_list_is_a_list_copy(self):
        # render_config must NOT return the module-level tuple — mutating the
        # dict should not affect the upstream constant.
        cfg = render_config("US", 1080)
        assert isinstance(cfg["RemoteServerListURLs"], list)
        cfg["RemoteServerListURLs"].append("https://example.invalid/")
        assert len(PSIPHON_REMOTE_SERVER_LIST_URLS) == 1


# ---------------------------------------------------------------------------
# write_config
# ---------------------------------------------------------------------------
class TestWriteConfig:
    def test_writes_parsable_json(self, tmp_path):
        path = write_config("US", 11080, config_dir=tmp_path)
        assert path == tmp_path / "US.json"
        assert path.is_file()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["EgressRegion"] == "US"
        assert data["LocalSocksProxyPort"] == 11080

    def test_country_code_uppercased_in_filename(self, tmp_path):
        path = write_config("de", 11081, config_dir=tmp_path)
        assert path.name == "DE.json"

    def test_creates_config_dir_if_missing(self, tmp_path):
        nested = tmp_path / "deeper" / "and_deeper"
        path = write_config("JP", 11082, config_dir=nested)
        assert path.is_file()
        assert path == nested / "JP.json"

    def test_overwrites_existing_file(self, tmp_path):
        write_config("US", 11083, config_dir=tmp_path)
        # Second write with a different port must replace the file's content.
        path = write_config("US", 11084, config_dir=tmp_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["LocalSocksProxyPort"] == 11084


# ---------------------------------------------------------------------------
# _unit_name
# ---------------------------------------------------------------------------
def test_unit_name_format():
    assert _unit_name("US") == "psiphon-tunnel@US.service"
    assert _unit_name(" de ") == "psiphon-tunnel@DE.service"


def test_unit_name_rejects_invalid_codes():
    for bad in ("", "U", "USA", "1A"):
        with pytest.raises(ValueError):
            _unit_name(bad)


# ---------------------------------------------------------------------------
# systemctl wrappers — drive `subprocess.run` via monkeypatch.
# ---------------------------------------------------------------------------
class _FakeProc:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_systemctl(
    monkeypatch, *, returncode: int = 0, stdout: str = "", stderr: str = ""
) -> list[list[str]]:
    """Patch ``subprocess.run`` to capture the argv and return a fake proc.

    Returns the list of argv lists captured so tests can assert the exact
    systemctl invocation.
    """
    calls: list[list[str]] = []

    def _fake_run(argv, **kwargs):  # noqa: ANN001  test-only stub
        calls.append(list(argv))
        return _FakeProc(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(subprocess, "run", _fake_run)
    return calls


class TestStartStopRestart:
    def test_start_invokes_systemctl_start_with_unit_name(self, monkeypatch):
        calls = _patch_systemctl(monkeypatch, returncode=0)
        start_unit("US")
        assert calls == [["systemctl", "start", "psiphon-tunnel@US.service"]]

    def test_stop_invokes_systemctl_stop(self, monkeypatch):
        calls = _patch_systemctl(monkeypatch, returncode=0)
        stop_unit("DE")
        assert calls == [["systemctl", "stop", "psiphon-tunnel@DE.service"]]

    def test_restart_invokes_systemctl_restart(self, monkeypatch):
        calls = _patch_systemctl(monkeypatch, returncode=0)
        restart_unit("JP")
        assert calls == [["systemctl", "restart", "psiphon-tunnel@JP.service"]]

    def test_nonzero_exit_raises_psiphon_unit_error(self, monkeypatch):
        _patch_systemctl(monkeypatch, returncode=1, stderr="unit not loaded")
        with pytest.raises(PsiphonUnitError, match="exit 1"):
            start_unit("US")

    def test_systemctl_missing_returns_psiphon_unit_error(self, monkeypatch):
        def _raise_filenotfound(*a, **kw):  # noqa: ANN001  test stub
            raise FileNotFoundError("systemctl")

        monkeypatch.setattr(subprocess, "run", _raise_filenotfound)
        with pytest.raises(PsiphonUnitError, match="systemctl not found"):
            start_unit("US")

    def test_timeout_raises_psiphon_unit_error(self, monkeypatch):
        def _raise_timeout(*a, **kw):  # noqa: ANN001  test stub
            raise subprocess.TimeoutExpired(cmd="systemctl", timeout=15)

        monkeypatch.setattr(subprocess, "run", _raise_timeout)
        with pytest.raises(PsiphonUnitError, match="timed out"):
            stop_unit("DE")


class TestIsActive:
    def test_active_unit_returns_true(self, monkeypatch):
        _patch_systemctl(monkeypatch, returncode=0, stdout="active\n")
        assert is_unit_active("US") is True

    def test_inactive_returns_false_without_raising(self, monkeypatch):
        # `systemctl is-active` returns 3 when the unit is inactive — our
        # is_unit_active must swallow that and return False.
        _patch_systemctl(monkeypatch, returncode=3, stdout="inactive\n")
        assert is_unit_active("DE") is False

    def test_failed_unit_returns_false(self, monkeypatch):
        _patch_systemctl(monkeypatch, returncode=3, stdout="failed\n")
        assert is_unit_active("JP") is False


# ---------------------------------------------------------------------------
# health_probe — inject a fake socket via `_sock_factory`.
# ---------------------------------------------------------------------------
class _FakeSocket:
    """Minimal `socket.socket()`-shaped stub for SOCKS5 health-probe tests."""

    def __init__(
        self,
        *,
        recv_payload: bytes = b"\x05\x00",
        connect_raises: type[Exception] | None = None,
        sendall_raises: type[Exception] | None = None,
        recv_raises: type[Exception] | None = None,
    ) -> None:
        self._recv_payload = recv_payload
        self._connect_raises = connect_raises
        self._sendall_raises = sendall_raises
        self._recv_raises = recv_raises
        self.closed = False
        self.connect_calls: list[tuple[str, int]] = []
        self.sendall_calls: list[bytes] = []
        self.timeout: float | None = None

    def settimeout(self, t: float) -> None:
        self.timeout = t

    def connect(self, addr: tuple[str, int]) -> None:
        if self._connect_raises is not None:
            raise self._connect_raises(f"connect refused: {addr}")
        self.connect_calls.append(addr)

    def sendall(self, data: bytes) -> None:
        if self._sendall_raises is not None:
            raise self._sendall_raises("sendall failed")
        self.sendall_calls.append(data)

    def recv(self, n: int) -> bytes:
        if self._recv_raises is not None:
            raise self._recv_raises("recv failed")
        return self._recv_payload[:n]

    def close(self) -> None:
        self.closed = True


class TestHealthProbe:
    def test_healthy_describes_selected_method(self):
        sock = _FakeSocket(recv_payload=b"\x05\x00")
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result is not None
        assert result.healthy is True
        assert "method 0x0" in result.detail.lower()

    def test_sends_socks5_greeting(self):
        sock = _FakeSocket(recv_payload=b"\x05\x00")
        health_probe(11080, _sock_factory=lambda: sock)
        assert sock.sendall_calls == [bytes([0x05, 0x01, 0x00])]
        assert sock.connect_calls == [("127.0.0.1", 11080)]

    def test_connect_refused_is_unhealthy(self):
        sock = _FakeSocket(connect_raises=ConnectionRefusedError)
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result.healthy is False
        assert "connect" in result.detail.lower()
        assert sock.closed is True

    def test_sendall_failure_is_unhealthy(self):
        sock = _FakeSocket(sendall_raises=OSError)
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result.healthy is False
        assert "send" in result.detail.lower()

    def test_recv_failure_is_unhealthy(self):
        sock = _FakeSocket(recv_raises=OSError)
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result.healthy is False
        assert "recv" in result.detail.lower()

    def test_short_greeting_is_unhealthy(self):
        sock = _FakeSocket(recv_payload=b"\x05")  # only 1 byte back
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result.healthy is False
        assert "short" in result.detail.lower()

    def test_wrong_socks_version_unhealthy(self):
        # VER byte != 0x05 → not SOCKS5.
        sock = _FakeSocket(recv_payload=b"\x04\x00")
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result.healthy is False
        assert "version" in result.detail.lower()

    def test_no_acceptable_methods_unhealthy(self):
        # selected method == 0xFF → listener rejected everything we offered.
        sock = _FakeSocket(recv_payload=b"\x05\xff")
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result.healthy is False
        assert "refused" in result.detail.lower()

    def test_invalid_port_returns_unhealthy_without_opening_socket(self):
        # Port outside [1024, 65535] short-circuits before opening a socket.
        opened = {"yes": False}

        def _factory():  # noqa: ANN202
            opened["yes"] = True
            return _FakeSocket()

        result = health_probe(80, _sock_factory=_factory)  # 80 < 1024
        assert result.healthy is False
        assert "out of range" in result.detail.lower()
        assert opened["yes"] is False, "factory must not be called for invalid ports"

    def test_socket_closed_even_on_failure(self):
        # The finally-branch's contextlib.suppress must close the socket.
        sock = _FakeSocket(connect_raises=ConnectionRefusedError)
        health_probe(11080, _sock_factory=lambda: sock)
        assert sock.closed is True


# ---------------------------------------------------------------------------
# Extra coverage: HealthProbeResult dataclass shape (frozen + default detail).
# ---------------------------------------------------------------------------
def test_health_probe_result_is_frozen():
    r = HealthProbeResult(healthy=True, detail="ok")
    assert r.healthy is True
    assert r.detail == "ok"
    with pytest.raises(FrozenInstanceError):
        r.healthy = False  # type: ignore[misc]


def test_health_probe_result_default_detail_empty():
    r = HealthProbeResult(healthy=False)
    assert r.detail == ""
