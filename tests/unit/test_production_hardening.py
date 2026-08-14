from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest
from fastapi import Request
from pydantic import ValidationError

from app.auth.rate_limit import LoginRateLimiter
from app.core.abuse import AbuseRateLimiter
from app.core.config import AppEnvironment, Settings
from app.core.logging import JsonFormatter, log_event
from app.core.proxy import host_is_allowed, resolve_client_address
from app.core.qualification import qualify_filesystem, qualify_runtime
from app.storage.paths import StoragePaths


def _request(*, peer: str, headers: list[tuple[bytes, bytes]]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": headers,
            "client": (peer, 12345),
            "server": ("127.0.0.1", 8000),
        }
    )


def test_one_hop_proxy_resolution_ignores_untrusted_and_rejects_chains() -> None:
    settings = Settings(
        env=AppEnvironment.TEST,
        trusted_proxy_ips="127.0.0.1,::1",
        application_origin="http://docguard.example",
    )
    assert (
        resolve_client_address(
            _request(peer="192.0.2.10", headers=[(b"x-real-ip", b"198.51.100.9")]), settings
        )
        == "192.0.2.10"
    )
    assert (
        resolve_client_address(
            _request(peer="127.0.0.1", headers=[(b"x-real-ip", b"198.51.100.9")]), settings
        )
        == "198.51.100.9"
    )
    for malformed in (b"198.51.100.9, 203.0.113.8", b"not-an-ip", b" 198.51.100.9"):
        assert (
            resolve_client_address(
                _request(peer="127.0.0.1", headers=[(b"x-real-ip", malformed)]), settings
            )
            == "127.0.0.1"
        )
    duplicate = _request(
        peer="127.0.0.1",
        headers=[(b"x-real-ip", b"198.51.100.9"), (b"x-real-ip", b"203.0.113.8")],
    )
    assert resolve_client_address(duplicate, settings) == "127.0.0.1"


def test_production_host_and_proxy_configuration_are_strict() -> None:
    settings = Settings(application_origin="https://docguard.example:8443")
    assert host_is_allowed("docguard.example:8443", settings)
    for value in (
        "docguard.example",
        "evil.example",
        "docguard.example@evil.example",
        "docguard.example:443",
        "docguard.example\r\nX-Fake: yes",
    ):
        assert not host_is_allowed(value, settings)
    with pytest.raises(ValidationError, match="trusted proxy"):
        Settings(trusted_proxy_ips="127.0.0.1,not-an-ip")
    with pytest.raises(ValidationError, match="Origin"):
        Settings(require_origin_header=False)
    with pytest.raises(ValidationError, match="stale threshold"):
        Settings(reconciliation_stale_seconds=60)


def test_process_local_abuse_limiter_is_bounded_and_action_specific() -> None:
    limiter = AbuseRateLimiter()
    assert limiter.consume(action="upload", actor_id="a", limit=2, window_seconds=60)
    assert limiter.consume(action="upload", actor_id="a", limit=2, window_seconds=60)
    assert not limiter.consume(action="upload", actor_id="a", limit=2, window_seconds=60)
    assert limiter.consume(action="cdr", actor_id="a", limit=1, window_seconds=60)
    assert limiter.consume(action="upload", actor_id="b", limit=1, window_seconds=60)


def test_process_local_abuse_limiter_refuses_unbounded_bucket_growth() -> None:
    limiter = AbuseRateLimiter()
    for index in range(20_000):
        assert limiter.consume(
            action="read", actor_id=f"actor-{index}", limit=1, window_seconds=3_600
        )
    assert not limiter.consume(
        action="read", actor_id="one-too-many", limit=1, window_seconds=3_600
    )


def test_login_hour_and_username_buckets_are_independent_and_bounded() -> None:
    hourly = LoginRateLimiter(per_minute=100, per_hour=2)
    hourly.record_failure("192.0.2.1", "operator")
    hourly.record_failure("192.0.2.1", "operator")
    assert not hourly.check("192.0.2.1", "operator").allowed

    per_username = LoginRateLimiter(per_minute=1, per_hour=10)
    per_username.record_failure("192.0.2.1", "operator-a")
    assert not per_username.check("192.0.2.2", "operator-a").allowed
    assert per_username.check("192.0.2.2", "operator-b").allowed


def test_json_logs_encode_control_characters_as_one_record() -> None:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "event", (), None)
    record.structured_fields = {  # type: ignore[attr-defined]
        "attacker": 'line1\nline2\r\x1b[31m"quoted"\u202e'
    }
    rendered = JsonFormatter().format(record)
    assert len(rendered.splitlines()) == 1
    decoded = json.loads(rendered)
    assert decoded["attacker"].startswith("line1\nline2")


def test_filesystem_qualification_rejects_modes_symlinks_and_static_overlap(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    paths = StoragePaths(state)
    paths.initialize()
    database = tmp_path / "database" / "docguard.db"
    database.parent.mkdir(mode=0o700)
    database.touch(mode=0o600)
    worker_dependencies = tmp_path / "worker-deps"
    worker_dependencies.mkdir(mode=0o755)
    worker = tmp_path / "worker" / "rules"
    worker.mkdir(parents=True, mode=0o755)
    rule = worker / "docguard_v1.yar"
    rule.write_text("rule fixture { condition: true }", encoding="utf-8")
    rule.chmod(0o644)
    static = tmp_path / "static"
    static.mkdir(mode=0o755)
    settings = Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{database}",
        storage_root=state,
        worker_dependency_root=worker_dependencies,
        worker_source_root=tmp_path / "worker",
    )
    assert qualify_filesystem(settings, paths, static_root=static, project_root=tmp_path).passed

    state.chmod(0o755)
    assert not qualify_filesystem(settings, paths, static_root=static, project_root=tmp_path).passed
    state.chmod(0o700)
    assert not qualify_filesystem(
        settings, paths, static_root=paths.quarantine, project_root=tmp_path
    ).checks["static_private_separation"]
    linked = tmp_path / "linked-static"
    linked.symlink_to(static, target_is_directory=True)
    assert not qualify_filesystem(
        settings, paths, static_root=linked, project_root=tmp_path
    ).checks["static_assets_trusted"]


def test_storage_initialization_rejects_symlink_root(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(RuntimeError, match="symbolic links"):
        StoragePaths(linked).initialize()


def test_production_storage_initialization_rejects_existing_permissive_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "permissive"
    root.mkdir(mode=0o755)
    with pytest.raises(RuntimeError, match="permissions are unsafe"):
        StoragePaths(root).initialize(strict_existing_permissions=True)
    assert root.stat().st_mode & 0o777 == 0o755


def test_runtime_locks_are_exact_and_manifest_is_locally_qualified() -> None:
    report = qualify_runtime(Settings(), project_root=Path.cwd())
    assert report.checks["python_runtime"]
    assert report.checks["trusted_dependency_versions"]
    assert report.checks["worker_dependency_versions"]
    assert report.checks["trusted_lock_exact_pins"]
    assert report.checks["worker_lock_exact_pins"]


def test_log_helper_does_not_interpolate_control_fields(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("docguard-control-test")
    with caplog.at_level(logging.INFO):
        log_event(logger, logging.INFO, "security_event", value="x\ny\r\x1b")
    assert "security_event" in caplog.text
    assert os.linesep in caplog.text
