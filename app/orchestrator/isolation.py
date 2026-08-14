"""Isolation boundary implementations with fail-closed bounded process handling."""

from __future__ import annotations

import json
import logging
import os
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from app.core.config import AppEnvironment, Settings
from app.core.logging import log_event
from app.orchestrator.contract import WorkerRequest

logger = logging.getLogger(__name__)

_SANDBOX_INPUT_PATH = "/input/document"
_SANDBOX_OUTPUT_PATH = "/output/document"
_SANDBOX_RUNTIME_ROOT = "/opt/docguard-runtime"


class IsolationError(RuntimeError):
    """Base class for isolation backend failures."""


class IsolationUnavailable(IsolationError):
    """Raised when a real isolation backend cannot establish its boundary."""


@dataclass(frozen=True, slots=True)
class WorkerExecution:
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    output_limit_exceeded: bool = False


@dataclass(frozen=True, slots=True)
class SandboxSelfTest:
    process_executes: bool = False
    network_blocked: bool = False
    parent_file_hidden: bool = False
    parent_environment_hidden: bool = False
    outside_write_blocked: bool = False
    input_readable: bool = False
    input_read_only: bool = False
    work_writable: bool = False
    trusted_paths_hidden: bool = False
    capabilities_dropped: bool = False
    resource_limits_applied: bool = False
    worker_dependencies_load: bool = False
    renderer_runtime_loads: bool = False
    archive_runtime_loads: bool = False
    yara_rule_pack_qualifies: bool = False
    yara_rules_read_only: bool = False
    timeout_enforced: bool = False
    output_limit_enforced: bool = False
    sanitize_output_writable: bool = False
    sanitize_output_contained: bool = False
    diagnostics: str = ""

    @property
    def passed(self) -> bool:
        return all(
            (
                self.process_executes,
                self.network_blocked,
                self.parent_file_hidden,
                self.parent_environment_hidden,
                self.outside_write_blocked,
                self.input_readable,
                self.input_read_only,
                self.work_writable,
                self.trusted_paths_hidden,
                self.capabilities_dropped,
                self.resource_limits_applied,
                self.worker_dependencies_load,
                self.renderer_runtime_loads,
                self.archive_runtime_loads,
                self.yara_rule_pack_qualifies,
                self.yara_rules_read_only,
                self.timeout_enforced,
                self.output_limit_enforced,
                self.sanitize_output_writable,
                self.sanitize_output_contained,
            )
        )


class IsolationBackend(Protocol):
    """Execution interface; implementations own all untrusted process handling."""

    @property
    def ready(self) -> bool: ...

    def execute(self, request: WorkerRequest, timeout_seconds: float) -> WorkerExecution: ...

    def sanitize(
        self, request: WorkerRequest, output_path: Path, timeout_seconds: float
    ) -> WorkerExecution: ...


class BubblewrapBackend:
    """Per-job systemd cgroup, rlimit, namespace, and filesystem isolation."""

    def __init__(self, settings: Settings, *, project_root: Path | None = None) -> None:
        self._settings = settings
        self._project_root = (project_root or Path.cwd()).resolve()
        self._worker_source = self._resolve_config_path(settings.worker_source_root)
        self._contract_source = self._resolve_config_path(settings.worker_contract_root)
        self._dependency_source = self._resolve_config_path(settings.worker_dependency_root)
        self._cache_lock = threading.Lock()
        self._cached_self_test: tuple[float, SandboxSelfTest] | None = None

    @property
    def ready(self) -> bool:
        return self.self_test().passed

    def execute(self, request: WorkerRequest, timeout_seconds: float) -> WorkerExecution:
        self._require_prerequisites()
        sandbox_request = request.model_copy(update={"sample_path": _SANDBOX_INPUT_PATH})
        return self._execute_entrypoint(
            sample_path=Path(request.sample_path),
            request_json=sandbox_request.to_json(),
            entrypoint="main.py",
            timeout_seconds=timeout_seconds,
            stdout_limit=self._settings.worker_stdout_max_bytes,
            stderr_limit=self._settings.worker_stderr_max_bytes,
        )

    def sanitize(
        self, request: WorkerRequest, output_path: Path, timeout_seconds: float
    ) -> WorkerExecution:
        self._require_prerequisites()
        sandbox_request = request.model_copy(update={"sample_path": _SANDBOX_INPUT_PATH})
        return self._execute_entrypoint(
            sample_path=Path(request.sample_path),
            output_path=output_path,
            request_json=sandbox_request.to_json(),
            entrypoint="main.py",
            timeout_seconds=timeout_seconds,
            stdout_limit=self._settings.worker_stdout_max_bytes,
            stderr_limit=self._settings.worker_stderr_max_bytes,
        )

    def self_test(self, *, force: bool = False) -> SandboxSelfTest:
        now = time.monotonic()
        with self._cache_lock:
            if not force and self._cached_self_test is not None:
                cached_at, result = self._cached_self_test
                if now - cached_at <= self._settings.isolation_self_test_cache_seconds:
                    return result
            result = self._run_self_test()
            self._cached_self_test = (now, result)
            return result

    def _run_self_test(self) -> SandboxSelfTest:
        try:
            self._require_prerequisites()
        except IsolationUnavailable as exc:
            return SandboxSelfTest(diagnostics=str(exc))

        with tempfile.TemporaryDirectory(prefix="docguard-isolation-self-test-") as directory:
            root = Path(directory)
            input_path = root / "input"
            sentinel_path = root / "parent-only-sentinel"
            input_path.write_bytes(b"docguard-self-test")
            input_path.chmod(0o400)
            sentinel_path.write_text("parent-only", encoding="utf-8")
            boundary_request = json.dumps(
                {
                    "mode": "boundary",
                    "parent_sentinel_path": str(sentinel_path),
                    "project_path": str(self._project_root),
                    "memory_limit": self._settings.worker_memory_limit_bytes,
                    "open_files_limit": self._settings.worker_open_files_limit,
                    "file_size_limit": self._settings.worker_file_size_limit_bytes,
                    "cpu_limit": self._settings.worker_cpu_limit_seconds,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            boundary = self._execute_entrypoint(
                sample_path=input_path,
                request_json=boundary_request,
                entrypoint="probe.py",
                timeout_seconds=min(3.0, self._settings.worker_timeout_seconds),
                stdout_limit=self._settings.worker_stdout_max_bytes,
                stderr_limit=self._settings.worker_stderr_max_bytes,
            )
            values: dict[str, object] = {}
            if boundary.exit_code == 0 and not boundary.timed_out:
                try:
                    decoded = json.loads(boundary.stdout)
                    if isinstance(decoded, dict):
                        values = decoded
                except json.JSONDecodeError:
                    values = {}

            timeout_probe = self._execute_entrypoint(
                sample_path=input_path,
                request_json='{"mode":"sleep"}',
                entrypoint="probe.py",
                timeout_seconds=0.4,
                stdout_limit=self._settings.worker_stdout_max_bytes,
                stderr_limit=self._settings.worker_stderr_max_bytes,
            )
            stdout_probe = self._execute_entrypoint(
                sample_path=input_path,
                request_json=json.dumps(
                    {
                        "mode": "output",
                        "stream": "stdout",
                        "bytes": self._settings.worker_stdout_max_bytes * 4,
                    }
                ),
                entrypoint="probe.py",
                timeout_seconds=min(3.0, self._settings.worker_timeout_seconds),
                stdout_limit=self._settings.worker_stdout_max_bytes,
                stderr_limit=self._settings.worker_stderr_max_bytes,
            )
            stderr_probe = self._execute_entrypoint(
                sample_path=input_path,
                request_json=json.dumps(
                    {
                        "mode": "output",
                        "stream": "stderr",
                        "bytes": self._settings.worker_stderr_max_bytes * 4,
                    }
                ),
                entrypoint="probe.py",
                timeout_seconds=min(3.0, self._settings.worker_timeout_seconds),
                stdout_limit=self._settings.worker_stdout_max_bytes,
                stderr_limit=self._settings.worker_stderr_max_bytes,
            )
            output_path = root / "single-output"
            output_path.touch(mode=0o600)
            output_probe = self._execute_entrypoint(
                sample_path=input_path,
                output_path=output_path,
                request_json=json.dumps(
                    {
                        "mode": "cdr_boundary",
                        "memory_limit": self._settings.worker_memory_limit_bytes,
                        "open_files_limit": self._settings.worker_open_files_limit,
                        "file_size_limit": self._settings.worker_file_size_limit_bytes,
                        "cpu_limit": self._settings.worker_cpu_limit_seconds,
                        "parent_sentinel_path": str(sentinel_path),
                        "project_path": str(self._project_root),
                        "sanitized_path": str(self._settings.storage_root / "sanitized"),
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                entrypoint="probe.py",
                timeout_seconds=min(3.0, self._settings.worker_timeout_seconds),
                stdout_limit=self._settings.worker_stdout_max_bytes,
                stderr_limit=self._settings.worker_stderr_max_bytes,
            )
            output_values: dict[str, object] = {}
            if output_probe.exit_code == 0 and not output_probe.timed_out:
                try:
                    decoded_output = json.loads(output_probe.stdout)
                    if isinstance(decoded_output, dict):
                        output_values = decoded_output
                except json.JSONDecodeError:
                    output_values = {}
            output_was_written = output_path.read_bytes() == b"cdr-output-ok"

        return SandboxSelfTest(
            process_executes=values.get("process_executes") is True,
            network_blocked=values.get("network_blocked") is True,
            parent_file_hidden=values.get("parent_file_hidden") is True,
            parent_environment_hidden=values.get("parent_environment_hidden") is True,
            outside_write_blocked=values.get("outside_write_blocked") is True,
            input_readable=values.get("input_readable") is True,
            input_read_only=values.get("input_read_only") is True,
            work_writable=values.get("work_writable") is True,
            trusted_paths_hidden=values.get("trusted_paths_hidden") is True,
            capabilities_dropped=values.get("capabilities_dropped") is True,
            resource_limits_applied=values.get("resource_limits_applied") is True,
            worker_dependencies_load=values.get("worker_dependencies_load") is True,
            renderer_runtime_loads=values.get("renderer_runtime_loads") is True,
            archive_runtime_loads=values.get("archive_runtime_loads") is True,
            yara_rule_pack_qualifies=values.get("yara_rule_pack_qualifies") is True,
            yara_rules_read_only=values.get("yara_rules_read_only") is True,
            timeout_enforced=timeout_probe.timed_out,
            output_limit_enforced=(
                stdout_probe.output_limit_exceeded and stderr_probe.output_limit_exceeded
            ),
            sanitize_output_writable=(
                output_values.get("output_writable") is True and output_was_written
            ),
            sanitize_output_contained=output_values.get("output_contained") is True,
            diagnostics=boundary.stderr[:1_024],
        )

    def _execute_entrypoint(
        self,
        *,
        sample_path: Path,
        output_path: Path | None = None,
        request_json: str,
        entrypoint: str,
        timeout_seconds: float,
        stdout_limit: int,
        stderr_limit: int,
    ) -> WorkerExecution:
        input_fd = _open_regular_file_read_only(sample_path)
        output_fd = _open_regular_file_read_write(output_path) if output_path is not None else None
        try:
            return _run_bounded_process(
                self._build_command(input_fd=input_fd, output_fd=output_fd, entrypoint=entrypoint),
                stdin_bytes=request_json.encode("utf-8"),
                timeout_seconds=timeout_seconds,
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
                environment=_launcher_environment(),
                pass_fds=(input_fd,) if output_fd is None else (input_fd, output_fd),
            )
        finally:
            os.close(input_fd)
            if output_fd is not None:
                os.close(output_fd)

    def _build_command(self, *, input_fd: int, output_fd: int | None, entrypoint: str) -> list[str]:
        settings = self._settings
        command = [
            str(settings.systemd_run_path),
            "--user",
            "--scope",
            "--collect",
            "--quiet",
            f"--property=MemoryMax={settings.worker_memory_limit_bytes}",
            "--property=MemorySwapMax=0",
            f"--property=TasksMax={settings.worker_tasks_limit}",
            "--property=CPUQuota=100%",
            "--",
            str(settings.prlimit_path),
            f"--as={settings.worker_memory_limit_bytes}",
            f"--nofile={settings.worker_open_files_limit}",
            f"--fsize={settings.worker_file_size_limit_bytes}",
            f"--cpu={settings.worker_cpu_limit_seconds}",
            "--core=0",
            "--",
            str(settings.bubblewrap_path),
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--assert-userns-disabled",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
            "--setenv",
            "PYTHONUTF8",
            "1",
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--setenv",
            "PYTHONPATH",
            f"{_SANDBOX_RUNTIME_ROOT}:{_SANDBOX_RUNTIME_ROOT}/dependencies",
            "--hostname",
            "docguard-worker",
            "--cap-drop",
            "ALL",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind-try",
            "/lib64",
            "/lib64",
            "--dir",
            "/etc",
            "--ro-bind-try",
            "/etc/ld.so.cache",
            "/etc/ld.so.cache",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--dir",
            "/opt",
            "--dir",
            _SANDBOX_RUNTIME_ROOT,
            "--ro-bind",
            str(self._worker_source),
            f"{_SANDBOX_RUNTIME_ROOT}/worker",
            "--ro-bind",
            str(self._contract_source),
            f"{_SANDBOX_RUNTIME_ROOT}/docguard_contract",
            "--ro-bind",
            str(self._dependency_source),
            f"{_SANDBOX_RUNTIME_ROOT}/dependencies",
            "--dir",
            "/input",
            "--ro-bind-fd",
            str(input_fd),
            _SANDBOX_INPUT_PATH,
        ]
        if output_fd is not None:
            command.extend(
                [
                    "--dir",
                    "/output",
                    "--bind-fd",
                    str(output_fd),
                    _SANDBOX_OUTPUT_PATH,
                ]
            )
        command.extend(
            [
                "--size",
                str(settings.worker_tmpfs_bytes),
                "--tmpfs",
                "/work",
                "--chmod",
                "0700",
                "/work",
                "--size",
                str(settings.worker_tmpfs_bytes),
                "--tmpfs",
                "/tmp",  # noqa: S108 - isolated in-memory sandbox path
                "--chmod",
                "01777",
                "/tmp",  # noqa: S108 - isolated in-memory sandbox path
                "--remount-ro",
                "/",
                "--chdir",
                "/work",
                "--",
                "/usr/bin/python3",
                "-S",
                f"{_SANDBOX_RUNTIME_ROOT}/worker/{entrypoint}",
            ]
        )
        return command

    def _resolve_config_path(self, path: Path) -> Path:
        return (path if path.is_absolute() else self._project_root / path).resolve()

    def _require_prerequisites(self) -> None:
        launchers = (
            self._settings.bubblewrap_path,
            self._settings.prlimit_path,
            self._settings.systemd_run_path,
        )
        if any(not path.is_file() or not os.access(path, os.X_OK) for path in launchers):
            raise IsolationUnavailable("required isolation launcher executable is unavailable")
        if not self._worker_source.is_dir() or not self._contract_source.is_dir():
            raise IsolationUnavailable("worker runtime source is unavailable")
        if (
            not self._dependency_source.is_dir()
            or not (self._dependency_source / "pikepdf" / "__init__.py").is_file()
            or not (self._dependency_source / "oletools" / "olevba.py").is_file()
            or not (self._dependency_source / "olefile" / "__init__.py").is_file()
            or not (self._dependency_source / "defusedxml" / "__init__.py").is_file()
            or not any(self._dependency_source.glob("yara*.so"))
            or not (self._dependency_source / "pymupdf" / "__init__.py").is_file()
        ):
            raise IsolationUnavailable("worker parser artifact is unavailable")


class UnsafeDevelopmentBackend:
    """Unisolated fixture runner; explicit, bounded, scrubbed, and never production."""

    def __init__(self, settings: Settings, *, project_root: Path | None = None) -> None:
        if settings.env is AppEnvironment.PRODUCTION:
            raise IsolationUnavailable("unsafe development backend is forbidden in production")
        if not settings.allow_unsafe_development_backend:
            raise IsolationUnavailable("unsafe development backend requires explicit opt-in")
        self._settings = settings
        self._project_root = (project_root or Path.cwd()).resolve()
        dependency_root = settings.worker_dependency_root
        self._dependency_root = (
            dependency_root
            if dependency_root.is_absolute()
            else self._project_root / dependency_root
        ).resolve()
        log_event(
            logger,
            logging.CRITICAL,
            "UNSAFE_DEVELOPMENT_BACKEND_ENABLED",
            environment=settings.env.value,
            warning="UNISOLATED WORKER; GENERATED TEST FIXTURES ONLY",
        )

    @property
    def ready(self) -> bool:
        return True

    def execute(self, request: WorkerRequest, timeout_seconds: float) -> WorkerExecution:
        environment = {
            "PATH": "/usr/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONUTF8": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join((str(self._project_root), str(self._dependency_root))),
        }
        return _run_bounded_process(
            [sys.executable, "-S", "-m", "worker.main"],
            stdin_bytes=request.to_json().encode("utf-8"),
            timeout_seconds=timeout_seconds,
            stdout_limit=self._settings.worker_stdout_max_bytes,
            stderr_limit=self._settings.worker_stderr_max_bytes,
            environment=environment,
            cwd=self._project_root,
        )

    def sanitize(
        self, request: WorkerRequest, output_path: Path, timeout_seconds: float
    ) -> WorkerExecution:
        del request, output_path, timeout_seconds
        raise IsolationUnavailable("PDF CDR is unavailable through the unsafe development backend")


def _open_regular_file_read_only(path: Path) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise IsolationUnavailable("sample cannot be opened safely") from exc
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise IsolationUnavailable("sample is not a regular file")
    return descriptor


def _open_regular_file_read_write(path: Path) -> int:
    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise IsolationUnavailable("CDR output cannot be opened safely") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != 0:
        os.close(descriptor)
        raise IsolationUnavailable("CDR output must be an empty regular file")
    return descriptor


def _launcher_environment() -> dict[str, str]:
    runtime_directory = f"/run/user/{os.getuid()}"
    return {
        "PATH": "/usr/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "XDG_RUNTIME_DIR": runtime_directory,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_directory}/bus",
    }


def _run_bounded_process(
    command: list[str],
    *,
    stdin_bytes: bytes,
    timeout_seconds: float,
    stdout_limit: int,
    stderr_limit: int,
    environment: dict[str, str],
    cwd: Path | None = None,
    pass_fds: tuple[int, ...] = (),
) -> WorkerExecution:
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed launcher and argument vector
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            pass_fds=pass_fds,
        )
    except OSError as exc:
        raise IsolationUnavailable("worker launcher could not start") from exc

    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        process.stdin.write(stdin_bytes)
        process.stdin.close()
    except BrokenPipeError:
        pass

    stdout = bytearray()
    stderr = bytearray()
    output_limit_exceeded = False
    timed_out = False
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout.fileno(): (process.stdout, stdout, stdout_limit),
        process.stderr.fileno(): (process.stderr, stderr, stderr_limit),
    }
    for file_number, (stream, _, _) in streams.items():
        os.set_blocking(file_number, False)
        selector.register(stream, selectors.EVENT_READ, data=file_number)

    deadline = time.monotonic() + timeout_seconds
    while selector.get_map():
        if time.monotonic() >= deadline and not timed_out:
            timed_out = True
            _kill_process_group(process)
        events = selector.select(timeout=0.05)
        for key, _ in events:
            file_number = int(key.data)
            stream, target, limit = streams[file_number]
            try:
                chunk = os.read(file_number, 65_536)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(stream)
                stream.close()
                continue
            remaining = max(0, limit - len(target))
            target.extend(chunk[:remaining])
            if len(chunk) > remaining and not output_limit_exceeded:
                output_limit_exceeded = True
                _kill_process_group(process)
        if (timed_out or output_limit_exceeded) and process.poll() is not None and not events:
            for key in list(selector.get_map().values()):
                stream = streams[int(key.data)][0]
                selector.unregister(stream)
                stream.close()

    try:
        exit_code = process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        exit_code = process.wait(timeout=1.0)
    finally:
        selector.close()

    return WorkerExecution(
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
        exit_code=exit_code,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
    )


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
