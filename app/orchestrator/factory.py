"""Central backend selection with no implicit unsafe fallback."""

from pathlib import Path

from app.core.config import IsolationBackendName, Settings
from app.orchestrator.isolation import (
    BubblewrapBackend,
    IsolationBackend,
    UnsafeDevelopmentBackend,
)


def create_isolation_backend(
    settings: Settings, *, project_root: Path | None = None
) -> IsolationBackend:
    if settings.isolation_backend is IsolationBackendName.BUBBLEWRAP:
        return BubblewrapBackend(settings, project_root=project_root)
    if settings.isolation_backend is IsolationBackendName.UNSAFE_DEVELOPMENT:
        return UnsafeDevelopmentBackend(settings, project_root=project_root)
    raise AssertionError("validated isolation backend was not handled")
