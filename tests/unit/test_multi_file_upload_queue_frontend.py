"""Narrow regression guards for the multi-file upload queue.

There is no DOM/browser-JS test harness in this repository (see the icon/skip-link
regression tests for the established precedent). These are plain source/markup
assertions against app.js and dashboard.html — they guard the specific
architectural promises this feature makes (bounded, centralized concurrency;
an explicit queue cap; per-item failure isolation; an authentication-expiry
halt that still lets in-flight requests finish) rather than proving pixel- or
runtime-accurate behavior, which was verified manually in a real browser.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base
from tests.auth_helpers import authenticate_operator

_JS_PATH = Path("app/web/static/app.js")
_DASHBOARD_PATH = Path("app/web/templates/dashboard.html")
_TEMPLATES_DIR = Path("app/web/templates")


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'queue-frontend.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


def test_file_input_accepts_multiple_files_and_is_not_required() -> None:
    html = _DASHBOARD_PATH.read_text(encoding="utf-8")
    input_tag = re.search(r'<input\s+id="document"[^>]*>', html)
    assert input_tag is not None, "expected the #document file input"
    tag = input_tag.group(0)
    assert 'type="file"' in tag
    assert "multiple" in tag
    # `required` would block submitting the queue once a queued item has been
    # removed and the native input's own FileList is empty/stale.
    assert "required" not in tag


def test_upload_status_is_a_polite_live_region() -> None:
    html = _DASHBOARD_PATH.read_text(encoding="utf-8")
    assert '<p id="upload-status" class="hint" aria-live="polite"></p>' in html


def test_concurrency_and_queue_caps_are_centralized_constants() -> None:
    js = _JS_PATH.read_text(encoding="utf-8")
    assert re.search(r"const MAX_CONCURRENT_UPLOADS = 2;", js), (
        "expected one centralized MAX_CONCURRENT_UPLOADS constant, not a scattered magic number"
    )
    assert re.search(r"const MAX_QUEUE_FILES = 20;", js), (
        "expected one centralized MAX_QUEUE_FILES constant, not a scattered magic number"
    )
    # The concurrency constant must actually gate the scheduler loop.
    assert "activeCount < MAX_CONCURRENT_UPLOADS" in js
    # The queue cap must actually bound how many files get added.
    assert "MAX_QUEUE_FILES - queueItems.length" in js


def test_one_failed_item_does_not_stop_the_remaining_queue() -> None:
    js = _JS_PATH.read_text(encoding="utf-8")
    # Every item's fetch is wrapped so a single item's rejection/exception is
    # caught locally (never thrown out of runItem) and the scheduler always
    # re-arms itself in `.finally`, regardless of that item's outcome.
    run_item = re.search(r"async function runItem\(item\) \{.*?\n    \}\n", js, re.DOTALL)
    assert run_item is not None
    assert "try {" in run_item.group(0)
    assert "} catch {" in run_item.group(0)
    assert re.search(r"runItem\(next\)\.finally\(\(\) => \{", js)
    assert "ensureWorkers();" in js


def test_authentication_expiry_halts_new_work_but_not_in_flight_requests() -> None:
    js = _JS_PATH.read_text(encoding="utf-8")
    assert "response.status === 401" in js
    assert "authBlocked = true;" in js
    assert "skipRemainingQueuedItems(" in js
    # Only items still in the QUEUED state are converted to skipped — an item
    # that is already `active` (its fetch already in flight) is left alone and
    # allowed to resolve independently.
    skip_fn = re.search(
        r"function skipRemainingQueuedItems\(message\) \{.*?\n    \}\n", js, re.DOTALL
    )
    assert skip_fn is not None
    assert "item.state === 'queued'" in skip_fn.group(0)
    # The scheduler must stop pulling new work once blocked.
    assert "while (!authBlocked && activeCount < MAX_CONCURRENT_UPLOADS)" in js


def test_terminal_decisions_reuse_the_existing_accessible_badge_component() -> None:
    js = _JS_PATH.read_text(encoding="utf-8")
    assert "const DECISION_STATES = new Set(['allow', 'review', 'quarantine', 'block']);" in js
    assert "badge badge-${item.state}" in js


def test_view_scan_link_targets_the_real_scan_detail_route() -> None:
    js = _JS_PATH.read_text(encoding="utf-8")
    assert "/app/scans/${encodeURIComponent(item.scanId)}" in js


def test_error_text_is_never_a_raw_server_traceback() -> None:
    js = _JS_PATH.read_text(encoding="utf-8")
    assert "traceback" not in js.lower()
    assert "stack" not in js.lower()


def test_no_inline_style_or_event_handler_attributes_in_dashboard() -> None:
    html = _DASHBOARD_PATH.read_text(encoding="utf-8")
    assert 'style="' not in html
    assert not re.search(r"\bon\w+=", html)


def test_no_inline_style_or_event_handler_attributes_in_any_template() -> None:
    for template in _TEMPLATES_DIR.rglob("*.html"):
        text = template.read_text(encoding="utf-8")
        assert 'style="' not in text, f"inline style found in {template}"
        assert not re.search(r"\bon\w+=", text), f"inline event handler found in {template}"


@pytest.mark.asyncio
async def test_dashboard_renders_the_queue_scaffold_and_reuses_csrf(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        dashboard = await client.get("/app")

    assert 'id="upload-form"' in dashboard.text
    assert f'data-csrf-token="{csrf}"' in dashboard.text
    assert 'id="upload-drop-zone"' in dashboard.text
    assert 'id="upload-queue"' in dashboard.text
    assert 'id="upload-start"' in dashboard.text
    assert "content-security-policy" in dashboard.headers
    assert "unsafe-inline" not in dashboard.headers["content-security-policy"]
