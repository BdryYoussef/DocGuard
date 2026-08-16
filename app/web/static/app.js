'use strict';

function setStatus(element, message, isError) {
  element.textContent = message;
  element.classList.toggle('status-error', Boolean(isError));
}

// Scroll reveal for below-the-fold content (see `.motion-reveal` /
// `.motion-stagger-reveal` in app.css). Marks an element visible the first time
// it crosses into the viewport, then stops observing it — a one-shot reveal, not
// a scroll-position animation. If IntersectionObserver is unavailable, elements
// stay in their default CSS state (visible), so this is a pure enhancement.
if ('IntersectionObserver' in window) {
  const revealTargets = document.querySelectorAll('.motion-reveal, .motion-stagger-reveal');
  if (revealTargets.length > 0) {
    const revealObserver = new IntersectionObserver(
      (entries, observer) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add('in-view');
          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.15, rootMargin: '0px 0px -40px 0px' },
    );
    revealTargets.forEach((target) => revealObserver.observe(target));
  }
}

// Bounded client-side upload queue. Each file is submitted independently to the
// unmodified single-file scan endpoint; the browser orchestrates the fan-out.
// Centralized so the concurrency/queue caps are never scattered magic numbers.
const MAX_CONCURRENT_UPLOADS = 2;
const MAX_QUEUE_FILES = 20;
const TERMINAL_STATES = new Set(['allow', 'review', 'quarantine', 'block', 'error', 'skipped']);
const DECISION_STATES = new Set(['allow', 'review', 'quarantine', 'block']);

function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unitIndex]}`;
}

const uploadForm = document.querySelector('#upload-form');
if (uploadForm instanceof HTMLFormElement) {
  const fileInput = uploadForm.querySelector('input[type="file"]');
  const dropZone = uploadForm.querySelector('#upload-drop-zone');
  const startButton = uploadForm.querySelector('#upload-start');
  const clearButton = uploadForm.querySelector('#upload-clear-completed');
  const queueList = uploadForm.querySelector('#upload-queue');
  const statusEl = uploadForm.querySelector('#upload-status');

  if (
    fileInput instanceof HTMLInputElement &&
    dropZone instanceof HTMLElement &&
    startButton instanceof HTMLButtonElement &&
    clearButton instanceof HTMLButtonElement &&
    queueList instanceof HTMLElement &&
    statusEl instanceof HTMLElement
  ) {
    let queueItems = [];
    let itemCounter = 0;
    let activeCount = 0;
    let authBlocked = false;

    const pendingCount = () => queueItems.filter((item) => item.state === 'queued').length;

    function updateControls() {
      startButton.disabled = authBlocked || pendingCount() === 0;
      clearButton.hidden = !queueItems.some((item) => TERMINAL_STATES.has(item.state));
      const atCapacity = queueItems.length >= MAX_QUEUE_FILES;
      fileInput.disabled = atCapacity || authBlocked;
      dropZone.setAttribute('aria-disabled', atCapacity || authBlocked ? 'true' : 'false');
    }

    function updateSummary() {
      if (queueItems.length === 0) {
        setStatus(statusEl, '', false);
        return;
      }
      if (authBlocked) {
        const remaining = pendingCount();
        setStatus(
          statusEl,
          remaining > 0
            ? `Sign-in is required to continue. ${remaining} document(s) were not analyzed.`
            : 'Sign-in is required to continue.',
          true,
        );
        return;
      }
      const terminal = queueItems.filter((item) => TERMINAL_STATES.has(item.state));
      if (activeCount > 0) {
        setStatus(statusEl, `Analyzing… ${terminal.length} of ${queueItems.length} complete.`, false);
        return;
      }
      if (terminal.length === queueItems.length) {
        const counts = { allow: 0, review: 0, quarantine: 0, block: 0, error: 0, skipped: 0 };
        terminal.forEach((item) => {
          counts[item.state] += 1;
        });
        const parts = [];
        if (counts.allow) parts.push(`${counts.allow} allowed`);
        if (counts.review) parts.push(`${counts.review} review`);
        if (counts.quarantine) parts.push(`${counts.quarantine} quarantined`);
        if (counts.block) parts.push(`${counts.block} blocked`);
        if (counts.error) parts.push(`${counts.error} failed`);
        if (counts.skipped) parts.push(`${counts.skipped} not started`);
        setStatus(statusEl, `${terminal.length} of ${queueItems.length} complete: ${parts.join(', ')}.`, false);
        return;
      }
      setStatus(statusEl, `${pendingCount()} document(s) ready to analyze.`, false);
    }

    function createQueueItemElement() {
      const li = document.createElement('li');
      li.className = 'upload-queue-item';
      const name = document.createElement('span');
      name.className = 'upload-queue-name';
      const size = document.createElement('span');
      size.className = 'upload-queue-size';
      const state = document.createElement('span');
      state.className = 'upload-queue-state';
      const actions = document.createElement('span');
      actions.className = 'upload-queue-actions';
      li.append(name, size, state, actions);
      return li;
    }

    function renderQueueItem(item) {
      const li = item.element;
      li.dataset.state = item.state;
      li.querySelector('.upload-queue-name').textContent = item.file.name;
      li.querySelector('.upload-queue-size').textContent = formatFileSize(item.file.size);
      const stateCell = li.querySelector('.upload-queue-state');
      const actionsCell = li.querySelector('.upload-queue-actions');
      stateCell.textContent = '';
      actionsCell.textContent = '';

      if (item.state === 'queued') {
        stateCell.textContent = 'Queued';
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'button button-quiet';
        remove.textContent = 'Remove';
        remove.addEventListener('click', () => removeQueueItem(item));
        actionsCell.appendChild(remove);
      } else if (item.state === 'active') {
        stateCell.textContent = 'Uploading and analyzing…';
      } else if (DECISION_STATES.has(item.state)) {
        const badge = document.createElement('span');
        badge.className = `badge badge-${item.state}`;
        badge.textContent = item.state.toUpperCase();
        stateCell.appendChild(badge);
        if (item.scanId) {
          const link = document.createElement('a');
          link.className = 'button button-quiet';
          link.href = `/app/scans/${encodeURIComponent(item.scanId)}`;
          link.textContent = 'View scan';
          actionsCell.appendChild(link);
        }
      } else if (item.state === 'error' || item.state === 'skipped') {
        const text = document.createElement('span');
        text.className = 'status-error';
        text.textContent = item.message || 'Upload failed.';
        stateCell.appendChild(text);
        if (item.retryable) {
          const retry = document.createElement('button');
          retry.type = 'button';
          retry.className = 'button button-quiet';
          retry.textContent = 'Retry';
          retry.addEventListener('click', () => retryQueueItem(item));
          actionsCell.appendChild(retry);
        }
      }
    }

    function removeQueueItem(item) {
      if (item.state !== 'queued') return;
      queueItems = queueItems.filter((candidate) => candidate !== item);
      item.element.remove();
      updateControls();
      updateSummary();
    }

    function retryQueueItem(item) {
      if (item.state !== 'error' || !item.retryable) return;
      item.state = 'queued';
      item.message = null;
      item.retryable = false;
      renderQueueItem(item);
      updateControls();
      updateSummary();
    }

    function skipRemainingQueuedItems(message) {
      queueItems.forEach((item) => {
        if (item.state === 'queued') {
          item.state = 'skipped';
          item.message = message;
          item.retryable = false;
          renderQueueItem(item);
        }
      });
    }

    function dedupeWithinBatch(files) {
      const seen = new Set();
      const result = [];
      files.forEach((file) => {
        const key = `${file.name}::${file.size}::${file.lastModified}`;
        if (seen.has(key)) return;
        seen.add(key);
        result.push(file);
      });
      return result;
    }

    function addFiles(fileList) {
      const files = dedupeWithinBatch(Array.from(fileList));
      const capacity = Math.max(MAX_QUEUE_FILES - queueItems.length, 0);
      const accepted = files.slice(0, capacity);
      const maximumBytes = Number(uploadForm.dataset.maximumBytes || '0');
      accepted.forEach((file) => {
        itemCounter += 1;
        const oversized = maximumBytes > 0 && file.size > maximumBytes;
        const item = {
          key: itemCounter,
          file,
          state: oversized ? 'error' : 'queued',
          scanId: null,
          message: oversized
            ? `This file exceeds the configured maximum of ${(maximumBytes / 1048576).toFixed(1)} MiB.`
            : null,
          retryable: false,
          element: createQueueItemElement(),
        };
        queueItems.push(item);
        queueList.appendChild(item.element);
        renderQueueItem(item);
      });
      updateControls();
      if (files.length > accepted.length) {
        setStatus(
          statusEl,
          `Only ${accepted.length} of ${files.length} selected file(s) were added — the queue holds at most ${MAX_QUEUE_FILES} files. Remove or clear completed items to add more.`,
          true,
        );
      } else {
        updateSummary();
      }
    }

    async function runItem(item) {
      item.state = 'active';
      renderQueueItem(item);
      updateSummary();
      try {
        const query = new URLSearchParams({ filename: item.file.name });
        const response = await fetch(`/api/v1/scans?${query.toString()}`, {
          method: 'POST',
          body: item.file,
          credentials: 'same-origin',
          headers: {
            'Content-Type': item.file.type || 'application/octet-stream',
            'X-CSRF-Token': uploadForm.dataset.csrfToken || '',
          },
        });
        let payload = null;
        try {
          payload = await response.json();
        } catch {
          payload = null;
        }
        const detail = payload && typeof payload.detail === 'string' ? payload.detail : null;
        if (response.status === 201 && payload && typeof payload.scan_id === 'string') {
          item.scanId = payload.scan_id;
          const decision = typeof payload.decision === 'string' ? payload.decision.toLowerCase() : '';
          item.state = DECISION_STATES.has(decision) ? decision : 'review';
        } else if (response.status === 401) {
          authBlocked = true;
          item.state = 'error';
          item.message = detail || 'Authentication is required.';
          item.retryable = false;
          skipRemainingQueuedItems(
            'Your session has expired. Sign in again, then re-add any documents that were not analyzed.',
          );
        } else if (response.status === 429) {
          const retryAfter = response.headers.get('retry-after');
          item.state = 'error';
          item.message = detail
            ? detail
            : retryAfter
              ? `Upload rate limit reached. Wait about ${retryAfter}s, then retry.`
              : 'Upload rate limit reached. Wait a few minutes, then retry.';
          item.retryable = true;
        } else {
          item.state = 'error';
          item.message = detail || 'Upload failed.';
          item.retryable = true;
        }
      } catch {
        item.state = 'error';
        item.message = 'Upload failed — the connection was lost before a response was received.';
        item.retryable = false;
      }
      renderQueueItem(item);
    }

    function ensureWorkers() {
      while (!authBlocked && activeCount < MAX_CONCURRENT_UPLOADS) {
        const next = queueItems.find((item) => item.state === 'queued');
        if (!next) break;
        activeCount += 1;
        updateControls();
        runItem(next).finally(() => {
          activeCount -= 1;
          updateControls();
          updateSummary();
          ensureWorkers();
        });
      }
      updateControls();
      updateSummary();
    }

    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files.length > 0) {
        addFiles(fileInput.files);
      }
      fileInput.value = '';
    });

    ['dragenter', 'dragover'].forEach((type) => {
      dropZone.addEventListener(type, (event) => {
        event.preventDefault();
        dropZone.dataset.active = 'true';
      });
    });
    ['dragleave', 'dragend'].forEach((type) => {
      dropZone.addEventListener(type, () => {
        dropZone.dataset.active = 'false';
      });
    });
    dropZone.addEventListener('drop', (event) => {
      event.preventDefault();
      dropZone.dataset.active = 'false';
      if (
        !authBlocked &&
        event.dataTransfer &&
        event.dataTransfer.files &&
        event.dataTransfer.files.length > 0
      ) {
        addFiles(event.dataTransfer.files);
      }
    });

    clearButton.addEventListener('click', () => {
      const survivors = [];
      queueItems.forEach((item) => {
        if (TERMINAL_STATES.has(item.state)) {
          item.element.remove();
        } else {
          survivors.push(item);
        }
      });
      queueItems = survivors;
      updateControls();
      updateSummary();
    });

    uploadForm.addEventListener('submit', (event) => {
      event.preventDefault();
      if (authBlocked) return;
      ensureWorkers();
    });

    updateControls();
  }
}

document.querySelectorAll('.cdr-form').forEach((candidate) => {
  if (!(candidate instanceof HTMLFormElement)) return;
  candidate.addEventListener('submit', async (event) => {
    event.preventDefault();
    const status = candidate.querySelector('[aria-live]');
    const button = candidate.querySelector('button[type="submit"]');
    if (!(status instanceof HTMLElement)) return;
    if (button instanceof HTMLButtonElement) button.disabled = true;
    setStatus(status, 'Reconstructing and re-analyzing the derivative…', false);
    try {
      const scanId = candidate.dataset.scanId || '';
      const response = await fetch(`/api/v1/scans/${encodeURIComponent(scanId)}/sanitize`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'X-CSRF-Token': candidate.dataset.csrfToken || '' },
      });
      const payload = await response.json();
      if (!response.ok || payload.approved !== true) {
        throw new Error('This document is not eligible for PDF sanitization.');
      }
      window.location.reload();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Sanitization failed.';
      setStatus(status, message, true);
      if (button instanceof HTMLButtonElement) button.disabled = false;
    }
  });
});
