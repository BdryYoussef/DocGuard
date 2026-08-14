'use strict';

function setStatus(element, message, isError) {
  element.textContent = message;
  element.classList.toggle('status-error', Boolean(isError));
}

const uploadForm = document.querySelector('#upload-form');
if (uploadForm instanceof HTMLFormElement) {
  uploadForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const input = uploadForm.querySelector('input[type="file"]');
    const status = uploadForm.querySelector('#upload-status');
    const button = uploadForm.querySelector('button[type="submit"]');
    if (!(input instanceof HTMLInputElement) || !(status instanceof HTMLElement) || !input.files?.length) {
      return;
    }
    const file = input.files[0];
    const maximum = Number(uploadForm.dataset.maximumBytes || '0');
    if (maximum > 0 && file.size > maximum) {
      setStatus(status, 'The selected file exceeds the configured maximum.', true);
      return;
    }
    if (button instanceof HTMLButtonElement) button.disabled = true;
    setStatus(status, 'Uploading and analyzing…', false);
    try {
      const query = new URLSearchParams({ filename: file.name });
      const response = await fetch(`/api/v1/scans?${query.toString()}`, {
        method: 'POST',
        body: file,
        credentials: 'same-origin',
        headers: {
          'Content-Type': file.type || 'application/octet-stream',
          'X-CSRF-Token': uploadForm.dataset.csrfToken || '',
        },
      });
      const payload = await response.json();
      if (!response.ok || typeof payload.scan_id !== 'string') {
        throw new Error(typeof payload.detail === 'string' ? payload.detail : 'Upload failed.');
      }
      window.location.assign(`/app/scans/${encodeURIComponent(payload.scan_id)}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Upload failed.';
      setStatus(status, message, true);
      if (button instanceof HTMLButtonElement) button.disabled = false;
    }
  });
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
