"""Explicit trusted-side application errors."""


class DocGuardError(RuntimeError):
    """Base class for errors safe to translate into a generic client response."""
