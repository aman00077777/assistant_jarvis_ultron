"""Audit module (root wrapper for backward compatibility with audit package)."""

from audit.audit import log_event

__all__ = ["log_event"]
