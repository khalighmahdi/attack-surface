"""
core/version.py — single source of truth for the tool version.

Every consumer (CLI banner, ScanContext, DB rows, .deb packaging,
self-updater) imports from here so the version can never drift again.
"""

__version__ = "0.21.0"

# PEP 440 friendly alias
VERSION = __version__
