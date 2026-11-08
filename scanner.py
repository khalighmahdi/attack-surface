#!/usr/bin/env python3
"""
scanner.py
===========
DEPRECATED legacy entry point. Kept for backward compatibility with
existing scripts and tutorials. New code should use:

    python attack_surface.py -d example.com

This shim just forwards to attack_surface.py with the same arguments.
"""

from __future__ import annotations

import sys
import warnings


def main() -> int:
    warnings.warn(
        "scanner.py is deprecated; use attack_surface.py instead",
        DeprecationWarning,
        stacklevel=2,
    )
    # Strip "scanner.py" from argv if present
    argv = sys.argv[1:]
    # Re-invoke the main entry point
    from attack_surface import main as asm
    return asm(argv)


if __name__ == "__main__":
    sys.exit(main())
