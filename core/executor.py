"""
core/executor.py
=================
Lightweight wrapper that runs a module function safely.

Used when a module exports a legacy `run(context)` entry point.
The runner.py already wraps each phase internally, so this is mainly
kept for backward compatibility with the old `ScannerRunner.load_modules`
plugin-discovery style.

API:
    executor.run_module(callable, context) -> Any
"""

from __future__ import annotations

import logging
import traceback
from typing import Any, Callable

logger = logging.getLogger("AttackSurface.Executor")


class ModuleExecutor:
    def run_module(self, module_func: Callable, context) -> Any:
        """
        Execute a module function with a context. Returns the module's
        return value (or [] on failure). Never raises.
        """
        if not callable(module_func):
            logger.error("Module function is not callable: %r", module_func)
            return []
        try:
            return module_func(context)
        except Exception:
            logger.error("Module %s failed:", getattr(module_func, "__name__", module_func))
            logger.debug(traceback.format_exc())
            return []
