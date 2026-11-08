"""Backward-compatible shim.

The autonomous agent now lives in :mod:`modules.knull` under the name Knull.
This module keeps every old ``from modules.autonomous_agent import ...``
working.
"""

from modules.knull import (  # noqa: F401
    AgentEvent,
    AgentState,
    AutonomousAgent,
    KillChainProgress,
    Knull,
)

__all__ = [
    "AgentEvent",
    "AgentState",
    "AutonomousAgent",
    "KillChainProgress",
    "Knull",
]
