# modules/payload_registry.py

from typing import Dict, List

# Payloads waiting to be shown/executed (Expert Mode)
PENDING_PAYLOADS: List[Dict] = []


def register_payload(payload: Dict):
    """
    Payload schema:
    {
        "id": str,
        "title": str,
        "description": str,
        "command": str,
        "requires_expert": bool,
        "on_success": str | None
    }
    """

    if not isinstance(payload, dict):
        return

    # ✅ Basic validation
    required_keys = ("id", "title", "command", "requires_expert")
    for key in required_keys:
        if key not in payload:
            return

    # ✅ Normalize optional fields
    payload.setdefault("description", "")
    payload.setdefault("on_success", None)

    # ✅ Prevent duplicates (by id)
    for p in PENDING_PAYLOADS:
        if p.get("id") == payload["id"]:
            return

    PENDING_PAYLOADS.append(payload)


def get_pending_payloads(expert_mode: bool = False) -> List[Dict]:
    """
    Returns payloads that are allowed to be shown
    depending on expert mode flag.
    """
    if expert_mode:
        return list(PENDING_PAYLOADS)

    # Non-expert users should not see expert payloads
    return [
        p for p in PENDING_PAYLOADS
        if not p.get("requires_expert", True)
    ]


def clear_payloads():
    """Clears all registered payloads (per scan)."""
    PENDING_PAYLOADS.clear()

