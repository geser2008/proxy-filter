from __future__ import annotations


def normalize_payload_valid(record: dict | None) -> None:
    """Normalize public payload validity to strict tri-state semantics.

    True means the expected byte count was explicitly confirmed. False remains
    reserved for an explicitly detected invalid payload. Everything else is
    unknown (None), including transport failures where completeness was not
    proven. This function is diagnostic-only and must not reinterpret probe
    acceptance decisions.
    """
    if not record:
        return

    current = record.get("payload_valid")
    if current is False:
        return

    expected = record.get("expected_bytes")
    transferred = record.get("bytes")
    if expected is None or transferred is None:
        record["payload_valid"] = None
        return

    try:
        expected_value = int(expected)
        transferred_value = int(transferred)
    except (TypeError, ValueError):
        record["payload_valid"] = None
        return

    record["payload_valid"] = True if transferred_value == expected_value else None
