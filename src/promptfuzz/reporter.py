"""Optional AegisTrace integration: report bypassed payloads to the
AI Action Approval Queue via POST /api/ingest/promptfuzz-event.

Mirrors the mcp-aegis -> /api/ingest/mcp-event integration pattern.
"""
from __future__ import annotations

from typing import Any

import httpx

from .engine import FuzzResult


async def send_to_aegistrace(
    aegistrace_url: str,
    aegistrace_key: str,
    target: str,
    results: list[FuzzResult],
    timeout: float = 10.0,
) -> dict[str, Any]:
    """POST each bypassed payload to AegisTrace's ingest endpoint.

    Returns {"sent": N, "failed": N} so callers can report ingestion status.
    """
    url = aegistrace_url.rstrip("/") + "/api/ingest/promptfuzz-event"
    headers = {"X-AegisTrace-Key": aegistrace_key, "Content-Type": "application/json"}

    sent = 0
    failed = 0

    bypassed = [r for r in results if r.bypassed and not r.error]
    if not bypassed:
        return {"sent": 0, "failed": 0}

    async with httpx.AsyncClient() as client:
        for r in bypassed:
            payload = {
                "target": target,
                "payload_id": r.payload_id,
                "payload_name": r.name,
                "category": r.category,
                "severity": r.severity,
                "prompt": r.prompt,
                "response_preview": r.response_text[:500],
                "reasons": r.reasons,
            }
            try:
                resp = await client.post(url, json=payload, headers=headers, timeout=timeout)
                resp.raise_for_status()
                sent += 1
            except Exception:  # noqa: BLE001 - best-effort reporting, never fatal
                failed += 1

    return {"sent": sent, "failed": failed}
