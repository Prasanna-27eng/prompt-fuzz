"""Async fuzzing engine for prompt-fuzz.

Sends each payload to an OpenAI-compatible /v1/chat/completions endpoint
with bounded concurrency, and evaluates the response with `detectors.evaluate`.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from . import detectors


@dataclass
class FuzzResult:
    payload_id: str
    name: str
    category: str
    severity: str
    prompt: str
    response_text: str = ""
    bypassed: bool = False
    refused: bool = False
    canary_leaked: bool = False
    markers_found: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload_id": self.payload_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "prompt": self.prompt,
            "response_text": self.response_text,
            "bypassed": self.bypassed,
            "refused": self.refused,
            "canary_leaked": self.canary_leaked,
            "markers_found": self.markers_found,
            "reasons": self.reasons,
            "error": self.error,
        }


class FuzzEngine:
    """Fires payloads at an OpenAI-compatible chat completions endpoint."""

    def __init__(
        self,
        target: str,
        model: str = "gpt-4",
        api_key: Optional[str] = None,
        concurrency: int = 10,
        timeout: float = 30.0,
        system_prompt: Optional[str] = None,
        canary: Optional[str] = None,
        extra_headers: Optional[dict[str, str]] = None,
        max_tokens: int = 300,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        self.target = target
        self.model = model
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.system_prompt = system_prompt
        self.canary = canary
        self.max_tokens = max_tokens
        self.transport = transport

        self.headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"
        if extra_headers:
            self.headers.update(extra_headers)

    def _build_messages(self, prompt: str) -> list[dict[str, str]]:
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": prompt})
        return messages

    async def _send_one(self, client: httpx.AsyncClient, payload: dict[str, Any]) -> FuzzResult:
        result = FuzzResult(
            payload_id=payload["id"],
            name=payload.get("name", payload["id"]),
            category=payload.get("category", "uncategorized"),
            severity=payload.get("severity", "medium"),
            prompt=payload["prompt"],
        )

        body = {
            "model": self.model,
            "messages": self._build_messages(payload["prompt"]),
            "temperature": 0,
            "max_tokens": self.max_tokens,
        }

        try:
            resp = await client.post(self.target, json=body, headers=self.headers, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            result.response_text = data["choices"][0]["message"]["content"]
        except Exception as exc:  # noqa: BLE001 - report any transport/parse error per-payload
            result.error = str(exc)
            return result

        verdict = detectors.evaluate(result.response_text, payload, self.canary)
        result.bypassed = verdict.bypassed
        result.refused = verdict.refused
        result.canary_leaked = verdict.canary_leaked
        result.markers_found = verdict.markers_found
        result.reasons = verdict.reasons
        return result

    async def run(self, payloads: list[dict[str, Any]]) -> list[FuzzResult]:
        """Run all payloads concurrently (bounded by `self.concurrency`) and return results."""
        semaphore = asyncio.Semaphore(self.concurrency)

        async def _bounded(payload: dict[str, Any], client: httpx.AsyncClient) -> FuzzResult:
            async with semaphore:
                return await self._send_one(client, payload)

        async with httpx.AsyncClient(transport=self.transport) as client:
            tasks = [_bounded(p, client) for p in payloads]
            return await asyncio.gather(*tasks)


def summarize(results: list[FuzzResult]) -> dict[str, Any]:
    """Compute summary stats for a list of FuzzResults."""
    total = len(results)
    errors = [r for r in results if r.error]
    evaluated = [r for r in results if not r.error]
    bypassed = [r for r in evaluated if r.bypassed]
    blocked = [r for r in evaluated if not r.bypassed]

    by_category: dict[str, dict[str, int]] = {}
    for r in evaluated:
        cat = by_category.setdefault(r.category, {"total": 0, "bypassed": 0})
        cat["total"] += 1
        if r.bypassed:
            cat["bypassed"] += 1

    return {
        "total": total,
        "evaluated": len(evaluated),
        "errors": len(errors),
        "blocked": len(blocked),
        "bypassed": len(bypassed),
        "bypass_rate": (len(bypassed) / len(evaluated)) if evaluated else 0.0,
        "by_category": by_category,
    }
