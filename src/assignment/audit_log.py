"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        rid = request_id or f"req-{len(self.logs) + 1}"
        self._open[rid] = time.time()
        self.logs.append(
            {
                "request_id": rid,
                "user_id": user_id,
                "input": text,
                "input_timestamp": utc_now_iso(),
                "output": None,
                "blocked": False,
                "layer": None,
                "latency_ms": None,
            }
        )
        return rid

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        rid = request_id or f"req-{len(self.logs) + 1}"
        start = self._open.pop(rid, None)
        latency_ms = None
        if start is not None:
            latency_ms = round((time.time() - start) * 1000, 2)

        # If an entry with this request_id exists (from record_input), update it;
        # otherwise append a new entry.
        for entry in self.logs:
            if entry["request_id"] == rid:
                entry["output"] = text
                entry["blocked"] = blocked
                entry["layer"] = layer
                entry["latency_ms"] = latency_ms
                break
        else:
            self.logs.append(
                {
                    "request_id": rid,
                    "user_id": user_id,
                    "input": None,
                    "input_timestamp": None,
                    "output": text,
                    "blocked": blocked,
                    "layer": layer,
                    "latency_ms": latency_ms,
                }
            )

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = filepath or default_audit_log_path()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(
            json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8"
        )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
