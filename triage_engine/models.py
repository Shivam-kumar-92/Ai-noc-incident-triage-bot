"""Typed telemetry and AI Root Cause Analysis (RCA) data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class TelemetryAnomaly:
    source_type: str  # "live_probe" | "pcap" | "json_telemetry"
    source_ref: str
    category: str     # "DNS_FAILURE" | "TCP_FIREWALL_DROP" | "TCP_PORT_CLOSED" | "HIGH_LATENCY" | "ARP_SPOOFING" | "CLEARTEXT_HTTP"
    osi_layer: str    # "L2" | "L3" | "L4" | "L7"
    severity: str     # "SEV-1" | "SEV-2" | "SEV-3"
    target: str
    summary: str
    evidence: tuple[str, ...] = ()
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RCAReport:
    incident_id: str
    timestamp_utc: str
    title: str
    severity: str
    osi_layer: str
    category: str
    target: str
    root_cause: str
    blast_radius: str
    evidence: tuple[str, ...]
    remediation_steps: tuple[str, ...]
    verification_commands: tuple[str, ...]
    confidence: float
    engine_used: str  # "gemini" | "openai" | "heuristic-offline"
    prompt_tokens_est: int
    raw_tokens_avoided_est: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        ev_lines = "\n".join(f"- {e}" for e in self.evidence) or "- None"
        rem_lines = "\n".join(f"{i}. {step}" for i, step in enumerate(self.remediation_steps, 1))
        ver_lines = "\n".join(f"```bash\n{cmd}\n```" for cmd in self.verification_commands)
        return (
            f"# Incident RCA: {self.title}\n\n"
            f"| Field | Value |\n"
            f"| :--- | :--- |\n"
            f"| **Incident ID** | `{self.incident_id}` |\n"
            f"| **Timestamp (UTC)** | `{self.timestamp_utc}` |\n"
            f"| **Severity / OSI Layer** | **{self.severity}** / `{self.osi_layer}` |\n"
            f"| **Category / Target** | `{self.category}` / `{self.target}` |\n"
            f"| **Triage Engine** | `{self.engine_used}` (confidence: `{self.confidence:.0%}`) |\n"
            f"| **Token Optimization** | `{self.prompt_tokens_est}` prompt tokens (~`{self.raw_tokens_avoided_est}` raw telemetry tokens filtered in Tier 1) |\n\n"
            f"## Root Cause Analysis\n{self.root_cause}\n\n"
            f"## Blast Radius\n{self.blast_radius}\n\n"
            f"## Wire & Telemetry Evidence\n{ev_lines}\n\n"
            f"## Remediation Runbook\n{rem_lines}\n\n"
            f"## Verification Commands\n{ver_lines}\n"
        )
