"""Tier-2 Multi-Provider LLM RCA Engine (Gemini / OpenAI / Deterministic Offline Fallback).

Synthesizes structured JSON Root Cause Analyses and Cisco/Linux/AWS remediation
runbooks from compact Tier-1 TelemetryAnomaly payloads.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from typing import Any
from urllib import request as url_request
import uuid

from .models import RCAReport, TelemetryAnomaly

SYSTEM_PROMPT = (
    "You are a Principal NOC & SRE Network Engineer. Given a compact Tier-1 network "
    "anomaly payload, return STRICT JSON ONLY (no markdown fences) with keys: "
    "title (string), root_cause (string), blast_radius (string), "
    "remediation_steps (array of 3-5 concise steps), "
    "verification_commands (array of 2-3 CLI commands), confidence (float 0.0-1.0)."
)


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _heuristic_rca(anomaly: TelemetryAnomaly) -> dict[str, Any]:
    """Deterministic L2/L3 NOC expert-system fallback (runs 100% offline, zero API key needed)."""
    cat = anomaly.category.upper()
    target = anomaly.target

    if cat == "DNS_FAILURE":
        return {
            "title": f"DNS Resolution Failure Detected on {target}",
            "root_cause": (
                "Internal resolver returned NXDOMAIN/SERVFAIL. Fast NXDOMAIN replies indicate "
                "a missing/misconfigured DNS record, whereas delayed SERVFAIL with successful "
                "upstream resolution isolates the fault to the local DNS forwarder or DNSSEC path."
            ),
            "blast_radius": "Applications and users relying on the affected internal DNS resolver cannot resolve impacted FQDNs.",
            "remediation_steps": [
                "Run comparative lookups against internal DNS vs. public upstream (1.1.1.1) to isolate forwarder vs. authoritative faults.",
                "Verify outbound UDP/53 and TCP/53 firewall rules on the internal DNS server.",
                "Flush stale negative DNS cache entries (rndc flush / unbound-control flush) and verify upstream forwarder health.",
                "Correct any retired or typo'd FQDNs in application configuration.",
            ],
            "verification_commands": [
                "dig @10.20.1.10 erp.vendor-cloud.example +stats",
                "dig @1.1.1.1 erp.vendor-cloud.example +short",
            ],
            "confidence": 0.93,
        }

    if cat == "TCP_FIREWALL_DROP":
        return {
            "title": f"TCP 3-Way Handshake Timeout / Silent Firewall DROP ({target})",
            "root_cause": (
                "Repeated TCP SYN transmissions received zero SYN-ACK, RST, or ICMP Unreachable replies. "
                "This exponential backoff signature indicates a stateful firewall policy DROP, missing AWS "
                "Security Group inbound rule, host firewall drop, or asymmetric return routing."
            ),
            "blast_radius": f"Client-to-service TCP connectivity to {target} hangs until client timeout (~30s+), causing application outages.",
            "remediation_steps": [
                f"Capture simultaneously on destination host ({target}) with tcpdump to separate network firewall vs. host firewall.",
                "Audit AWS Security Group / NACL / Palo Alto / UFW rules for least-privilege TCP allow rules from the source subnet.",
                "Verify return routing symmetry (OSPF/HSRP path & Linux rp_filter) if SYN arrives at destination with no SYN-ACK.",
                "Apply scoped allow rule (never 0.0.0.0/0 for internal DB/SSH ports) and re-verify handshake RTT.",
            ],
            "verification_commands": [
                f"nc -zv -w 3 {target.replace(':', ' ')}",
                f"sudo tcpdump -nn -i any host {target.split(':')[0]} and tcp",
            ],
            "confidence": 0.95,
        }

    if cat == "TCP_PORT_CLOSED":
        return {
            "title": f"TCP Connection Refused (RST) on {target}",
            "root_cause": (
                "Destination host responded immediately with TCP RST/ACK. Layer-3 routing and network firewalls "
                "are passing traffic, but no daemon is bound to the target port (service crashed, stopped, or bound to localhost only)."
            ),
            "blast_radius": f"Direct service unavailability on {target}, though host OS and network path remain operational.",
            "remediation_steps": [
                f"Inspect listening sockets on {target.split(':')[0]} using `ss -tlnp` to confirm service bind address.",
                "Check systemd service status and recent journald crash logs (`journalctl -xeu <service>`).",
                "Restart the target daemon and verify bind address (0.0.0.0 or private interface IP instead of 127.0.0.1).",
            ],
            "verification_commands": [
                "ss -tlnp",
                f"nc -zv -w 2 {target.replace(':', ' ')}",
            ],
            "confidence": 0.94,
        }

    if cat == "ARP_SPOOFING":
        return {
            "title": f"Layer-2 ARP Spoofing / Duplicate IP Conflict ({target})",
            "root_cause": (
                f"Multiple distinct MAC addresses claimed IP {target} on the same broadcast domain. "
                "Unsolicited ARP replies claiming the gateway IP indicate active ARP cache poisoning (MITM), "
                "while conflicting host MACs indicate a static IP overlapping the DHCP pool."
            ),
            "blast_radius": "Active L2 traffic interception risk, intermittent subnet dropouts, and TLS certificate mismatch warnings across the VLAN.",
            "remediation_steps": [
                "Trace the rogue MAC address in the switch CAM table (`show mac address-table address <mac>`) and shut down the offending access port.",
                "Flush poisoned ARP caches on affected hosts (`ip -s -s neigh flush all` / `arp -d *`).",
                "Enable DHCP Snooping, Dynamic ARP Inspection (DAI), and Port Security on access switches (trust uplinks only).",
                "Verify static IP reservations do not overlap active DHCP lease scopes.",
            ],
            "verification_commands": [
                "show ip arp inspection statistics vlan 20",
                "ip neigh show",
            ],
            "confidence": 0.96,
        }

    if cat == "CLEARTEXT_HTTP":
        return {
            "title": f"Cleartext Credential / Cookie Exposure on HTTP Port 80 ({target})",
            "root_cause": (
                "Sensitive Authorization headers or session cookies were transmitted over unencrypted HTTP (TCP/80), "
                "making credentials trivially readable via passive packet capture."
            ),
            "blast_radius": "Full credential and session hijacking exposure for any user traversing untrusted or shared network segments.",
            "remediation_steps": [
                "Enforce HTTP 301 permanent redirect to HTTPS (TLS 1.2/1.3) and enable HSTS headers at the reverse proxy/ALB.",
                "Mark all authentication cookies with `Secure; HttpOnly; SameSite=Lax`.",
                "Immediately rotate exposed credentials and invalidate active plaintext session tokens.",
            ],
            "verification_commands": [
                "curl -I http://<hostname>",
                "openssl s_client -connect <hostname>:443 -servername <hostname> </dev/null",
            ],
            "confidence": 0.95,
        }

    return {
        "title": f"Network Degradation Detected on {target} ({cat})",
        "root_cause": (
            f"Automated Tier-1 telemetry detected {anomaly.summary} Elevated latency or packet loss "
            "typically stems from WAN uplink congestion, suboptimal routing, or host resource saturation."
        ),
        "blast_radius": f"Degraded user experience and elevated p95 response times for workloads dependent on {target}.",
        "remediation_steps": [
            f"Run continuous path diagnostics (`mtr -rwzbc 20 {target}`) to pinpoint the hop introducing latency or loss.",
            "Inspect interface error/drop counters (`show interfaces` / `ip -s link`) for duplex mismatches or buffer exhaustion.",
            "Verify HSRP/OSPF primary path health and fail over to standby uplink if primary transit is degraded.",
        ],
        "verification_commands": [
            f"mtr -rwzbc 10 {target.split(':')[0]}",
            "ip -s link show",
        ],
        "confidence": 0.86,
    }


def _call_gemini(prompt: str, api_key: str, model: str = "gemini-2.0-flash", timeout: float = 12.0) -> dict[str, Any]:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": f"{SYSTEM_PROMPT}\n\nAnomaly JSON:\n{prompt}"}]}],
        "generationConfig": {"responseMimeType": "application/json", "temperature": 0.2},
    }
    req = url_request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "AI-NOC-Triage-Bot/1.0"},
        method="POST",
    )
    with url_request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    text = body["candidates"][0]["content"]["parts"][0]["text"]
    return json.loads(text)


def _call_openai(prompt: str, api_key: str, model: str = "gpt-4o-mini", timeout: float = 12.0) -> dict[str, Any]:
    url = "https://api.openai.com/v1/chat/completions"
    payload = {
        "model": model,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Anomaly JSON:\n{prompt}"},
        ],
    }
    req = url_request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "AI-NOC-Triage-Bot/1.0",
        },
        method="POST",
    )
    with url_request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    text = body["choices"][0]["message"]["content"]
    return json.loads(text)


class MultiTierRCAEngine:
    """Routes Tier-1 anomalies to Gemini -> OpenAI -> Offline Heuristic Fallback."""

    def __init__(
        self,
        gemini_api_key: str | None = None,
        openai_api_key: str | None = None,
        prefer_offline: bool = False,
    ) -> None:
        self.gemini_api_key = (gemini_api_key if gemini_api_key is not None else os.environ.get("GEMINI_API_KEY", "")).strip()
        self.openai_api_key = (openai_api_key if openai_api_key is not None else os.environ.get("OPENAI_API_KEY", "")).strip()
        self.prefer_offline = prefer_offline

    def active_provider(self) -> str:
        if self.prefer_offline:
            return "heuristic-offline"
        if self.gemini_api_key:
            return "gemini"
        if self.openai_api_key:
            return "openai"
        return "heuristic-offline"

    def triage(self, anomaly: TelemetryAnomaly, raw_context_bytes: int = 4096) -> RCAReport:
        compact_payload = json.dumps(anomaly.to_dict(), indent=2)
        prompt_tokens = _estimate_tokens(SYSTEM_PROMPT + compact_payload)
        raw_tokens_avoided = max(0, (raw_context_bytes // 4) - prompt_tokens)

        parsed: dict[str, Any] | None = None
        engine_used = "heuristic-offline"

        if not self.prefer_offline and self.gemini_api_key:
            try:
                parsed = _call_gemini(compact_payload, self.gemini_api_key)
                engine_used = "gemini"
            except Exception:
                parsed = None

        if parsed is None and not self.prefer_offline and self.openai_api_key:
            try:
                parsed = _call_openai(compact_payload, self.openai_api_key)
                engine_used = "openai"
            except Exception:
                parsed = None

        if parsed is None:
            parsed = _heuristic_rca(anomaly)
            engine_used = "heuristic-offline"

        now_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        inc_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        return RCAReport(
            incident_id=inc_id,
            timestamp_utc=now_utc,
            title=str(parsed.get("title", anomaly.summary)),
            severity=anomaly.severity,
            osi_layer=anomaly.osi_layer,
            category=anomaly.category,
            target=anomaly.target,
            root_cause=str(parsed.get("root_cause", anomaly.summary)),
            blast_radius=str(parsed.get("blast_radius", "Impacted target endpoint.")),
            evidence=anomaly.evidence,
            remediation_steps=tuple(str(s) for s in parsed.get("remediation_steps", ())),
            verification_commands=tuple(str(c) for c in parsed.get("verification_commands", ())),
            confidence=float(parsed.get("confidence", 0.9)),
            engine_used=engine_used,
            prompt_tokens_est=prompt_tokens,
            raw_tokens_avoided_est=raw_tokens_avoided,
        )
