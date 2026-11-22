"""Tier-1 Deterministic Telemetry: Async network probes, PCAP forensics & JSON ingestion.

Filters healthy traffic locally at zero LLM token cost and emits compact
TelemetryAnomaly objects only when genuine failures or degradations occur.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
import json
from pathlib import Path
import socket
import struct
import time
from typing import Any, Sequence

from .models import TelemetryAnomaly

DNS_RCODES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


# ---------------------------------------------------------------------------
# 1. Async Live Network Probes (Bounded Concurrency)
# ---------------------------------------------------------------------------

async def _probe_tcp(host: str, port: int, timeout: float) -> dict[str, Any]:
    start = time.perf_counter()
    try:
        _r, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        ms = round((time.perf_counter() - start) * 1000.0, 2)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return {"port": port, "status": "OPEN", "latency_ms": ms, "error": None}
    except asyncio.TimeoutError:
        return {"port": port, "status": "TIMEOUT", "latency_ms": None, "error": f"TCP handshake timed out after {timeout}s"}
    except OSError as exc:
        return {"port": port, "status": "CLOSED", "latency_ms": None, "error": exc.strerror or str(exc)}


async def probe_endpoints_async(
    specs: Sequence[str],
    timeout: float = 2.0,
    latency_warn_ms: float = 150.0,
    concurrency: int = 32,
) -> tuple[list[dict[str, Any]], list[TelemetryAnomaly]]:
    """Probe targets formatted as 'host:port1,port2' concurrently via asyncio."""
    sem = asyncio.Semaphore(max(1, concurrency))
    raw_results: list[dict[str, Any]] = []
    anomalies: list[TelemetryAnomaly] = []

    async def check_one(spec: str) -> None:
        if ":" in spec:
            host, port_str = spec.rsplit(":", 1)
            ports = [int(p.strip()) for p in port_str.split(",") if p.strip()]
        else:
            host, ports = spec.strip(), [80, 443]

        async with sem:
            probes = await asyncio.gather(*(_probe_tcp(host, p, timeout) for p in ports))

        entry = {"host": host, "ports": list(probes)}
        raw_results.append(entry)

        timed_out = [p for p in probes if p["status"] == "TIMEOUT"]
        closed = [p for p in probes if p["status"] == "CLOSED"]
        slow = [p for p in probes if p["status"] == "OPEN" and (p["latency_ms"] or 0.0) >= latency_warn_ms]

        if timed_out:
            anomalies.append(
                TelemetryAnomaly(
                    source_type="live_probe",
                    source_ref=spec,
                    category="TCP_FIREWALL_DROP",
                    osi_layer="L4",
                    severity="SEV-1",
                    target=host,
                    summary=f"TCP SYN timeout on {host} port(s) {[p['port'] for p in timed_out]} (probable stateful firewall DROP or unreachable host).",
                    evidence=tuple(f"Port {p['port']}: {p['error']}" for p in timed_out),
                    metrics={"timed_out_ports": [p["port"] for p in timed_out], "timeout_sec": timeout},
                )
            )
        if closed:
            anomalies.append(
                TelemetryAnomaly(
                    source_type="live_probe",
                    source_ref=spec,
                    category="TCP_PORT_CLOSED",
                    osi_layer="L4",
                    severity="SEV-2",
                    target=host,
                    summary=f"TCP connection refused (RST) on {host} port(s) {[p['port'] for p in closed]} (host reachable, service not listening).",
                    evidence=tuple(f"Port {p['port']}: {p['error']}" for p in closed),
                    metrics={"closed_ports": [p["port"] for p in closed]},
                )
            )
        if slow:
            anomalies.append(
                TelemetryAnomaly(
                    source_type="live_probe",
                    source_ref=spec,
                    category="HIGH_LATENCY",
                    osi_layer="L3",
                    severity="SEV-3",
                    target=host,
                    summary=f"Elevated TCP handshake latency on {host} (>={latency_warn_ms}ms).",
                    evidence=tuple(f"Port {p['port']}: {p['latency_ms']}ms" for p in slow),
                    metrics={"slow_ports": {p["port"]: p["latency_ms"] for p in slow}},
                )
            )

    await asyncio.gather(*(check_one(s) for s in specs))
    return raw_results, anomalies


# ---------------------------------------------------------------------------
# 2. Binary Wireshark .pcap Forensic Extractor
# ---------------------------------------------------------------------------

def _fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _fmt_ip(b: bytes) -> str:
    return socket.inet_ntoa(b)


def _parse_dns_qname(buf: bytes, offset: int) -> str:
    labels: list[str] = []
    pos = offset
    for _ in range(64):
        if pos >= len(buf):
            break
        ln = buf[pos]
        if ln == 0:
            break
        if (ln & 0xC0) == 0xC0:
            pos = ((ln & 0x3F) << 8) | buf[pos + 1]
            continue
        pos += 1
        labels.append(buf[pos : pos + ln].decode("ascii", errors="replace"))
        pos += ln
    return ".".join(labels)


def analyze_pcap_anomalies(pcap_path: Path) -> tuple[int, list[TelemetryAnomaly]]:
    """Parse a standard libpcap (.pcap) file and extract high-signal anomalies."""
    raw = pcap_path.read_bytes()
    if len(raw) < 24:
        raise ValueError(f"Invalid PCAP (too short): {pcap_path}")
    magic = struct.unpack("<I", raw[:4])[0]
    endian = "<" if magic == 0xA1B2C3D4 else (">" if magic == 0xD4C3B2A1 else "")
    if not endian:
        raise ValueError(f"Unsupported PCAP magic header: 0x{magic:08x}")

    offset = 24
    pkt_count = 0
    first_ts: float | None = None

    dns_errors: list[str] = []
    dns_resolvers: dict[str, set[str]] = defaultdict(set)
    tcp_syns: dict[tuple[str, int, str, int], list[float]] = defaultdict(list)
    tcp_syn_acks: set[tuple[str, int, str, int]] = set()
    tcp_rsts: set[tuple[str, int, str, int]] = set()
    arp_ip_macs: dict[str, list[str]] = defaultdict(list)
    http_cleartext: list[str] = []

    while offset + 16 <= len(raw):
        ts_sec, ts_usec, incl_len, _ = struct.unpack(endian + "IIII", raw[offset : offset + 16])
        offset += 16
        frame = raw[offset : offset + incl_len]
        offset += incl_len
        pkt_count += 1
        ts = ts_sec + ts_usec / 1_000_000.0
        if first_ts is None:
            first_ts = ts
        rel = round(ts - first_ts, 3)

        if len(frame) < 14:
            continue
        ethertype = struct.unpack("!H", frame[12:14])[0]
        payload = frame[14:]

        if ethertype == 0x0806 and len(payload) >= 28:
            _, _, _, _, _op, smac_b, sip_b, _, _ = struct.unpack("!HHBBH6s4s6s4s", payload[:28])
            smac, sip = _fmt_mac(smac_b), _fmt_ip(sip_b)
            if smac not in arp_ip_macs[sip]:
                arp_ip_macs[sip].append(smac)
            continue

        if ethertype != 0x0800 or len(payload) < 20:
            continue
        ihl = (payload[0] & 0x0F) * 4
        proto = payload[9]
        sip, dip = _fmt_ip(payload[12:16]), _fmt_ip(payload[16:20])
        l4 = payload[ihl:]

        if proto == 17 and len(l4) >= 20:
            sp, dp = struct.unpack("!HH", l4[:4])
            if sp == 53 or dp == 53:
                dns = l4[8:]
                _txid, flags = struct.unpack("!HH", dns[:4])
                if flags & 0x8000:
                    rcode = flags & 0x000F
                    qname = _parse_dns_qname(dns, 12)
                    dns_resolvers[qname].add(f"{sip}:{DNS_RCODES.get(rcode, rcode)}")
                    if rcode in (2, 3, 5):
                        dns_errors.append(
                            f"Frame #{pkt_count} ({rel}s): {sip} returned {DNS_RCODES[rcode]} for '{qname}'"
                        )

        elif proto == 6 and len(l4) >= 20:
            sp, dp, _seq, _ack, off_res, flags = struct.unpack("!HHIIBB", l4[:14])
            app = l4[(off_res >> 4) * 4 :]
            if (flags & 0x02) and not (flags & 0x10):
                tcp_syns[(sip, sp, dip, dp)].append(rel)
            elif (flags & 0x12) == 0x12:
                tcp_syn_acks.add((dip, dp, sip, sp))
            elif flags & 0x04:
                tcp_rsts.add((dip, dp, sip, sp))
            if app and (sp == 80 or dp == 80):
                text = app.decode("utf-8", errors="ignore")
                if "Authorization:" in text or "Set-Cookie:" in text:
                    first_line = text.splitlines()[0] if text.splitlines() else "HTTP payload"
                    http_cleartext.append(f"Frame #{pkt_count} ({sip}:{sp}->{dip}:{dp}): {first_line}")

    anomalies: list[TelemetryAnomaly] = []

    if dns_errors:
        anomalies.append(
            TelemetryAnomaly(
                source_type="pcap",
                source_ref=pcap_path.name,
                category="DNS_FAILURE",
                osi_layer="L7",
                severity="SEV-2",
                target=pcap_path.name,
                summary=f"Detected {len(dns_errors)} failed DNS response(s) (NXDOMAIN/SERVFAIL/REFUSED).",
                evidence=tuple(dns_errors),
                metrics={"resolver_matrix": {k: sorted(v) for k, v in dns_resolvers.items()}},
            )
        )

    for flow, times in tcp_syns.items():
        sip, sp, dip, dp = flow
        if flow not in tcp_syn_acks and flow not in tcp_rsts and len(times) >= 2:
            deltas = [round(times[i] - times[i - 1], 2) for i in range(1, len(times))]
            anomalies.append(
                TelemetryAnomaly(
                    source_type="pcap",
                    source_ref=pcap_path.name,
                    category="TCP_FIREWALL_DROP",
                    osi_layer="L4",
                    severity="SEV-1",
                    target=f"{dip}:{dp}",
                    summary=f"Silent TCP firewall DROP: {sip}:{sp} -> {dip}:{dp} sent {len(times)} SYNs with 0 replies (backoff {deltas}s).",
                    evidence=(
                        f"Source {sip}:{sp} -> Destination {dip}:{dp}",
                        f"{len(times)} SYN attempts, 0 SYN-ACK, 0 RST, backoff intervals={deltas}s",
                    ),
                    metrics={"syn_count": len(times), "backoff_seconds": deltas},
                )
            )
        elif flow in tcp_rsts and flow not in tcp_syn_acks:
            anomalies.append(
                TelemetryAnomaly(
                    source_type="pcap",
                    source_ref=pcap_path.name,
                    category="TCP_PORT_CLOSED",
                    osi_layer="L4",
                    severity="SEV-2",
                    target=f"{dip}:{dp}",
                    summary=f"TCP RST received from {dip}:{dp} (host reachable at L3, port closed or actively rejected).",
                    evidence=(f"Source {sip}:{sp} -> Destination {dip}:{dp} replied with RST,ACK",),
                    metrics={"dest_port": dp},
                )
            )

    if http_cleartext:
        anomalies.append(
            TelemetryAnomaly(
                source_type="pcap",
                source_ref=pcap_path.name,
                category="CLEARTEXT_HTTP",
                osi_layer="L7",
                severity="SEV-2",
                target=pcap_path.name,
                summary="Sensitive authentication/session headers transmitted in cleartext over HTTP port 80.",
                evidence=tuple(http_cleartext),
                metrics={"exposed_frames": len(http_cleartext)},
            )
        )

    for ip, macs in arp_ip_macs.items():
        if len(macs) > 1:
            anomalies.append(
                TelemetryAnomaly(
                    source_type="pcap",
                    source_ref=pcap_path.name,
                    category="ARP_SPOOFING",
                    osi_layer="L2",
                    severity="SEV-1",
                    target=ip,
                    summary=f"L2 ARP conflict / spoofing detected: IP {ip} claimed by multiple MACs ({', '.join(macs)}).",
                    evidence=(f"Conflicting MACs for {ip}: {', '.join(macs)}",),
                    metrics={"ip": ip, "macs": macs},
                )
            )

    return pkt_count, anomalies


# ---------------------------------------------------------------------------
# 3. Structured JSON Telemetry Ingestion (Compatible with NOC & Async Monitor)
# ---------------------------------------------------------------------------

def ingest_json_telemetry(json_path: Path) -> list[TelemetryAnomaly]:
    """Ingest JSON telemetry reports (e.g., from async-subnet-monitor or NOC alerts)."""
    data = json.loads(json_path.read_text(encoding="utf-8"))
    anomalies: list[TelemetryAnomaly] = []

    # Format A: async-subnet-monitor report ("hosts": [...])
    if "hosts" in data and isinstance(data["hosts"], list):
        for host in data["hosts"]:
            ip = str(host.get("ip", "unknown"))
            ports = host.get("ports", [])
            timed_out = [p for p in ports if p.get("status") == "TIMEOUT"]
            closed = [p for p in ports if p.get("status") == "CLOSED"]
            if timed_out:
                anomalies.append(
                    TelemetryAnomaly(
                        source_type="json_telemetry",
                        source_ref=json_path.name,
                        category="TCP_FIREWALL_DROP",
                        osi_layer="L4",
                        severity="SEV-1",
                        target=ip,
                        summary=f"Subnet scan reported TCP timeout on {ip} ports {[p['port'] for p in timed_out]}.",
                        evidence=tuple(f"Port {p['port']}: {p.get('error', 'TIMEOUT')}" for p in timed_out),
                        metrics={"subnet": data.get("subnet"), "ports": [p["port"] for p in timed_out]},
                    )
                )
            elif closed and not host.get("reachable", False):
                anomalies.append(
                    TelemetryAnomaly(
                        source_type="json_telemetry",
                        source_ref=json_path.name,
                        category="TCP_PORT_CLOSED",
                        osi_layer="L4",
                        severity="SEV-2",
                        target=ip,
                        summary=f"Host {ip} unreachable across all probed ports {[p['port'] for p in closed]}.",
                        evidence=tuple(f"Port {p['port']}: {p.get('error', 'CLOSED')}" for p in closed),
                        metrics={"subnet": data.get("subnet")},
                    )
                )
        return anomalies

    # Format B: explicit NOC incident event JSON ("events": [...] or single event dict)
    events = data.get("events", [data]) if isinstance(data, dict) else data
    for ev in events:
        if str(ev.get("status", "")).upper() in ("UP", "OK", "HEALTHY"):
            continue
        anomalies.append(
            TelemetryAnomaly(
                source_type="json_telemetry",
                source_ref=json_path.name,
                category=str(ev.get("category", "DNS_FAILURE")).upper(),
                osi_layer=str(ev.get("osi_layer", "L7")),
                severity=str(ev.get("severity", "SEV-2")),
                target=str(ev.get("target", ev.get("host", "unknown"))),
                summary=str(ev.get("summary", "Network telemetry anomaly detected")),
                evidence=tuple(str(x) for x in ev.get("evidence", [])),
                metrics=dict(ev.get("metrics", {})),
            )
        )
    return anomalies
