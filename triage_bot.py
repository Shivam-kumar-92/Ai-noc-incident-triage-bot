#!/usr/bin/env python3
"""AI-Powered NOC Incident Triage Bot — CLI Entry Point."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys
import time

from triage_engine import __version__
from triage_engine.dashboard import start_console_server
from triage_engine.llm_rca import MultiTierRCAEngine
from triage_engine.models import RCAReport, TelemetryAnomaly
from triage_engine.notifier import RCANotifier
from triage_engine.storage import IncidentStore
from triage_engine.telemetry import analyze_pcap_anomalies, ingest_json_telemetry, probe_endpoints_async


def _print_rca(rca: RCAReport) -> None:
    print("\n" + "=" * 90)
    print(f"[{rca.severity} | {rca.osi_layer}] {rca.title}")
    print(f"Incident ID : {rca.incident_id} | Target: {rca.target} | Engine: {rca.engine_used} ({rca.confidence:.0%})")
    print(f"Token Opt.  : {rca.prompt_tokens_est} prompt tokens (~{rca.raw_tokens_avoided_est} raw telemetry tokens filtered in Tier-1)")
    print("-" * 90)
    print(f"Root Cause  : {rca.root_cause}")
    print(f"Blast Radius: {rca.blast_radius}")
    if rca.evidence:
        print("Evidence    :")
        for ev in rca.evidence:
            print(f"  - {ev}")
    print("Remediation :")
    for idx, step in enumerate(rca.remediation_steps, 1):
        print(f"  {idx}. {step}")
    if rca.verification_commands:
        print("Verify CLI  :")
        for cmd in rca.verification_commands:
            print(f"  $ {cmd}")
    print("=" * 90)


def _process_anomalies(
    anomalies: list[TelemetryAnomaly],
    engine: MultiTierRCAEngine,
    store: IncidentStore,
    notifier: RCANotifier,
    raw_bytes: int,
    export_dir: Path | None,
) -> list[RCAReport]:
    reports: list[RCAReport] = []
    if not anomalies:
        print("Tier-1 Telemetry Clean: 0 anomalies detected (0 LLM tokens consumed).")
        return reports

    for anomaly in anomalies:
        rca = engine.triage(anomaly, raw_context_bytes=raw_bytes)
        store.save_report(rca)
        notifier.send(rca)
        _print_rca(rca)
        if export_dir is not None:
            export_dir.mkdir(parents=True, exist_ok=True)
            md_path = export_dir / f"{rca.incident_id}.md"
            md_path.write_text(rca.to_markdown(), encoding="utf-8")
            print(f"Exported Markdown Postmortem -> {md_path}")
        reports.append(rca)
    return reports


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="triage_bot.py",
        description="AI-Powered NOC Incident Triage Bot (Async Probes + PCAP Forensics + Multi-Provider LLM RCA)",
    )
    p.add_argument("--probe", nargs="+", help="Live async TCP probes formatted as host:p1,p2 (e.g., 1.1.1.1:53,443)")
    p.add_argument("--triage-pcap", type=Path, help="Analyze a Wireshark .pcap file and generate AI RCA")
    p.add_argument("--triage-json", type=Path, help="Ingest a JSON telemetry report and generate AI RCA")
    p.add_argument("--demo", action="store_true", help="Run full multi-layer showcase (DNS + TCP Firewall Drop + ARP Spoofing)")
    p.add_argument("--offline", action="store_true", help="Force deterministic offline expert-system engine (no external API calls)")
    p.add_argument("--db", type=Path, default=Path("data/triage_incidents.db"), help="SQLite database path")
    p.add_argument("--export-md", type=Path, default=None, help="Directory to export Markdown postmortem reports")
    p.add_argument("--dashboard", action="store_true", help="Launch live AI-NOC Web Console")
    p.add_argument("--dashboard-port", type=int, default=8085, help="Web Console port (default: 8085)")
    p.add_argument("--json-out", type=Path, default=None, help="Write structured JSON array of generated RCAs")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = IncidentStore(args.db)
    engine = MultiTierRCAEngine(prefer_offline=args.offline)
    notifier = RCANotifier()

    all_reports: list[RCAReport] = []

    if args.demo:
        root = Path(__file__).resolve().parent
        sample_json = root / "samples" / "sample_dns_outage.json"
        sample_pcap = root / "samples" / "sample_firewall_drop.pcap"
        print(f"Running AI-NOC Triage Demo | Active Engine: {engine.active_provider()}")
        if sample_json.is_file():
            anomalies = ingest_json_telemetry(sample_json)
            all_reports.extend(
                _process_anomalies(anomalies, engine, store, notifier, sample_json.stat().st_size * 4, args.export_md)
            )
        if sample_pcap.is_file():
            pkt_cnt, anomalies = analyze_pcap_anomalies(sample_pcap)
            print(f"\nParsed {pkt_cnt} packets from {sample_pcap.name} -> {len(anomalies)} anomaly(ies) escalated to Tier-2")
            all_reports.extend(
                _process_anomalies(anomalies, engine, store, notifier, sample_pcap.stat().st_size * 8, args.export_md)
            )

    if args.triage_pcap:
        pkt_cnt, anomalies = analyze_pcap_anomalies(args.triage_pcap)
        print(f"Parsed {pkt_cnt} packets from {args.triage_pcap.name} -> {len(anomalies)} anomaly(ies)")
        all_reports.extend(
            _process_anomalies(anomalies, engine, store, notifier, args.triage_pcap.stat().st_size * 8, args.export_md)
        )

    if args.triage_json:
        anomalies = ingest_json_telemetry(args.triage_json)
        all_reports.extend(
            _process_anomalies(anomalies, engine, store, notifier, args.triage_json.stat().st_size * 4, args.export_md)
        )

    if args.probe:
        raw_res, anomalies = asyncio.run(probe_endpoints_async(args.probe))
        raw_size = len(json.dumps(raw_res))
        all_reports.extend(_process_anomalies(anomalies, engine, store, notifier, raw_size * 4, args.export_md))

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps([r.to_dict() for r in all_reports], indent=2), encoding="utf-8")
        print(f"Saved JSON RCA bundle -> {args.json_out.resolve()}")

    metrics = store.get_metrics()
    print(
        f"\nStore Summary: {metrics['total_incidents']} total incident(s) | "
        f"SEV-1: {metrics['sev1_count']} | Tier-1 Token Savings: {metrics['token_savings_pct']}%"
    )

    if args.dashboard:
        srv = start_console_server(store, host="127.0.0.1", port=args.dashboard_port)
        print(f"AI-NOC Triage Web Console running at http://127.0.0.1:{args.dashboard_port} (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            srv.shutdown()
            srv.server_close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
