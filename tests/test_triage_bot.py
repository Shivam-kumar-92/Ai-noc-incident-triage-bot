"""Automated unit & integration tests for AI-Powered NOC Incident Triage Bot."""

from __future__ import annotations

import asyncio
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib import request as url_request

from triage_engine.dashboard import start_console_server
from triage_engine.llm_rca import MultiTierRCAEngine
from triage_engine.models import TelemetryAnomaly
from triage_engine.notifier import RCANotifier
from triage_engine.storage import IncidentStore
from triage_engine.telemetry import analyze_pcap_anomalies, ingest_json_telemetry, probe_endpoints_async

ROOT = Path(__file__).resolve().parent.parent


class TestAINOCTriageBot(unittest.TestCase):
    def test_pcap_forensic_triage_and_markdown_export(self) -> None:
        pcap = ROOT / "samples" / "sample_firewall_drop.pcap"
        pkt_cnt, anomalies = analyze_pcap_anomalies(pcap)
        self.assertGreaterEqual(pkt_cnt, 10)
        categories = {a.category for a in anomalies}
        self.assertIn("TCP_FIREWALL_DROP", categories)
        self.assertIn("TCP_PORT_CLOSED", categories)

        engine = MultiTierRCAEngine(prefer_offline=True)
        rca = engine.triage(anomalies[0], raw_context_bytes=8192)
        self.assertEqual(rca.engine_used, "heuristic-offline")
        self.assertGreater(len(rca.remediation_steps), 0)
        self.assertIn("## Root Cause Analysis", rca.to_markdown())

    def test_json_telemetry_ingestion(self) -> None:
        sample = ROOT / "samples" / "sample_dns_outage.json"
        anomalies = ingest_json_telemetry(sample)
        self.assertEqual(len(anomalies), 2)
        cats = {a.category for a in anomalies}
        self.assertEqual(cats, {"DNS_FAILURE", "ARP_SPOOFING"})

    def test_async_live_probe_detects_closed_port_and_ignores_open_port(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        open_port = srv.getsockname()[1]

        def accept_once() -> None:
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                pass

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unused:
            unused.bind(("127.0.0.1", 0))
            closed_port = unused.getsockname()[1]

        t = threading.Thread(target=accept_once, daemon=True)
        t.start()
        try:
            _raw, anomalies = asyncio.run(
                probe_endpoints_async([f"127.0.0.1:{open_port},{closed_port}"], timeout=4.0)
            )
        finally:
            t.join(timeout=2.0)
            srv.close()

        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].category, "TCP_PORT_CLOSED")
        self.assertEqual(anomalies[0].metrics["closed_ports"], [closed_port])

    def test_mocked_gemini_provider_routing(self) -> None:
        anomaly = TelemetryAnomaly(
            source_type="pcap",
            source_ref="test.pcap",
            category="DNS_FAILURE",
            osi_layer="L7",
            severity="SEV-2",
            target="10.20.1.10",
            summary="SERVFAIL from internal resolver",
            evidence=("Frame #6 SERVFAIL",),
        )
        mocked_json = {
            "title": "Internal DNS Forwarder Failure",
            "root_cause": "Upstream forwarder unreachable from 10.20.1.10.",
            "blast_radius": "External SaaS resolution failing for LAN hosts.",
            "remediation_steps": ["Check UDP/TCP 53 egress", "Reload BIND9 forwarders"],
            "verification_commands": ["dig @10.20.1.10 example.com"],
            "confidence": 0.97,
        }
        engine = MultiTierRCAEngine(gemini_api_key="fake-test-key", prefer_offline=False)
        with patch("triage_engine.llm_rca._call_gemini", return_value=mocked_json):
            rca = engine.triage(anomaly, raw_context_bytes=6000)

        self.assertEqual(rca.engine_used, "gemini")
        self.assertEqual(rca.title, "Internal DNS Forwarder Failure")
        self.assertAlmostEqual(rca.confidence, 0.97)

    def test_sqlite_store_notifier_and_web_console(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = IncidentStore(Path(tmp) / "incidents.db")
            engine = MultiTierRCAEngine(prefer_offline=True)
            anomalies = ingest_json_telemetry(ROOT / "samples" / "sample_dns_outage.json")
            rca = engine.triage(anomalies[0], raw_context_bytes=8192)
            store.save_report(rca)

            metrics = store.get_metrics()
            self.assertEqual(metrics["total_incidents"], 1)
            self.assertGreater(metrics["token_savings_pct"], 50.0)

            notifier = RCANotifier(
                discord_url="https://discord.example/hook",
                slack_url="https://slack.example/hook",
                telegram_token="123:abc",
                telegram_chat_id="-1001",
            )
            self.assertIn("embeds", notifier.build_discord_payload(rca))
            self.assertIn("attachments", notifier.build_slack_payload(rca))
            self.assertIn("chat_id", notifier.build_telegram_payload(rca))

            srv = start_console_server(store, host="127.0.0.1", port=0)
            port = srv.server_address[1]
            try:
                with url_request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3) as resp:
                    self.assertEqual(resp.status, 200)
                with url_request.urlopen(f"http://127.0.0.1:{port}/api/incidents", timeout=3) as resp:
                    body = json.loads(resp.read())
                    self.assertEqual(len(body["incidents"]), 1)
            finally:
                srv.shutdown()
                srv.server_close()


if __name__ == "__main__":
    unittest.main()
