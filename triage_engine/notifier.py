"""Webhook dispatcher sending structured AI RCA cards to Discord, Slack & Telegram."""

from __future__ import annotations

import json
import os
from typing import Any
from urllib import request as url_request

from .models import RCAReport


class RCANotifier:
    """Delivers structured AI-generated RCA alerts to configured chatOps channels."""

    def __init__(
        self,
        discord_url: str | None = None,
        slack_url: str | None = None,
        telegram_token: str | None = None,
        telegram_chat_id: str | None = None,
        timeout: float = 8.0,
    ) -> None:
        self.discord_url = (discord_url if discord_url is not None else os.environ.get("DISCORD_WEBHOOK_URL", "")).strip()
        self.slack_url = (slack_url if slack_url is not None else os.environ.get("SLACK_WEBHOOK_URL", "")).strip()
        self.telegram_token = (telegram_token if telegram_token is not None else os.environ.get("TELEGRAM_BOT_TOKEN", "")).strip()
        self.telegram_chat_id = (telegram_chat_id if telegram_chat_id is not None else os.environ.get("TELEGRAM_CHAT_ID", "")).strip()
        self.timeout = timeout

    def configured_channels(self) -> list[str]:
        ch: list[str] = []
        if self.discord_url:
            ch.append("discord")
        if self.slack_url:
            ch.append("slack")
        if self.telegram_token and self.telegram_chat_id:
            ch.append("telegram")
        return ch

    def build_discord_payload(self, rca: RCAReport) -> dict[str, Any]:
        colors = {"SEV-1": 0xEF4444, "SEV-2": 0xF59E0B, "SEV-3": 0x38BDF8}
        top_steps = "\n".join(f"{i}. {s}" for i, s in enumerate(rca.remediation_steps[:3], 1))
        return {
            "username": "AI NOC Triage Bot",
            "embeds": [
                {
                    "title": f"[{rca.severity} · {rca.osi_layer}] {rca.title}",
                    "description": rca.root_cause,
                    "color": colors.get(rca.severity, 0x38BDF8),
                    "fields": [
                        {"name": "Incident ID", "value": f"`{rca.incident_id}`", "inline": True},
                        {"name": "Target", "value": f"`{rca.target}`", "inline": True},
                        {"name": "AI Engine", "value": f"`{rca.engine_used}` ({rca.confidence:.0%})", "inline": True},
                        {"name": "Recommended Remediation", "value": top_steps or "Inspect target", "inline": False},
                    ],
                    "footer": {"text": f"Tier-1 filtered ~{rca.raw_tokens_avoided_est} raw tokens"},
                    "timestamp": rca.timestamp_utc,
                }
            ],
        }

    def build_slack_payload(self, rca: RCAReport) -> dict[str, Any]:
        colors = {"SEV-1": "#EF4444", "SEV-2": "#F59E0B", "SEV-3": "#38BDF8"}
        steps = "\n".join(f"• {s}" for s in rca.remediation_steps[:3])
        return {
            "attachments": [
                {
                    "color": colors.get(rca.severity, "#38BDF8"),
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": (
                                    f"*[{rca.severity} | {rca.osi_layer}] {rca.title}*\n"
                                    f"*ID:* `{rca.incident_id}` | *Target:* `{rca.target}` | *Engine:* `{rca.engine_used}`\n"
                                    f"*Root Cause:* {rca.root_cause}\n"
                                    f"*Top Remediation:*\n{steps}"
                                ),
                            },
                        }
                    ],
                }
            ]
        }

    def build_telegram_payload(self, rca: RCAReport) -> dict[str, Any]:
        steps = "\n".join(f"{i}. {s}" for i, s in enumerate(rca.remediation_steps[:3], 1))
        text = (
            f"<b>AI NOC TRIAGE [{rca.severity} / {rca.osi_layer}]</b>\n"
            f"<b>{rca.title}</b>\n"
            f"<b>ID:</b> <code>{rca.incident_id}</code> | <b>Target:</b> <code>{rca.target}</code>\n"
            f"<b>Root Cause:</b> {rca.root_cause}\n\n"
            f"<b>Remediation:</b>\n{steps}"
        )
        return {"chat_id": self.telegram_chat_id, "text": text, "parse_mode": "HTML"}

    def _post(self, url: str, payload: dict[str, Any]) -> tuple[bool, str]:
        req = url_request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "AI-NOC-Triage-Bot/1.0"},
            method="POST",
        )
        try:
            with url_request.urlopen(req, timeout=self.timeout) as resp:
                return (200 <= resp.status < 300), f"HTTP {resp.status}"
        except Exception as exc:
            return False, str(exc)

    def send(self, rca: RCAReport) -> dict[str, tuple[bool, str]]:
        out: dict[str, tuple[bool, str]] = {}
        if self.discord_url:
            out["discord"] = self._post(self.discord_url, self.build_discord_payload(rca))
        if self.slack_url:
            out["slack"] = self._post(self.slack_url, self.build_slack_payload(rca))
        if self.telegram_token and self.telegram_chat_id:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            out["telegram"] = self._post(url, self.build_telegram_payload(rca))
        return out
