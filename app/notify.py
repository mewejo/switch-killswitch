"""Notification engine: email (SMTP) and Home Assistant (event bus).

Events emitted by the actor:
  port_killed   — ifAdminStatus confirmed down after a kill
  kill_failed   — SET failed/rejected or read-back verification mismatched
  rate_limited  — global rate limit refused an action (possible storm/abuse)
  port_restored — a port was deliberately re-enabled (e.g. Home Assistant toggle)
  port_disabled — a port was deliberately disabled on demand (not a link-loss kill)

Design constraints:
  - Notification failure must never block or break the kill path: every
    channel send is wrapped, logged on error, and bounded by a timeout.
  - Blocking I/O (smtplib, urllib) runs in worker threads via asyncio.to_thread.
"""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage

from .config import Config, EmailConfig, HomeAssistantConfig

log = logging.getLogger("killswitch.notify")

SEND_TIMEOUT = 10.0


def make_event(kind: str, switch_name: str, switch_ip: str, ifindex: int,
               reason: str, verified: bool | None = None) -> dict:
    event = {
        "event": kind,
        "switch": switch_name,
        "switch_ip": switch_ip,
        "ifindex": ifindex,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if verified is not None:
        event["verified"] = verified
    return event


def make_cluster_event(kind: str, node: str, peer: str | None = None,
                       master: str | None = None, online: list[str] | None = None,
                       expected: int | None = None, degraded: bool = False) -> dict:
    """Build a cluster-membership event (peer_up/peer_down/role changes).

    Node-oriented rather than port-oriented, but goes through the same channels
    as a kill so redundancy changes land in the same inbox as security events.
    """
    return {
        "event": kind,
        "node": node,
        "peer": peer or "",
        "master": master or "",
        "online": online or [],
        "online_count": len(online or []),
        "expected": expected,
        "degraded": degraded,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


class _SafeDict(dict):
    """Formatting helper: an unknown {field} renders as '?' instead of raising."""

    def __missing__(self, key: str) -> str:
        return "?"


class Notifier:
    def __init__(self, cfg: Config) -> None:
        self._email = cfg.notifications.email
        self._ha = cfg.notifications.home_assistant

    @property
    def channels(self) -> list[str]:
        names = []
        if self._email:
            names.append("email")
        if self._ha:
            names.append("home_assistant")
        return names

    async def notify(self, event: dict) -> None:
        senders = []
        if self._email:
            senders.append(self._guard("email", self._send_email(event)))
        if self._ha:
            senders.append(self._guard("home_assistant", self._send_home_assistant(event)))
        if senders:
            await asyncio.gather(*senders)

    @staticmethod
    async def _guard(channel: str, coro) -> None:
        try:
            await asyncio.wait_for(coro, timeout=SEND_TIMEOUT + 5)
            log.info("notified via %s", channel)
        except Exception as exc:
            log.error("notification via %s failed: %s", channel, exc)

    # ---------------- email ----------------

    async def _send_email(self, event: dict) -> None:
        await asyncio.to_thread(self._send_email_sync, self._email, event)

    @staticmethod
    def _send_email_sync(cfg: EmailConfig, event: dict) -> None:
        msg = EmailMessage()
        headline = {
            "port_killed": "port {ifindex} KILLED on {switch}",
            "kill_failed": "FAILED to kill port {ifindex} on {switch}",
            "rate_limited": "rate limit hit — kill refused for port {ifindex} on {switch}",
            "port_restored": "port {ifindex} RE-ENABLED on {switch}",
            "port_disabled": "port {ifindex} manually disabled on {switch}",
            "peer_down": "peer {peer} is DOWN — redundancy degraded (online: {online_count})",
            "peer_up": "peer {peer} is back UP (online: {online_count})",
            "became_master": "node {node} is now MASTER of the killswitch cluster",
            "resigned_master": "node {node} handed master to {peer}",
        }.get(event["event"], "{event}").format_map(_SafeDict(event))
        msg["Subject"] = f"{cfg.subject_prefix} {headline}"
        msg["From"] = cfg.sender
        msg["To"] = ", ".join(cfg.recipients)
        body = "\n".join(f"{k}: {v}" for k, v in event.items())
        if event["event"] == "port_killed":
            body += "\n\nThe port stays down until manually re-enabled on the switch."
        msg.set_content(body)

        if cfg.security == "ssl":
            smtp = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=SEND_TIMEOUT)
        else:
            smtp = smtplib.SMTP(cfg.host, cfg.port, timeout=SEND_TIMEOUT)
        with smtp:
            if cfg.security == "starttls":
                smtp.starttls()
            if cfg.username:
                smtp.login(cfg.username, cfg.password)
            smtp.send_message(msg)

    # ---------------- home assistant ----------------

    async def _send_home_assistant(self, event: dict) -> None:
        await asyncio.to_thread(self._send_home_assistant_sync, self._ha, event)

    @staticmethod
    def _send_home_assistant_sync(cfg: HomeAssistantConfig, event: dict) -> None:
        url = f"{cfg.base_url}/api/events/{cfg.event_type}"
        request = urllib.request.Request(
            url,
            data=json.dumps(event).encode(),
            headers={
                "Authorization": f"Bearer {cfg.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=SEND_TIMEOUT) as response:
            if response.status >= 300:
                raise RuntimeError(f"HA API returned HTTP {response.status}")
