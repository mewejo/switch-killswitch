"""Sends the SNMPv3 SET that administratively shuts a port, with
per-port debounce, a global rate limit, and read-back verification."""

from __future__ import annotations

import asyncio
import logging
import time

from pysnmp.hlapi.v3arch.asyncio import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    set_cmd,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
)
from pysnmp.proto.rfc1902 import Integer

from .config import Config, SwitchConfig
from .notify import Notifier, make_event

log = logging.getLogger("killswitch.actor")

IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
ADMIN_DOWN = 2

AUTH_MAP = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
}
PRIV_MAP = {
    "DES": usmDESPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES128": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol,
    "AES256": usmAesCfb256Protocol,
}


class PortShutdownActor:
    def __init__(self, cfg: Config, notifier: Notifier | None = None) -> None:
        self._cfg = cfg
        self._notifier = notifier
        self._engine = SnmpEngine()
        self._last_action: dict[tuple[str, int], float] = {}
        self._action_times: list[float] = []  # global rate-limit window

    async def _notify(self, kind: str, switch: SwitchConfig, ifindex: int,
                      reason: str, verified: bool | None = None) -> None:
        if self._notifier is not None:
            await self._notifier.notify(
                make_event(kind, switch.name, switch.ip, ifindex, reason, verified)
            )

    def _usm(self) -> UsmUserData:
        c = self._cfg.snmp
        return UsmUserData(
            c.user,
            authKey=c.auth_password,
            privKey=c.priv_password,
            authProtocol=AUTH_MAP[c.auth_protocol],
            privProtocol=PRIV_MAP[c.priv_protocol],
        )

    def _debounced(self, switch: SwitchConfig, ifindex: int) -> bool:
        now = time.monotonic()
        last = self._last_action.get((switch.ip, ifindex))
        if last is not None and now - last < switch.debounce_seconds:
            return True
        return False

    def _rate_limited(self) -> bool:
        now = time.monotonic()
        window = self._cfg.rate_limit.per_seconds
        self._action_times = [t for t in self._action_times if now - t < window]
        return len(self._action_times) >= self._cfg.rate_limit.max_actions

    async def shutdown_port(self, switch: SwitchConfig, ifindex: int,
                            reason: str = "link down") -> bool:
        """Set ifAdminStatus.<ifindex> = down(2). Returns True on confirmed success."""
        key = (switch.ip, ifindex)
        if self._debounced(switch, ifindex):
            log.info(
                "suppressed (debounce %.0fs) switch=%s ifindex=%d",
                switch.debounce_seconds, switch.name, ifindex,
            )
            return False
        if self._rate_limited():
            log.error(
                "GLOBAL RATE LIMIT hit (%d actions / %.0fs) — refusing action "
                "switch=%s ifindex=%d. Possible trap storm or abuse.",
                self._cfg.rate_limit.max_actions, self._cfg.rate_limit.per_seconds,
                switch.name, ifindex,
            )
            await self._notify("rate_limited", switch, ifindex, reason)
            return False
        # Mark before sending so retries of a failing SET are also debounced.
        self._last_action[key] = time.monotonic()
        self._action_times.append(time.monotonic())

        oid = f"{IF_ADMIN_STATUS}.{ifindex}"

        # Redundancy: standbys wait for the primary instance to act first...
        if self._cfg.standby_delay > 0:
            await asyncio.sleep(self._cfg.standby_delay)
        # ...and every instance stands down if the port is already shut
        # (by a peer instance, or deliberately by an admin).
        if await self._read_admin_status(switch, ifindex, oid) == ADMIN_DOWN:
            log.info(
                "port already admin-down (peer instance or manual) — standing down "
                "switch=%s ifindex=%d", switch.name, ifindex,
            )
            return False
        log.warning(
            "ACTION: setting ifAdminStatus.%d = down(2) on switch=%s (%s)",
            ifindex, switch.name, switch.ip,
        )
        target = await UdpTransportTarget.create(
            (switch.ip, switch.snmp_port), timeout=5, retries=1
        )
        error_indication, error_status, error_index, var_binds = await set_cmd(
            self._engine,
            self._usm(),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(oid), Integer(ADMIN_DOWN)),
        )
        if error_indication:
            log.error("SET failed switch=%s ifindex=%d: %s", switch.name, ifindex, error_indication)
            await self._notify("kill_failed", switch, ifindex,
                               f"{reason}; SET failed: {error_indication}", verified=False)
            return False
        if error_status:
            log.error(
                "SET rejected switch=%s ifindex=%d: %s at %s",
                switch.name, ifindex, error_status.prettyPrint(),
                error_index and var_binds[int(error_index) - 1][0] or "?",
            )
            await self._notify("kill_failed", switch, ifindex,
                               f"{reason}; SET rejected: {error_status.prettyPrint()}",
                               verified=False)
            return False

        ok = await self._verify(switch, ifindex, oid)
        if ok:
            await self._notify("port_killed", switch, ifindex, reason, verified=True)
        else:
            await self._notify("kill_failed", switch, ifindex,
                               f"{reason}; SET sent but verification failed", verified=False)
        return ok

    async def _read_admin_status(self, switch: SwitchConfig, ifindex: int, oid: str) -> int | None:
        """Current ifAdminStatus, or None if unreadable (then we act anyway)."""
        target = await UdpTransportTarget.create(
            (switch.ip, switch.snmp_port), timeout=5, retries=1
        )
        error_indication, error_status, _, var_binds = await get_cmd(
            self._engine, self._usm(), target, ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        if error_indication or error_status:
            log.warning(
                "pre-action admin-status read failed switch=%s ifindex=%d: %s — acting anyway",
                switch.name, ifindex, error_indication or error_status.prettyPrint(),
            )
            return None
        try:
            return int(var_binds[0][1])
        except (ValueError, TypeError):
            return None

    async def _verify(self, switch: SwitchConfig, ifindex: int, oid: str) -> bool:
        target = await UdpTransportTarget.create(
            (switch.ip, switch.snmp_port), timeout=5, retries=1
        )
        error_indication, error_status, _, var_binds = await get_cmd(
            self._engine, self._usm(), target, ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        if error_indication or error_status:
            log.error(
                "SET sent but verification read failed switch=%s ifindex=%d: %s",
                switch.name, ifindex, error_indication or error_status.prettyPrint(),
            )
            return False
        value = var_binds[0][1]
        try:
            ok = int(value) == ADMIN_DOWN
        except (ValueError, TypeError):
            ok = False
        if ok:
            log.warning(
                "CONFIRMED: ifAdminStatus.%d = down(2) on switch=%s. "
                "Port stays down until manually re-enabled.",
                ifindex, switch.name,
            )
        else:
            log.error(
                "VERIFY MISMATCH: switch=%s ifindex=%d reports ifAdminStatus=%s after SET",
                switch.name, ifindex, value.prettyPrint(),
            )
        return ok
