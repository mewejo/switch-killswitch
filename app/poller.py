"""Link-down detection by SNMPv3 polling.

Polling (not traps) is the detection mechanism by design: it needs no
inbound ports, survives trap loss, and some switch firmware logs trap
events without ever transmitting them.

Each poll reads two columns per allowlisted port in a single GET:

  ifOperStatus  (1.3.6.1.2.1.2.2.1.8)  — current link state
  ifLastChange  (1.3.6.1.2.1.2.2.1.9)  — sysUpTime of the last state change

Triggers:
  - up -> down transition of ifOperStatus.
  - FLAP: ifOperStatus reads up on consecutive polls but ifLastChange moved —
    the link dropped and recovered inside one poll window (e.g. a quick
    device swap). Without this a fast replug would go unnoticed.
    This also fires after a switch reboot (ifLastChange resets), which is
    the safe direction for a killswitch: a power cycle that would otherwise
    silently clear an unsaved admin-down gets re-killed.

A port first seen in the down state is baseline, not a trigger, so
restarting the service against an already-killed port does nothing.
"""

from __future__ import annotations

import asyncio
import logging

from pysnmp.hlapi.v3arch.asyncio import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
)

from .actor import AUTH_MAP, PRIV_MAP, PortShutdownActor
from .config import Config, SwitchConfig

log = logging.getLogger("killswitch.poller")

IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_LAST_CHANGE = "1.3.6.1.2.1.2.2.1.9"
UP = 1
DOWN_STATES = {2, 7}  # down, lowerLayerDown


class LinkPoller:
    def __init__(self, cfg: Config, actor: PortShutdownActor) -> None:
        self._cfg = cfg
        self._actor = actor
        self._engine = SnmpEngine()
        # (switch_ip, ifindex) -> (oper, last_change)
        self._last: dict[tuple[str, int], tuple[int, int]] = {}
        self._tasks: list[asyncio.Task] = []

    def start(self) -> None:
        for sw in self._cfg.switches.values():
            self._tasks.append(asyncio.get_event_loop().create_task(self._poll_switch(sw)))
        log.info("link poller started (interval %.2fs)", self._cfg.poll_interval)

    def _usm(self) -> UsmUserData:
        c = self._cfg.snmp
        return UsmUserData(
            c.user,
            authKey=c.auth_password,
            privKey=c.priv_password,
            authProtocol=AUTH_MAP[c.auth_protocol],
            privProtocol=PRIV_MAP[c.priv_protocol],
        )

    async def _poll_switch(self, switch: SwitchConfig) -> None:
        ifindexes = sorted(switch.allowed_ifindexes)
        oids = [ObjectType(ObjectIdentity(f"{IF_OPER_STATUS}.{i}")) for i in ifindexes]
        oids += [ObjectType(ObjectIdentity(f"{IF_LAST_CHANGE}.{i}")) for i in ifindexes]
        fail_streak = 0
        while True:
            try:
                target = await UdpTransportTarget.create(
                    (switch.ip, switch.snmp_port), timeout=2, retries=0
                )
                error_indication, error_status, _, var_binds = await get_cmd(
                    self._engine, self._usm(), target, ContextData(), *oids
                )
                if error_indication or error_status:
                    fail_streak += 1
                    if fail_streak in (3, 30) or fail_streak % 300 == 0:
                        log.warning(
                            "poll failing (streak %d) switch=%s: %s",
                            fail_streak, switch.name,
                            error_indication or error_status.prettyPrint(),
                        )
                else:
                    fail_streak = 0
                    self._evaluate(switch, ifindexes, var_binds)
            except Exception:
                log.exception("poll crashed for switch=%s", switch.name)
            await asyncio.sleep(self._cfg.poll_interval)

    def _evaluate(self, switch: SwitchConfig, ifindexes: list[int], var_binds) -> None:
        n = len(ifindexes)
        for pos, ifindex in enumerate(ifindexes):
            try:
                oper = int(var_binds[pos][1])
                last_change = int(var_binds[n + pos][1])
            except (ValueError, TypeError):
                log.warning(
                    "unparseable poll values for switch=%s ifindex=%d", switch.name, ifindex
                )
                continue
            key = (switch.ip, ifindex)
            prev = self._last.get(key)
            self._last[key] = (oper, last_change)
            if prev is None:
                log.info(
                    "baseline switch=%s ifindex=%d oper=%d", switch.name, ifindex, oper
                )
                continue
            prev_oper, prev_change = prev
            if prev_oper == UP and oper in DOWN_STATES:
                reason = "link transition up->down"
            elif prev_oper == UP and oper == UP and last_change != prev_change:
                reason = "link flapped between polls (or agent restarted)"
            else:
                continue
            log.warning(
                "POLL MATCH: %s — switch=%s ifindex=%d", reason, switch.name, ifindex
            )
            task = asyncio.get_event_loop().create_task(
                self._actor.shutdown_port(switch, ifindex, reason)
            )
            task.add_done_callback(lambda t: t.exception())
