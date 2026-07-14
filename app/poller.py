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

Arming: links commonly bounce once shortly after an admin re-enable
(autonegotiation restart, PoE device init, device-side interface reset).
A port must therefore be continuously up for `arm_delay` before it is on
the instant trigger; while still settling, a drop must persist
`unarmed_persist` seconds to fire — bring-up blips are forgiven, a real
pull during the window still kills, just a few seconds later.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Callable

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

IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_LAST_CHANGE = "1.3.6.1.2.1.2.2.1.9"
UP = 1
DOWN_STATES = {2, 7}  # down, lowerLayerDown

# Reports (switch, ifindex, oper_status, admin_status|None, last_change) each
# poll. Purely for surfacing state (e.g. the Home Assistant MQTT entity);
# link-down detection uses only oper/last_change.
StateSink = Callable[[SwitchConfig, int, int, int | None, int], None]


@dataclass
class PortState:
    oper: int
    last_change: int
    up_since: float | None      # monotonic time the current up-streak began
    pending_since: float | None = None  # unarmed down observed at this time


class LinkPoller:
    def __init__(self, cfg: Config, actor: PortShutdownActor,
                 state_sink: StateSink | None = None) -> None:
        self._cfg = cfg
        self._actor = actor
        # Optional observer of per-port status, read alongside link state each
        # poll. When set, ifAdminStatus is polled too so the sink sees it.
        self._state_sink = state_sink
        self._engine = SnmpEngine()
        self._state: dict[tuple[str, int], PortState] = {}
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
        # Only read ifAdminStatus when someone is watching (keeps the default
        # detection GET, and its VACM view, byte-for-byte unchanged).
        if self._state_sink is not None:
            oids += [ObjectType(ObjectIdentity(f"{IF_ADMIN_STATUS}.{i}")) for i in ifindexes]
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
        now = time.monotonic()
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
            admin = None
            if self._state_sink is not None:
                try:
                    admin = int(var_binds[2 * n + pos][1])
                except (ValueError, TypeError, IndexError):
                    admin = None  # reporting is best-effort; detection is unaffected
            key = (switch.ip, ifindex)
            state = self._state.get(key)
            if state is None:
                self._state[key] = PortState(
                    oper, last_change, up_since=now if oper == UP else None
                )
                log.info("baseline switch=%s ifindex=%d oper=%d", switch.name, ifindex, oper)
            else:
                self._transition(switch, ifindex, state, oper, last_change, now)
                state.oper = oper
                state.last_change = last_change
            if self._state_sink is not None:
                try:
                    self._state_sink(switch, ifindex, oper, admin, last_change)
                except Exception:
                    log.exception("state sink failed switch=%s ifindex=%d", switch.name, ifindex)

    def _transition(self, switch: SwitchConfig, ifindex: int, state: PortState,
                    oper: int, last_change: int, now: float) -> None:
        armed = (
            state.up_since is not None
            and now - state.up_since >= self._cfg.arm_delay
        )
        if oper == UP:
            if state.oper == UP and last_change != state.last_change:
                # link dropped and recovered entirely between two polls
                if armed:
                    self._kill(switch, ifindex,
                               "link flapped between polls (or agent restarted)")
                else:
                    log.info(
                        "forgiven: bring-up blip while settling (up %.1fs < arm %.0fs) "
                        "switch=%s ifindex=%d — settle timer restarted",
                        now - (state.up_since or now), self._cfg.arm_delay,
                        switch.name, ifindex,
                    )
                state.up_since = now  # a bounce restarts the settle window
            elif state.oper != UP:
                if state.pending_since is not None:
                    log.info(
                        "forgiven: link back up %.1fs after unarmed drop switch=%s ifindex=%d",
                        now - state.pending_since, switch.name, ifindex,
                    )
                state.up_since = now
            state.pending_since = None
        elif oper in DOWN_STATES:
            if state.oper == UP:
                if armed:
                    self._kill(switch, ifindex, "link transition up->down")
                    state.up_since = None
                else:
                    state.pending_since = now
                    log.warning(
                        "link down while settling (up %.1fs < arm %.0fs) — kill fires "
                        "if still down in %.0fs switch=%s ifindex=%d",
                        now - (state.up_since or now), self._cfg.arm_delay,
                        self._cfg.unarmed_persist, switch.name, ifindex,
                    )
            elif (
                state.pending_since is not None
                and now - state.pending_since >= self._cfg.unarmed_persist
            ):
                state.pending_since = None
                state.up_since = None
                self._kill(switch, ifindex, "sustained link-down during settle window")

    def _kill(self, switch: SwitchConfig, ifindex: int, reason: str) -> None:
        log.warning("POLL MATCH: %s — switch=%s ifindex=%d", reason, switch.name, ifindex)
        task = asyncio.get_event_loop().create_task(
            self._actor.shutdown_port(switch, ifindex, reason)
        )
        task.add_done_callback(lambda t: t.exception())
