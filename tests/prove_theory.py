"""End-to-end proof of the polling killswitch, all on localhost.

Topology:
  [fake switch agent :10161]  <--SNMPv3 GET (poll) / SET (kill)--  [service]
  [SMTP sink :10250] and [fake Home Assistant API :10251]  <--notifications--

The fake agent exposes ifOperStatus/ifLastChange (read) and a writable
ifAdminStatus for port 24. The harness manipulates the fake port's state
and asserts the service reacts correctly.

Scenarios:
  1. oper up -> down                    -> ifAdminStatus.24 set to down(2), verified
     + email received and HA event fired for the kill
  2. repeat drop within debounce window -> suppressed, still exactly one action
  3. already-down port at baseline      -> covered by startup (port starts up; implicit)
  4. flap: oper stays up but ifLastChange moves -> kill fires (fast-replug defence)

Run:  .venv/bin/python -m tests.prove_theory
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config as ecfg
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto.rfc1902 import Integer, TimeTicks

from app.actor import PortShutdownActor
from app.config import load_config, load_config_from_env
from app.notify import Notifier
from app.poller import LinkPoller

USER = "portshut-user"
AUTH_PASS = "authpass-1234"
PRIV_PASS = "privpass-1234"
AGENT_PORT = 10161
SMTP_PORT = 10250
HA_PORT = 10251
HA_TOKEN = "test-ha-token-1234"
POLL_INTERVAL = 0.3
DEBOUNCE = 6.0  # must exceed the settle sleeps between scenarios 1 and 2

log = logging.getLogger("prove")


# --------------------------------------------------------------------------
# Notification sinks: minimal SMTP server and fake Home Assistant API
# --------------------------------------------------------------------------
class SmtpSink:
    """Just enough SMTP to make smtplib happy; records message bodies."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    async def serve(self) -> None:
        await asyncio.start_server(self._handle, "127.0.0.1", SMTP_PORT)

    async def _handle(self, reader, writer) -> None:
        writer.write(b"220 sink ESMTP\r\n")
        data_lines: list[bytes] = []
        in_data = False
        while line := await reader.readline():
            if in_data:
                if line == b".\r\n":
                    self.messages.append(b"".join(data_lines).decode(errors="replace"))
                    in_data = False
                    writer.write(b"250 ok\r\n")
                else:
                    data_lines.append(line)
                continue
            verb = line[:4].upper()
            if verb in (b"EHLO", b"HELO"):
                writer.write(b"250-sink\r\n250 8BITMIME\r\n")
            elif verb == b"DATA":
                in_data = True
                data_lines = []
                writer.write(b"354 go\r\n")
            elif verb == b"QUIT":
                writer.write(b"221 bye\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"250 ok\r\n")
            await writer.drain()
        writer.close()


class FakeHomeAssistant:
    """Records POSTs to /api/events/<type>, checking the bearer token."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    async def serve(self) -> None:
        await asyncio.start_server(self._handle, "127.0.0.1", HA_PORT)

    async def _handle(self, reader, writer) -> None:
        request_line = (await reader.readline()).decode()
        headers = {}
        while (line := (await reader.readline()).decode().strip()):
            k, _, v = line.partition(":")
            headers[k.lower()] = v.strip()
        body = await reader.readexactly(int(headers.get("content-length", 0)))
        method, path, _ = request_line.split()
        authed = headers.get("authorization") == f"Bearer {HA_TOKEN}"
        if method == "POST" and path.startswith("/api/events/") and authed:
            self.events.append((path.removeprefix("/api/events/"), json.loads(body)))
            payload = b'{"message": "Event fired."}'
            status = b"HTTP/1.1 200 OK\r\n"
        else:
            payload = b'{"message": "no"}'
            status = b"HTTP/1.1 401 Unauthorized\r\n"
        writer.write(status
                     + b"Content-Type: application/json\r\n"
                     + f"Content-Length: {len(payload)}\r\n\r\n".encode()
                     + payload)
        await writer.drain()
        writer.close()


# --------------------------------------------------------------------------
# Fake switch: SNMPv3 authPriv agent, port 24 with oper/lastchange/admin
# --------------------------------------------------------------------------
class FakePort:
    def __init__(self, mib_builder, ifindex: int):
        MibScalar, MibScalarInstance = mib_builder.import_symbols(
            "SNMPv2-SMI", "MibScalar", "MibScalarInstance"
        )
        base = (1, 3, 6, 1, 2, 1, 2, 2, 1)
        self.admin = MibScalarInstance(base + (7,), (ifindex,), Integer(1))
        self.oper = MibScalarInstance(base + (8,), (ifindex,), Integer(1))
        self.last_change = MibScalarInstance(base + (9,), (ifindex,), TimeTicks(1000))
        cols = [
            MibScalar(base + (7,), Integer()).setMaxAccess("read-write"),
            MibScalar(base + (8,), Integer()).setMaxAccess("read-only"),
            MibScalar(base + (9,), TimeTicks()).setMaxAccess("read-only"),
        ]
        mib_builder.export_symbols(
            f"__IFKILL-MIB-{ifindex}", *cols, self.admin, self.oper, self.last_change
        )

    def set_link(self, up: bool) -> None:
        self.oper.syntax = Integer(1 if up else 2)
        self.last_change.syntax = TimeTicks(int(self.last_change.syntax) + 100)

    def flap_invisibly(self) -> None:
        """Simulate a drop+recover that happens entirely between two polls."""
        self.last_change.syntax = TimeTicks(int(self.last_change.syntax) + 100)


def start_fake_switch_agent() -> FakePort:
    agent = engine.SnmpEngine()
    ecfg.add_transport(
        agent,
        udp.DOMAIN_NAME + (2,),
        udp.UdpTransport().open_server_mode(("127.0.0.1", AGENT_PORT)),
    )
    ecfg.add_v3_user(
        agent, USER,
        ecfg.USM_AUTH_HMAC96_SHA, AUTH_PASS,
        ecfg.USM_PRIV_CBC56_DES, PRIV_PASS,
    )
    # read: the ifTable entry columns; write: ifAdminStatus only — mirrors the
    # narrowest sensible VACM view on a real switch.
    ecfg.add_vacm_user(
        agent, 3, USER, "authPriv",
        (1, 3, 6, 1, 2, 1, 2, 2, 1),
        (1, 3, 6, 1, 2, 1, 2, 2, 1, 7),
    )
    snmp_context = context.SnmpContext(agent)
    port = FakePort(snmp_context.get_mib_instrum().get_mib_builder(), 24)
    cmdrsp.GetCommandResponder(agent, snmp_context)
    cmdrsp.SetCommandResponder(agent, snmp_context)
    agent.transport_dispatcher.job_started(1)
    log.info("fake switch agent up on 127.0.0.1:%d (port 24 admin=up oper=up)", AGENT_PORT)
    return port


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------
class ActionCounter(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.actions = 0
        self.suppressed = 0

    def emit(self, record: logging.LogRecord) -> None:
        msg = record.getMessage()
        if msg.startswith("ACTION:"):
            self.actions += 1
        if msg.startswith("suppressed"):
            self.suppressed += 1


def write_test_config(tmp: Path) -> Path:
    (tmp / "auth").write_text(AUTH_PASS)
    (tmp / "priv").write_text(PRIV_PASS)
    (tmp / "ha_token").write_text(HA_TOKEN)
    cfg = f"""
snmp:
  user: "{USER}"
  auth_protocol: "SHA"
  auth_password_file: "{tmp / 'auth'}"
  priv_protocol: "DES"
  priv_password_file: "{tmp / 'priv'}"

poll:
  interval_seconds: {POLL_INTERVAL}

notifications:
  email:
    enabled: true
    # exercises env expansion: no-default and default forms
    smtp_host: "${{TEST_SMTP_HOST:-127.0.0.1}}"
    smtp_port: "${{TEST_SMTP_PORT}}"
    security: "none"
    from: "killswitch@test.local"
    to: ["alerts@test.local"]
  home_assistant:
    enabled: true
    base_url: "http://127.0.0.1:{HA_PORT}"
    token_file: "{tmp / 'ha_token'}"

switches:
  - name: "fake-switch"
    ip: "127.0.0.1"
    snmp_port: {AGENT_PORT}
    allowed_ifindexes: [24]
    debounce_seconds: {DEBOUNCE}
"""
    (tmp / "config.yaml").write_text(cfg)
    return tmp / "config.yaml"


CHECKS: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, ok))
    log.log(
        logging.INFO if ok else logging.ERROR,
        "%s %s %s", "PASS" if ok else "FAIL", name, detail,
    )


async def settle(cycles: float = 4) -> None:
    await asyncio.sleep(POLL_INTERVAL * cycles + 0.3)


async def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
        stream=sys.stdout,
    )
    counter = ActionCounter()
    logging.getLogger("killswitch.actor").addHandler(counter)

    tmp = Path(tempfile.mkdtemp(prefix="killswitch-proof-"))
    os.environ["TEST_SMTP_PORT"] = str(SMTP_PORT)
    config_path = write_test_config(tmp)

    smtp_sink = SmtpSink()
    ha = FakeHomeAssistant()
    await smtp_sink.serve()
    await ha.serve()

    port = start_fake_switch_agent()
    cfg = load_config(str(config_path))
    actor = PortShutdownActor(cfg, Notifier(cfg))
    poller = LinkPoller(cfg, actor)
    poller.start()
    await settle()  # baseline poll(s) with the port up

    # --- Scenario 1: link drops -> port administratively shut ---
    log.info("=== scenario 1: oper up -> down ===")
    port.set_link(up=False)
    await settle()
    check(
        "link drop triggers admin-down",
        int(port.admin.syntax) == 2,
        f"(agent now reports ifAdminStatus.24={int(port.admin.syntax)})",
    )
    check("exactly one SET action", counter.actions == 1, f"(actions={counter.actions})")
    await asyncio.sleep(0.5)  # let notifications flush
    check(
        "kill email received",
        len(smtp_sink.messages) == 1 and "port_killed" in smtp_sink.messages[0]
        and "ifindex: 24" in smtp_sink.messages[0],
        f"(messages={len(smtp_sink.messages)})",
    )
    check(
        "home assistant event fired",
        len(ha.events) == 1
        and ha.events[0][0] == "switch_killswitch"
        and ha.events[0][1].get("event") == "port_killed"
        and ha.events[0][1].get("ifindex") == 24
        and ha.events[0][1].get("verified") is True,
        f"(events={ha.events})",
    )

    # --- Scenario 2: bounce within debounce window -> suppressed ---
    log.info("=== scenario 2: repeat drop within debounce window ===")
    port.set_link(up=True)
    await settle()
    port.set_link(up=False)
    await settle()
    check(
        "repeat drop is debounced",
        counter.actions == 1 and counter.suppressed >= 1,
        f"(actions={counter.actions}, suppressed={counter.suppressed})",
    )

    # --- Scenario R: redundancy — peer already shut the port -> stand down ---
    log.info("=== scenario R: port already admin-down (peer instance) ===")
    port.set_link(up=True)
    port.admin.syntax = Integer(1)
    await asyncio.sleep(DEBOUNCE + 0.5)
    await settle()  # steady up, debounce lapsed
    emails_before, ha_before = len(smtp_sink.messages), len(ha.events)
    port.admin.syntax = Integer(2)  # a "peer" kills the port first...
    port.set_link(up=False)         # ...as the link drops
    await settle()
    check(
        "stands down when peer already killed port",
        counter.actions == 1
        and len(smtp_sink.messages) == emails_before
        and len(ha.events) == ha_before,
        f"(actions={counter.actions}, emails={len(smtp_sink.messages)}, ha={len(ha.events)})",
    )

    # --- Scenario 3: invisible flap (drop+recover between polls) ---
    log.info("=== scenario 3: flap between polls (ifLastChange moves, oper stays up) ===")
    port.set_link(up=True)
    port.admin.syntax = Integer(1)  # re-arm the fake port
    await asyncio.sleep(DEBOUNCE + 0.5)  # let the debounce window lapse
    await settle()  # poller records steady 'up' state
    port.flap_invisibly()
    await settle()
    check(
        "invisible flap triggers admin-down",
        int(port.admin.syntax) == 2 and counter.actions == 2,
        f"(ifAdminStatus.24={int(port.admin.syntax)}, actions={counter.actions})",
    )

    # --- Scenario E: file-less config, entirely from environment variables ---
    log.info("=== scenario E: env-only configuration mode ===")
    os.environ.update({
        "SWITCHES": "sw-a@192.0.2.10:24,25;192.0.2.20:3",
        "SNMP_AUTH_PASSWORD": AUTH_PASS,
        "SNMP_PRIV_PASSWORD": PRIV_PASS,
        "KILL_DELAY": "2.5",
        "SMTP_TO": "a@test.local, b@test.local",
    })
    env_cfg = load_config_from_env()
    sw_a, sw_b = env_cfg.switches.get("192.0.2.10"), env_cfg.switches.get("192.0.2.20")
    check(
        "env-only config mode works",
        sw_a is not None and sw_a.name == "sw-a"
        and sw_a.allowed_ifindexes == frozenset({24, 25})
        and sw_b is not None and sw_b.name == "192.0.2.20"
        and sw_b.allowed_ifindexes == frozenset({3})
        and env_cfg.snmp.auth_password == AUTH_PASS
        and env_cfg.standby_delay == 2.5
        and env_cfg.notifications.email is not None
        and env_cfg.notifications.email.recipients == ("a@test.local", "b@test.local")
        and env_cfg.notifications.home_assistant is None,
        f"(switches={list(env_cfg.switches)})",
    )

    failed = [n for n, ok in CHECKS if not ok]
    print()
    print("=" * 64)
    for name, ok in CHECKS:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print("=" * 64)
    print("ALL CHECKS PASSED" if not failed else f"{len(failed)} CHECK(S) FAILED")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
