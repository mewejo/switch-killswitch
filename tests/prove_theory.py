"""End-to-end proof of the polling killswitch, all on localhost.

Topology:
  [fake switch agent :10161]  <--SNMPv3 GET (poll) / SET (kill)--  [service]
  [SMTP sink :10250] and [fake Home Assistant API :10251]  <--notifications--
  [fake MQTT broker :10252]  <--discovery + state / toggle commands--

The fake agent exposes ifOperStatus/ifLastChange (read) and a writable
ifAdminStatus for port 24. The harness manipulates the fake port's state
and asserts the service reacts correctly.

Scenarios:
  1. oper up -> down                    -> ifAdminStatus.24 set to down(2), verified
     + email received and HA event fired for the kill
  2. repeat drop within debounce window -> suppressed, still exactly one action
  3. already-down port at baseline      -> covered by startup (port starts up; implicit)
  4. flap: oper stays up but ifLastChange moves -> kill fires (fast-replug defence)
  M. Home Assistant MQTT control: discovery entity published, live state
     tracks a kill, and an HA "ON" command re-enables the port (audited)
  C. Cluster: two instances elect a master by lowest priority, the standby is
     promoted when the master leaves, and the survivor raises a peer_down alert
  CH. The elected master owns the HA control surface (passive until master,
     takes over on promotion, releases on demotion)

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
from app.cluster import Cluster
from app.config import ClusterConfig, load_config, load_config_from_env
from app.ha_control import HAController
from app.notify import Notifier
from app.poller import LinkPoller

USER = "portshut-user"
AUTH_PASS = "authpass-1234"
PRIV_PASS = "privpass-1234"
AGENT_PORT = 10161
SMTP_PORT = 10250
HA_PORT = 10251
MQTT_PORT = 10252
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


class FakeMqttBroker:
    """Minimal MQTT 3.1.1 broker — just enough for paho-mqtt to connect,
    subscribe, publish (QoS 0/1), and receive broker-pushed commands.

    Records published messages (so the harness can assert discovery/state) and
    can push a PUBLISH to subscribers (so the harness can play Home Assistant
    sending a toggle command).
    """

    def __init__(self) -> None:
        self.published: dict[str, bytes] = {}          # topic -> last payload
        self.messages: list[tuple[str, bytes]] = []    # every publish, in order
        self.subscriptions: list[tuple[str, object]] = []  # (filter, writer)
        self.retained: dict[str, bytes] = {}           # topic -> retained payload

    async def serve(self) -> None:
        await asyncio.start_server(self._handle, "127.0.0.1", MQTT_PORT)

    @staticmethod
    def _topic_matches(filt: str, topic: str) -> bool:
        f, t = filt.split("/"), topic.split("/")
        for i, part in enumerate(f):
            if part == "#":
                return True
            if i >= len(t):
                return False
            if part == "+":
                continue
            if part != t[i]:
                return False
        return len(f) == len(t)

    @staticmethod
    def _parse_connect(body: bytes):
        """Return (client_id, will|None) from a CONNECT packet body."""
        try:
            i = 0
            nlen = int.from_bytes(body[i:i + 2], "big"); i += 2 + nlen  # protocol name
            i += 1                                                       # protocol level
            flags = body[i]; i += 1
            i += 2                                                       # keepalive
            clen = int.from_bytes(body[i:i + 2], "big"); i += 2
            client_id = body[i:i + clen].decode(errors="replace"); i += clen
            will = None
            if flags & 0x04:  # will flag
                tlen = int.from_bytes(body[i:i + 2], "big"); i += 2
                wtopic = body[i:i + tlen].decode(errors="replace"); i += tlen
                mlen = int.from_bytes(body[i:i + 2], "big"); i += 2
                wpayload = body[i:i + mlen]; i += mlen
                will = (wtopic, wpayload, bool(flags & 0x20))  # topic, payload, retain
            return client_id, will
        except Exception:
            return "", None

    def _publish_packet(self, topic: str, payload: bytes) -> bytes:
        tb = topic.encode()
        var = len(tb).to_bytes(2, "big") + tb + payload
        return bytes([0x30]) + self._encode_len(len(var)) + var

    def _route(self, topic: str, payload: bytes, retain: bool) -> None:
        """Store retained (if flagged) and push to every matching subscriber."""
        self.published[topic] = payload
        self.messages.append((topic, payload))
        if retain:
            if payload:
                self.retained[topic] = payload
            else:
                self.retained.pop(topic, None)  # empty retained clears it
        packet = self._publish_packet(topic, payload)
        for filt, writer in list(self.subscriptions):
            if self._topic_matches(filt, topic):
                try:
                    writer.write(packet)
                except Exception:
                    pass

    @staticmethod
    def _encode_len(n: int) -> bytes:
        out = bytearray()
        while True:
            byte = n % 128
            n //= 128
            if n > 0:
                byte |= 0x80
            out.append(byte)
            if n == 0:
                return bytes(out)

    @staticmethod
    async def _read_len(reader) -> int:
        multiplier = 1
        value = 0
        while True:
            byte = (await reader.readexactly(1))[0]
            value += (byte & 0x7F) * multiplier
            if not byte & 0x80:
                return value
            multiplier *= 128

    async def _handle(self, reader, writer) -> None:
        will = None
        graceful = False
        try:
            while True:
                header = (await reader.readexactly(1))[0]
                ptype, flags = header & 0xF0, header & 0x0F
                remaining = await self._read_len(reader)
                body = await reader.readexactly(remaining) if remaining else b""
                if ptype == 0x10:        # CONNECT
                    _, will = self._parse_connect(body)
                    writer.write(bytes([0x20, 0x02, 0x00, 0x00]))       # CONNACK
                elif ptype == 0x30:      # PUBLISH from client
                    qos = (flags & 0x06) >> 1
                    retain = bool(flags & 0x01)
                    tlen = int.from_bytes(body[0:2], "big")
                    topic = body[2:2 + tlen].decode()
                    rest = body[2 + tlen:]
                    if qos > 0:
                        pid, payload = rest[0:2], rest[2:]
                        writer.write(bytes([0x40, 0x02]) + pid)         # PUBACK
                    else:
                        payload = rest
                    self._route(topic, payload, retain)
                elif ptype == 0x80:      # SUBSCRIBE
                    pid, rest, i = body[0:2], body[2:], 0
                    count = 0
                    new_filters = []
                    while i < len(rest):
                        flen = int.from_bytes(rest[i:i + 2], "big"); i += 2
                        topic = rest[i:i + flen].decode(); i += flen
                        i += 1  # requested QoS byte
                        self.subscriptions.append((topic, writer))
                        new_filters.append(topic)
                        count += 1
                    writer.write(bytes([0x90]) + self._encode_len(2 + count)
                                 + pid + bytes([0x00] * count))          # SUBACK
                    # Deliver matching retained messages to the new subscriber.
                    for filt in new_filters:
                        for rt, rp in list(self.retained.items()):
                            if self._topic_matches(filt, rt):
                                writer.write(self._publish_packet(rt, rp))
                elif ptype == 0xA0:      # UNSUBSCRIBE (flags nibble is 0x2)
                    pid, rest, i = body[0:2], body[2:], 0
                    while i < len(rest):
                        flen = int.from_bytes(rest[i:i + 2], "big"); i += 2
                        topic = rest[i:i + flen].decode(); i += flen
                        self.subscriptions = [
                            (t, w) for (t, w) in self.subscriptions
                            if not (w is writer and t == topic)
                        ]
                    writer.write(bytes([0xB0, 0x02]) + pid)             # UNSUBACK
                elif ptype == 0xC0:      # PINGREQ
                    writer.write(bytes([0xD0, 0x00]))                    # PINGRESP
                elif ptype == 0xE0:      # DISCONNECT
                    graceful = True
                    break
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            self.subscriptions = [(t, w) for (t, w) in self.subscriptions if w is not writer]
            # An unclean disconnect publishes the client's Last-Will.
            if will is not None and not graceful:
                wtopic, wpayload, wretain = will
                self._route(wtopic, wpayload, wretain)
            writer.close()

    async def wait_for_subscription(self, topic: str, timeout: float = 5.0) -> bool:
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            if any(t == topic for t, _ in self.subscriptions):
                return True
            await asyncio.sleep(0.05)
        return False

    async def publish_to_subscribers(self, topic: str, payload: bytes) -> None:
        """Push a QoS-0 PUBLISH to every subscriber of `topic` (plays HA)."""
        tb = topic.encode()
        var = len(tb).to_bytes(2, "big") + tb + payload
        packet = bytes([0x30]) + self._encode_len(len(var)) + var
        for filt, writer in list(self.subscriptions):
            if filt == topic:
                writer.write(packet)
                await writer.drain()


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


_MIB_BUILDER = None


def add_fake_port(ifindex: int) -> FakePort:
    return FakePort(_MIB_BUILDER, ifindex)


def start_fake_switch_agent() -> FakePort:
    global _MIB_BUILDER
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
    _MIB_BUILDER = snmp_context.get_mib_instrum().get_mib_builder()
    port = FakePort(_MIB_BUILDER, 24)
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
  arm_delay_seconds: 0   # scenarios 1-4 test the always-armed hair trigger

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
    broker = FakeMqttBroker()
    await smtp_sink.serve()
    await ha.serve()
    await broker.serve()

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

    # --- Scenarios A: arming delay — bring-up blips forgiven, real pulls not ---
    log.info("=== scenario A: arming delay (settle window after link-up) ===")
    ARM_DELAY, ARM_PERSIST = 2.0, 1.0
    arm_cfg_text = (tmp / "config.yaml").read_text().replace(
        "arm_delay_seconds: 0   # scenarios 1-4 test the always-armed hair trigger",
        f"arm_delay_seconds: {ARM_DELAY}\n  unarmed_persist_seconds: {ARM_PERSIST}",
    ).replace("allowed_ifindexes: [24]", "allowed_ifindexes: [26]"
    ).replace(f"debounce_seconds: {DEBOUNCE}", "debounce_seconds: 2")
    (tmp / "arm_config.yaml").write_text(arm_cfg_text)
    arm_port = add_fake_port(26)
    arm_cfg = load_config(str(tmp / "arm_config.yaml"))
    arm_actor = PortShutdownActor(arm_cfg)  # no notifier: kills counted via admin status
    arm_poller = LinkPoller(arm_cfg, arm_actor)
    arm_poller.start()
    await settle()  # baseline up; port is now SETTLING (up < ARM_DELAY)

    # A1: quick blip while settling -> forgiven
    arm_port.set_link(up=False)
    await asyncio.sleep(POLL_INTERVAL + 0.2)   # one poll sees it down (pending)
    arm_port.set_link(up=True)
    await settle()
    check(
        "bring-up blip while settling is forgiven",
        int(arm_port.admin.syntax) == 1,
        f"(ifAdminStatus.26={int(arm_port.admin.syntax)})",
    )

    # A2: sustained drop while settling -> still killed (after persist)
    arm_port.set_link(up=False)
    await asyncio.sleep(ARM_PERSIST + POLL_INTERVAL * 2 + 0.5)
    check(
        "sustained drop during settle window still kills",
        int(arm_port.admin.syntax) == 2,
        f"(ifAdminStatus.26={int(arm_port.admin.syntax)})",
    )

    # A3: once armed (up >= ARM_DELAY), a drop kills instantly
    arm_port.admin.syntax = Integer(1)
    arm_port.set_link(up=True)
    await asyncio.sleep(ARM_DELAY + 1.0)       # let it arm (also clears debounce)
    arm_port.set_link(up=False)
    await asyncio.sleep(POLL_INTERVAL * 3 + 0.5)
    check(
        "armed port still killed instantly",
        int(arm_port.admin.syntax) == 2,
        f"(ifAdminStatus.26={int(arm_port.admin.syntax)})",
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

    # --- Scenario M: Home Assistant control over MQTT ---
    log.info("=== scenario M: home assistant MQTT control (see + toggle) ===")
    ha_events_before = len(ha.events)
    mqtt_cfg_text = f"""
snmp:
  user: "{USER}"
  auth_protocol: "SHA"
  auth_password_file: "{tmp / 'auth'}"
  priv_protocol: "DES"
  priv_password_file: "{tmp / 'priv'}"
poll:
  interval_seconds: {POLL_INTERVAL}
  arm_delay_seconds: 0
notifications:
  home_assistant:
    enabled: true
    base_url: "http://127.0.0.1:{HA_PORT}"
    token_file: "{tmp / 'ha_token'}"
mqtt_control:
  enabled: true
  host: "127.0.0.1"
  port: {MQTT_PORT}
  base_topic: "switch_killswitch"
  discovery_prefix: "homeassistant"
switches:
  - name: "fake-switch"
    ip: "127.0.0.1"
    snmp_port: {AGENT_PORT}
    allowed_ifindexes: [28]
    debounce_seconds: 2
"""
    (tmp / "mqtt_config.yaml").write_text(mqtt_cfg_text)
    mqtt_agent_port = add_fake_port(28)
    mqtt_cfg = load_config(str(tmp / "mqtt_config.yaml"))
    mqtt_actor = PortShutdownActor(mqtt_cfg, Notifier(mqtt_cfg))
    controller = HAController(mqtt_cfg, mqtt_actor)
    mqtt_poller = LinkPoller(mqtt_cfg, mqtt_actor, state_sink=controller.on_port_state)
    mqtt_poller.start()
    await controller.start()

    entity = controller._port_for("127.0.0.1", 28)
    subscribed = await broker.wait_for_subscription(entity.command_topic, timeout=5)
    await settle()

    check(
        "MQTT discovery entity published with a command topic",
        entity.discovery_topic in broker.published
        and b'"command_topic"' in broker.published[entity.discovery_topic]
        and b"switch_killswitch/127_0_0_1/28/set" in broker.published[entity.discovery_topic],
        f"(config_topics={[t for t in broker.published if t.endswith('/config')]})",
    )
    check(
        "MQTT state shows the port up (ON) at baseline",
        subscribed and broker.published.get(entity.state_topic) == b"ON",
        f"(subscribed={subscribed}, state={broker.published.get(entity.state_topic)})",
    )

    # A kill must be reflected in the entity's state.
    mqtt_agent_port.set_link(up=False)
    await settle()
    check(
        "MQTT state tracks the kill (OFF)",
        int(mqtt_agent_port.admin.syntax) == 2
        and broker.published.get(entity.state_topic) == b"OFF",
        f"(admin={int(mqtt_agent_port.admin.syntax)}, "
        f"state={broker.published.get(entity.state_topic)})",
    )

    # Home Assistant sends "ON" -> the killed port is re-enabled...
    await broker.publish_to_subscribers(entity.command_topic, b"ON")
    await settle()
    check(
        "HA 'ON' command re-enables the killed port",
        int(mqtt_agent_port.admin.syntax) == 1
        and broker.published.get(entity.state_topic) == b"ON",
        f"(admin={int(mqtt_agent_port.admin.syntax)}, "
        f"state={broker.published.get(entity.state_topic)})",
    )
    # ...and that manual re-enable is audited like any other action.
    restored = [e for _, e in ha.events[ha_events_before:]
                if e.get("event") == "port_restored" and e.get("ifindex") == 28]
    check(
        "manual re-enable is audited (port_restored event, verified)",
        len(restored) >= 1 and restored[-1].get("verified") is True,
        f"(restored_events={restored})",
    )

    # A malformed command must NOT disable the port (no silent fall-through to OFF).
    await broker.publish_to_subscribers(entity.command_topic, b"garbage")
    await settle()
    check(
        "malformed MQTT command is ignored (port not disabled)",
        int(mqtt_agent_port.admin.syntax) == 1
        and broker.published.get(entity.state_topic) == b"ON",
        f"(admin={int(mqtt_agent_port.admin.syntax)}, "
        f"state={broker.published.get(entity.state_topic)})",
    )
    controller.stop()

    # --- Scenario MR: a broadcast HA toggle is redundancy-safe ---
    # An MQTT toggle reaches every instance; only one should act. A primary
    # (standby_delay 0) and a standby (standby_delay > 0) both re-enable the
    # same killed port concurrently -> one SET, one port_restored notification.
    log.info("=== scenario MR: HA toggle across redundant instances ===")
    standby_text = mqtt_cfg_text.replace(
        "poll:", "redundancy:\n  standby_delay_seconds: 1.5\npoll:", 1
    )
    (tmp / "mqtt_standby.yaml").write_text(standby_text)
    standby_cfg = load_config(str(tmp / "mqtt_standby.yaml"))
    standby_actor = PortShutdownActor(standby_cfg, Notifier(standby_cfg))
    primary_sw = mqtt_cfg.switches["127.0.0.1"]        # mqtt_actor: standby_delay 0
    standby_sw = standby_cfg.switches["127.0.0.1"]
    mqtt_agent_port.set_link(up=False)
    mqtt_agent_port.admin.syntax = Integer(2)          # start from a killed port
    restored_before = sum(1 for _, e in ha.events
                          if e.get("event") == "port_restored" and e.get("ifindex") == 28)
    await asyncio.gather(
        mqtt_actor.set_admin(primary_sw, 28, True, reason="ha toggle"),
        standby_actor.set_admin(standby_sw, 28, True, reason="ha toggle"),
    )
    await asyncio.sleep(0.4)  # let the single notification flush
    restored_after = sum(1 for _, e in ha.events
                         if e.get("event") == "port_restored" and e.get("ifindex") == 28)
    check(
        "redundant instances dedupe a toggle (one SET, one notification)",
        int(mqtt_agent_port.admin.syntax) == 1 and (restored_after - restored_before) == 1,
        f"(admin={int(mqtt_agent_port.admin.syntax)}, "
        f"restored_delta={restored_after - restored_before})",
    )

    # --- Scenario C: peer awareness + self-organising master election ---
    # Two instances see each other over MQTT and agree, with no coordinator, on
    # a single master (lowest priority). When the master dies the standby takes
    # over and the surviving master reports the loss.
    log.info("=== scenario C: cluster election + failover + peer alerts ===")
    cluster_notifier = Notifier(cfg)  # reuse fake HA/SMTP sinks to catch alerts
    HB, PEER_TIMEOUT = 0.4, 1.2

    def make_cluster(node: str, priority: int) -> Cluster:
        ccfg = ClusterConfig(
            host="127.0.0.1", port=MQTT_PORT, node_id=node, priority=priority,
            boot_id=f"{node}-boot", client_id=f"test-cluster-{node}",
            base_topic="switch_killswitch/cluster",
            heartbeat_interval=HB, peer_timeout=PEER_TIMEOUT, expected_nodes=2,
        )
        return Cluster(ccfg, cluster_notifier)

    node_a = make_cluster("node-a", priority=10)
    node_b = make_cluster("node-b", priority=20)
    master_topic = "switch_killswitch/cluster/master"
    sensor_disc = "homeassistant/sensor/switch_killswitch_cluster/config"

    await node_a.start()
    await asyncio.sleep(0.3)
    await node_b.start()
    await asyncio.sleep(HB + 0.9)  # let presence propagate + grace window elapse

    check(
        "lower-priority node elected master, the other stands by",
        node_a.is_master and not node_b.is_master
        and node_a.master == "node-a" and node_b.master == "node-a",
        f"(a.master={node_a.is_master}, b.master={node_b.is_master})",
    )
    check(
        "master pointer + HA status sensor published by the master",
        broker.published.get(master_topic) == b"node-a"
        and sensor_disc in broker.published
        and b"Cluster master" in broker.published[sensor_disc],
        f"(master_topic={broker.published.get(master_topic)})",
    )

    # The master dies -> the standby must take over and report the loss.
    cluster_events_before = len(ha.events)
    node_a.stop()
    await asyncio.sleep(1.0)
    check(
        "standby is promoted to master when the master leaves",
        node_b.is_master and node_b.master == "node-b"
        and broker.published.get(master_topic) == b"node-b",
        f"(b.master={node_b.is_master}, master_topic={broker.published.get(master_topic)})",
    )
    cluster_events = [e for _, e in ha.events[cluster_events_before:]]
    peer_downs = [e for e in cluster_events
                  if e.get("event") == "peer_down" and e.get("peer") == "node-a"]
    became = [e for e in cluster_events
              if e.get("event") == "became_master" and e.get("node") == "node-b"]
    check(
        "surviving master raises a peer_down alert for the lost instance",
        len(peer_downs) >= 1 and peer_downs[-1].get("degraded") is True,
        f"(peer_down_events={peer_downs})",
    )
    check(
        "failover announces the new master (became_master alert)",
        len(became) >= 1,
        f"(became_master_events={became})",
    )
    node_b.stop()
    await asyncio.sleep(0.2)

    # --- Scenario CH: the elected master owns the HA control surface ---
    # A clustered HAController is passive until told it is master, then it takes
    # over the entity (subscribes to commands, asserts availability) and releases
    # it cleanly on demotion — this is the automatic-failover handoff.
    log.info("=== scenario CH: HA control surface follows the elected master ===")
    ch_controller = HAController(mqtt_cfg, mqtt_actor, clustered=True)
    await ch_controller.start()
    await asyncio.sleep(0.4)
    ch_entity = ch_controller._port_for("127.0.0.1", 28)
    passive = not any(t == ch_entity.command_topic for t, _ in broker.subscriptions)
    check(
        "a clustered controller stays passive until it is master",
        passive,
        f"(subscribed_while_passive={not passive})",
    )

    ch_controller.set_master(True)
    took_over = await broker.wait_for_subscription(ch_entity.command_topic, timeout=3)
    await asyncio.sleep(0.2)
    check(
        "becoming master takes over the entity (subscribe + availability online)",
        took_over
        and broker.published.get("switch_killswitch/availability") == b"online",
        f"(subscribed={took_over}, "
        f"avail={broker.published.get('switch_killswitch/availability')})",
    )

    ch_controller.set_master(False)
    await asyncio.sleep(0.3)
    released = not any(t == ch_entity.command_topic for t, _ in broker.subscriptions)
    check(
        "losing master releases the entity (unsubscribes from commands)",
        released,
        f"(still_subscribed={not released})",
    )
    ch_controller.stop()

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
