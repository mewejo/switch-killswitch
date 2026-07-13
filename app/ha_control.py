"""Home Assistant control surface over MQTT.

Exposes each watched port to Home Assistant as an MQTT-discovery `switch`
entity, so you can *see* the port's state (up / killed, and whether a cable is
actually linked) and *toggle* it — re-enable a killed port, or shut one on
demand — straight from the HA dashboard.

Why MQTT (and not an HTTP endpoint): the rest of this service is strictly
outbound-only — it opens no inbound ports. An MQTT client keeps that property.
The service makes one outbound connection to your broker and both publishes
state and receives toggle commands over it; nothing listens for connections.
That is also exactly how Home Assistant expects third-party devices to expose
controllable entities, so the entity, its state, and its toggle appear with no
YAML editing on the HA side.

Trust model: anyone who can publish to the command topic can re-enable a killed
port, so the feature is opt-in, supports broker auth + TLS, and every toggle it
performs is announced through the same notifier as an automatic kill
(`port_restored` / `port_disabled`) — manual changes stay auditable. Either
direction of the toggle can be withheld (`allow_reenable` / `allow_disable`);
turn both off for a visibility-only entity.

The kill path never depends on this: broker connectivity is best-effort, every
publish is guarded, and a down broker only means the HA entity goes stale.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re

import paho.mqtt.client as mqtt

from .actor import PortShutdownActor
from .config import Config, MqttControlConfig, SwitchConfig

log = logging.getLogger("killswitch.ha_control")

STATE_ON = "ON"
STATE_OFF = "OFF"
AVAIL_ONLINE = "online"
AVAIL_OFFLINE = "offline"
_ON_PAYLOADS = {"ON", "1", "TRUE", "ONLINE", "UP", "ENABLE", "ENABLED"}


def _slug(value: str) -> str:
    """A safe MQTT topic / object-id fragment: keep [A-Za-z0-9_-], fold the rest."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", value)


class _Port:
    """Precomputed topics and identity for one watched port."""

    def __init__(self, cfg: MqttControlConfig, switch: SwitchConfig, ifindex: int) -> None:
        self.switch = switch
        self.ifindex = ifindex
        sw_slug = _slug(switch.ip)
        base = f"{cfg.base_topic}/{sw_slug}/{ifindex}"
        self.state_topic = f"{base}/state"
        self.attributes_topic = f"{base}/attributes"
        self.command_topic = f"{base}/set"
        self.unique_id = f"{cfg.device_id}_{sw_slug}_{ifindex}"
        self.discovery_topic = f"{cfg.discovery_prefix}/switch/{self.unique_id}/config"


class HAController:
    """Bridges watched ports to Home Assistant over MQTT."""

    def __init__(self, cfg: Config, actor: PortShutdownActor) -> None:
        if cfg.mqtt_control is None:
            raise ValueError("HAController requires cfg.mqtt_control")
        self._cfg = cfg.mqtt_control
        self._actor = actor
        self._availability_topic = f"{self._cfg.base_topic}/availability"
        self._controllable = self._cfg.allow_reenable or self._cfg.allow_disable

        self._ports: list[_Port] = []
        self._by_command: dict[str, _Port] = {}
        for switch in cfg.switches.values():
            for ifindex in sorted(switch.allowed_ifindexes):
                port = _Port(self._cfg, switch, ifindex)
                self._ports.append(port)
                self._by_command[port.command_topic] = port

        # Last published (state, attributes) per port — publish only on change.
        self._published: dict[str, tuple[str, str]] = {}
        # Last observed link state per port, for optimistic publishes after a toggle.
        self._last_link: dict[str, bool | None] = {}

        self._loop: asyncio.AbstractEventLoop | None = None
        self._client: mqtt.Client | None = None

    # ------------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=self._cfg.client_id,
            protocol=mqtt.MQTTv311,
        )
        if self._cfg.username:
            client.username_pw_set(self._cfg.username, self._cfg.password or None)
        if self._cfg.tls:
            client.tls_set()
        client.will_set(self._availability_topic, AVAIL_OFFLINE, qos=1, retain=True)
        client.reconnect_delay_set(min_delay=1, max_delay=30)
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        self._client = client
        try:
            client.connect_async(self._cfg.host, self._cfg.port, self._cfg.keepalive)
            client.loop_start()
        except Exception as exc:  # never let a broker problem break the kill path
            log.error("MQTT control could not start (broker %s:%d): %s — kill path "
                      "unaffected, HA entity will be unavailable",
                      self._cfg.host, self._cfg.port, exc)
            return
        log.info(
            "home assistant control: MQTT %s:%d, %d port entit%s, toggle=%s",
            self._cfg.host, self._cfg.port, len(self._ports),
            "y" if len(self._ports) == 1 else "ies",
            "re-enable+disable" if (self._cfg.allow_reenable and self._cfg.allow_disable)
            else "re-enable" if self._cfg.allow_reenable
            else "disable" if self._cfg.allow_disable
            else "read-only",
        )

    def stop(self) -> None:
        if self._client is None:
            return
        try:
            self._client.publish(self._availability_topic, AVAIL_OFFLINE, qos=1, retain=True)
            self._client.loop_stop()
            self._client.disconnect()
        except Exception:
            pass

    # ------------------------------------------------------------------ mqtt callbacks

    def _on_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        if reason_code != 0:
            log.warning("MQTT connect failed: %s", reason_code)
            return
        log.info("MQTT connected to %s:%d", self._cfg.host, self._cfg.port)
        client.publish(self._availability_topic, AVAIL_ONLINE, qos=1, retain=True)
        for port in self._ports:
            client.publish(
                port.discovery_topic,
                json.dumps(self._discovery_payload(port)),
                qos=1, retain=True,
            )
            if self._controllable:
                client.subscribe(port.command_topic, qos=1)
        # Forget what we think HA has so the next poll re-publishes every port's
        # state — this restores entities after a broker restart wiped retained.
        self._published.clear()

    def _on_message(self, client, userdata, message) -> None:
        # Runs on paho's network thread — hop to the event loop to touch SNMP.
        if self._loop is None:
            return
        try:
            payload = message.payload.decode(errors="replace")
        except Exception:
            payload = ""
        self._loop.call_soon_threadsafe(self._dispatch_command, message.topic, payload)

    # ------------------------------------------------------------------ commands

    def _dispatch_command(self, topic: str, payload: str) -> None:
        port = self._by_command.get(topic)
        if port is None:
            return
        want_up = payload.strip().upper() in _ON_PAYLOADS
        if want_up and not self._cfg.allow_reenable:
            log.warning("ignoring HA re-enable of switch=%s ifindex=%d (allow_reenable=false)",
                        port.switch.name, port.ifindex)
            self._republish_known(port)
            return
        if not want_up and not self._cfg.allow_disable:
            log.warning("ignoring HA disable of switch=%s ifindex=%d (allow_disable=false)",
                        port.switch.name, port.ifindex)
            self._republish_known(port)
            return
        log.warning("HA toggle: switch=%s ifindex=%d -> %s",
                    port.switch.name, port.ifindex, "up" if want_up else "down")
        task = self._loop.create_task(self._apply(port, want_up))
        task.add_done_callback(lambda t: t.exception())

    async def _apply(self, port: _Port, want_up: bool) -> None:
        ok = await self._actor.set_admin(
            port.switch, port.ifindex, want_up, reason="home assistant toggle"
        )
        # Optimistic UI update; the poller reconciles from the switch shortly.
        admin = want_up if ok else None
        if admin is not None:
            self.publish_state(port.switch, port.ifindex,
                               admin_up=admin, link_up=self._last_link.get(port.unique_id))
        else:
            self._republish_known(port)

    # ------------------------------------------------------------------ state out

    def on_port_state(self, switch: SwitchConfig, ifindex: int,
                      oper_status: int, admin_status: int | None, last_change: int) -> None:
        """Poller state sink: called every poll with the freshly read status."""
        if admin_status is None:
            return
        self.publish_state(switch, ifindex,
                           admin_up=(admin_status == 1),
                           link_up=(oper_status == 1))

    def publish_state(self, switch: SwitchConfig, ifindex: int,
                      admin_up: bool, link_up: bool | None) -> None:
        client = self._client
        if client is None:
            return
        port = self._port_for(switch.ip, ifindex)
        if port is None:
            return
        self._last_link[port.unique_id] = link_up
        state = STATE_ON if admin_up else STATE_OFF
        attributes = json.dumps({
            "switch": switch.name,
            "switch_ip": switch.ip,
            "ifindex": ifindex,
            "admin_status": "up" if admin_up else "down",
            "link_status": ("up" if link_up else "down") if link_up is not None else "unknown",
            "killed": not admin_up,
        }, sort_keys=True)
        if self._published.get(port.unique_id) == (state, attributes):
            return
        self._published[port.unique_id] = (state, attributes)
        try:
            client.publish(port.state_topic, state, qos=1, retain=self._cfg.retain)
            client.publish(port.attributes_topic, attributes, qos=1, retain=self._cfg.retain)
        except Exception as exc:
            log.debug("MQTT state publish failed switch=%s ifindex=%d: %s",
                      switch.name, ifindex, exc)

    def _republish_known(self, port: _Port) -> None:
        """Re-send the last known state so a rejected toggle snaps HA back."""
        client = self._client
        cached = self._published.get(port.unique_id)
        if client is None or cached is None:
            return
        state, attributes = cached
        try:
            client.publish(port.state_topic, state, qos=1, retain=self._cfg.retain)
            client.publish(port.attributes_topic, attributes, qos=1, retain=self._cfg.retain)
        except Exception:
            pass

    # ------------------------------------------------------------------ helpers

    def _port_for(self, ip: str, ifindex: int) -> _Port | None:
        for port in self._ports:
            if port.switch.ip == ip and port.ifindex == ifindex:
                return port
        return None

    def _discovery_payload(self, port: _Port) -> dict:
        payload = {
            "name": f"{port.switch.name} port {port.ifindex}",
            "unique_id": port.unique_id,
            "object_id": port.unique_id,
            "state_topic": port.state_topic,
            "json_attributes_topic": port.attributes_topic,
            "payload_on": STATE_ON,
            "payload_off": STATE_OFF,
            "state_on": STATE_ON,
            "state_off": STATE_OFF,
            "availability_topic": self._availability_topic,
            "payload_available": AVAIL_ONLINE,
            "payload_not_available": AVAIL_OFFLINE,
            "icon": "mdi:ethernet-cable",
            "device": {
                "identifiers": [self._cfg.device_id],
                "name": self._cfg.device_name,
                "manufacturer": "switch-killswitch",
                "model": "SNMP switch port killswitch",
            },
        }
        if self._controllable:
            payload["command_topic"] = port.command_topic
        return payload
