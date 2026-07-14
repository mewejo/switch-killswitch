"""Peer awareness and self-organising master election over MQTT.

Run more than one killswitch instance for redundancy and this module lets the
instances *see each other* and agree, without a coordinator, on which one is
"master". It exists to answer two operational questions that the leaderless
kill path deliberately doesn't:

  1. "Is my other instance still alive?" — if a peer disconnects or hangs, the
     surviving instances notice and raise a `peer_down` alert (redundancy is
     now degraded); `peer_up` when it returns.
  2. "Which instance owns the shared, single-owner conveniences?" — chiefly the
     Home Assistant MQTT control surface, which wants exactly one publisher.
     The elected master owns it and hands it off automatically on failure.

Why this must NOT gate the kill path
-------------------------------------
The safety-critical shutdown stays leaderless on purpose. Every instance polls
and can kill; they coordinate through the switch itself (an idempotent
`ifAdminStatus` SET plus a stand-down read-back). If killing were gated on "am
I master?", a cable pulled during the sub-second window after a master died —
before a new one is elected — would go unhandled. So election here governs only
convenience/ownership duties; a brief disagreement about who is master can at
worst duplicate a notification or an idempotent SET, never miss a kill.

How election works
------------------
There is no election *protocol* — no votes, no coordinator, no split-brain to
resolve. Each instance publishes a small retained presence record to
`<base>/nodes/<node-id>` (with an MQTT Last-Will that flips it to `offline` if
the instance dies uncleanly) and subscribes to everyone's. "Master" is then a
pure function over the set of live nodes: the live node with the lowest
`(priority, node-id)`. Because every instance sees the same set, they each
compute the same answer independently. `priority` lets you pin a preferred
master (like `KILL_DELAY` picks a preferred actor); node-id breaks ties.

Liveness combines two signals: the retained `offline` will (clean/unclean
disconnect) and a heartbeat — each instance re-publishes its presence every
`heartbeat_interval`, and a peer whose record hasn't been refreshed within
`peer_timeout` is treated as down even if its TCP session lingers (a hung
process). Broker connectivity is best-effort throughout: a down broker only
means the instances can't see each other, never that the kill path stops.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable

import paho.mqtt.client as mqtt

from .config import ClusterConfig
from .notify import Notifier, make_cluster_event

log = logging.getLogger("killswitch.cluster")

STATE_ONLINE = "online"
STATE_OFFLINE = "offline"

MasterChangeCallback = Callable[[bool], None]


@dataclass
class _Peer:
    node: str
    priority: int
    state: str
    last_seen: float           # monotonic time of the last presence record
    boot: str = ""


@dataclass
class _View:
    """Immutable-ish snapshot of who is alive and who is master."""
    online: list[str] = field(default_factory=list)
    master: str | None = None


class Cluster:
    """Tracks peers over MQTT and elects a master by a pure lowest-id rule."""

    def __init__(self, cfg: ClusterConfig, notifier: Notifier | None = None) -> None:
        self._cfg = cfg
        self._notifier = notifier
        self._node = cfg.node_id
        self._priority = cfg.priority

        base = cfg.base_topic
        self._nodes_prefix = f"{base}/nodes"
        self._self_topic = f"{self._nodes_prefix}/{self._node}"
        self._nodes_filter = f"{self._nodes_prefix}/+"
        self._master_topic = f"{base}/master"
        self._summary_topic = f"{base}/summary"
        self._availability_topic = f"{base}/availability"

        # Home Assistant status sensor (published only while we are master).
        self._sensor_state_topic = f"{base}/status"
        self._sensor_attr_topic = f"{base}/status/attributes"
        self._sensor_discovery_topic = (
            f"{cfg.discovery_prefix}/sensor/{cfg.device_id}_cluster/config"
        )

        # Seed our own presence so a solo instance is immediately master.
        now = time.monotonic()
        self._peers: dict[str, _Peer] = {
            self._node: _Peer(self._node, self._priority, STATE_ONLINE, now, cfg.boot_id)
        }
        self._is_master = False
        self._master: str | None = None
        self._live_nodes_cache: list[str] | None = None
        # Alerts are held during a startup convergence window: a node briefly
        # thinks it is solo master before it has ingested its peers' retained
        # presence, and we don't want that transient to page anyone. Ownership
        # callbacks still fire throughout — only notifications wait.
        self._alerts_enabled = False

        self._loop: asyncio.AbstractEventLoop | None = None
        self._client: mqtt.Client | None = None
        self._reaper: asyncio.Task | None = None
        self._heartbeat: asyncio.Task | None = None
        self._grace: asyncio.Task | None = None
        self._seq = 0
        self._master_callbacks: list[MasterChangeCallback] = []

    # ------------------------------------------------------------------ public

    @property
    def is_master(self) -> bool:
        return self._is_master

    @property
    def master(self) -> str | None:
        return self._master

    def on_master_change(self, callback: MasterChangeCallback) -> None:
        """Register a callback invoked (on the event loop) when this node's
        master status flips. Called once with the initial status at start."""
        self._master_callbacks.append(callback)

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
        # If we die uncleanly the broker publishes this for us: peers see the
        # retained record flip to offline and re-elect within a poll.
        client.will_set(self._self_topic, self._presence_payload(STATE_OFFLINE),
                        qos=1, retain=True)
        client.reconnect_delay_set(min_delay=1, max_delay=30)
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        self._client = client
        try:
            client.connect_async(self._cfg.host, self._cfg.port, self._cfg.keepalive)
            client.loop_start()
        except Exception as exc:  # a broker problem must never break anything
            log.error("cluster MQTT could not start (broker %s:%d): %s — running "
                      "solo; peer awareness disabled, kill path unaffected",
                      self._cfg.host, self._cfg.port, exc)
        self._reaper = self._loop.create_task(self._reap_loop())
        self._heartbeat = self._loop.create_task(self._heartbeat_loop())
        self._grace = self._loop.create_task(self._enable_alerts_after_grace())
        # Announce our initial (solo) master status to listeners immediately.
        self._recompute("startup")
        log.info(
            "cluster: node=%s priority=%d broker=%s:%d heartbeat=%.0fs timeout=%.0fs",
            self._node, self._priority, self._cfg.host, self._cfg.port,
            self._cfg.heartbeat_interval, self._cfg.peer_timeout,
        )

    def stop(self) -> None:
        for task in (self._reaper, self._heartbeat, self._grace):
            if task is not None:
                task.cancel()
        client = self._client
        if client is None:
            return
        try:
            # A clean leave: publish offline ourselves (the broker then discards
            # the will), so peers fail over promptly instead of waiting for the
            # heartbeat to age out.
            info = client.publish(self._self_topic,
                                  self._presence_payload(STATE_OFFLINE),
                                  qos=1, retain=True)
            if self._is_master:
                self._clear_master_owned_topics(client)
            try:
                info.wait_for_publish(1.0)  # ensure peers see us leave
            except (ValueError, RuntimeError):
                pass
            # disconnect() before loop_stop() is paho's supported shutdown order.
            client.disconnect()
            client.loop_stop()
        except Exception:
            pass

    # ------------------------------------------------------------------ mqtt callbacks

    def _on_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        if reason_code != 0:
            log.warning("cluster MQTT connect failed: %s", reason_code)
            return
        log.info("cluster MQTT connected to %s:%d", self._cfg.host, self._cfg.port)
        client.subscribe(self._nodes_filter, qos=1)
        client.publish(self._self_topic, self._presence_payload(STATE_ONLINE),
                       qos=1, retain=True)

    def _on_message(self, client, userdata, message) -> None:
        # paho network thread — hop to the loop before touching shared state.
        if self._loop is None:
            return
        try:
            payload = message.payload.decode(errors="replace")
        except Exception:
            payload = ""
        self._loop.call_soon_threadsafe(self._ingest, message.topic, payload)

    # ------------------------------------------------------------------ state

    def _ingest(self, topic: str, payload: str) -> None:
        if not topic.startswith(self._nodes_prefix + "/"):
            return
        node = topic[len(self._nodes_prefix) + 1:]
        if not node:
            return
        if not payload:  # a cleared retained record — treat as gone
            self._peers.pop(node, None)
            self._recompute(f"{node} record cleared")
            return
        try:
            data = json.loads(payload)
        except Exception:
            log.debug("cluster: ignoring unparseable presence for %s", node)
            return
        state = str(data.get("state", STATE_ONLINE))
        priority = int(data.get("priority", 100))
        boot = str(data.get("boot", ""))
        # Our own retained/echoed record must never override our live identity.
        if node == self._node:
            self._peers[self._node].last_seen = time.monotonic()
            return
        prev = self._peers.get(node)
        self._peers[node] = _Peer(node, priority, state, time.monotonic(), boot)
        if state == STATE_OFFLINE:
            self._recompute(f"{node} announced offline")
        elif prev is None or prev.state != STATE_ONLINE:
            self._recompute(f"{node} online")
        else:
            # Routine heartbeat from a known-online peer: refresh liveness but
            # only recompute if a reboot (new boot id) might change ordering.
            if prev.boot != boot:
                self._recompute(f"{node} rebooted")

    async def _reap_loop(self) -> None:
        interval = max(1.0, self._cfg.heartbeat_interval / 2)
        while True:
            await asyncio.sleep(interval)
            now = time.monotonic()
            stale = [
                n for n, p in self._peers.items()
                if n != self._node and p.state == STATE_ONLINE
                and now - p.last_seen > self._cfg.peer_timeout
            ]
            for n in stale:
                self._peers[n].state = STATE_OFFLINE
                log.warning("cluster: peer %s went stale (no heartbeat within %.0fs)",
                            n, self._cfg.peer_timeout)
            if stale:
                self._recompute("peer(s) timed out")

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(self._cfg.heartbeat_interval)
            self._peers[self._node].last_seen = time.monotonic()
            client = self._client
            if client is None:
                continue
            try:
                client.publish(self._self_topic, self._presence_payload(STATE_ONLINE),
                               qos=1, retain=True)
                if self._is_master:
                    # Keep the HA status sensor fresh (it uses expire_after).
                    self._publish_summary(client)
            except Exception as exc:
                log.debug("cluster heartbeat publish failed: %s", exc)

    # ------------------------------------------------------------------ election

    def _live_nodes(self) -> list[str]:
        return sorted(n for n, p in self._peers.items() if p.state == STATE_ONLINE)

    def _elect(self) -> str | None:
        live = [p for p in self._peers.values() if p.state == STATE_ONLINE]
        if not live:
            return None
        return min(live, key=lambda p: (p.priority, p.node)).node

    async def _enable_alerts_after_grace(self) -> None:
        await asyncio.sleep(self._cfg.heartbeat_interval)
        # Rebaseline to the converged view so we don't backfire peer_up for
        # every node that was already present at startup.
        self._live_nodes_cache = self._live_nodes()
        self._alerts_enabled = True
        log.info("cluster: startup convergence window elapsed — alerts active "
                 "(master=%s live=%s)", self._master or "<none>", self._live_nodes_cache)

    def _recompute(self, cause: str) -> None:
        prev_online = set(self._live_nodes_cache) if self._live_nodes_cache is not None else None
        online = self._live_nodes()
        self._live_nodes_cache = online
        new_master = self._elect()
        was_master = self._is_master
        master_changed = new_master != self._master
        self._master = new_master
        self._is_master = new_master == self._node

        if master_changed:
            log.info("cluster: master=%s (live=%s) — %s",
                     new_master or "<none>", online, cause)

        # Membership deltas — alerts are raised by whoever is master, so exactly
        # one instance reports them (the new master reports a dead old master).
        if prev_online is not None and self._is_master:
            for node in sorted(set(online) - prev_online):
                if node != self._node:
                    self._alert("peer_up", peer=node, online=online)
            for node in sorted(prev_online - set(online)):
                if node != self._node:
                    self._alert("peer_down", peer=node, online=online)

        # Our own role transitions — reported by us regardless of master gate.
        if self._is_master and not was_master:
            self._on_became_master()
            if prev_online is not None:
                self._alert("became_master", online=online)
        elif was_master and not self._is_master:
            self._on_resigned_master()
            if prev_online is not None:
                self._alert("resigned_master", peer=new_master, online=online)

        if self._is_master:
            self._publish_master_state()

    # ------------------------------------------------------------------ master duties

    def _on_became_master(self) -> None:
        log.warning("cluster: THIS node (%s) is now MASTER", self._node)
        for cb in self._master_callbacks:
            self._safe_callback(cb, True)

    def _on_resigned_master(self) -> None:
        log.warning("cluster: this node (%s) resigned master to %s",
                    self._node, self._master or "<none>")
        for cb in self._master_callbacks:
            self._safe_callback(cb, False)

    def _safe_callback(self, cb: MasterChangeCallback, is_master: bool) -> None:
        try:
            cb(is_master)
        except Exception:
            log.exception("cluster: master-change callback failed")

    def _publish_master_state(self) -> None:
        client = self._client
        if client is None:
            return
        try:
            client.publish(self._master_topic, self._node, qos=1, retain=True)
            self._publish_summary(client)
        except Exception as exc:
            log.debug("cluster master-state publish failed: %s", exc)

    def _publish_summary(self, client: mqtt.Client) -> None:
        online = self._live_nodes()
        degraded = (
            self._cfg.expected_nodes > 0 and len(online) < self._cfg.expected_nodes
        )
        summary = {
            "master": self._node,
            "online": online,
            "online_count": len(online),
            "expected": self._cfg.expected_nodes or None,
            "degraded": degraded,
            "updated": datetime.now(timezone.utc).isoformat(),
        }
        client.publish(self._summary_topic, json.dumps(summary, sort_keys=True),
                       qos=1, retain=True)
        if self._cfg.ha_sensor:
            self._publish_ha_sensor(client, summary)

    def _publish_ha_sensor(self, client: mqtt.Client, summary: dict) -> None:
        client.publish(self._sensor_discovery_topic,
                       json.dumps(self._sensor_discovery_payload()), qos=1, retain=True)
        client.publish(self._sensor_state_topic, self._node, qos=1, retain=True)
        client.publish(self._sensor_attr_topic, json.dumps(summary, sort_keys=True),
                       qos=1, retain=True)

    def _sensor_discovery_payload(self) -> dict:
        return {
            "name": "Cluster master",
            "unique_id": f"{self._cfg.device_id}_cluster_master",
            "object_id": f"{self._cfg.device_id}_cluster_master",
            "state_topic": self._sensor_state_topic,
            "json_attributes_topic": self._sensor_attr_topic,
            "icon": "mdi:server-network",
            # If no master refreshes this within the window, HA marks it
            # unavailable — surfacing "the whole cluster is gone" in the UI.
            "expire_after": int(max(self._cfg.peer_timeout, self._cfg.heartbeat_interval * 3)),
            "device": {
                "identifiers": [self._cfg.device_id],
                "name": self._cfg.device_name,
                "manufacturer": "switch-killswitch",
                "model": "SNMP switch port killswitch",
            },
        }

    def _clear_master_owned_topics(self, client: mqtt.Client) -> None:
        # On a clean master shutdown, drop the retained master pointer so a
        # stale name doesn't linger until the next master claims it.
        try:
            client.publish(self._master_topic, "", qos=1, retain=True)
        except Exception:
            pass

    # ------------------------------------------------------------------ helpers

    def _presence_payload(self, state: str) -> str:
        self._seq += 1
        return json.dumps({
            "node": self._node,
            "priority": self._priority,
            "state": state,
            "boot": self._cfg.boot_id,
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(),
        }, sort_keys=True)

    def _alert(self, kind: str, peer: str | None = None,
               online: list[str] | None = None) -> None:
        if not self._alerts_enabled:
            return  # suppressed during the startup convergence window
        degraded = (
            self._cfg.expected_nodes > 0
            and online is not None
            and len(online) < self._cfg.expected_nodes
        )
        log.info("cluster event: %s node=%s peer=%s online=%s",
                 kind, self._node, peer, online)
        if self._notifier is None:
            return
        event = make_cluster_event(
            kind, node=self._node, peer=peer, master=self._master,
            online=online or [], expected=self._cfg.expected_nodes or None,
            degraded=degraded,
        )
        self._fire(self._notifier.notify(event))

    def _fire(self, coro: Awaitable) -> None:
        if self._loop is None:
            return
        task = self._loop.create_task(coro)
        task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
