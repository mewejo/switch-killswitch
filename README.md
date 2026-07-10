# switch-killswitch

When a watched switch port loses link, administratively shut it
(`ifAdminStatus = down(2)`) so plugging anything back in does nothing until
an admin manually re-enables the port. Useful wherever an unplugged cable
should be treated as a security event rather than an inconvenience.

Vendor-agnostic: works against any managed switch that supports SNMPv3 with
write access to standard IF-MIB (tested on Ubiquiti EdgeSwitch / Broadcom
FASTPATH — extra notes for that family in `docs/fastpath-notes.md`).

## How it works

- **Detect** — polls `ifOperStatus` + `ifLastChange` for the allowlisted
  ports (default every 0.5s) over SNMPv3 authPriv. Polling was chosen over
  traps deliberately: no inbound ports, no reliance on the switch's trap
  engine (which some firmware ships broken), and the `ifLastChange`
  comparison catches drops that recover between two polls — a fast device
  swap can't slip through unseen. A switch reboot also moves `ifLastChange`,
  so a power-cycle that would revive an unsaved admin-down gets re-killed.
- **Kill** — SNMPv3 SET of `ifAdminStatus.<ifIndex> = down(2)`, then a
  read-back to verify. Debounced per port, rate-limited globally.
- **Never un-kill** — re-enabling is manual, on the switch. A port that is
  already down when the service starts is baseline, never retro-killed.
- **Arming delay** — links commonly bounce once shortly after an admin
  re-enable (autoneg restart, PoE device init), so a port must be
  continuously up for `ARM_DELAY` (default 30s) before it's on the instant
  trigger. While settling, a drop must persist `ARM_PERSIST` (default 5s)
  to fire — bring-up blips are forgiven, a real pull during the window
  still kills, just a few seconds later.

## Configuration

Entirely via **environment variables** — the service needs no files or
persistent storage. Copy `.env.example` to `.env` and fill in the three
required values:

```
SWITCHES=core@192.0.2.10:24        # name@ip:ifIndex[,ifIndex] entries, ;-separated
SNMP_AUTH_PASSWORD=...
SNMP_PRIV_PASSWORD=...
```

Everything else (SNMP protocols, poll interval, debounce, rate limit,
notifications, redundancy delay) has sensible defaults — see `.env.example`
for the full reference. Create a dedicated SNMPv3 user on the switch with
those credentials (write access to ifAdminStatus; the narrower the view the
better), and verify the ifIndex mapping with an ifDescr walk before
trusting it.

A YAML file (`config/config.example.yaml`) is also supported for local
development: pass `--config <path>`; its values support `${VAR:-default}`
env expansion.

## Run

### Docker

```
docker compose up -d
```

No volumes, no mounts — config is the environment (`env_file: .env`). Uses
host networking (must reach the switch's management IP; the default SMTP
target `localhost:25` means the relay on the docker host). No inbound ports
are ever opened. Run it on a host attached to the switch's management
network. The image is built and published by GitHub Actions on every push
to main. Or without compose:

```
docker run -d --restart unless-stopped --network host --env-file .env \
  ghcr.io/mewejo/switch-killswitch:latest
```

### Bare Python

```
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
set -a; source .env; set +a
.venv/bin/python -m app.main
```

No privileged ports, no root: the service only makes outbound SNMP requests.

## Redundancy

Run as many instances as you like, on different hosts. Before acting, every
instance re-reads `ifAdminStatus` and stands down — no SET, no notification —
if the port is already shut, so the switch itself is the coordination point.
Stagger instances with `KILL_DELAY`: `0` on the primary, a few seconds on
standbys, so a standby acts only when the primary failed to. Two instances
at delay 0 still converge (the SET is idempotent); the worst case is a
duplicate notification in the sub-second race window.

## Notifications

Events: `port_killed` (confirmed), `kill_failed` (SET rejected or read-back
mismatch), `rate_limited` (storm guard refused an action). Notification
failures are logged and never block the kill path.

- **Email** — SMTP via stdlib; defaults to an unauthenticated local relay
  at `localhost:25`, with `SMTP_SECURITY=starttls|ssl` and
  `SMTP_USERNAME`/`SMTP_PASSWORD` for non-local relays.
- **Home Assistant** — fires the event on the HA event bus with the full
  payload (switch, ifindex, reason, verified, timestamp); react with an
  automation:

  ```yaml
  trigger:
    - platform: event
      event_type: switch_killswitch
      event_data:
        event: port_killed
  action:
    - service: notify.mobile_app_your_phone
      data:
        message: >
          Port {{ trigger.event.data.ifindex }} killed on
          {{ trigger.event.data.switch }} ({{ trigger.event.data.reason }})
  ```

## Test

Full local end-to-end proof — fake SNMPv3 switch agent, SMTP sink, and fake
Home Assistant API; no hardware needed:

```
.venv/bin/python -m tests.prove_theory
```

Live view of a port while testing against real hardware:

```
.venv/bin/python -m tools.watch_port --config config/config.yaml --switch <ip> --ifindex <n>
```
