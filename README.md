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

## Setup

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp config/config.example.yaml config/config.yaml   # then edit for your network
mkdir -p secrets && umask 077
openssl rand -hex 12 > secrets/snmp_auth
openssl rand -hex 12 > secrets/snmp_priv
```

Create a dedicated SNMPv3 user on the switch with those credentials (write
access to ifAdminStatus; the narrower the view the better) and put the
switch IP + allowlisted ifIndexes in `config/config.yaml`. Verify the
ifIndex mapping with an ifDescr walk before trusting it.

## Run

```
.venv/bin/python -m app.main --config config/config.yaml
```

No privileged ports, no root: the service only makes outbound SNMP requests.

### Docker

```
docker compose up -d
```

Uses host networking (needs to reach the switch's management IP; the default
SMTP target `localhost:25` means the relay on the docker host) and mounts
`./config` and `./secrets` read-only. `PUID` (default 1000) must match the
owner of `secrets/`. Run it on a host attached to the switch's management
network. The image is built and published by GitHub Actions on every push
to main.

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

Config values support `${VAR}` / `${VAR:-default}` environment expansion
(an unset variable without a default fails startup loudly). The example
config is fully env-driven:

| Variable | Default | Meaning |
| --- | --- | --- |
| `EMAIL_ENABLED` | `true` | email channel on/off |
| `SMTP_HOST` / `SMTP_PORT` | `localhost` / `25` | local relay, no TLS/auth |
| `SMTP_FROM` / `SMTP_TO` | `killswitch@localhost` / `alerts@example.com` | addresses |
| `HA_ENABLED` | `false` | Home Assistant channel on/off |
| `HA_BASE_URL` | `http://homeassistant.local:8123` | HA instance |
| `HA_TOKEN` | — (required when enabled) | long-lived access token (HA profile → Security) |
| `HA_EVENT_TYPE` | `switch_killswitch` | event fired on the HA bus |
| `KILL_DELAY` | `0` | standby delay for redundant instances (seconds) |

- **Email** — SMTP via stdlib; starttls/ssl also supported in config for
  non-local relays, with optional auth.
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
