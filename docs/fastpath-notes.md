# Notes for FASTPATH-based switches (Ubiquiti EdgeSwitch and friends)

Field notes from deploying against a FASTPATH-CLI switch. None of this is
required reading — the service is vendor-agnostic (standard IF-MIB over
SNMPv3) — but if your switch has a `(Config)#` prompt, this saves time.

## Why this project polls instead of using traps

At least some FASTPATH "lite" firmware builds log link up/down events in
`show logging traplogs` but **never transmit a trap**: `snmpOutTraps` stays
at 0 even with a fully-populated, active SNMP-TARGET-MIB (target address,
params, and snmpNotifyTable rows all correct, notify view present, link trap
flags enabled, receiver reachable). If you're debugging missing traps,
check `snmpOutTraps` (1.3.6.1.2.1.11.29.0) first — if it never increments,
stop debugging your receiver.

Polling sidesteps the whole subsystem and needs no inbound connectivity.

## Creating the SNMPv3 user

```
configure
snmp-server user portshut-user DefaultWrite auth-sha <auth-pass> priv-des <priv-pass>
```

- Check `snmp-server user <name> <group> auth-sha <pw> ?` for a `priv-aes128`
  option and prefer it over DES where offered (set `priv_protocol: AES`).
- Tighter than `DefaultWrite`: build a group whose write view only covers
  ifAdminStatus (1.3.6.1.2.1.2.2.1.7) via `snmp-server view` / `snmp-server group`.
- Names are limited to ~16 chars; passwords must be >= 8.

## CLI gotchas observed

- `snmp-server host <ip> <community>` silently registers the trap receiver
  with **UDP port 0** — traps go nowhere. Append `udp-port 162` explicitly.
  (Not that traps worked anyway; see above.)
- The `no` forms of notification hosts take the notification type, not the
  username: `no snmp-server v3-host <ip> {informs|traps}`.
- Verify ifIndex-to-port mapping with an ifDescr walk; on EdgeSwitch,
  port 0/N is typically ifIndex N.

## Operational notes

- A killed port is running-config state. If nobody saves the config, a
  switch power-cycle revives the port — but the poller detects the agent
  restart via ifLastChange reset and re-kills watched ports.
- Re-enable a killed port with `configure` → `interface 0/<n>` → `no shutdown`,
  or an SNMP SET of ifAdminStatus.<ifIndex> = 1.
