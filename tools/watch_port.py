"""Live on-screen status of a switch port. Polls ifAdminStatus/ifOperStatus once
a second and prints a line whenever anything changes (plus a heartbeat).

Read via SNMPv3 (from the service config) or v2c read-only:

  .venv/bin/python -m tools.watch_port --config config/config.yaml --switch 192.0.2.10 --ifindex 24
  .venv/bin/python -m tools.watch_port --v2c public --switch 192.0.2.10 --ifindex 24
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from datetime import datetime

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
)

from app.actor import AUTH_MAP, PRIV_MAP
from app.config import load_config

STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}
GREEN, RED, YELLOW, BOLD, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[0m"


def colour(status: str) -> str:
    if status == "up":
        return f"{GREEN}{status}{RESET}"
    if status in ("down", "lowerLayerDown"):
        return f"{RED}{status}{RESET}"
    return f"{YELLOW}{status}{RESET}"


async def watch(auth, switch_ip: str, snmp_port: int, ifindex: int) -> None:
    engine = SnmpEngine()
    oids = [
        ObjectType(ObjectIdentity(f"1.3.6.1.2.1.2.2.1.2.{ifindex}")),   # ifDescr
        ObjectType(ObjectIdentity(f"1.3.6.1.2.1.2.2.1.7.{ifindex}")),   # ifAdminStatus
        ObjectType(ObjectIdentity(f"1.3.6.1.2.1.2.2.1.8.{ifindex}")),   # ifOperStatus
    ]
    last: tuple | None = None
    last_print = 0.0
    print(f"{BOLD}watching {switch_ip} ifIndex {ifindex} — Ctrl+C to stop{RESET}")
    while True:
        target = await UdpTransportTarget.create((switch_ip, snmp_port), timeout=2, retries=0)
        error_indication, error_status, _, var_binds = await get_cmd(
            engine, auth, target, ContextData(), *oids
        )
        now = datetime.now().strftime("%H:%M:%S")
        if error_indication or error_status:
            state = ("ERROR", str(error_indication or error_status.prettyPrint()))
            if state != last:
                print(f"{now}  {RED}poll failed:{RESET} {state[1]}")
        else:
            descr = str(var_binds[0][1])
            admin = STATUS.get(int(var_binds[1][1]), "?")
            oper = STATUS.get(int(var_binds[2][1]), "?")
            state = (descr, admin, oper)
            changed = state != last
            heartbeat = time.monotonic() - last_print > 10
            if changed or heartbeat:
                marker = f"  {BOLD}<<< CHANGED{RESET}" if changed and last is not None else ""
                print(
                    f"{now}  {descr:<28} admin={colour(admin):<16} oper={colour(oper):<16}{marker}"
                )
                last_print = time.monotonic()
                if changed and admin == "down":
                    print(f"{now}  {RED}{BOLD}*** PORT ADMINISTRATIVELY SHUT — killswitch fired ***{RESET}")
        last = state
        await asyncio.sleep(1.0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--switch", required=True)
    parser.add_argument("--ifindex", type=int, required=True)
    parser.add_argument("--port", type=int, default=161)
    parser.add_argument("--config", help="service config.yaml (SNMPv3 creds)")
    parser.add_argument("--v2c", metavar="COMMUNITY", help="poll with v2c read-only instead")
    args = parser.parse_args()

    if args.v2c:
        auth = CommunityData(args.v2c, mpModel=1)
    elif args.config:
        cfg = load_config(args.config)
        auth = UsmUserData(
            cfg.snmp.user,
            authKey=cfg.snmp.auth_password,
            privKey=cfg.snmp.priv_password,
            authProtocol=AUTH_MAP[cfg.snmp.auth_protocol],
            privProtocol=PRIV_MAP[cfg.snmp.priv_protocol],
        )
    else:
        parser.error("need --config or --v2c")

    try:
        asyncio.run(watch(auth, args.switch, args.port, args.ifindex))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
