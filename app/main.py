"""Entrypoint: python -m app.main --config config/config.yaml"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .actor import PortShutdownActor
from .config import ConfigError, load_config, load_config_from_env
from .notify import Notifier
from .poller import LinkPoller


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
        stream=sys.stdout,
    )


async def run(config_path: str | None) -> None:
    cfg = load_config(config_path) if config_path else load_config_from_env()
    logging.getLogger("killswitch").info(
        "configuration source: %s", config_path or "environment variables"
    )
    notifier = Notifier(cfg)
    actor = PortShutdownActor(cfg, notifier)
    poller = LinkPoller(cfg, actor)
    poller.start()
    log = logging.getLogger("killswitch")
    log.info(
        "notification channels: %s",
        ", ".join(notifier.channels) or "none configured",
    )
    for sw in cfg.switches.values():
        log.info(
            "armed: switch=%s ip=%s ports(ifindex)=%s debounce=%.0fs",
            sw.name, sw.ip, sorted(sw.allowed_ifindexes), sw.debounce_seconds,
        )
    log.info("ports are never auto re-enabled; re-enable manually on the switch")
    await asyncio.Event().wait()  # run forever


def main() -> None:
    parser = argparse.ArgumentParser(description="SNMP switch port killswitch")
    parser.add_argument("--config", help="YAML config file; omit to configure entirely from env")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    setup_logging(args.verbose)
    try:
        asyncio.run(run(args.config))
    except ConfigError as exc:
        logging.getLogger("killswitch").error("bad config: %s", exc)
        sys.exit(2)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
