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

    clustered = cfg.cluster is not None
    controller = None
    if cfg.mqtt_control is not None:
        from .ha_control import HAController
        controller = HAController(cfg, actor, clustered=clustered)

    cluster = None
    if clustered:
        from .cluster import Cluster
        cluster = Cluster(cfg.cluster, notifier)
        # The elected master owns the HA control surface; hand it over on change.
        if controller is not None:
            cluster.on_master_change(controller.set_master)

    poller = LinkPoller(cfg, actor, state_sink=controller.on_port_state if controller else None)
    poller.start()
    if controller is not None:
        await controller.start()
    if cluster is not None:
        await cluster.start()
    log = logging.getLogger("killswitch")
    log.info(
        "notification channels: %s",
        ", ".join(notifier.channels) or "none configured",
    )
    log.info(
        "home assistant control (mqtt): %s",
        "enabled" if controller is not None else "disabled",
    )
    log.info(
        "cluster (peer awareness + master election): %s",
        "enabled" if cluster is not None else "disabled",
    )
    for sw in cfg.switches.values():
        log.info(
            "armed: switch=%s ip=%s ports(ifindex)=%s debounce=%.0fs",
            sw.name, sw.ip, sorted(sw.allowed_ifindexes), sw.debounce_seconds,
        )
    log.info("ports are never auto re-enabled; re-enable manually on the switch or via Home Assistant")
    try:
        await asyncio.Event().wait()  # run forever
    finally:
        if cluster is not None:
            cluster.stop()
        if controller is not None:
            controller.stop()


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
