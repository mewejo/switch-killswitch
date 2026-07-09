"""Configuration loading and validation."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field

import yaml

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

AUTH_PROTOCOLS = {"MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"}
PRIV_PROTOCOLS = {"DES", "AES", "AES128", "AES192", "AES256"}

MIN_POLL_INTERVAL = 0.2


class ConfigError(Exception):
    pass


def _expand_env(node):
    """Expand ${VAR} and ${VAR:-default} in every string value.

    A referenced variable that is unset and has no default is an error —
    silently substituting an empty string would hide misconfiguration.
    """
    if isinstance(node, dict):
        return {k: _expand_env(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_expand_env(v) for v in node]
    if isinstance(node, str):
        def sub(match: re.Match) -> str:
            name, default = match.group(1), match.group(2)
            value = os.environ.get(name)
            if value is not None:
                return value
            if default is not None:
                return default
            raise ConfigError(f"environment variable {name} is not set (referenced in config)")
        return _ENV_PATTERN.sub(sub, node)
    return node


def _read_secret(entry: dict, key: str) -> str:
    """Resolve a secret from <key>_file, <key>_env, or (discouraged) <key> inline."""
    file_key, env_key = f"{key}_file", f"{key}_env"
    if entry.get(file_key):
        path = entry[file_key]
        try:
            with open(path, encoding="utf-8") as fh:
                value = fh.read().strip()
        except OSError as exc:
            raise ConfigError(f"cannot read secret file {path!r}: {exc}") from exc
    elif entry.get(env_key):
        value = os.environ.get(entry[env_key], "")
    else:
        value = str(entry.get(key, "") or "")
    if len(value) < 8:
        raise ConfigError(f"secret {key!r} missing or shorter than 8 characters")
    return value


@dataclass(frozen=True)
class SnmpCredentials:
    user: str
    auth_protocol: str
    auth_password: str
    priv_protocol: str
    priv_password: str


@dataclass(frozen=True)
class SwitchConfig:
    name: str
    ip: str
    allowed_ifindexes: frozenset[int]
    debounce_seconds: float = 10.0
    # Port we talk SNMP to (161 on a real switch; overridable for testing).
    snmp_port: int = 161


@dataclass(frozen=True)
class RateLimit:
    max_actions: int = 10
    per_seconds: float = 60.0


@dataclass(frozen=True)
class EmailConfig:
    host: str
    port: int
    security: str  # "starttls" | "ssl" | "none"
    sender: str
    recipients: tuple[str, ...]
    username: str = ""
    password: str = ""
    subject_prefix: str = "[killswitch]"


@dataclass(frozen=True)
class HomeAssistantConfig:
    base_url: str
    token: str
    event_type: str = "switch_killswitch"


@dataclass(frozen=True)
class NotificationsConfig:
    email: EmailConfig | None = None
    home_assistant: HomeAssistantConfig | None = None


@dataclass(frozen=True)
class Config:
    snmp: SnmpCredentials
    switches: dict[str, SwitchConfig]  # keyed by switch IP
    poll_interval: float = 1.0
    # Redundancy: multiple instances may watch the same switch. Before
    # acting, an instance re-reads ifAdminStatus and stands down if a peer
    # already shut the port. standby_delay staggers instances so only the
    # primary (0) normally acts; standbys (>0) act only if it didn't.
    standby_delay: float = 0.0
    rate_limit: RateLimit = field(default_factory=RateLimit)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)


def _as_bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _load_email(raw: dict) -> EmailConfig | None:
    if not _as_bool(raw.get("enabled")):
        return None
    host = str(raw.get("smtp_host", ""))
    if not host:
        raise ConfigError("notifications.email: smtp_host is required")
    security = str(raw.get("security", "starttls")).lower()
    if security not in ("starttls", "ssl", "none"):
        raise ConfigError("notifications.email: security must be starttls, ssl or none")
    sender = str(raw.get("from", ""))
    recipients = tuple(str(r) for r in raw.get("to") or [])
    if not sender or not recipients:
        raise ConfigError("notifications.email: 'from' and non-empty 'to' are required")
    username = str(raw.get("username", "") or "")
    password = _read_secret(raw, "password") if username else ""
    return EmailConfig(
        host=host,
        port=int(raw.get("smtp_port", 587)),
        security=security,
        sender=sender,
        recipients=recipients,
        username=username,
        password=password,
        subject_prefix=str(raw.get("subject_prefix", "[killswitch]")),
    )


def _load_home_assistant(raw: dict) -> HomeAssistantConfig | None:
    if not _as_bool(raw.get("enabled")):
        return None
    base_url = str(raw.get("base_url", "")).rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        raise ConfigError("notifications.home_assistant: base_url must be http(s)://...")
    return HomeAssistantConfig(
        base_url=base_url,
        token=_read_secret(raw, "token"),
        event_type=str(raw.get("event_type", "switch_killswitch")),
    )


def _parse_ifindexes(value) -> list[int]:
    """Accept a YAML list or a comma-separated string (env form)."""
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace(";", ",").split(",")]
        value = [p for p in parts if p]
    try:
        return [int(v) for v in value or []]
    except (ValueError, TypeError) as exc:
        raise ConfigError(f"bad allowed_ifindexes {value!r}") from exc


_SWITCH_SPEC = re.compile(r"(?:(?P<name>[^@\s;]+)@)?(?P<ip>[0-9a-fA-F:.]+):(?P<ports>[0-9,]+)")


def load_config_from_env() -> Config:
    """Build the whole config from environment variables (no files needed).

    SWITCHES is a compact spec: `name@ip:if1,if2` entries separated by
    whitespace or `;`, e.g. `SWITCHES="core@192.0.2.10:24,25;lab@192.0.2.20:3"`.
    """
    env = os.environ
    switches = []
    spec = env.get("SWITCHES", "").strip()
    if not spec:
        raise ConfigError("SWITCHES is required in env-config mode (name@ip:if1,if2 ...)")
    for entry in re.split(r"[;\s]+", spec):
        if not entry:
            continue
        match = _SWITCH_SPEC.fullmatch(entry)
        if not match:
            raise ConfigError(f"bad SWITCHES entry {entry!r} (want name@ip:if1,if2)")
        switches.append({
            "name": match["name"] or match["ip"],
            "ip": match["ip"],
            "allowed_ifindexes": match["ports"],
            "debounce_seconds": env.get("DEBOUNCE_SECONDS", 10),
            "snmp_port": env.get("SNMP_PORT", 161),
        })
    raw = {
        "snmp": {
            "user": env.get("SNMP_USER", "portshut-user"),
            "auth_protocol": env.get("SNMP_AUTH_PROTOCOL", "SHA"),
            "auth_password_env": "SNMP_AUTH_PASSWORD",
            "priv_protocol": env.get("SNMP_PRIV_PROTOCOL", "DES"),
            "priv_password_env": "SNMP_PRIV_PASSWORD",
        },
        "poll": {"interval_seconds": env.get("POLL_INTERVAL", 0.5)},
        "redundancy": {"standby_delay_seconds": env.get("KILL_DELAY", 0)},
        "rate_limit": {
            "max_actions": env.get("RATE_MAX_ACTIONS", 10),
            "per_seconds": env.get("RATE_PER_SECONDS", 60),
        },
        "notifications": {
            "email": {
                "enabled": env.get("EMAIL_ENABLED", "true"),
                "smtp_host": env.get("SMTP_HOST", "localhost"),
                "smtp_port": env.get("SMTP_PORT", 25),
                "security": env.get("SMTP_SECURITY", "none"),
                "username": env.get("SMTP_USERNAME", ""),
                "password_env": "SMTP_PASSWORD",
                "from": env.get("SMTP_FROM", "killswitch@localhost"),
                "to": [a.strip() for a in env.get("SMTP_TO", "alerts@example.com").split(",")],
                "subject_prefix": env.get("SMTP_SUBJECT_PREFIX", "[killswitch]"),
            },
            "home_assistant": {
                "enabled": env.get("HA_ENABLED", "false"),
                "base_url": env.get("HA_BASE_URL", "http://homeassistant.local:8123"),
                "token_env": "HA_TOKEN",
                "event_type": env.get("HA_EVENT_TYPE", "switch_killswitch"),
            },
        },
        "switches": switches,
    }
    return _build_config(raw)


def load_config(path: str) -> Config:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")
    return _build_config(_expand_env(raw))


def _build_config(raw: dict) -> Config:
    snmp = raw.get("snmp") or {}

    auth_protocol = str(snmp.get("auth_protocol", "SHA")).upper()
    priv_protocol = str(snmp.get("priv_protocol", "DES")).upper()
    if auth_protocol not in AUTH_PROTOCOLS:
        raise ConfigError(f"auth_protocol must be one of {sorted(AUTH_PROTOCOLS)}")
    if priv_protocol not in PRIV_PROTOCOLS:
        raise ConfigError(f"priv_protocol must be one of {sorted(PRIV_PROTOCOLS)}")
    if not snmp.get("user"):
        raise ConfigError("snmp.user is required")

    creds = SnmpCredentials(
        user=str(snmp["user"]),
        auth_protocol=auth_protocol,
        auth_password=_read_secret(snmp, "auth_password"),
        priv_protocol=priv_protocol,
        priv_password=_read_secret(snmp, "priv_password"),
    )

    switches: dict[str, SwitchConfig] = {}
    for entry in raw.get("switches") or []:
        ip = str(entry.get("ip", ""))
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ConfigError(f"switch {entry.get('name')!r}: bad ip {ip!r}") from exc
        ifindexes = _parse_ifindexes(entry.get("allowed_ifindexes"))
        if not all(i > 0 for i in ifindexes):
            raise ConfigError(f"switch {ip}: allowed_ifindexes must be positive integers")
        if not ifindexes:
            raise ConfigError(f"switch {ip}: allowed_ifindexes is empty; refusing ambiguous config")
        if ip in switches:
            raise ConfigError(f"duplicate switch ip {ip}")
        switches[ip] = SwitchConfig(
            name=str(entry.get("name", ip)),
            ip=ip,
            allowed_ifindexes=frozenset(ifindexes),
            debounce_seconds=float(entry.get("debounce_seconds", 10.0)),
            snmp_port=int(entry.get("snmp_port", 161)),
        )
    if not switches:
        raise ConfigError("no switches configured")

    poll_raw = raw.get("poll") or {}
    poll_interval = float(poll_raw.get("interval_seconds", 1.0))
    if poll_interval < MIN_POLL_INTERVAL:
        raise ConfigError(f"poll.interval_seconds must be >= {MIN_POLL_INTERVAL}")

    redundancy_raw = raw.get("redundancy") or {}
    standby_delay = float(redundancy_raw.get("standby_delay_seconds", 0.0))
    if standby_delay < 0:
        raise ConfigError("redundancy.standby_delay_seconds must be >= 0")

    rl_raw = raw.get("rate_limit") or {}
    rate_limit = RateLimit(
        max_actions=int(rl_raw.get("max_actions", 10)),
        per_seconds=float(rl_raw.get("per_seconds", 60.0)),
    )

    notif_raw = raw.get("notifications") or {}
    notifications = NotificationsConfig(
        email=_load_email(notif_raw.get("email") or {}),
        home_assistant=_load_home_assistant(notif_raw.get("home_assistant") or {}),
    )

    return Config(
        snmp=creds,
        switches=switches,
        poll_interval=poll_interval,
        standby_delay=standby_delay,
        rate_limit=rate_limit,
        notifications=notifications,
    )
