"""Network checks: firewall, exposed services and kernel network settings.

Listening sockets are read straight from /proc/net/{tcp,udp}{,6}, the same
source `ss -tulpn` uses. No root needed.

Each line holds the local address in hex:  0100007F:0CEA = 127.0.0.1:3306
(IPv4 bytes are little-endian, the port is plain hex). An all-zero address
(0.0.0.0 or ::) means "every network interface": reachable from outside.
"""

from __future__ import annotations

from hardaudit.context import SystemContext
from hardaudit.models import Outcome, Severity, SkipCheck, failed, passed
from hardaudit.registry import check

GROUP = "network"
SYSCTL_DROPIN = "/etc/sysctl.d/60-hardening.conf"

TCP_LISTEN = "0A"
UDP_BOUND = "07"

# Services that should almost never be reachable from other machines.
RISKY_PORTS = {
    21: "FTP (plain-text passwords)",
    23: "Telnet (plain-text passwords)",
    111: "rpcbind",
    139: "NetBIOS/SMB",
    445: "SMB",
    502: "Modbus (industrial control, no authentication)",
    631: "CUPS printing",
    2375: "Docker API without TLS (root access to the host)",
    3306: "MySQL",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}
KNOWN_PORTS = {22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS"}


def _parse_conf(text: str) -> dict[str, str]:
    """Parse shell-style KEY=value files such as /etc/ufw/ufw.conf."""
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip("\"'")
    return values


@check(
    id="NET-001",
    title="UFW firewall is enabled and denies incoming traffic by default",
    group=GROUP,
    severity=Severity.HIGH,
    mitre=("T1562.004",),
)
def ufw_enabled(ctx: SystemContext) -> Outcome:
    # We read the configuration (state at boot). The live state needs
    # `sudo ufw status`, which cannot be read from a mounted --root.
    conf = ctx.read_text("/etc/ufw/ufw.conf")
    if conf is None:
        return failed(
            "UFW is not installed",
            ["sudo apt install ufw", "sudo ufw default deny incoming", "sudo ufw enable"],
        )
    enabled = _parse_conf(conf).get("ENABLED", "no").lower() == "yes"
    defaults = _parse_conf(ctx.read_text("/etc/default/ufw") or "")
    policy = defaults.get("DEFAULT_INPUT_POLICY", "DROP").upper()
    detail = f"UFW enabled={'yes' if enabled else 'no'}, default incoming policy={policy}"
    if enabled and policy in ("DROP", "REJECT"):
        return passed(detail)
    return failed(
        detail,
        [
            "sudo ufw default deny incoming",
            "# If you use SSH, allow it BEFORE enabling or you will lose access",
            "sudo ufw allow OpenSSH",
            "sudo ufw enable",
        ],
    )


def _hex_port(address: str) -> tuple[bool, int]:
    """'00000000:0016' -> (listens on all interfaces, 22)."""
    host, port = address.split(":")
    return set(host) == {"0"}, int(port, 16)


def _listening(ctx: SystemContext) -> list[tuple[int, str]] | None:
    """(port, proto) of sockets bound to all interfaces, or None if /proc is unavailable."""
    sources = {"tcp": TCP_LISTEN, "tcp6": TCP_LISTEN, "udp": UDP_BOUND, "udp6": UDP_BOUND}
    found: set[tuple[int, str]] = set()
    any_file = False
    for name, wanted_state in sources.items():
        text = ctx.read_text(f"/proc/net/{name}")
        if text is None:
            continue
        any_file = True
        for line in text.splitlines()[1:]:  # first line is the header
            fields = line.split()
            if len(fields) < 4 or fields[3] != wanted_state:
                continue
            all_interfaces, port = _hex_port(fields[1])
            if all_interfaces:
                found.add((port, name.rstrip("6")))
    return sorted(found) if any_file else None


@check(
    id="NET-002",
    title="No risky service exposed on all network interfaces",
    group=GROUP,
    severity=Severity.HIGH,
    mitre=("T1190",),
)
def exposed_services(ctx: SystemContext) -> Outcome:
    sockets = _listening(ctx)
    if sockets is None:
        raise SkipCheck("/proc/net not available (auditing a mounted filesystem?)")

    def label(port: int, proto: str) -> str:
        name = RISKY_PORTS.get(port) or KNOWN_PORTS.get(port)
        return f"{port}/{proto}" + (f" {name}" if name else "")

    exposed = ", ".join(label(p, proto) for p, proto in sockets) or "nothing"
    risky = [(p, proto) for p, proto in sockets if p in RISKY_PORTS]
    if not risky:
        return passed(f"Listening on all interfaces: {exposed}")
    fix = []
    for port, proto in risky:
        fix.append(f"# {RISKY_PORTS[port]}: bind it to 127.0.0.1 in its config, or block it:")
        fix.append(f"sudo ufw deny {port}/{proto}")
    return failed(f"Listening on all interfaces: {exposed}", fix)


def _sysctl(ctx: SystemContext, key: str) -> str | None:
    """Read a kernel setting, e.g. net.ipv4.ip_forward -> /proc/sys/net/ipv4/ip_forward."""
    text = ctx.read_text("/proc/sys/" + key.replace(".", "/"))
    return None if text is None else text.strip()


def _sysctl_fix(settings: dict[str, str]) -> list[str]:
    lines = "\\n".join(f"{key} = {value}" for key, value in settings.items())
    return [f"printf '{lines}\\n' | sudo tee -a {SYSCTL_DROPIN}", "sudo sysctl --system"]


@check(
    id="NET-003",
    title="IP forwarding is disabled",
    group=GROUP,
    severity=Severity.MEDIUM,
    mitre=("T1090",),
)
def ip_forward(ctx: SystemContext) -> Outcome:
    # With forwarding on, the machine routes packets between networks: an
    # attacker who gets in can use it as a bridge (pivot) to other networks.
    value = _sysctl(ctx, "net.ipv4.ip_forward")
    if value is None:
        raise SkipCheck("/proc/sys not available (auditing a mounted filesystem?)")
    if value == "0":
        return passed("net.ipv4.ip_forward = 0")
    detail = f"net.ipv4.ip_forward = {value}"
    fix = []
    if ctx.path("/usr/bin/docker").exists() or ctx.path("/usr/bin/dockerd").exists():
        detail += " (Docker is installed and needs it: expected on Docker hosts)"
        fix.append("# Docker needs forwarding: disabling it breaks container networking")
    return failed(detail, fix + _sysctl_fix({"net.ipv4.ip_forward": "0"}))


@check(
    id="NET-004",
    title="ICMP redirects are not accepted",
    group=GROUP,
    severity=Severity.MEDIUM,
    mitre=("T1557",),
)
def icmp_redirects(ctx: SystemContext) -> Outcome:
    # A forged ICMP redirect can change this machine's routes and send its
    # traffic through the attacker (man-in-the-middle).
    keys = ("net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects")
    values = {key: _sysctl(ctx, key) for key in keys}
    if any(v is None for v in values.values()):
        raise SkipCheck("/proc/sys not available (auditing a mounted filesystem?)")
    detail = ", ".join(f"{key.split('.')[3]}.accept_redirects = {v}" for key, v in values.items())
    if all(v == "0" for v in values.values()):
        return passed(detail)
    return failed(detail, _sysctl_fix(dict.fromkeys(keys, "0")))
