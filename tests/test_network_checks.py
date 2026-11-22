from conftest import results_by_id

from hardaudit.models import Status

HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"


def _socket(local: str, state: str) -> str:
    return f"   0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000  0\n"


def net(**files: str) -> dict[str, str]:
    """Fake /proc/net files: net(tcp=[...lines]) -> {"/proc/net/tcp": header + lines}."""
    return {f"/proc/net/{name}": HEADER + "".join(lines) for name, lines in files.items()}


def test_ufw_enabled_with_deny_policy_passes(make_root):
    ctx = make_root(
        {
            "/etc/ufw/ufw.conf": "# comment\nENABLED=yes\n",
            "/etc/default/ufw": 'DEFAULT_INPUT_POLICY="DROP"\n',
        }
    )
    assert results_by_id(ctx, "network")["NET-001"].status is Status.PASS


def test_ufw_disabled_fails_and_warns_about_ssh(make_root):
    ctx = make_root({"/etc/ufw/ufw.conf": "ENABLED=no\n"})
    result = results_by_id(ctx, "network")["NET-001"]
    assert result.status is Status.FAIL
    assert "sudo ufw allow OpenSSH" in result.remediation


def test_ufw_enabled_but_accepting_everything_fails(make_root):
    ctx = make_root(
        {"/etc/ufw/ufw.conf": "ENABLED=yes\n", "/etc/default/ufw": "DEFAULT_INPUT_POLICY=ACCEPT\n"}
    )
    assert results_by_id(ctx, "network")["NET-001"].status is Status.FAIL


def test_ufw_missing_fails(make_root):
    result = results_by_id(make_root({"/etc/hosts": ""}), "network")["NET-001"]
    assert result.detail == "UFW is not installed"


def test_database_on_all_interfaces_fails(make_root):
    files = net(
        tcp=[
            _socket("00000000:0016", "0A"),  # 0.0.0.0:22 SSH, listening
            _socket("00000000:0CEA", "0A"),  # 0.0.0.0:3306 MySQL, listening
            _socket("0100007F:18EB", "0A"),  # 127.0.0.1:6379 Redis, local only: fine
            _socket("00000000:1F90", "01"),  # established connection, not a listener
        ],
        tcp6=[_socket("00000000000000000000000000000000:0016", "0A")],  # [::]:22
    )
    result = results_by_id(make_root(files), "network")["NET-002"]
    assert result.status is Status.FAIL
    assert result.detail == "Listening on all interfaces: 22/tcp SSH, 3306/tcp MySQL"
    assert "sudo ufw deny 3306/tcp" in result.remediation


def test_only_ssh_exposed_passes(make_root):
    files = net(tcp=[_socket("00000000:0016", "0A")], udp=[_socket("0100007F:0035", "07")])
    result = results_by_id(make_root(files), "network")["NET-002"]
    assert result.status is Status.PASS


def test_modbus_exposed_is_flagged(make_root):
    files = net(tcp=[_socket("00000000:01F6", "0A")])  # 502
    result = results_by_id(make_root(files), "network")["NET-002"]
    assert "Modbus" in result.detail


def test_ip_forward_on_with_docker_explains_why(make_root):
    ctx = make_root({"/proc/sys/net/ipv4/ip_forward": "1\n", "/usr/bin/docker": ""})
    result = results_by_id(ctx, "network")["NET-003"]
    assert result.status is Status.FAIL
    assert "Docker" in result.detail
    assert result.remediation[0].startswith("# Docker needs forwarding")


def test_icmp_redirects(make_root):
    base = "/proc/sys/net/ipv4/conf"
    ok = make_root({f"{base}/all/accept_redirects": "0\n", f"{base}/default/accept_redirects": "0"})
    assert results_by_id(ok, "network")["NET-004"].status is Status.PASS


def test_icmp_redirects_enabled_fails(make_root):
    base = "/proc/sys/net/ipv4/conf"
    ctx = make_root({f"{base}/all/accept_redirects": "1", f"{base}/default/accept_redirects": "0"})
    result = results_by_id(ctx, "network")["NET-004"]
    assert result.status is Status.FAIL
    assert result.detail == "all.accept_redirects = 1, default.accept_redirects = 0"
    assert "sysctl --system" in result.remediation[-1]


def test_without_proc_runtime_checks_are_skipped(make_root):
    results = results_by_id(make_root({"/etc/hosts": ""}), "network")
    assert {results[i].status for i in ("NET-002", "NET-003", "NET-004")} == {Status.SKIP}
