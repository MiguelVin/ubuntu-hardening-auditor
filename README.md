**English** | [Português](README.pt-BR.md)

# ubuntu-hardening-auditor

[![CI](https://github.com/MiguelVin/ubuntu-hardening-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/MiguelVin/ubuntu-hardening-auditor/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A Python command-line tool that audits the security of an Ubuntu system, gives it a **risk score from 0 to 100**, explains every problem and **automatically fixes what is safe to fix**.

![Audit of a vulnerable Ubuntu](docs/img/audit.svg)

## The problem

A freshly installed or hastily managed Ubuntu often ships with settings that make an attack easier: SSH accepting root logins, the firewall turned off, password files readable by any user, programs that turn into a root shell. Checking all of that by hand is slow and easy to forget.

## The solution

- **17 checks** across 6 areas: SSH, accounts, permissions, network, logs and password policy
- **Severity-weighted score**: one critical failure weighs more than several low ones, and the coverage is shown next to the score
- **A fix command** for every failure, with warnings (e.g. "make sure key login works first, or you will lock yourself out")
- **`--fix`**: automatic remediation with backups, validation and confirmation
- **Reports** in HTML, Markdown and JSON (sample: [`docs/sample-report.html`](docs/sample-report.html), download it and open it in a browser)
- **Docker lab** with a deliberately vulnerable Ubuntu to try everything safely

## Automatic fixes, but only the safe ones

![Automatic fixes in the lab: score 0 → 62](docs/img/fix.svg)

In the lab, `--fix` raises the score from **0 to 62** and **refuses to fix 7 problems on its own**. That is on purpose:

| Fixed automatically | Left for a person to decide | Why |
|---|---|---|
| SSH settings | Extra account with UID 0 | Deleting an account needs an investigation first |
| Passwordless account (locked) | `NOPASSWD` in sudoers | A broken sudoers file takes sudo away from everyone |
| Permissions of `/etc/shadow` and friends | Firewall disabled | Enabling it without allowing SSH cuts remote access |
| World-writable files in `/etc` | Exposed service | Stopping it may take an application down |
| SUID on GTFOBins binaries | IP forwarding / ICMP redirects | Affects routing, Docker and VPNs |
| Minimum password length | Brute force in `auth.log` | It is evidence of an attack: investigate, don't just block |

`--fix` safeguards:
- `--dry-run` shows the plan without changing anything; without `--yes` it always asks for confirmation
- Every file is backed up before its first change, **always with mode 600** (a backup of an exposed `/etc/shadow` must not leak the hashes again)
- The SSH configuration is validated with `sshd -t`; if it is invalid, the change is rolled back
- Idempotent: running it again changes nothing

## Concepts applied

| Area | Concept |
|---|---|
| SSH | In `sshd_config` **the first value wins**: that is why the fix goes into a `00-hardening.conf` drop-in, read before the others |
| Accounts | Linux grants root power by **UID**, not by name; an empty field in `/etc/shadow` = login without a password |
| Permissions | Octal modes (`640`), **SUID/SGID** bits and privilege escalation via [GTFOBins](https://gtfobins.github.io/) |
| Network | Sockets read straight from `/proc/net/tcp` (the same source `ss` uses); `0.0.0.0` = exposed on every interface |
| Passwords | Minimum length via `pam_pwquality`, following **NIST SP 800-63B** (length instead of forced rotation) |
| Mapping | Every check lists the **MITRE ATT&CK** techniques it helps prevent |

## Running it

Requirements: Ubuntu (or WSL) with Python 3.11+.

```bash
git clone https://github.com/MiguelVin/ubuntu-hardening-auditor.git
cd ubuntu-hardening-auditor
python3 -m venv .venv
.venv/bin/pip install -e .

.venv/bin/hardaudit                     # audit as a normal user (some checks are skipped)
sudo .venv/bin/hardaudit                # full audit
sudo .venv/bin/hardaudit -o reports/    # also saves report.html, report.md and report.json
.venv/bin/hardaudit --fix --dry-run     # shows what would be fixed
sudo .venv/bin/hardaudit --fix          # fixes it (asks for confirmation)
```

Other options: `--format json|markdown`, `--group ssh` (a single group), `--root /path` (audit a mounted filesystem), `--screenshot output.svg`, `--no-hints`.

Exit codes: `0` everything passed, `1` something failed, `2` `--fix` needs root. Handy in CI pipelines.

## Docker lab

```bash
bash lab/demo.sh                               # starts the lab, audits, fixes and saves the reports to lab/reports/
docker compose -f lab/docker-compose.yml down  # stops the lab
```

The container is **deliberately insecure** (SSH with root login and an empty password, a UID 0 backdoor, `find` with SUID, an exposed "Redis", simulated brute force in `auth.log` using RFC 5737 documentation IPs) and **publishes no ports**: nothing is reachable from your network.

## Quality

- 69 `pytest` tests: every check and every fix runs against a "fake Ubuntu" in a temporary folder, thanks to the `--root` option
- Linting and formatting with `ruff`
- GitHub Actions CI: tests on Python 3.11, 3.12 and 3.13, plus a job that starts the lab and confirms `--fix` raises the score

## Project structure

```
src/hardaudit/
├── checks/      # ssh, accounts, permissions, network, logs, passwords
├── fix/         # fix plan, fixers and backups
├── reports/     # terminal, HTML, Markdown, JSON
├── sshd.py      # sshd_config parser (Include, Match, first value wins)
├── score.py     # severity-weighted score
└── cli.py
lab/             # vulnerable Ubuntu in Docker + demo
tests/
```

## Stack

Python · Rich · Jinja2 · pytest · ruff · Docker · GitHub Actions · Linux (PAM, sshd, UFW, /proc)

## Lessons learned

- **Testing on a real system finds what unit tests don't**: on Ubuntu 26.04 the tool flagged `/usr/bin/sudo.ws` as a suspicious SUID binary. It was a recent change in the distribution (`sudo` became `sudo-rs`, written in Rust, and the classic one was renamed `sudo.ws`).
- **A high score over few checks proves nothing**: the first version gave 100/100 while evaluating only 1 of 8 items. Coverage is now shown next to the score.
- **Automating fixes means knowing when NOT to automate.**

## Next steps

- Read `journald` logs (systems without `/var/log/auth.log`)
- Reference the CIS Ubuntu Benchmark section in every check
- Checks for services (`systemd`), pending updates and AppArmor

## Author

**MiguelVin** · Computer Engineering student · [GitHub](https://github.com/MiguelVin)

> For educational use. Run it only on systems you own or are explicitly authorized to audit. Review every command before running it.
