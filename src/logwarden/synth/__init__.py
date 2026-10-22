"""Deterministic synthetic log generator.

It writes an OpenSSH syslog file and a web-app JSON Lines file containing normal
office activity plus (optionally) labelled attack scenarios, and a
`ground_truth.json` describing those scenarios. The ground truth is kept in a
separate file - it is never visible to the detection code.

All IP addresses come from the documentation ranges reserved by RFC 5737
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24): they cannot belong to anyone.
No real password is ever generated.
"""

from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path

HOST = "srv-prod-01"
APP = "intranet"

# Employees, their usual workstation IPs and whether they also use SSH.
EMPLOYEES = {
    "alice": ("192.0.2.10", True),
    "bob": ("192.0.2.11", True),
    "carol": ("192.0.2.12", False),
    "dave": ("192.0.2.13", True),
    "erin": ("192.0.2.14", False),
    "frank": ("192.0.2.15", False),
    "grace": ("192.0.2.16", False),
    "heidi": ("192.0.2.17", False),
    "admin": ("192.0.2.20", True),  # the sysadmin's account
}
SERVICE_ACCOUNT = ("svc_backup", "192.0.2.50")
SPRAY_USERS = [
    "admin",
    "alice",
    "test",
    "oracle",
    "bob",
    "guest",
    "ubuntu",
    "postgres",
    "deploy",
    "git",
    "carol",
    "user",
    "pi",
    "ftp",
]


@dataclass
class Scenario:
    name: str
    source: str
    src_ip: str
    start: str
    end: str
    malicious: bool
    expected_rules: list[str]
    description: str


@dataclass
class GroundTruth:
    seed: int
    start_date: str
    days: int
    year: int
    scenarios: list[Scenario] = field(default_factory=list)
    background_ips: list[str] = field(default_factory=list)
    injected_quality_issues: dict[str, int] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @staticmethod
    def load(path: str | Path) -> GroundTruth:
        data = json.loads(Path(path).read_text("utf-8"))
        data["scenarios"] = [Scenario(**s) for s in data["scenarios"]]
        return GroundTruth(**data)


class _Writer:
    """Collects (timestamp, line) pairs for both log files, then writes them sorted."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.ssh: list[tuple[datetime, str]] = []
        self.web: list[tuple[datetime, str]] = []

    def _pid(self) -> int:
        return self.rng.randint(1000, 65000)

    def _port(self) -> int:
        return self.rng.randint(32768, 60999)

    def syslog(self, ts: datetime, prog: str, msg: str) -> None:
        stamp = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"
        self.ssh.append((ts, f"{stamp} {HOST} {prog}[{self._pid()}]: {msg}"))

    def ssh_failed(self, ts: datetime, user: str, ip: str, invalid: bool = False) -> None:
        if invalid:
            self.syslog(ts, "sshd", f"Invalid user {user} from {ip} port {self._port()}")
        who = f"invalid user {user}" if invalid else user
        self.syslog(ts, "sshd", f"Failed password for {who} from {ip} port {self._port()} ssh2")

    def ssh_accepted(self, ts: datetime, user: str, ip: str, method: str = "publickey") -> None:
        self.syslog(ts, "sshd", f"Accepted {method} for {user} from {ip} port {self._port()} ssh2")
        self.syslog(
            ts,
            "sshd",
            f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)",
        )

    def web_event(self, ts: datetime, event: str, user: str, ip: str, **extra: str) -> None:
        record = {
            "ts": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "app": APP,
            "event": event,
            "user": user,
            "ip": ip,
            **extra,
        }
        self.web.append((ts, json.dumps(record)))

    def write(self, out_dir: Path) -> tuple[Path, Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        ssh_path, web_path = out_dir / "auth.log", out_dir / "app_auth.jsonl"
        for path, lines in ((ssh_path, self.ssh), (web_path, self.web)):
            ordered = [line for _, line in sorted(lines, key=lambda x: x[0])]
            path.write_text("\n".join(ordered) + "\n", encoding="utf-8")
        return ssh_path, web_path


def _at(day: date, hour: int, minute: int = 0, second: int = 0) -> datetime:
    return datetime.combine(day, time(hour, minute, second), tzinfo=UTC)


def _normal_activity(w: _Writer, day: date, rng: random.Random) -> None:
    # Night-time backup job: expected, exempt from the off-hours rule.
    w.ssh_accepted(_at(day, 2, rng.randint(0, 4), rng.randint(0, 59)), *SERVICE_ACCOUNT)
    for minute in range(0, 60, 15):  # cron noise every 15 min from 6:00 to 22:00
        for hour in range(6, 22):
            if rng.random() < 0.3:
                w.syslog(
                    _at(day, hour, minute),
                    "CRON",
                    "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
                )
    if day.weekday() >= 5:
        return  # nobody works on weekends

    for user, (ip, uses_ssh) in EMPLOYEES.items():
        for _ in range(rng.randint(2, 5)):
            ts = _at(day, rng.randint(8, 18), rng.randint(0, 59), rng.randint(0, 59))
            if rng.random() < 0.08:  # typo: 1-2 failures shortly before the success
                for k in range(rng.randint(1, 2), 0, -1):
                    w.web_event(
                        ts - timedelta(seconds=15 * k),
                        "login_failed",
                        user,
                        ip,
                        reason="bad_password",
                    )
            w.web_event(ts, "login_success", user, ip)
            w.web_event(
                ts + timedelta(minutes=rng.randint(1, 40)),
                "page_view",
                user,
                ip,
                path=rng.choice(["/home", "/wiki", "/tickets", "/hr"]),
            )
            w.web_event(ts + timedelta(minutes=rng.randint(41, 180)), "logout", user, ip)
        if uses_ssh:
            for _ in range(rng.randint(1, 3)):
                ts = _at(day, rng.randint(8, 18), rng.randint(0, 59), rng.randint(0, 59))
                if rng.random() < 0.05:
                    w.ssh_failed(ts - timedelta(seconds=10), user, ip)
                w.ssh_accepted(ts, user, ip, rng.choice(["publickey", "publickey", "password"]))
                w.syslog(
                    ts + timedelta(minutes=rng.randint(5, 120)),
                    "sshd",
                    f"Received disconnect from {ip} port {w._port()}:11: disconnected by user",
                )


def _background_noise(w: _Writer, day: date, rng: random.Random, gt: GroundTruth) -> None:
    """Internet background radiation: a few isolated attempts, below every threshold."""
    for _ in range(3):
        ip = f"198.51.100.{rng.randint(150, 250)}"
        if ip in gt.background_ips:
            continue
        gt.background_ips.append(ip)
        ts = _at(day, rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59))
        for k in range(rng.randint(1, 2)):
            w.ssh_failed(
                ts + timedelta(seconds=7 * k),
                rng.choice(["test", "ubuntu", "oracle"]),
                ip,
                invalid=True,
            )


def _attacks(w: _Writer, start: date, rng: random.Random, gt: GroundTruth) -> None:
    def add(
        name: str,
        source: str,
        ip: str,
        t0: datetime,
        t1: datetime,
        rules: list[str],
        text: str,
        malicious: bool = True,
    ) -> None:
        gt.scenarios.append(
            Scenario(name, source, ip, t0.isoformat(), t1.isoformat(), malicious, rules, text)
        )

    # S1 - SSH brute force against root (day 2, afternoon).
    ip, ts = "203.0.113.10", _at(start + timedelta(days=1), 14, 20, 5)
    t0 = ts
    for _ in range(40):
        w.ssh_failed(ts, "root", ip)
        ts += timedelta(seconds=rng.randint(3, 8))
    add(
        "ssh_brute_force_root",
        "ssh",
        ip,
        t0,
        ts,
        ["LW-001"],
        "40 password guesses against root over SSH in about 4 minutes.",
    )

    # S2 - SSH password spraying, mostly against non-existent accounts (day 3, night).
    ip, ts = "198.51.100.23", _at(start + timedelta(days=2), 3, 10, 0)
    t0 = ts
    for user in SPRAY_USERS:
        w.ssh_failed(ts, user, ip, invalid=user not in EMPLOYEES)
        ts += timedelta(seconds=rng.randint(15, 40))
    add(
        "ssh_password_spray",
        "ssh",
        ip,
        t0,
        ts,
        ["LW-001", "LW-002", "LW-005"],
        "One attempt on each of 14 accounts (10 of them non-existent) within a few minutes.",
    )

    # S3 - Web app admin account takeover at night (day 3, 23:41).
    ip, ts = "203.0.113.45", _at(start + timedelta(days=2), 23, 41, 2)
    t0 = ts
    for _ in range(9):
        w.web_event(ts, "login_failed", "admin", ip, reason="bad_password")
        ts += timedelta(seconds=rng.randint(10, 25))
    w.web_event(ts, "login_success", "admin", ip)
    w.web_event(ts + timedelta(minutes=2), "page_view", "admin", ip, path="/admin/users/export")
    add(
        "webapp_admin_takeover",
        "webapp",
        ip,
        t0,
        ts,
        ["LW-001", "LW-003", "LW-004", "LW-005"],
        "9 failed logins on the web app 'admin' account, then a success, at 23:41.",
    )

    # S4 - Employee login at 03:12 from the usual workstation (day 4): policy anomaly.
    ip, ts = EMPLOYEES["dave"][0], _at(start + timedelta(days=3), 3, 12, 40)
    w.ssh_accepted(ts, "dave", ip, "password")
    add(
        "off_hours_login",
        "ssh",
        ip,
        ts,
        ts,
        ["LW-004"],
        "dave logs in over SSH at 03:12 from his usual workstation (insider or stolen session).",
    )

    # S5 - Low-and-slow guessing (day 4, 09:00-12:00): designed to stay under rule thresholds.
    ip, ts = "198.51.100.77", _at(start + timedelta(days=3), 9, 0, 30)
    t0, targets, k = ts, ["bob", "carol", "erin"], 0
    while ts < _at(start + timedelta(days=3), 12, 0):
        w.web_event(ts, "login_failed", targets[k % 3], ip, reason="bad_password")
        k += 1
        ts += timedelta(minutes=rng.randint(4, 7), seconds=rng.randint(0, 59))
    add(
        "low_and_slow_guessing",
        "webapp",
        ip,
        t0,
        ts,
        [],
        f"{k} failures spread over 3 hours on 3 accounts: under every rule threshold.",
    )


def _quality_issues(w: _Writer, start: date, gt: GroundTruth) -> None:
    """Inject realistic defects so the robustness of ingestion is visible in the report."""
    day = start + timedelta(days=1)
    w.ssh.append((_at(day, 10, 0, 1), "this line is not a syslog record"))
    w.ssh.append(
        (
            _at(day, 10, 0, 2),
            f"Feb 30 10:00:02 {HOST} sshd[999]: Failed password for bob "
            "from 192.0.2.11 port 50000 ssh2",
        )
    )
    duplicate = next(line for ts, line in sorted(w.ssh) if "Accepted" in line)
    dup_ts = next(ts for ts, line in w.ssh if line == duplicate)
    w.ssh.append((dup_ts, duplicate))
    w.web.append((_at(day, 11, 0, 0), '{"ts": "2026-10-13T11:00:00Z", "event": "login_fail'))
    w.web.append(
        (
            _at(day, 11, 0, 1),
            json.dumps(
                {
                    "ts": "13/10/2026 11:00",
                    "app": APP,
                    "event": "login_success",
                    "user": "carol",
                    "ip": "192.0.2.12",
                }
            ),
        )
    )
    # A buggy client that logs the submitted password: LogWarden must redact it.
    w.web_event(
        _at(day, 11, 5, 0),
        "login_failed",
        "frank",
        EMPLOYEES["frank"][0],
        reason="bad_password",
        password="not-a-real-password",  # noqa: S106 - fake value, used to test redaction
    )
    gt.injected_quality_issues = {
        "malformed_ssh": 2,
        "duplicate_ssh": 1,
        "malformed_webapp": 2,
        "redacted_field": 1,
    }


def generate(
    out_dir: str | Path,
    seed: int = 42,
    start: date = date(2026, 10, 12),
    days: int = 5,
    attacks: bool = True,
    quality_issues: bool = True,
) -> tuple[list[Path], GroundTruth]:
    rng = random.Random(seed)
    writer = _Writer(rng)
    gt = GroundTruth(seed=seed, start_date=start.isoformat(), days=days, year=start.year)
    for offset in range(days):
        day = start + timedelta(days=offset)
        _normal_activity(writer, day, rng)
        _background_noise(writer, day, rng, gt)
    if attacks:
        _attacks(writer, start, rng, gt)
    if quality_issues:
        _quality_issues(writer, start, gt)
    out = Path(out_dir)
    paths = list(writer.write(out))
    gt_path = out / "ground_truth.json"
    gt_path.write_text(gt.to_json() + "\n", encoding="utf-8")
    return [*paths, gt_path], gt
