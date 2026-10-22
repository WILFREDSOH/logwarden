# Data / Données

**All data in this project is synthetic.** It is produced by `src/logwarden/synth/` with a fixed
random seed, so every run gives byte-identical files.
*Toutes les données sont synthétiques et reproductibles (graine fixe).*

| Path | Content | Versioned |
|---|---|---|
| `samples/auth.log` | OpenSSH syslog (traditional `Oct 14 10:00:00` timestamps, year 2026, UTC) | yes |
| `samples/app_auth.jsonl` | Web app authentication log, one JSON object per line | yes |
| `samples/ground_truth.json` | Attack scenarios injected in the two files above (never read by the detectors) | yes |
| `generated/` | Output of `logwarden demo` (demo + baseline datasets, `demo.db`) | no (`.gitignore`) |

`samples/` is exactly `logwarden generate --out data/samples` (seed 42): a test checks it.

## What the demo dataset contains

* **Normal activity**, Monday 12 to Friday 16 October 2026: 9 employees logging in to the web
  app (and 4 of them over SSH) between 08:00 and 19:00, with occasional typos (1-2 failures
  before a success); a `svc_backup` service account logging in every night at 02:00; cron and
  sshd noise lines.
* **Background noise**: a few isolated attempts on non-existent accounts from random IPs.
* **Five labelled scenarios** (see `ground_truth.json`):

| Scenario | IP | What happens | Expected rules |
|---|---|---|---|
| `ssh_brute_force_root` | 203.0.113.10 | 40 SSH password guesses on `root` in ~4 min | LW-001 |
| `ssh_password_spray` | 198.51.100.23 | 14 accounts tried once each in ~6 min at 03:10 | LW-001, LW-002, LW-005 |
| `webapp_admin_takeover` | 203.0.113.45 | 9 failures then a success on web `admin` at 23:41 | LW-001, LW-003, LW-004, LW-005 |
| `off_hours_login` | 192.0.2.13 | `dave` logs in over SSH at 03:12 | LW-004 |
| `low_and_slow_guessing` | 198.51.100.77 | 31 failures over 3 h on 3 accounts | none (by design) |

* **Injected data-quality defects**: 2 malformed SSH lines, 1 duplicated SSH line, 1 truncated
  JSON line, 1 JSON record with an invalid date, 1 record containing a `password` field
  (value `not-a-real-password`) to demonstrate redaction.

## Safety

* IP addresses come only from the RFC 5737 documentation ranges (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24); a test enforces it.
* No real user, host or password appears anywhere.
* The **baseline** dataset (`generated/baseline`, seed 7, 28 Sep - 11 Oct 2026, no attacks) is
  only used to calibrate the anomaly model.
