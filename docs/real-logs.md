# Validation on real public SSH logs

*Version française : [fr/logs-reels.md](fr/logs-reels.md)*

## Dataset

* **Source**: Loghub, `OpenSSH_2k.log`, https://github.com/logpai/loghub
  (Zhu et al., *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics*,
  ISSRE 2023). Free for research and academic use with a reference to the repository.
* 2,000 lines from a real Internet-facing OpenSSH server (December, year not recorded).
* The file is **not redistributed** in this repository (`data/external/` is git-ignored).

## How to reproduce

    mkdir -p data/external
    curl -sS -o data/external/OpenSSH_2k.log \
      https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log
    logwarden ingest data/external/OpenSSH_2k.log --db data/external/loghub.db --year 2015
    logwarden detect --db data/external/loghub.db
    logwarden dashboard --db data/external/loghub.db

## Results (measured)

| Metric | Value |
|---|---|
| Lines read | 2,000 |
| Authentication events | 519 (383 failures, 135 attempts on non-existent accounts, 1 success) |
| Malformed lines | 0 |
| Alerts | 22 (18 high, 4 medium) |
| Rules fired | LW-001 brute force (10), LW-002 password spraying (5), LW-005 suspicious IP (7) |

Example: one source IP tried 19 different accounts (`admin`, `cisco`, `guest`, `ftpuser`...) in
1.4 minutes, flagged as password spraying (LW-002) and as a suspicious IP (LW-005).

## What this shows, and what it does not

* The parser handles real OpenSSH output without a single malformed line, and the rules fire on
  genuine automated attacks (dictionary scans of common account names).
* There is **no ground truth** for this file: we cannot compute precision or recall, only check
  by reading that the alerts are plausible.
* Repeated-message lines (`message repeated N times`) and PAM summary lines are skipped, so some
  attempts are under-counted.