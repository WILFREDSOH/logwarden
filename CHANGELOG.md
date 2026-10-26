# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions: [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-10-26

### Added
- **LW-006 distributed attack** rule: many distinct IPs failing on the same account within a
  time window (covers attacks that the per-IP rules miss), with EN/FR texts, tests and a sample log.
- **Sandbox tab** in the dashboard: analyse an uploaded log file in memory (never stored),
  2 MB limit, `.log`/`.txt`/`.jsonl` only, IPs and account names masked by default,
  downloadable synthetic examples.
- Documentation of a run on a **public real-world dataset** (Loghub OpenSSH, not redistributed).
- Live demo on Streamlit Community Cloud and a GitHub Codespaces configuration.
- **CI security checks**: bandit (static analysis), pip-audit (known vulnerabilities),
  test coverage with a minimum threshold (80 %), Dependabot for pip and GitHub Actions.

### Changed
- Test suite: 379 → 419 tests, coverage 87 %.
- Dashboard sidebar simplified.

## [1.0.0] - 2026-10-22

### Added
- First version: SSH and web-app log ingestion, five explainable rules with risk scoring,
  SQLite storage, Markdown/CSV/JSON reports, bilingual Streamlit dashboard, optional
  Isolation Forest, synthetic data generator.