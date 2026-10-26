# Security considerations and limitations

*Version française : [fr/securite-et-limites.md](fr/securite-et-limites.md)*

## Scope and ethics

LogWarden is a **defensive, educational** tool. It only reads log files it is given. It performs
no network scan, no active test and contacts no external service (the dashboard has Streamlit
telemetry disabled). All demo data is synthetic and uses RFC 5737 documentation IP ranges.

## Threat model of the tool itself

Log content is **attacker-controlled**: an attacker chooses the username they type. Every
place where log data flows was treated as untrusted input.

| Risk | Mitigation | Test |
|---|---|---|
| Command execution from log content | logs are only matched with regular expressions / `json.loads`; nothing is ever evaluated or passed to a shell; the dashboard launcher uses a fixed argument list (no `shell=True`) | parser tests |
| SQL injection | every query is parameterised | `test_sql_injection_payload_is_stored_as_data` |
| Terminal escape injection (`\x1b[...`) | control characters replaced by `?` before storage/display | `test_control_characters_are_neutralised` |
| Markdown/HTML injection in the dashboard (e.g. a username `![x](http://evil/p.png)` would make the browser contact a server) | log-derived text is escaped or shown in data tables; no `unsafe_allow_html` | `test_dashboard_markdown_escape` |
| CSV/formula injection when an analyst opens the export in a spreadsheet | cells starting with `= + - @` are prefixed with `'` | `test_csv_injection_is_neutralised` |
| Secrets in logs (a client logging passwords/tokens) | configurable `redacted_fields` replaced by `[REDACTED]` before storage | `test_sensitive_fields_are_redacted` |
| Huge or hostile files (memory exhaustion, deep JSON) | size limit (50 MB), line length limit, binary detection, `RecursionError` caught | ingestion tests |
| Dashboard exposed on the network | binds to `127.0.0.1` only; DB opened read-only; upload only in the sandbox tab (2 MB, analysed in memory, never stored, IPs and accounts masked) | `ss -ltn` check, read-only test |
| Unsafe model loading | ML model never serialised (no pickle) | design |
| Corrupted or unwritable database | wrapped into a clear, localised `StorageError`; transactions roll back | storage tests |

Known residual risks: dependencies (Streamlit, scikit-learn, matplotlib) are third-party code;
run `pip-audit` before any real use. `reports/` and the database contain usernames and IPs from
the logs and must be protected like the logs themselves.

## Functional limitations

* **Two log formats only**: OpenSSH messages in syslog, and the demo web app JSON format. Other
  sources need a new parser (the interface is small: `parse_line(str) -> Event | Skip | Malformed`).
* **Batch, not real time**: files are imported on demand; no `tail -f`, no streaming.
* **Syslog has no year**: given with `--year`; a December→January rollover is inferred. A
  traditional timestamp without timezone is interpreted with `--tz` (default UTC). Naive JSON
  timestamps are read as UTC.
* **Deduplication by content**: two genuinely distinct events producing byte-identical lines
  with the same timestamp are counted once.
* **Per-IP rules**: an attack distributed across many IPs (botnet) is invisible to LW-001/LW-002;
  an attacker behind a shared NAT/proxy IP may cause false positives on legitimate users.
* **No allowlist / threat intelligence**: no GeoIP or reputation lookup (would require an external
  service).
* **Thresholds are generic defaults**, not tuned on real traffic.
* **Evaluation is on synthetic data only** (see [ml.md](ml.md)).
* **Single user, local**: no authentication on the dashboard (acceptable only because it listens
  on localhost).

## Possible improvements

1. More parsers: `journalctl -o json`, nginx/Apache access logs, Windows Security events (EVTX via
   a JSON export).
2. Export alerts in a standard format (ECS / Sigma-like rule definitions, syslog/CEF to a SIEM).
3. Per-user baselines (usual IPs, usual hours) to reduce LW-004 false positives.
4. Distributed-attack rule: many IPs targeting the same account.
5. Alert lifecycle in the dashboard (acknowledged / false positive), which would require write
   access and authentication.
6. Evaluate on a public labelled dataset whose licence allows it.
7. `pip-audit` and `bandit` in CI.
