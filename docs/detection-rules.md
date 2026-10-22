# Detection rules

*Version française : [fr/detection-rules.md](fr/detection-rules.md)*

All parameters live in `src/logwarden/default_config.toml` and can be overridden with
`--config my.toml`. "Failure" means `auth_failure` **or** `invalid_user`.

## Risk score

```
score = base score of the rule
      + 15  if a targeted account is privileged (root, admin, administrator)
      + 20  if a successful login is part of the evidence (LW-005 only; for LW-003/LW-004 the
            success is already the point of the rule and is priced in the base score)
      + 5   per volume step reached: count >= 2x, 4x, 8x the rule threshold (max +15)
capped to 0..100
```

| Score | Severity |
|---|---|
| 0-29 | low |
| 30-59 | medium |
| 60-84 | high |
| 85-100 | critical |

Every alert stores its breakdown, e.g. `base +70 ; privileged account +15 ; high volume +5 = 90`.

## LW-001 Brute force

* **Behaviour**: many failed logins from one source IP in a short time.
* **Trigger**: ≥ `threshold` (5) failures from the same IP within `window_minutes` (5), boundary
  inclusive. One alert per burst; the burst ends after `window_minutes` without failure.
* **Score**: base 40 + privileged + volume (failures vs threshold).
* **Edge cases**: failures on several accounts are still one brute force (`username` empty, list
  in the explanation); different IPs are never combined (a distributed attack is missed, see
  limitations); successes do not count.
* **Tests**: `tests/unit/test_rule_lw001_brute_force.py` (threshold, below threshold, exact window
  boundary, burst grouping, two bursts, IP separation, privileged bonus, configurable params).

## LW-002 Password spraying

* **Behaviour**: one IP tries many different accounts (few attempts each) to avoid lockouts.
* **Trigger**: ≥ `distinct_users` (4) distinct accounts failing from the same IP within
  `window_minutes` (10).
* **Score**: base 55 + privileged (if any target is privileged) + volume (accounts vs threshold).
* **Edge cases**: 20 failures on one account is not spraying; events without username ignored;
  a fast spray also triggers LW-001 (both are reported; LW-005 then correlates them).
* **Tests**: `test_rule_lw002_password_spray.py`.

## LW-003 Success after failures

* **Behaviour**: a successful login preceded by repeated failures from the same IP → password
  probably guessed.
* **Trigger**: success from IP X such that ≥ `failures` (3) failures from X (any account) happened
  in the previous `window_minutes` (10). Counting any account covers "spray then success".
* **Score**: base 70 + privileged + volume. A privileged takeover reaches **critical**.
* **Edge cases**: a user who mistypes twice then succeeds is normal (threshold 3); a second success
  of the same user/IP within the window is not re-reported; failures from another IP are ignored.
* **Tests**: `test_rule_lw003_success_after_failures.py`.

## LW-004 Off-hours login

* **Behaviour**: successful login outside business hours or on weekends.
* **Trigger**: success with local time (`timezone`, default UTC) outside
  `[business_start_hour, business_end_hour)` = [7, 20), or on Saturday/Sunday if
  `weekends_are_off_hours`. Accounts in `exempt_users` (e.g. `svc_backup`) are ignored. Successes
  of the same user/IP/day are grouped.
* **Score**: base 25 (low) + privileged → medium for root/admin.
* **Edge cases**: 07:00 is business time, 20:00 is not; on-call staff will cause false positives;
  timezone must be correct (`Europe/Paris` supported).
* **Tests**: `test_rule_lw004_off_hours.py` (boundaries, weekend, exemption, timezone, grouping).

## LW-005 Suspicious IP (correlation)

* **Behaviour**: an IP whose overall behaviour in the dataset is suspicious.
* **Trigger**: the IP triggered ≥ `min_distinct_rules` (2) *different* rules, **or** tried
  ≥ `invalid_user_threshold` (3) non-existent accounts (dictionary scanners).
* **Score**: base 50 + privileged + success (+20 if any login from this IP succeeded) + volume
  (invalid accounts vs threshold).
* **Edge cases**: runs after the other rules and receives their alerts; ignores its own alerts;
  two alerts of the same rule count once.
* **Tests**: `test_rule_lw005_suspicious_ip.py`.

## Engine

`detection/__init__.py::run_detection` sorts events by time, runs LW-001..LW-004, then
correlation rules with the previous alerts, then sorts alerts by severity, score and time.
Alert ids are deterministic (hash of rule + event ids), so two runs on the same data give
identical results (tested).
