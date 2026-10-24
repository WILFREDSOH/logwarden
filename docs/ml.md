# Anomaly detection (experimental)

*Version française : [fr/ml.md](fr/ml.md)*

## Why add a model at all?

Rules only catch what they were written for. The demo contains a **low-and-slow** attack
(198.51.100.77: 31 failures over 3 hours on 3 accounts, ~1 every 5 min) that stays under every
rule threshold: **no rule fires**. The question was whether a simple unsupervised model adds
value there. On this synthetic data it does; that is the only claim made.

## Features (one row per source IP and 60-minute window)

| Feature | Meaning |
|---|---|
| `n_events` | authentication events |
| `n_failures` | failures (incl. unknown accounts) |
| `n_success` | successes |
| `n_invalid_user` | attempts on non-existent accounts |
| `failure_ratio` | failures / events |
| `n_users` | distinct accounts |
| `mean_gap_s` | mean time between events (one event = window length) |
| `off_hours_ratio` | share of events outside business hours (same definition as LW-004) |

Counts are `log1p`-scaled. No IP address or username is used as a feature.

## Training strategy

* **Baseline**: a separate dataset of normal activity only (seed 7, 14 days: 490 events, 372 windows), never
  the demo data. It plays the role of "known normal history".
* **Fit**: `IsolationForest(n_estimators=200, random_state=42)` on baseline windows **plus** the
  windows to score. This is unsupervised: no label is used, so there is no label leakage.
* **Threshold**: 99th percentile of the scores of the *baseline* windows
  (`ml.contamination_quantile = 0.01`) → about 1 % of normal windows would be flagged.
* **Explanation**: for each window, the 3 features furthest from the baseline median.
* The model is refitted on each run (< 1 s) and never written to disk (no pickle).

### A finding 

The first version fitted the forest on the baseline only. Result: the 40-failure brute force
scored *less* anomalous than normal traffic. An Isolation Forest splits each feature between the
min and max seen during training; a value far beyond the training range falls in the same leaf as
the training maximum, so the model **cannot extrapolate**. Fitting on baseline + scored windows
(with the threshold still calibrated on the baseline only) fixed it. This was observed, then
corrected, then locked by a test (`tests/integration/test_pipeline.py`).

## Results on the demo dataset (actually measured)

Unit = (source IP, hour) window; 189 windows; a window is "malicious" if it overlaps a labelled
attack of that IP.

| Detector | TP | FP | FN | TN | Precision | Recall |
|---|---|---|---|---|---|---|
| Rules | 4 | 0 | 3 | 182 | 100 % | 57 % |
| Isolation Forest | 6 | 1 | 1 | 181 | 86 % | 86 % |
| Rules + ML | 7 | 1 | 0 | 181 | 88 % | 100 % |

* The 3 windows missed by the rules are the low-and-slow attack; the model flags all three.
* The model misses `dave`'s 03:12 login: a single, normal-looking event; the rule LW-004 catches
  it. **The two approaches are complementary.**
* The model's false positive is a background-noise IP (1 attempt on an unknown account), which
  is arguably a real scanner but labelled benign.

## Limits — read before quoting these numbers

* **Synthetic and circular**: the attacks were designed by the same person who designed the
  features. Real-world precision/recall is unknown and would certainly be lower.
* 189 windows and 7 positive windows: far too few for statistically meaningful metrics.
* The threshold is a choice (1 %); on real traffic 1 % of hundreds of thousands of windows is a
  large number of alerts to triage.
* Anomalies are shown as **triage hints, not alerts**: they have no severity and no
  recommendation, and the rules remain the reference.
* Concept drift (new users, holidays) would require recalibrating on a recent baseline.

Keeping the model is justified by the low-and-slow case, but it stays optional
(`pip install -e ".[ml]"`, `logwarden demo --no-ml`).
