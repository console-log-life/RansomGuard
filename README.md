# Real-Time Ransomware Detection and File Recovery

Using Entropy, Canary Files and Process Behaviour Monitoring.

A background tool that watches one folder, detects ransomware-like file activity in real
time from three independent signals, stops the responsible process when a combined
suspicion score crosses a threshold, and restores the damaged files from a hash-verified
backup. Everything is measured, so the project produces numbers (detection time, files
lost, files restored, false positives) and not just a demo.

> **Everything happens inside `./sandbox/`.** The detector, the recovery code and the
> attack simulator all route every write and delete through `config.ensure_inside()`,
> which refuses any path outside the sandbox. The simulator is a file-level mimic only:
> it does not spread, persist, hide, touch the network, or delete anything outside
> `./sandbox/protected`, and its AES key is always saved to `./sandbox/sim_key.bin` so
> every file it encrypts can be decrypted again.

## Status

| Phase | Contents | State |
|-------|----------|-------|
| 1 | entropy / chi-square / magic bytes, test corpus, demo, unit tests | done |
| 2 | attack simulator + undo | planned |
| 3 | baseline, canary files, watchdog monitor, scorer (log only) | planned |
| 4 | process monitor + responder (suspend/stop) | planned |
| 5 | backup + hash-verified recovery | planned |
| 6 | evaluation runs, results table, charts | planned |
| 7 | Streamlit dashboard, README polish | planned |

## Setup

Target environment is Ubuntu with Python 3.10+; the code is pure Python and also runs on
Windows (process suspension in phase 4 is the only platform-specific part).

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run (phase 1)

```bash
# 1. build the safe test corpus in ./sandbox/protected
python tools/make_test_files.py --clean

# 2. the demo to show first: entropy of text vs jpg vs zip vs AES-encrypted text
python demo_entropy.py

# 3. unit tests
python -m pytest tests -q
```

Example output of `demo_entropy.py`:

```
file                              size  entropy     chi-square    magic        verdict
--------------------------------------------------------------------------------------
essay.txt (plain text)          9.1 KB    4.188        157,155      n/a     structured
photo.jpg (compressed)        117.2 KB    7.997            234       ok   looks random
project.zip (compressed)        2.2 KB    7.577          4,123       ok     structured
essay.txt.locked (AES)          9.1 KB    7.982            231      n/a   looks random
```

Read it as the argument for the whole design: encryption pushes entropy to ~8.0 and
chi-square down to ~255 — but a JPEG does the same, so **entropy alone is not a
detector**. That is why the score combines several signals.

## Architecture

```
                         ./sandbox/protected  (the only folder we touch)
                                   |
                   file events     |      process stats
         watchdog  ---------->  monitor.py  <---------- process_monitor.py (psutil)
                                   |                      write-rate per PID,
                                   |                      open files in sandbox
              +--------------------+--------------------+
              |                    |                    |
         entropy.py            canary.py           baseline.py
      entropy, chi-square,  canary files touched?  startup entropy +
      magic-byte check                             SHA-256 of every file
              |                    |                    |
              +--------------------+--------------------+
                                   v
                              scorer.py          weighted score per process,
                                   |             decays by half every 30 s
                        score >= 70 (config)
                                   v
                             responder.py        suspend -> log alert -> stop
                                   |
                                   v
                             recovery.py         compare hashes against the
                                   |             manifest, restore originals,
                                   v             verify, remove .locked files
                      backup.py  ./sandbox/.backup + manifest.json
                                   |
                              logger.py  ->  events.jsonl  ->  dashboard / evaluation
```

## The signals, and why each one is needed

| Signal | Module | What it catches | Why it is not enough alone |
|--------|--------|-----------------|----------------------------|
| Shannon entropy jump | `entropy.py` | plaintext turning into ciphertext | jpg/zip/mp4 are already at ~7.9 |
| Chi-square near uniform | `entropy.py` | byte distribution flattening out | same compressed-file problem |
| Magic bytes broken | `entropy.py` | a `.pdf` that no longer starts with `%PDF` | says nothing about `.txt` files |
| Canary file touched | `canary.py` | a crawler walking the whole folder | a targeted attack may skip them |
| Suspicious extension | `scorer.py` | renames to `.locked`, `.enc`, … | in-place encryption keeps the name |
| Write burst | `scorer.py` | many modifications in 5 s | a backup tool also writes in bursts |
| Write-rate per process | `process_monitor.py` | *which* process is doing it | the OS does not tell us who wrote a file |

**Shannon entropy.** `H = -Σ p(x)·log₂ p(x)` over the 256 byte values, so `H` is in
bits per byte and maxes out at 8.0. One repeated byte gives 0.0, English text ~4.2,
AES-GCM output ~7.99. Only the first 64 KB of a file is sampled so the live monitor stays
fast on large files.

**Chi-square.** `X² = Σ (observed(x) − n/256)² / (n/256)`, i.e. the byte histogram against
a uniform one. With 256 buckets there are 255 degrees of freedom, so truly random bytes
score near 255 while text scores in the tens of thousands. A *low* chi-square therefore
means "this looks random" — hence the threshold name `CHI_SQUARE_RANDOM_MAX`.

## Known limitations

- **PID attribution.** `watchdog` (inotify) reports *what* changed, never *who* changed
  it. Phase 4 attributes an event to the most likely PID by intersecting "processes with
  an open file inside the sandbox" with "processes whose write rate spiked in the same
  time window". This is a heuristic and can mis-attribute under heavy concurrent I/O. An
  optional fanotify path (`config.USE_FANOTIFY`, Linux only) is planned as the exact
  alternative; the psutil method must work on its own.
- Entropy is measured on the first 64 KB only, so a file encrypted from the tail backwards
  would be missed by that one signal (the magic-byte and canary signals still fire).
- The simulator mimics file behaviour only. Real ransomware also kills services, clears
  shadow copies and spreads laterally; none of that is implemented, by design.
- Detection is reactive, so some files are always lost before the process is stopped. The
  evaluation in phase 6 measures exactly how many.

## Layout

```
ransomguard/    detection engine (config, entropy, baseline, canary, process_monitor,
                scorer, responder, backup, recovery, monitor, logger)
simulator/      safe attack simulator + undo script
tools/          test-corpus generator, benign workload generator
evaluation/     experiment runner, results table and charts
dashboard/      Streamlit live view
tests/          pytest unit tests
sandbox/        generated at runtime: protected/, .backup/, events.jsonl (git-ignored)
```
