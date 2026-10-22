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

## Two-minute demo

```bash
pip install -r requirements.txt
python tools/make_test_files.py --clean        # build a safe test corpus in ./sandbox
python demo_entropy.py                          # why entropy alone is not enough
python -m ransomguard.monitor --enforce --duration 30   # terminal 1: the detector
python -m simulator.fake_ransomware --delay 0.3         # terminal 2: the attack
# watch terminal 1: ALERT -> culprit -> suspend -> recovery -> kill, folder restored
python -m pytest tests -q                       # 67 tests
```

## Status

| Phase | Contents | State |
|-------|----------|-------|
| 1 | entropy / chi-square / magic bytes, test corpus, demo, unit tests | done |
| 2 | attack simulator + undo | done |
| 3 | baseline, canary files, watchdog monitor, scorer (log only) | done |
| 4 | process monitor + responder (suspend/kill) | done |
| 5 | backup + hash-verified recovery | done |
| 6 | evaluation runs, results table, charts | done |
| 7 | Streamlit dashboard | done |

All 67 unit tests pass. Developed and demoed on Windows 11 (Python 3.15); the code is pure
Python and also runs on Ubuntu. The one platform-specific area is process attribution -
see **Known limitations** for the measured Windows behaviour and how it is handled.

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

## Run (phase 3: live monitor, log-only)

```bash
# terminal 1 - start the detector (rebuilds baseline + canaries, then watches)
python -m ransomguard.monitor --path ./sandbox/protected
#   or auto-stop after N seconds for a scripted demo:
python -m ransomguard.monitor --duration 20

# terminal 2 - launch the safe simulator against it
python -m simulator.fake_ransomware --delay 0.12 --order alphabetical

# afterwards: inspect the structured log
python -c "import json;[print(l.strip()) for l in open('sandbox/events.jsonl')]"
python -m simulator.undo        # restore the corpus
```

In phase 3 the monitor only *logs* the alert; it does not kill or restore yet. With
alphabetical order the attacker meets the `aaa_` canary first, so the alert fires on the
very first encrypted file (score 85 = canary 60 + low-chi 10 + suspicious-ext 15).

## Run (phase 4: enforcing - suspend + kill)

```bash
# terminal 1 - enforcing monitor (suspends then kills the attributed process)
python -m ransomguard.monitor --enforce --duration 25

# terminal 2 - the attacker; note the PID it prints
python -m simulator.fake_ransomware --delay 0.12 --order alphabetical
```

The monitor logs `ALERT -> culprit(pid) -> suspend -> kill`. The killed PID matches the
PID the simulator printed, which is how we verify the right process was stopped. A typical
run stops the attack after ~10 of 16 files (corpus + canaries); the gap is the time to
attribute a PID, and phase 5 restores those encrypted files from the backup.

## Run (phase 5: enforce + recover - the full pipeline)

```bash
python -m ransomguard.monitor --enforce --duration 25
python -m simulator.fake_ransomware --delay 0.25 --order alphabetical
```

The monitor now logs the complete response, in this deliberate order:

```
ALERT -> culprit(pid) -> suspend -> recovery(affected/restored/failed) -> kill
```

The order matters: we **suspend first** (freezing the attacker so it cannot damage more
files), **recover while it is frozen** (restore every changed/deleted/`.locked` file from
the hash-verified backup and delete the artifacts), and **kill last**. A clean run ends
with the folder byte-for-byte identical to its clean state - every restored file is
re-hashed against the manifest, so `restored` is a verified count, and `.locked` files
left = 0.

Backup details: at startup the folder is snapshotted to `./sandbox/.backup` with a
SHA-256 manifest. A background thread folds **benign** edits into the backup every few
seconds (same name, magic bytes intact, no high-entropy jump), but never while an alert is
active - so ransomware output can never overwrite a good backup. Recovery restores from
this backup, not from the simulator's key, so it works against real ransomware too.

If an attack is so fast it finishes before a PID can be attributed, the monitor still runs
recovery (logged as `enforce_unattributed -> recovery`) and restores 100% of the files -
the kill simply has nothing left to stop.

## Run (phase 6: evaluation - the numbers for the report)

```bash
# run the trials (>=10 attack trials across speeds/orders + benign false-positive runs)
python -m evaluation.run_experiment          # full matrix
python -m evaluation.run_experiment --quick  # short smoke run

# render the markdown table + charts from the recorded results
python -m evaluation.report
```

Each **attack trial** builds a fresh corpus, starts the enforcing monitor, runs the
simulator at a given speed/order, and records four metrics: detection time (attack start ->
process suspended), files encrypted before the attacker was stopped, files restored
(hash-verified), and failures. Each **benign trial** runs `tools/benign_workload.py`
(editing documents, copying photos, zipping, writing a large gzip) under the same monitor
and counts false positives - the target is 0. The benign workload deliberately does not
touch the canaries, exactly as a real user would not.

Outputs land in `evaluation/results/`: `results.json` (raw), `results.md` (the table), and
three PNG charts (`encrypted_vs_restored.png`, `detection_time.png`,
`recovery_vs_false_positives.png`). The results directory is git-ignored; regenerate it
with the two commands above.

## Run (phase 7: live dashboard)

```bash
# terminal 1 - enforcing monitor
python -m ransomguard.monitor --enforce

# terminal 2 - the Streamlit dashboard (opens in your browser)
streamlit run dashboard/app.py

# terminal 3 - launch the attack and watch the dashboard react
python -m simulator.fake_ransomware --delay 0.3 --order alphabetical
```

The dashboard reads only `./sandbox/events.jsonl` - it never touches the sandbox or the
detector, so it is safe to leave running. It shows the live suspicion score vs. the
threshold, the alert and the response taken (culprit PID, suspend, kill), how many files
were encrypted and how many were restored, the canary status, a score-over-time chart and a
scrolling feed of file events with the signals that fired. It auto-refreshes every 2 s.

### Results (one representative full run, 10 attack + 3 benign trials)

| metric | value |
|--------|-------|
| attacks attributed + killed | 9 / 10 (the 0.05 s/file trial finished before a PID could be attributed) |
| detection time (attack start → suspended) | mean 1.63 s, min 0.59 s, max 3.17 s |
| files encrypted before the attacker was stopped | mean 7.6 of 16, min 2, max 16 |
| **folder fully clean at end (ground truth)** | **10 / 10 trials**, 0 leftover `.locked`, 0 failures |
| false positives on benign work | **0** across 3 runs |
| wrongful kills on benign work | **0** |

The "folder fully clean" row is the honest one: the harness re-hashes every file against a
snapshot taken *before* the attack, rather than trusting what recovery reported. It is 10/10
because the monitor **re-arms** after each response and does a final recovery sweep, so even
when attribution first kills the wrong writer, the ongoing attack trips the score again, the
real attacker is identified on the next wave, and recovery restores everything from the
hash-verified backup. Meanwhile ordinary heavy work - editing documents, copying photos,
zipping, writing a 2 MB gzip - raises no alarms. Numbers vary slightly run to run (live
timing); regenerate with the commands above, the shape is stable.

Example output of `demo_entropy.py` (phase 1):

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
  it. We attribute damage to a process behaviourally, and **never by process name or
  command line** — renaming the attacker does not help it hide (proven by a test that runs
  the simulator as `invoice_viewer.py` and still catches it). An optional fanotify path
  (`config.USE_FANOTIFY`, Linux only) is left as the exact alternative.
- **Windows psutil reality (measured on the demo machine, on the *real* worker PID).**
  An earlier note here claimed `io_counters()` returned 0 and was wrong: it had queried the
  venv **launcher stub** PID, which does no I/O. On the real worker:
  - `io_counters().write_bytes` **works** — it climbs ~MB/s as the process encrypts.
  - `open_files()` **misses** the simulator: it opens/writes/closes each file in well under
    one sampling interval (measured 0 hits in 12 samples). It is reliable only for a process
    that keeps a handle open, and on Linux — so it is used there (behind
    `config.ATTRIB_USE_OPEN_FILES`) but disabled on Windows, where it can also *block* the
    sampler on a busy system process.

  So attribution is **write-behaviour based**: while the sandbox is actively changing (the
  monitor feeds each event's byte count to the process monitor), the culprit is the
  non-whitelisted process that wrote the most in that window. A name/PID **whitelist**
  (matched case-insensitively, ignoring `.exe`, so one entry `code` covers `Code.exe`)
  protects shells, editors, browsers and kernel pseudo-processes such as `Registry` — this
  is the safety net that stops an innocent heavy writer from ever being suspended, and is
  the one place names are used (to *protect*, never to *accuse*). Because the venv's
  `python.exe` is a launcher that re-spawns the real interpreter as a child, the attributed
  PID is that child — the same PID the simulator prints with `os.getpid()`.
- **Detection-to-kill gap.** The monitor suspends the attacker as soon as it is attributed
  (a few seconds after the first alert, once its write volume is unambiguous), then recovers
  and kills. Some files are encrypted in that gap; they are not lost — recovery restores
  them from the hash-verified backup, and across runs the folder comes back byte-for-byte
  clean. If an attack finishes before attribution, recovery still restores 100%. Phase 6
  measures the gap.
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
