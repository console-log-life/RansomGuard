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

## Threat model

**What RansomGuard defends against.** User-level crypto-ransomware: a program running with
the current user's privileges that encrypts the user's local files. It covers the behaviours
real families use and that our simulator reproduces: whole-file encryption, rename to a new
extension (`.locked`), in-place encryption that keeps the original name, intermittent/partial
encryption (only some blocks), base64-encoded ciphertext (low-entropy evasion), and
deliberately slow drip encryption to dodge burst/rate signals.

**Entry point is out of scope - and that is the point.** How the ransomware arrives -
phishing attachment or macro, malicious download, an exploited vulnerability (e.g.
WannaCry's SMB exploit), stolen/brute-forced RDP credentials, or a USB drive - is not what
RansomGuard addresses. It is a **last line of defence that acts after execution**, on the
file-system behaviour, regardless of how the attacker got in. In the demo, **launching the
simulator stands in for a user opening a malicious file**; everything after that point is
what we detect and recover from.

**Explicitly out of scope:**
- Locker ransomware (locks the screen/desktop but does not encrypt files).
- Disk- or MBR-level encryptors (e.g. Petya-style) that work below the file system.
- Kernel-level or SYSTEM/admin-level ransomware - such activity is still *detected and
  recovered from*, but RansomGuard is a user-level tool and will not try to suspend or kill
  a process it does not own (see **Known limitations**: that needs a kernel driver).
- Data exfiltration / double-extortion (theft of data, not just encryption).

Within scope, RansomGuard's job is narrow and measurable: notice the encryption fast,
stop the responsible user-owned process, and restore every file from a hash-verified,
cryptographically protected backup.

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
| 8 | threat model, NapierOne real dataset, file-level classifier evaluation | done |
| 9 | header-kept attack + structural-validity gate, dual-corpus evaluation | done |

All 114 unit tests pass. Developed and demoed on Windows 11 (Python 3.15); the code is pure
Python and also runs on Ubuntu. The one platform-specific area is process attribution -
see **Known limitations** for the measured Windows behaviour and how it is handled.


## How to run

### Setup

Python 3.10+. Developed and demoed on Windows 11; the code is pure Python and also runs on
Ubuntu. Process suspension is the only platform-specific part.

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### The demo (three terminals)

First build the safe corpus and show why entropy alone is not a detector:

```bash
python tools/make_test_files.py --clean   # safe corpus in ./sandbox/protected
python demo_entropy.py                    # text vs jpg vs zip vs AES-encrypted text
```

Then run the live pipeline:

```bash
# terminal 1 - the enforcing monitor (builds baseline + canaries, then watches)
python -m ransomguard.monitor --enforce

# terminal 2 - the live dashboard (optional, opens in your browser)
streamlit run dashboard/app.py

# terminal 3 - the attack; note the PID it prints
python -m simulator.fake_ransomware --delay 0.3 --order alphabetical
```

Terminal 1 logs the complete response, in this deliberate order:

```
ALERT -> culprit(pid) -> suspend -> recovery(affected/restored/failed) -> kill
```

The order matters: we **suspend first** (freezing the attacker so it cannot damage more
files), **recover while it is frozen** (restore every changed/deleted/`.locked` file from
the hash-verified backup and delete the artifacts), and **kill last**. A clean run ends
with the folder byte-for-byte identical to its clean state - every restored file is
re-hashed against the manifest, so `restored` is a verified count, and `.locked` files
left = 0. If an attack is so fast it finishes before a PID can be attributed, the monitor
still runs recovery (logged as `enforce_unattributed -> recovery`) and restores 100% of
the files - the kill simply has nothing left to stop.

Useful variations:

```bash
python -m ransomguard.monitor                     # log-only: no suspend, no kill
python -m ransomguard.monitor --enforce --duration 30   # auto-stop, for a scripted demo
python -m simulator.fake_ransomware --mode base64       # full | no-rename | base64 |
                                                        # intermittent | header-kept
python -m simulator.undo                          # reverse the simulator's own damage
```

Backup details: at startup the folder is snapshotted to `./sandbox/.backup` with a SHA-256
manifest. A background thread folds **benign** edits into the backup every few seconds
(same name, magic bytes intact, no high-entropy jump), but never while an alert is active -
so ransomware output can never overwrite a good backup. Recovery restores from this backup,
not from the simulator's key, so it works against real ransomware too.

The dashboard reads only `./sandbox/events.jsonl` - it never touches the sandbox or the
detector, so it is safe to leave running. It shows the live suspicion score vs. the
threshold, the alert and the response taken (culprit PID, suspend, kill), files encrypted
and restored, canary status, a score-over-time chart and a scrolling feed of file events
with the signals that fired, refreshing every 2 s. Everything is scoped to the **current
run** (events after the latest `startup`), so an earlier demo never bleeds into the chart.

> **Reset between demos.** The log is append-only, so start each demo from a clean slate:
> `python tools/make_test_files.py --clean` rebuilds the corpus, and the next
> `python -m ransomguard.monitor --enforce` writes a fresh `startup` the dashboard scopes
> to. (To also clear history, delete `./sandbox/events.jsonl` before starting.)

### Evaluation

Run these **one at a time** - they all drive the same `./sandbox`, so a concurrent run
would corrupt another's measurements.

```bash
# live trials on the generated corpus (10 attack trials + 3 benign false-positive runs)
python -m evaluation.run_experiment --corpus synthetic
python -m evaluation.attack_matrix  --corpus synthetic

# the same on ~200 REAL files sampled from NapierOne (see Dataset below)
python -m evaluation.run_experiment --corpus napierone
python -m evaluation.attack_matrix  --corpus napierone

# render the combined report (both corpora side by side) + charts
python -m evaluation.report
```

Each **attack trial** builds a fresh corpus, starts the enforcing monitor, runs the
simulator at a given speed/order, and records detection time (attack start -> process
suspended), files encrypted before the attacker was stopped, files restored
(hash-verified), and failures. Each **benign trial** runs `tools/benign_workload.py`
(editing documents, copying photos, zipping, writing a large gzip) under the same monitor
and counts false positives - the target is 0; it deliberately does not touch the canaries,
exactly as a real user would not. The **attack matrix** crosses every attack mode with
canaries on/off and also replays each one offline against the original detector, which is
where the old-vs-new comparison comes from.

Outputs land in `evaluation/results/`: raw JSON per corpus, `results.md` (all tables) and
the PNG charts. The raw JSON is git-ignored; regenerate it with the commands above.

### Dataset (real NapierOne files)

```bash
python tools/fetch_napierone.py --count 40 --max-archive-mb 170   # -> datasets/napierone_sample/
python evaluation/build_dataset.py                                # -> datasets/labeled/ + labels.csv
python evaluation/dataset_eval.py                                 # -> dataset_results.md + charts
```

### Tests

```bash
python -m pytest tests -q        # 114 tests
```

## Results: synthetic vs real NapierOne corpus

Both corpora, 10 attack + 3 benign trials each, plus a 12-cell attack matrix each
(`evaluation/results/results.md`):

| corpus | files | attacker killed | folder clean | detection | files encrypted | false positives | matrix clean | new catches vs old |
|--------|-------|-----------------|--------------|-----------|-----------------|-----------------|--------------|--------------------|
| synthetic | 16 | 8/10 | **10/10** | 1.59 s | 9.5 (59 %) | **0** | 12/12 | 2 |
| **NapierOne (real)** | 204 | **10/10** | **10/10** | 2.28 s | 13.9 (**7 %**) | **0** | 12/12 | 0 |

Reading it:

- **On real files the detector does better, not worse.** With a realistic 204-file corpus
  every attacker was attributed and killed (10/10) and only ~7 % of files were touched,
  versus 59 % on the tiny 16-file synthetic set - a small corpus is simply consumed before
  attribution can finish, which is an artefact of the test size, not of the detector.
- **Folder fully clean 10/10 on both**, verified by re-hashing every file against a snapshot
  taken *before* the attack (not by trusting what recovery reported). The monitor re-arms
  after each response and does a final sweep, so even a mis-attributed first wave ends clean.
- **Zero false positives on both** during benign work (editing documents, copying photos,
  zipping, writing a 2 MB gzip).
- **"New catches vs old" is 2 on synthetic and 0 on NapierOne** - and that is the honest
  result, not a disappointment: real files carry magic bytes and structure that the original
  detector already exploited, so the base64/intermittent evasions only beat it on the
  text-only corpus. That hard case is exactly why the upgrades exist.

Numbers vary slightly run to run (live timing); regenerate with the commands above.

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
                                   |                   write volume per PID, correlated
                                   |                   with sandbox activity; CURRENT-USER
                                   |                   processes only, never matched by name
              +--------------------+--------------------+
              |                    |                    |
         entropy.py            canary.py           baseline.py
   entropy + chi-square,   canary files touched?  startup entropy +
   magic bytes, multi-offset                      SHA-256 of every file
   windows, base64/encoded
   detection, STRUCTURAL
   validity (zip/png/gz/pdf/jpg)
              |                    |                    |
              +--------------------+--------------------+
                                   v
                              scorer.py       weighted score for sandbox activity
                                   |          (one actor), decays by half every 30 s
                        score >= 70 (config)
                                   v
                             responder.py     1. SUSPEND the attacker (freeze damage)
                                   |
                                   v
                             recovery.py      2. verify manifest HMAC, decrypt the
                                   |             AES-GCM backup, restore + hash-verify,
                                   |             remove .locked artifacts
                                   v
                             responder.py     3. KILL  ->  4. final sweep  ->  5. RE-ARM
                                   |                        (loops back if the attack
                                   |                         is still running)
      backup.py  ./sandbox/.backup/  (AES-256-GCM encrypted copies, path bound as AAD)
                 ./sandbox/.backup/manifest.json  (HMAC-SHA256 signed)
                                   |
                              logger.py  ->  events.jsonl  ->  dashboard / evaluation
                                              (hash-chained, tamper-evident)
```

Note the response **order**: the attacker is suspended *first*, files are recovered while it
is frozen, and only then is it killed - after which the monitor re-arms, so a continuing
attack is caught on the next wave. Scoring is per *sandbox activity*, not per process; the
process monitor's job is only to decide **which** process to stop.

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

## Smarter attacks and stronger detection

The simulator has several modes, all still sandbox-only and fully reversible from the saved
key (one self-describing container format, reversed by `simulator/undo.py`):

| `--mode` | what it does | which signal it tries to dodge |
|----------|--------------|-------------------------------|
| `full` | AES-GCM the whole file, rename to `.locked` (the loud baseline) | none - trips everything |
| `slow` | full encryption, but one file every ~1-2 s | burst detection and score decay |
| `no-rename` | encrypt in place, keep the original name and extension | the suspicious-extension signal |
| `base64` | base64-encode the ciphertext (entropy ~6, not ~8), in place | entropy-jump and low-chi-square |
| `intermittent` | encrypt only some 64 KB blocks, leaving the first block plaintext | first-64 KB entropy sampling |

Two detection upgrades (both toggleable via `config.FEATURE_*`, which is how the evaluation
reproduces the "old" detector for the before/after comparison):

- **Multi-offset entropy.** Instead of sampling only the first 64 KB, the detector samples
  several windows (`config.ENTROPY_WINDOWS`, default 6) across the file and keeps the most
  suspicious one. Partial/intermittent encryption can no longer hide in an untouched region.
  *Latency trade-off (measured, not hidden):* reading 6 windows instead of 1 makes
  `analyse_file` on a large (~2 MB) file about 6x slower (~8 ms -> ~50 ms per call after
  optimising it to compute each window's entropy once). Because analysis runs synchronously
  on every watchdog event, this extra per-event latency lets a fast attacker encrypt a
  few more files before the score crosses the threshold - it is one of the reasons the
  slowest attacks are killed while the fastest finish first (currently 6/10 killed, mean
  12.2/16 files encrypted; see `evaluation/results/results.md`).
  No files are lost (recovery still restores 10/10 to a clean folder); it is a
  detection-latency cost of looking harder, and the sampling (windows, not whole files)
  keeps it bounded.
- **Encoded-content detection.** A charset + entropy heuristic (`entropy.is_encoded`) flags
  content that is ~95% base64 characters with entropy in the ~4.5-6.5 range - i.e. base64ed
  ciphertext, whose entropy is too low to trip the entropy-jump or chi-square signals. It
  only fires on a file that used to be ordinary low-entropy content, so a genuinely new
  base64 file is not blamed.

The magic-byte, canary and hash-mismatch signals (unchanged) catch `no-rename`: encrypting
in place destroys a known file's header and changes its hash versus the baseline/manifest.

```bash
python -m simulator.fake_ransomware --mode intermittent --delay 0.15
python -m simulator.fake_ransomware --mode base64 --delay 0.15
python -m simulator.undo                      # reverses every mode

# ablation + attack-matrix (attack modes x canaries on/off, old-vs-new detector):
python -m evaluation.attack_matrix --corpus synthetic
python -m evaluation.attack_matrix --corpus napierone
python -m evaluation.report                    # writes results.md + charts
```

The attack-matrix (committed in `evaluation/results/results.md`, with
`old_vs_new_detection.png`) scores every mode with the old and the new signal set, run on a
large **text-only** corpus (no magic bytes) so the entropy/encoded signals are what decide
the result. Headline before/after, with **canaries off** (so the decoy signal cannot mask
the comparison):

| mode | new detector | old detector |
|------|--------------|--------------|
| full | caught | caught |
| slow | caught | caught |
| no-rename | caught | caught (entropy jump) |
| **base64** | **caught** (encoded signal) | **MISSED** |
| **intermittent** | **caught** (multi-offset) | **MISSED** |
| header-kept | caught | caught (entropy jump) |

So the two upgrades newly catch exactly the two attacks designed to evade the original
entropy/magic signals; `no-rename` was already caught by magic/entropy, and with canaries
on every mode is caught. Recovery restored the folder to a byte-for-byte clean state in all
12 matrix cells on **both** corpora (ground truth), and `clean pre-sweep` shows several
cells needed the final stop() recovery sweep to get there.

`header-kept` is caught by the old detector too, and that is expected: this corpus is
text, whose baseline entropy is ~4.5, so encrypting the body past the kept header still
produces a large entropy jump. The same is true on the mixed NapierOne corpus, where every
mode is caught by both detectors - a whole-attack view saturates, because one low-entropy
text file anywhere in the folder is enough to raise the alarm. **The place header-kept
actually differentiates is the per-file evaluation**, where each file is judged alone: see
the Dataset section, where header-kept recall on MP3/MP4 goes 0.000 -> 1.000, MKV
0.000 -> 0.966, and DOCX/XLSX 0.417/0.185 -> 1.000.

One honest residual: on the NapierOne corpus the `slow` cell with canaries on ends
`no_kill` - at 1.5 s/file the attacker's write volume stays under the attribution rate, so
no PID is pinned. Recovery still restored all 64 affected files and the folder ended
byte-for-byte clean; the kill simply had no confident target.

> **Honest caveat.** This before/after gap is measured on a **text-only** corpus on
> purpose. Every encrypted file begins with the simulator's container header (`RGSIM1`),
> which destroys the original magic bytes - so on a **mixed** corpus the OLD detector would
> already catch `base64` and `intermittent` too, via the magic-byte signal on the
> structured files (pdf/jpg/docx/…). Text files have no magic bytes to break, so they are
> the hard case that isolates the new entropy/encoded signals. In other words, the upgrades
> matter most for plaintext-heavy data; for structured files the existing magic-byte signal
> was already doing the job.

## Cryptographic protection of the backup, manifest and log

The backup and the evidence are themselves hardened, so an attacker who reaches them cannot
quietly defeat recovery:

- **Encrypted backups (AES-256-GCM).** Every file in `./sandbox/.backup` is stored as
  ciphertext, with its relative path bound in as GCM associated data (blobs cannot be
  swapped between paths). Recovery decrypts and verifies the GCM tag *before* it will write
  anything back; a forged or bit-flipped blob is refused.
- **Signed manifest (HMAC-SHA256).** The manifest of clean hashes is signed. Recovery
  verifies the signature first and refuses a tampered manifest outright - otherwise an
  attacker could rewrite the "known-good" hashes and defeat verification.
- **Hash-chained log.** Each line of `events.jsonl` carries the SHA-256 of the previous
  line, so editing, inserting or deleting any earlier line breaks every hash after it.
- **Key location.** The AES and HMAC keys are two domain-separated subkeys of one master
  key in `./sandbox/backup_key.bin`. For this student project the key is a sandbox file; a
  real deployment would hold it in an OS keystore / TPM / HSM, off the protected disk. This
  is documented in `config.py` and `backup.py`, not hidden.

```bash
# the protections are exercised by the test suite:
python -m pytest tests/test_crypto_protection.py -q

# verify the live log chain at any time (True, -1 means intact):
python -c "from ransomguard.logger import verify_log; print(verify_log())"

# prove a tampered manifest is rejected: edit one hash digit in
# sandbox/.backup/manifest.json, then:
python -c "from ransomguard import backup; backup.load_manifest()"   # raises ManifestTampered
```

## Dataset

Beyond the generated corpus, the detector is evaluated on **real files** from **NapierOne**,
a modern mixed-file data set built for exactly this kind of work.

> Davies, S. R., Macfarlane, R., & Buchanan, W. J. (2022). *NapierOne: A modern mixed file
> data set alternative to Govdocs1.* Forensic Science International: Digital Investigation,
> 40, 301330.

The data is fetched anonymously (unsigned, no AWS account) from the project's public bucket
`s3://napierone.com`. It is **not redistributed here**: `datasets/` is git-ignored, and the
sample is rebuilt locally from the authors' own copy. All credit and rights remain with the
NapierOne authors; please cite them if you use it.

**What we sample.** NapierOne stores one large ZIP *bundle* per file type rather than loose
files, so the tool downloads the smallest bundle under a size cap and extracts a seeded
random sample from it (skipping anything over 5 MB). With a 170 MB cap that gives **480
files across 12 types** - JPG, PNG, MP3, MP4, MKV, PDF, DOCX, XLSX, TXT, CSV, JSON, HTML.
The remaining types (ZIP, RAR, 7ZIP, GZIP, PPTX) have 303-625 MB bundles and are skipped by
default; raise `--max-archive-mb` to include them.

```bash
pip install -r requirements.txt                      # boto3 for the unsigned S3 access
python tools/fetch_napierone.py --count 40 --max-archive-mb 170   # -> datasets/napierone_sample/
python evaluation/build_dataset.py                   # -> datasets/labeled/ + labels.csv
python evaluation/dataset_eval.py                    # -> dataset_results.md + charts
```

`build_dataset.py` turns each source file into 7 labelled variants - benign (original, ZIP,
GZIP) and ransomware (full, intermittent, base64, header-kept) - split 30/70 tuning/test
**by source file**, so no file's variants straddle the split. That is 3360 labelled samples
from 480 originals.

### File-level results (`evaluation/results/dataset_results.md`)

Each sample is scored **on its own**, with the threshold tuned on the tuning split only and
the test split never touched during tuning:

| detector | precision | recall | F1 | FPR | AUC |
|----------|-----------|--------|----|-----|-----|
| **new** (structural gate + multi-offset + encoded + structure_broken) | **0.998** | **0.980** | **0.989** | 0.003 | **0.989** |
| old (first-window entropy + magic only) | 0.997 | 0.893 | 0.942 | 0.003 | - |
| entropy alone | 0.600 | 0.998 | 0.749 | 0.888 | 0.564 |

The entropy-alone row is the point of the whole project: it catches nearly everything and
is useless anyway, flagging 89 % of benign files. Results are on the **fresh** split (seed
2025). Because the media structural checks were designed after looking at that split, a
**second independent split (seed 3031)** is also reported and agrees - precision 0.997,
recall 0.972, F1 0.984, AUC 0.985 - so the gain is not tuned to one split.

Header-kept recall is **1.000 for 10 of the 12 file types**. The three the media checks
were written for went from undetectable to near-perfect (MP3 and MP4 0.000 -> 1.000, MKV
0.000 -> 0.966), and scoring the structural finding directly lifted the compressed
container types (DOCX 0.417 -> 1.000, XLSX 0.185 -> 1.000). The two that fall short are
explainable: the remaining MKV misses are large files where the kept 10 % already satisfies
the child-element walk, and TXT stays at 0.778 because plain text has no structure to
check, so header-kept text is caught only when the encrypted remainder moves its entropy
far enough.

**Future work: MLRan.** A natural next step is a comparison against a machine-learning
baseline trained on behavioural traces - e.g. the **MLRan** dataset of ransomware API-call
and registry behaviour. That would test a different detection axis (process behaviour
sequences) than our file-content signals; it is out of scope here and listed only as future
work.

## Known limitations

- **PID attribution.** `watchdog` (inotify) reports *what* changed, never *who* changed
  it. We attribute damage to a process behaviourally, and **never by process name or
  command line** — renaming the attacker does not help it hide (proven by a test that runs
  the simulator as `invoice_viewer.py` and still catches it). An optional fanotify path
  (`config.USE_FANOTIFY`, Linux only) is left as the exact alternative.
- **Live mis-attribution we found and fixed.** In one live run the first ALERT fired (on a
  canary) before the real simulator had built up write volume, and the heaviest writer *at
  that instant* was a Windows background service (`Dell.TechHub.DataManager.SubAgent.exe`)
  flushing to disk. The detector picked it as culprit and tried to suspend it; it only
  failed because the terminal was not elevated, and the real attacker (`python.exe`) was
  caught ~2 s later by the re-arm logic. Two fixes followed, both still behaviour-based:
  (1) only processes **owned by the current user** are ever considered - SYSTEM / LOCAL
  SERVICE / NETWORK SERVICE and any process whose owner we cannot read are excluded, because
  a user-level tool must not touch system services; (2) if a suspend fails, the responder
  immediately tries the **next-ranked** suspect in the same wave. The deeper lesson is that
  user-space write-rate attribution is inherently a heuristic that can be fooled by a
  coincidental writer; a production EDR would need **kernel-level file→PID attribution** (a
  Windows minifilter driver, or fanotify/eBPF on Linux) to know for certain which process
  wrote a given file. That is out of scope for a user-space student project, and recovery
  from the hash-verified backup is the safety net when attribution is wrong.
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
- **Detection-to-kill gap, and why fast attacks are recovered rather than killed.** The
  monitor suspends the attacker as soon as it is attributed, then recovers and kills. To
  shorten the gap, the process sampler now wakes immediately on each sandbox write (a
  "kick") and samples faster (0.1 s) while the sandbox is hot. Measured effect over the 10
  trials: detection latency and mid-speed files-encrypted dropped slightly, but the **kill
  rate did not reliably improve (≈7–8/10, run-to-run noise)**. The honest reason, confirmed
  by a micro-benchmark: per-process `io_counters` on Windows updates too coarsely (~1 s) to
  attribute a sub-second attack, and a 0.05 s/file attack (~0.8 s total) simply *exits*
  before any user-space suspend can land. Faster sampling cannot beat that, because the
  write-volume gate is wall-clock bound, not sample-count bound. The guarantee for those
  attacks is **recovery, which restores 100 % (folder byte-for-byte clean in every trial)**;
  actually killing a sub-second attacker needs the kernel-level file→PID attribution noted
  above. This is a deliberate, measured trade-off, not a bug.
- Entropy is measured on the first 64 KB only, so a file encrypted from the tail backwards
  would be missed by that one signal (the magic-byte and canary signals still fire).
- The simulator mimics file behaviour only. Real ransomware also kills services, clears
  shadow copies and spreads laterally; none of that is implemented, by design.
- Detection is reactive, so some files are always lost before the process is stopped. The
  evaluation measures exactly how many.

## Layout

```
ransomguard/    detection engine (config, entropy, baseline, canary, process_monitor,
                scorer, responder, backup, recovery, monitor, logger)
simulator/      safe attack simulator + undo script
tools/          test-corpus generator, benign workload generator,
                fetch_napierone.py (unsigned-S3 fetch of the real data set)
evaluation/     live trial runner, attack matrix, labelled-dataset builder,
                file-level classifier evaluation, report tables and charts
dashboard/      Streamlit live view
tests/          pytest unit tests (114)
datasets/       generated locally: napierone_sample/, labeled/ (git-ignored, not
                redistributed - rebuild with the Dataset commands above)
sandbox/        generated at runtime: protected/, .backup/, events.jsonl (git-ignored)
```
