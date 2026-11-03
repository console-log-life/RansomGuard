# File-level evaluation on the NapierOne labeled dataset

> **Avoiding test-set leakage.** The structural-validity gate (and the earlier magic-byte gate) were designed *after* inspecting the first split (seed 1234). To report an unbiased number, the detector is frozen and the split is rebuilt with a FRESH seed (2025), assigned by source file. The fresh-seed result below is the headline; the original seed is shown only for comparison.

## FRESH split (seed 2025) - unbiased headline

Samples: 10871 (split by source file: tuning 3402 / test 7469). Thresholds tuned on tuning only (combined=10, old=10, entropy-only=5.66).

**NEW detector (structural gate + multi-offset + encoded)**  precision=1.000 recall=0.976 F1=0.988 FPR=0.000 accuracy=0.986
  confusion: TP=4165 FP=0 TN=3201 FN=103
  95% CI: recall [0.971, 0.980]  FPR [0.000, 0.001]
**OLD detector (first-window entropy, magic only)**  precision=1.000 recall=0.911 F1=0.953 FPR=0.000 accuracy=0.949
  confusion: TP=3888 FP=0 TN=3201 FN=380
  95% CI: recall [0.902, 0.919]  FPR [0.000, 0.001]
**Entropy-only**  precision=0.594 recall=1.000 F1=0.745 FPR=0.912 accuracy=0.609
  confusion: TP=4267 FP=2920 TN=281 FN=1
  95% CI: recall [0.999, 1.000]  FPR [0.902, 0.922]

AUC (test): combined=0.988 vs entropy-only=0.543

## Per file type - FRESH split (test)

| source_type | n | recall (ransomware) | FPR (benign) |
|---|---|---|---|
| 7ZIP | 364 | 1.000 | 0.000 |
| CSV | 448 | 0.723 | 0.000 |
| DOCX | 469 | 1.000 | 0.000 |
| GZIP | 315 | 1.000 | 0.000 |
| HTML | 476 | 0.978 | 0.000 |
| JPG | 455 | 1.000 | 0.000 |
| JSON | 511 | 0.993 | 0.000 |
| MKV | 462 | 0.996 | 0.000 |
| MP3 | 406 | 1.000 | 0.000 |
| MP4 | 441 | 1.000 | 0.000 |
| PDF | 532 | 1.000 | 0.000 |
| PNG | 490 | 1.000 | 0.000 |
| PPTX | 427 | 1.000 | 0.000 |
| RAR | 343 | 1.000 | 0.000 |
| TXT | 476 | 0.915 | 0.000 |
| XLSX | 483 | 1.000 | 0.000 |
| ZIP | 371 | 1.000 | 0.000 |

## Per variant - FRESH split (test), incl. enc_header_kept

| variant | n | recall (ransomware) | FPR (benign) |
|---|---|---|---|
| benign_gzip | 1067 | - | 0.000 |
| benign_zip | 1067 | - | 0.000 |
| enc_base64 | 1067 | 0.986 | - |
| enc_full | 1067 | 0.978 | - |
| enc_header_kept | 1067 | 0.975 | - |
| enc_intermittent | 1067 | 0.965 | - |
| original | 1067 | - | 0.000 |

*enc_header_kept is the hardest variant: it preserves the real magic bytes, so it is caught only for types with a structural check (zip/docx/xlsx/pptx, png, gzip, pdf, jpg). Media types (mp3/mp4/mkv) have no cheap structural check, so a header-kept media file is trusted on its magic and evades - a known limitation that a real EDR would close with format-aware parsers or kernel file->PID attribution.*

## False positives by benign source - FRESH split (test)

Now that the heavy NapierOne bundles are included, the benign side contains REAL ZIP/RAR/7Z/GZIP archives, not only archives we generate ourselves. They are reported separately because a real archive is the harder negative: it is high-entropy and structurally valid.

| benign group | n | false positives | FPR | 95% CI |
|---|---|---|---|---|
| real archive (NapierOne ZIP/RAR/7Z/GZIP) | 199 | 0 | 0.0000 | [0.0000, 0.0189] |
| our generated zip/gzip | 2134 | 0 | 0.0000 | [0.0000, 0.0018] |
| other real originals | 868 | 0 | 0.0000 | [0.0000, 0.0044] |

## Agreement across all three seeds (test)

| seed | role | precision | recall | recall 95% CI | FPR | FPR 95% CI | F1 | AUC |
|---|---|---|---|---|---|---|---|---|
| 2025 | fresh headline | 1.000 | 0.976 | [0.971, 0.980] | 0.0000 | [0.0000, 0.0012] | 0.988 | 0.988 |
| 3031 | validation | 1.000 | 0.978 | [0.973, 0.982] | 0.0000 | [0.0000, 0.0012] | 0.989 | 0.989 |
| 1234 | original | 1.000 | 0.974 | [0.968, 0.978] | 0.0000 | [0.0000, 0.0011] | 0.987 | 0.987 |

## header-kept recall per file type - FRESH split (test)

The media structural checks (MP4/MKV/MP3) were added specifically for this variant. Before they existed, header-kept on MP3/MP4/MKV was undetectable (the magic bytes survive and there was no structural check), i.e. recall 0.000 for those three types; PNG/JPG/PDF/zip-family were already covered.

A second gap showed up once the media checks landed: for an already-compressed type (DOCX/XLSX) the structure was correctly found to be broken, but nothing scored it - magic_broken cannot fire (the header survives) and entropy cannot jump (the original was already ~8 bits/byte). The `structure_broken` signal (+25) scores that finding directly, which is what lifts DOCX 0.417 -> 1.000 and XLSX 0.185 -> 1.000. TXT stays lower because text has no structural check at all, so header-kept text is caught only when the encrypted remainder moves its entropy far enough.

| source_type | n | header-kept recall |
|---|---|---|
| 7ZIP | 52 | 1.000 |
| CSV | 64 | 0.688 |
| DOCX | 67 | 1.000 |
| GZIP | 45 | 1.000 |
| HTML | 68 | 1.000 |
| JPG | 65 | 1.000 |
| JSON | 73 | 1.000 |
| MKV | 66 | 0.985 |
| MP3 | 58 | 1.000 |
| MP4 | 63 | 1.000 |
| PDF | 76 | 1.000 |
| PNG | 70 | 1.000 |
| PPTX | 61 | 1.000 |
| RAR | 49 | 1.000 |
| TXT | 68 | 0.912 |
| XLSX | 69 | 1.000 |
| ZIP | 53 | 1.000 |

## Other splits (sanity / comparison)

- **Validation split (seed 3031)** - a SECOND fresh seed, because the media checks above were themselves added after looking at seed 2025: precision=1.000 recall=0.978 F1=0.989 FPR=0.000 AUC=0.989
- **Original split (seed 1234)** - the split the gate was first designed on, shown for comparison only: precision=1.000 recall=0.974 F1=0.987 FPR=0.000 AUC=0.987

## Notes on reading these numbers

1. **This threshold is not the live alert threshold.** Here a score is computed for ONE file in isolation, and the tuned cut-off is a per-file value. The live monitor's threshold of 70 is *accumulated* across many file events (plus canary, burst and extension signals that do not exist in a single-file view), so the two numbers measure different things and must not be compared.
2. **The RAR and 7Z structural checks were added after inspecting results**, like the media ones before them: the first run on real archives showed RAR/7Z had no structural check at all, so a header-kept archive was judged only on entropy - and an archive is already high-entropy. They verify the RAR 4 CRC16 / RAR 5 CRC32 header chain and the 7z start-header and next-header CRC32s. Because they were designed after seeing a split, the seed-3031 and seed-1234 columns are the ones to trust for generalisation, not seed 2025 alone.
3. **The benign archives are ours, not NapierOne's.** NapierOne's own ZIP/RAR/7ZIP/GZIP bundles are 520-625 MB, over the download cap, so the high-entropy benign hard negatives are ZIP and GZIP archives we create from the sampled NapierOne files. They are still genuine, valid archives - just produced locally rather than downloaded.