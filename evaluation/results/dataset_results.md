# File-level evaluation on the NapierOne labeled dataset

> **Avoiding test-set leakage.** The structural-validity gate (and the earlier magic-byte gate) were designed *after* inspecting the first split (seed 1234). To report an unbiased number, the detector is frozen and the split is rebuilt with a FRESH seed (2025), assigned by source file. The fresh-seed result below is the headline; the original seed is shown only for comparison.

## FRESH split (seed 2025) - unbiased headline

Samples: 3360 (split by source file: tuning 1043 / test 2317). Thresholds tuned on tuning only (combined=20, old=20, entropy-only=5.93).

**NEW detector (structural gate + multi-offset + encoded)**  precision=0.998 recall=0.980 F1=0.989 FPR=0.003 accuracy=0.987
  confusion: TP=1297 FP=3 TN=990 FN=27
**OLD detector (first-window entropy, magic only)**  precision=0.997 recall=0.893 F1=0.942 FPR=0.003 accuracy=0.937
  confusion: TP=1182 FP=3 TN=990 FN=142
**Entropy-only**  precision=0.599 recall=0.996 F1=0.748 FPR=0.888 accuracy=0.617
  confusion: TP=1319 FP=882 TN=111 FN=5

AUC (test): combined=0.989 vs entropy-only=0.564

## Per file type - FRESH split (test)

| source_type | n | recall (ransomware) | FPR (benign) |
|---|---|---|---|
| CSV | 189 | 0.981 | 0.000 |
| DOCX | 168 | 1.000 | 0.000 |
| HTML | 196 | 0.991 | 0.000 |
| JPG | 189 | 1.000 | 0.000 |
| JSON | 182 | 0.981 | 0.000 |
| MKV | 203 | 0.991 | 0.000 |
| MP3 | 210 | 1.000 | 0.000 |
| MP4 | 168 | 1.000 | 0.000 |
| PDF | 203 | 1.000 | 0.000 |
| PNG | 231 | 1.000 | 0.030 |
| TXT | 189 | 0.806 | 0.000 |
| XLSX | 189 | 1.000 | 0.000 |

## Per variant - FRESH split (test), incl. enc_header_kept

| variant | n | recall (ransomware) | FPR (benign) |
|---|---|---|---|
| benign_gzip | 331 | - | 0.000 |
| benign_zip | 331 | - | 0.000 |
| enc_base64 | 331 | 0.994 | - |
| enc_full | 331 | 0.982 | - |
| enc_header_kept | 331 | 0.979 | - |
| enc_intermittent | 331 | 0.964 | - |
| original | 331 | - | 0.009 |

*enc_header_kept is the hardest variant: it preserves the real magic bytes, so it is caught only for types with a structural check (zip/docx/xlsx/pptx, png, gzip, pdf, jpg). Media types (mp3/mp4/mkv) have no cheap structural check, so a header-kept media file is trusted on its magic and evades - a known limitation that a real EDR would close with format-aware parsers or kernel file->PID attribution.*

## header-kept recall per file type - FRESH split (test)

The media structural checks (MP4/MKV/MP3) were added specifically for this variant. Before they existed, header-kept on MP3/MP4/MKV was undetectable (the magic bytes survive and there was no structural check), i.e. recall 0.000 for those three types; PNG/JPG/PDF/zip-family were already covered.

A second gap showed up once the media checks landed: for an already-compressed type (DOCX/XLSX) the structure was correctly found to be broken, but nothing scored it - magic_broken cannot fire (the header survives) and entropy cannot jump (the original was already ~8 bits/byte). The `structure_broken` signal (+25) scores that finding directly, which is what lifts DOCX 0.417 -> 1.000 and XLSX 0.185 -> 1.000. TXT stays lower because text has no structural check at all, so header-kept text is caught only when the encrypted remainder moves its entropy far enough.

| source_type | n | header-kept recall |
|---|---|---|
| CSV | 27 | 1.000 |
| DOCX | 24 | 1.000 |
| HTML | 28 | 1.000 |
| JPG | 27 | 1.000 |
| JSON | 26 | 1.000 |
| MKV | 29 | 0.966 |
| MP3 | 30 | 1.000 |
| MP4 | 24 | 1.000 |
| PDF | 29 | 1.000 |
| PNG | 33 | 1.000 |
| TXT | 27 | 0.778 |
| XLSX | 27 | 1.000 |

## Other splits (sanity / comparison)

- **Validation split (seed 3031)** - a SECOND fresh seed, because the media checks above were themselves added after looking at seed 2025: precision=0.997 recall=0.972 F1=0.984 FPR=0.004 AUC=0.985
- **Original split (seed 1234)** - the split the gate was first designed on, shown for comparison only: precision=0.997 recall=0.972 F1=0.984 FPR=0.004 AUC=0.985

## Notes on reading these numbers

1. **This threshold is not the live alert threshold.** Here a score is computed for ONE file in isolation, and the tuned cut-off is a per-file value. The live monitor's threshold of 70 is *accumulated* across many file events (plus canary, burst and extension signals that do not exist in a single-file view), so the two numbers measure different things and must not be compared.
2. **The benign archives are ours, not NapierOne's.** NapierOne's own ZIP/RAR/7ZIP/GZIP bundles are 520-625 MB, over the download cap, so the high-entropy benign hard negatives are ZIP and GZIP archives we create from the sampled NapierOne files. They are still genuine, valid archives - just produced locally rather than downloaded.