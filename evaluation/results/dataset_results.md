# File-level evaluation on the NapierOne labeled dataset

> **Avoiding test-set leakage.** The structural-validity gate (and the earlier magic-byte gate) were designed *after* inspecting the first split (seed 1234). To report an unbiased number, the detector is frozen and the split is rebuilt with a FRESH seed (2025), assigned by source file. The fresh-seed result below is the headline; the original seed is shown only for comparison.

## FRESH split (seed 2025) - unbiased headline

Samples: 3360 (split by source file: tuning 1043 / test 2317). Thresholds tuned on tuning only (combined=10, old=10, entropy-only=5.43).

**NEW detector (structural gate + multi-offset + encoded)**  precision=1.000 recall=0.841 F1=0.914 FPR=0.000 accuracy=0.909
  confusion: TP=1114 FP=0 TN=993 FN=210
**OLD detector (first-window entropy, magic only)**  precision=1.000 recall=0.687 F1=0.815 FPR=0.000 accuracy=0.821
  confusion: TP=910 FP=0 TN=993 FN=414
**Entropy-only**  precision=0.596 recall=0.986 F1=0.743 FPR=0.892 accuracy=0.609
  confusion: TP=1305 FP=886 TN=107 FN=19

AUC (test): combined=0.921 vs entropy-only=0.554

## Per file type - FRESH split (test)

| source_type | n | recall (ransomware) | FPR (benign) |
|---|---|---|---|
| CSV | 189 | 0.907 | 0.000 |
| DOCX | 168 | 0.854 | 0.000 |
| HTML | 196 | 0.982 | 0.000 |
| JPG | 189 | 0.926 | 0.000 |
| JSON | 182 | 0.827 | 0.000 |
| MKV | 203 | 0.716 | 0.000 |
| MP3 | 210 | 0.750 | 0.000 |
| MP4 | 168 | 0.750 | 0.000 |
| PDF | 203 | 0.983 | 0.000 |
| PNG | 231 | 0.924 | 0.000 |
| TXT | 189 | 0.657 | 0.000 |
| XLSX | 189 | 0.796 | 0.000 |

## Per variant - FRESH split (test), incl. enc_header_kept

| variant | n | recall (ransomware) | FPR (benign) |
|---|---|---|---|
| benign_gzip | 331 | - | 0.000 |
| benign_zip | 331 | - | 0.000 |
| enc_base64 | 331 | 0.906 | - |
| enc_full | 331 | 0.982 | - |
| enc_header_kept | 331 | 0.526 | - |
| enc_intermittent | 331 | 0.952 | - |
| original | 331 | - | 0.000 |

*enc_header_kept is the hardest variant: it preserves the real magic bytes, so it is caught only for types with a structural check (zip/docx/xlsx/pptx, png, gzip, pdf, jpg). Media types (mp3/mp4/mkv) have no cheap structural check, so a header-kept media file is trusted on its magic and evades - a known limitation that a real EDR would close with format-aware parsers or kernel file->PID attribution.*

## Original split (seed 1234) - for comparison only

**NEW detector**  precision=1.000 recall=0.832 F1=0.909 FPR=0.000 accuracy=0.904
  confusion: TP=1162 FP=0 TN=1047 FN=234

AUC (test): combined=0.916 vs entropy-only=0.549
