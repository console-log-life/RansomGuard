# File-level evaluation on the NapierOne labeled dataset

Samples: 1920 (960 ransomware / 960 benign), split by source file (tuning 546 / test 1374). Thresholds tuned on tuning only.

Tuned thresholds: combined(new)=20, combined(old)=20, entropy-only=5.95

## Test-split headline

**NEW detector (combined, multi-offset + encoded)**  precision=1.000 recall=0.943 F1=0.971 FPR=0.000 accuracy=0.972
  confusion: TP=648 FP=0 TN=687 FN=39
**OLD detector (combined, first-window only)**  precision=1.000 recall=0.774 F1=0.873 FPR=0.000 accuracy=0.887
  confusion: TP=532 FP=0 TN=687 FN=155
**Entropy-only**  precision=0.554 recall=0.985 F1=0.709 FPR=0.793 accuracy=0.596
  confusion: TP=677 FP=545 TN=142 FN=10

AUC (test): combined=0.972  vs  entropy-only=0.578

## Per file type (test)

| source_type | n | recall (ransomware) | FPR (benign) |
|---|---|---|---|
| CSV | 180 | 0.767 | 0.000 |
| DOCX | 168 | 1.000 | 0.000 |
| HTML | 186 | 0.989 | 0.000 |
| JPG | 150 | 1.000 | 0.000 |
| JSON | 180 | 0.989 | 0.000 |
| PNG | 156 | 1.000 | 0.000 |
| TXT | 180 | 0.822 | 0.000 |
| XLSX | 174 | 1.000 | 0.000 |

## Per variant (test)

| variant | n | recall (ransomware) | FPR (benign) |
|---|---|---|---|
| benign_gzip | 229 | - | 0.000 |
| benign_zip | 229 | - | 0.000 |
| enc_base64 | 229 | 0.965 | - |
| enc_full | 229 | 0.939 | - |
| enc_intermittent | 229 | 0.926 | - |
| original | 229 | - | 0.000 |