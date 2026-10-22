## Attack trials

| # | order | delay | files | detection (s) | attributed | killed | encrypted | final recovered | folder clean |
|---|-------|-------|-------|---------------|------------|--------|-----------|-----------------|--------------|
| 1 | alphabetical | 0.05s | 16 | - | no | no | 16 | 16/16 | yes |
| 2 | alphabetical | 0.1s | 16 | 1.283 | yes | yes | 10 | 16/16 | yes |
| 3 | alphabetical | 0.2s | 16 | 1.441 | yes | yes | 6 | 16/16 | yes |
| 4 | alphabetical | 0.3s | 16 | 1.308 | yes | yes | 4 | 16/16 | yes |
| 5 | alphabetical | 0.4s | 16 | 1.473 | yes | yes | 4 | 16/16 | yes |
| 6 | random | 0.05s | 16 | - | no | no | 16 | 16/16 | yes |
| 7 | random | 0.1s | 16 | 1.994 | yes | yes | 15 | 16/16 | yes |
| 8 | random | 0.2s | 16 | 3.956 | yes | yes | 15 | 16/16 | yes |
| 9 | random | 0.3s | 16 | 1.954 | yes | yes | 5 | 16/16 | yes |
| 10 | random | 0.4s | 16 | 3.032 | yes | yes | 7 | 16/16 | yes |

**Attack summary**

- trials: 10
- attributed + killed: 8/10
- detection time: mean 2.06s, min 1.28s, max 3.96s
- files encrypted before stop: mean 9.8, min 4, max 16
- recovery rate (recovery self-report): mean 100.0%
- **folder fully clean at end (ground truth): 10/10 trials**
- leftover .locked artifacts across all trials: 0
- files that failed to restore: 0

## Benign trials (false-positive test)

| trial | files | false positives | wrongful kills |
|-------|-------|-----------------|----------------|
| benign-1 | 16 | 0 | 0 |
| benign-2 | 16 | 0 | 0 |
| benign-3 | 16 | 0 | 0 |

**Benign summary:** 0 false positives and 0 wrongful kills across 3 runs.

## Attack matrix (smart attacks vs. the detector)

| mode | canaries | detected (new)? | would OLD detector catch? | detection (s) | encrypted | recovered | folder clean | clean pre-sweep | correct kill |
|------|----------|-----------------|---------------------------|---------------|-----------|-----------|--------------|-----------------|--------------|
| full | on | yes | yes | 1.113 | 10 | 10 | yes | yes | yes |
| slow | on | yes | yes | 1.794 | 2 | 2 | yes | yes | yes |
| no-rename | on | yes | yes | 1.301 | 8 | 8 | yes | yes | yes |
| base64 | on | yes | yes | 1.409 | 9 | 9 | yes | yes | yes |
| intermittent | on | yes | yes | 0.993 | 6 | 6 | yes | yes | yes |
| full | off | yes | yes | - | 6 | 6 | yes | no | no_kill |
| slow | off | yes | yes | 1.748 | 2 | 2 | yes | yes | yes |
| no-rename | off | yes | yes | - | 6 | 6 | yes | no | no_kill |
| base64 | off | yes | **NO (new catch)** | - | 6 | 6 | yes | no | no_kill |
| intermittent | off | yes | **NO (new catch)** | - | 6 | 6 | yes | no | no_kill |

**Before/after:** 2 of 10 attack cells are caught by the new detector but would have slipped past the original entropy/magic/canary detector
- base64 (canaries off)
- intermittent (canaries off)

**Recovery:** folder fully clean in 10/10 cells (ground truth).