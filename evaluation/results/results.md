## Attack trials

| # | order | delay | files | detection (s) | attributed | killed | encrypted | final recovered | folder clean |
|---|-------|-------|-------|---------------|------------|--------|-----------|-----------------|--------------|
| 1 | alphabetical | 0.05s | 16 | - | no | no | 16 | 16/16 | yes |
| 2 | alphabetical | 0.1s | 16 | - | no | no | 16 | 16/16 | yes |
| 3 | alphabetical | 0.2s | 16 | - | no | no | 16 | 16/16 | yes |
| 4 | alphabetical | 0.3s | 16 | 2.893 | yes | yes | 8 | 16/16 | yes |
| 5 | alphabetical | 0.4s | 16 | 2.963 | yes | yes | 7 | 16/16 | yes |
| 6 | random | 0.05s | 16 | - | no | no | 16 | 16/16 | yes |
| 7 | random | 0.1s | 16 | 2.207 | yes | yes | 13 | 16/16 | yes |
| 8 | random | 0.2s | 16 | 2.726 | yes | yes | 11 | 16/16 | yes |
| 9 | random | 0.3s | 16 | 3.518 | yes | yes | 10 | 16/16 | yes |
| 10 | random | 0.4s | 16 | 4.116 | yes | yes | 9 | 16/16 | yes |

**Attack summary**

- trials: 10
- attributed: 6/10; killed: 6/10 (fast attacks can finish before a kill; recovery still restores them)
- detection time: mean 3.07s, min 2.21s, max 4.12s
- files encrypted before stop: mean 12.2, min 7, max 16
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
| full | on | yes | yes | 1.986 | 3 | 3 | yes | yes | yes |
| slow | on | yes | yes | 2.77 | 2 | 2 | yes | yes | yes |
| no-rename | on | yes | yes | 2.398 | 5 | 5 | yes | yes | yes |
| base64 | on | yes | yes | - | 10 | 10 | yes | no | no_kill |
| intermittent | on | yes | yes | 1.636 | 3 | 3 | yes | yes | yes |
| full | off | yes | yes | 1.204 | 2 | 2 | yes | yes | yes |
| slow | off | yes | yes | 2.291 | 2 | 2 | yes | yes | yes |
| no-rename | off | yes | yes | 2.223 | 4 | 4 | yes | yes | yes |
| base64 | off | yes | **NO (new catch)** | 3.017 | 5 | 5 | yes | yes | yes |
| intermittent | off | yes | **NO (new catch)** | 3.451 | 6 | 6 | yes | yes | yes |

**Before/after:** 2 of 10 attack cells are caught by the new detector but would have slipped past the original entropy/magic/canary detector
- base64 (canaries off)
- intermittent (canaries off)

**Recovery:** folder fully clean in 10/10 cells (ground truth).