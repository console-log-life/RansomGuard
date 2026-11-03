# Headline: synthetic vs real NapierOne corpus

| corpus | files | attacker killed | folder clean | detection | files encrypted | false positives | matrix clean | new catches vs old |
|---|---|---|---|---|---|---|---|---|
| synthetic | 16 | 16/20 | 20/20 | 2.04 s | 8.7 (54%) | 0 | 12/12 | 2 |
| NapierOne (real) | 204 | 20/20 | 20/20 | 2.36 s | 10.9 (5%) | 0 | 12/12 | 0 |

*'new catches vs old' counts attack-matrix cells the upgraded detector catches that the original would have missed. It is 0 on NapierOne because real files carry magic bytes the old detector already used; the gap only shows on the text-only corpus, which is the hard case.*


# Synthetic corpus

## Attack trials

| # | order | delay | files | detection (s) | attributed | killed | encrypted | final recovered | folder clean |
|---|-------|-------|-------|---------------|------------|--------|-----------|-----------------|--------------|
| 1 | alphabetical | 0.05s | 16 | - | no | no | 16 | 16/16 | yes |
| 2 | alphabetical | 0.1s | 16 | - | yes | no | 16 | 16/16 | yes |
| 3 | alphabetical | 0.15s | 16 | 2.095 | yes | yes | 13 | 16/16 | yes |
| 4 | alphabetical | 0.2s | 16 | 1.795 | yes | yes | 7 | 16/16 | yes |
| 5 | alphabetical | 0.25s | 16 | 1.34 | yes | yes | 5 | 16/16 | yes |
| 6 | alphabetical | 0.3s | 16 | 1.878 | yes | yes | 5 | 16/16 | yes |
| 7 | alphabetical | 0.35s | 16 | 1.989 | yes | yes | 5 | 16/16 | yes |
| 8 | alphabetical | 0.4s | 16 | 1.632 | yes | yes | 4 | 16/16 | yes |
| 9 | alphabetical | 0.45s | 16 | 1.462 | yes | yes | 3 | 16/16 | yes |
| 10 | alphabetical | 0.5s | 16 | 1.44 | yes | yes | 3 | 16/16 | yes |
| 11 | random | 0.05s | 16 | - | no | no | 16 | 16/16 | yes |
| 12 | random | 0.1s | 16 | - | no | no | 16 | 16/16 | yes |
| 13 | random | 0.15s | 16 | 2.114 | yes | yes | 13 | 16/16 | yes |
| 14 | random | 0.2s | 16 | 2.051 | yes | yes | 10 | 16/16 | yes |
| 15 | random | 0.25s | 16 | 2.041 | yes | yes | 8 | 16/16 | yes |
| 16 | random | 0.3s | 16 | 2.108 | yes | yes | 7 | 16/16 | yes |
| 17 | random | 0.35s | 16 | 2.412 | yes | yes | 7 | 16/16 | yes |
| 18 | random | 0.4s | 16 | 2.052 | yes | yes | 5 | 16/16 | yes |
| 19 | random | 0.45s | 16 | 3.946 | yes | yes | 9 | 16/16 | yes |
| 20 | random | 0.5s | 16 | 2.238 | yes | yes | 5 | 16/16 | yes |

**Attack summary**

- trials: 20
- attributed: 17/20; killed: 16/20 (fast attacks can finish before a kill; recovery still restores them)
- detection time: mean 2.04s, min 1.34s, max 3.95s
- files encrypted before stop: mean 8.7, min 3, max 16
- recovery rate (recovery self-report): mean 100.0%
- **folder fully clean at end (ground truth): 20/20 trials**
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
| full | on | yes | yes | 0.994 | 2 | 2 | yes | yes | yes |
| slow | on | yes | yes | 2.268 | 2 | 2 | yes | yes | yes |
| no-rename | on | yes | yes | 1.404 | 3 | 3 | yes | yes | yes |
| base64 | on | yes | yes | 1.775 | 4 | 4 | yes | yes | yes |
| intermittent | on | yes | yes | 1.664 | 3 | 3 | yes | yes | yes |
| header-kept | on | yes | yes | 1.981 | 4 | 4 | yes | yes | yes |
| full | off | yes | yes | 2.063 | 4 | 4 | yes | yes | yes |
| slow | off | yes | yes | 2.253 | 2 | 2 | yes | yes | yes |
| no-rename | off | yes | yes | 1.524 | 3 | 3 | yes | yes | yes |
| base64 | off | yes | **NO (new catch)** | 1.714 | 4 | 4 | yes | yes | yes |
| intermittent | off | yes | **NO (new catch)** | 1.538 | 3 | 3 | yes | yes | yes |
| header-kept | off | yes | yes | 1.919 | 4 | 4 | yes | yes | yes |

**Before/after:** 2 of 12 attack cells are caught by the new detector but would have slipped past the original entropy/magic/canary detector
- base64 (canaries off)
- intermittent (canaries off)

**Recovery:** folder fully clean in 12/12 cells (ground truth).

# NapierOne corpus (real files)

## Attack trials

| # | order | delay | files | detection (s) | attributed | killed | encrypted | final recovered | folder clean |
|---|-------|-------|-------|---------------|------------|--------|-----------|-----------------|--------------|
| 1 | alphabetical | 0.05s | 204 | 2.619 | yes | yes | 39 | 204/204 | yes |
| 2 | alphabetical | 0.1s | 204 | 2.922 | yes | yes | 23 | 204/204 | yes |
| 3 | alphabetical | 0.15s | 204 | 3.253 | yes | yes | 17 | 204/204 | yes |
| 4 | alphabetical | 0.2s | 204 | 2.665 | yes | yes | 11 | 204/204 | yes |
| 5 | alphabetical | 0.25s | 204 | 2.674 | yes | yes | 9 | 204/204 | yes |
| 6 | alphabetical | 0.3s | 204 | 1.493 | yes | yes | 4 | 204/204 | yes |
| 7 | alphabetical | 0.35s | 204 | 1.857 | yes | yes | 4 | 204/204 | yes |
| 8 | alphabetical | 0.4s | 204 | 1.591 | yes | yes | 4 | 204/204 | yes |
| 9 | alphabetical | 0.45s | 204 | 1.711 | yes | yes | 3 | 204/204 | yes |
| 10 | alphabetical | 0.5s | 204 | 1.433 | yes | yes | 3 | 204/204 | yes |
| 11 | random | 0.05s | 204 | 1.632 | yes | yes | 23 | 204/204 | yes |
| 12 | random | 0.1s | 204 | 1.844 | yes | yes | 13 | 204/204 | yes |
| 13 | random | 0.15s | 204 | 2.723 | yes | yes | 14 | 204/204 | yes |
| 14 | random | 0.2s | 204 | 2.528 | yes | yes | 10 | 204/204 | yes |
| 15 | random | 0.25s | 204 | 2.609 | yes | yes | 9 | 204/204 | yes |
| 16 | random | 0.3s | 204 | 2.54 | yes | yes | 7 | 204/204 | yes |
| 17 | random | 0.35s | 204 | 3.047 | yes | yes | 8 | 204/204 | yes |
| 18 | random | 0.4s | 204 | 2.628 | yes | yes | 6 | 204/204 | yes |
| 19 | random | 0.45s | 204 | 2.793 | yes | yes | 6 | 204/204 | yes |
| 20 | random | 0.5s | 204 | 2.659 | yes | yes | 5 | 204/204 | yes |

**Attack summary**

- trials: 20
- attributed: 20/20; killed: 20/20 (fast attacks can finish before a kill; recovery still restores them)
- detection time: mean 2.36s, min 1.43s, max 3.25s
- files encrypted before stop: mean 10.9, min 3, max 39
- recovery rate (recovery self-report): mean 100.0%
- **folder fully clean at end (ground truth): 20/20 trials**
- leftover .locked artifacts across all trials: 0
- files that failed to restore: 0

## Benign trials (false-positive test)

| trial | files | false positives | wrongful kills |
|-------|-------|-----------------|----------------|
| benign-1 | 204 | 0 | 0 |
| benign-2 | 204 | 0 | 0 |
| benign-3 | 204 | 0 | 0 |

**Benign summary:** 0 false positives and 0 wrongful kills across 3 runs.

## Attack matrix (smart attacks vs. the detector)

| mode | canaries | detected (new)? | would OLD detector catch? | detection (s) | encrypted | recovered | folder clean | clean pre-sweep | correct kill |
|------|----------|-----------------|---------------------------|---------------|-----------|-----------|--------------|-----------------|--------------|
| full | on | yes | yes | 2.883 | 6 | 6 | yes | yes | yes |
| slow | on | yes | yes | 2.676 | 2 | 2 | yes | yes | yes |
| no-rename | on | yes | yes | 2.141 | 4 | 4 | yes | yes | yes |
| base64 | on | yes | yes | 2.293 | 5 | 5 | yes | yes | yes |
| intermittent | on | yes | yes | 2.034 | 4 | 4 | yes | yes | yes |
| header-kept | on | yes | yes | 3.313 | 6 | 6 | yes | yes | yes |
| full | off | yes | yes | 2.38 | 5 | 5 | yes | yes | yes |
| slow | off | yes | yes | 2.71 | 2 | 2 | yes | yes | yes |
| no-rename | off | yes | yes | 1.886 | 4 | 4 | yes | yes | yes |
| base64 | off | yes | yes | 2.72 | 5 | 5 | yes | yes | yes |
| intermittent | off | yes | yes | 2.028 | 4 | 4 | yes | yes | yes |
| header-kept | off | yes | yes | 2.123 | 4 | 4 | yes | yes | yes |

**Before/after:** 0 of 12 attack cells are caught by the new detector but would have slipped past the original entropy/magic/canary detector

**Recovery:** folder fully clean in 12/12 cells (ground truth).