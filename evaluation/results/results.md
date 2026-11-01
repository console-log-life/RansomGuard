# Headline: synthetic vs real NapierOne corpus

| corpus | files | attacker killed | folder clean | detection | files encrypted | false positives | matrix clean | new catches vs old |
|---|---|---|---|---|---|---|---|---|
| synthetic | 16 | 8/10 | 10/10 | 1.59 s | 9.5 (59%) | 0 | 10/10 | 2 |
| NapierOne (real) | 204 | 10/10 | 10/10 | 2.28 s | 13.9 (7%) | 0 | 10/10 | 0 |

*'new catches vs old' counts attack-matrix cells the upgraded detector catches that the original would have missed. It is 0 on NapierOne because real files carry magic bytes the old detector already used; the gap only shows on the text-only corpus, which is the hard case.*


# Synthetic corpus

## Attack trials

| # | order | delay | files | detection (s) | attributed | killed | encrypted | final recovered | folder clean |
|---|-------|-------|-------|---------------|------------|--------|-----------|-----------------|--------------|
| 1 | alphabetical | 0.05s | 16 | - | no | no | 16 | 16/16 | yes |
| 2 | alphabetical | 0.1s | 16 | 1.779 | yes | yes | 16 | 16/16 | yes |
| 3 | alphabetical | 0.2s | 16 | 1.25 | yes | yes | 5 | 16/16 | yes |
| 4 | alphabetical | 0.3s | 16 | 1.159 | yes | yes | 4 | 16/16 | yes |
| 5 | alphabetical | 0.4s | 16 | 1.493 | yes | yes | 4 | 16/16 | yes |
| 6 | random | 0.05s | 16 | 1.861 | yes | yes | 16 | 16/16 | yes |
| 7 | random | 0.1s | 16 | - | yes | no | 16 | 16/16 | yes |
| 8 | random | 0.2s | 16 | 1.902 | yes | yes | 9 | 16/16 | yes |
| 9 | random | 0.3s | 16 | 1.7 | yes | yes | 5 | 16/16 | yes |
| 10 | random | 0.4s | 16 | 1.603 | yes | yes | 4 | 16/16 | yes |

**Attack summary**

- trials: 10
- attributed: 9/10; killed: 8/10 (fast attacks can finish before a kill; recovery still restores them)
- detection time: mean 1.59s, min 1.16s, max 1.90s
- files encrypted before stop: mean 9.5, min 4, max 16
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
| full | on | yes | yes | 1.313 | 3 | 3 | yes | yes | yes |
| slow | on | yes | yes | 2.084 | 2 | 2 | yes | yes | yes |
| no-rename | on | yes | yes | 1.339 | 3 | 3 | yes | yes | yes |
| base64 | on | yes | yes | 1.305 | 3 | 3 | yes | yes | yes |
| intermittent | on | yes | yes | 1.73 | 4 | 4 | yes | yes | yes |
| full | off | yes | yes | 2.251 | 5 | 5 | yes | yes | yes |
| slow | off | yes | yes | 2.422 | 2 | 2 | yes | yes | yes |
| no-rename | off | yes | yes | 1.424 | 3 | 3 | yes | yes | yes |
| base64 | off | yes | **NO (new catch)** | 1.869 | 3 | 3 | yes | yes | yes |
| intermittent | off | yes | **NO (new catch)** | 1.804 | 4 | 4 | yes | yes | yes |

**Before/after:** 2 of 10 attack cells are caught by the new detector but would have slipped past the original entropy/magic/canary detector
- base64 (canaries off)
- intermittent (canaries off)

**Recovery:** folder fully clean in 10/10 cells (ground truth).

# NapierOne corpus (real files)

## Attack trials

| # | order | delay | files | detection (s) | attributed | killed | encrypted | final recovered | folder clean |
|---|-------|-------|-------|---------------|------------|--------|-----------|-----------------|--------------|
| 1 | alphabetical | 0.05s | 204 | 1.823 | yes | yes | 24 | 204/204 | yes |
| 2 | alphabetical | 0.1s | 204 | 1.73 | yes | yes | 14 | 204/204 | yes |
| 3 | alphabetical | 0.2s | 204 | 1.696 | yes | yes | 7 | 204/204 | yes |
| 4 | alphabetical | 0.3s | 204 | 2.384 | yes | yes | 7 | 204/204 | yes |
| 5 | alphabetical | 0.4s | 204 | 2.904 | yes | yes | 7 | 204/204 | yes |
| 6 | random | 0.05s | 204 | 2.301 | yes | yes | 36 | 204/204 | yes |
| 7 | random | 0.1s | 204 | 2.523 | yes | yes | 19 | 204/204 | yes |
| 8 | random | 0.2s | 204 | 2.754 | yes | yes | 12 | 204/204 | yes |
| 9 | random | 0.3s | 204 | 2.27 | yes | yes | 7 | 204/204 | yes |
| 10 | random | 0.4s | 204 | 2.395 | yes | yes | 6 | 204/204 | yes |

**Attack summary**

- trials: 10
- attributed: 10/10; killed: 10/10 (fast attacks can finish before a kill; recovery still restores them)
- detection time: mean 2.28s, min 1.70s, max 2.90s
- files encrypted before stop: mean 13.9, min 6, max 36
- recovery rate (recovery self-report): mean 100.0%
- **folder fully clean at end (ground truth): 10/10 trials**
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
| full | on | yes | yes | 3.007 | 6 | 6 | yes | yes | yes |
| slow | on | yes | yes | 21.202 | 14 | 14 | yes | yes | yes |
| no-rename | on | yes | yes | 3.433 | 7 | 7 | yes | yes | yes |
| base64 | on | yes | yes | 4.724 | 6 | 6 | yes | yes | yes |
| intermittent | on | yes | yes | 3.016 | 6 | 6 | yes | yes | yes |
| full | off | yes | yes | 2.462 | 5 | 5 | yes | yes | yes |
| slow | off | yes | yes | 6.848 | 5 | 5 | yes | yes | yes |
| no-rename | off | yes | yes | 2.871 | 6 | 6 | yes | yes | yes |
| base64 | off | yes | yes | 2.92 | 6 | 6 | yes | yes | yes |
| intermittent | off | yes | yes | 3.123 | 6 | 6 | yes | yes | yes |

**Before/after:** 0 of 10 attack cells are caught by the new detector but would have slipped past the original entropy/magic/canary detector

**Recovery:** folder fully clean in 10/10 cells (ground truth).