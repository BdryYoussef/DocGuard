# DocGuard Phase 11 Evaluation Report

## Corpus

- Total cases: 59
- Matched results: 59

| Category | Cases |
| --- | ---: |
| BENIGN_ARCHIVE | 5 |
| BENIGN_OFFICE | 6 |
| BENIGN_PDF | 4 |
| FILE_IDENTITY | 5 |
| RISKY_ARCHIVE | 12 |
| RISKY_OFFICE | 10 |
| RISKY_PDF | 12 |
| YARA | 5 |

## Reproducibility

- Timestamp: 2026-08-16T18:45:46.252836+00:00
- Git commit: f18961ccee2ba6215befabddd3275b93e16271f2
- Corpus version: 11A.1 (59 cases)
- Policy version / fingerprint: 1.0.2 / c6d18b6f67b79a91151567c99c8844c741820935ab9d4ad32bb131a30412469b
- YARA rule pack: 2026.08.1 / 7b9bab1889c4db6ead3b49263e93c10b138d2b8496668791b7ca8363c5385fe7
- Sanitizer: 1.0.0 / 46ceaaa938031df4952fbbf9fa23c374ed516be648456fdd256bcd5fcfd73bf2
- Python: 3.14.4; platform: Linux-x86_64

## Metrics

- Risky-case detection recall (A): 100.0% (41/41)
- Finding-level recall (B): 100.0% (72/72)
- Benign escalation rate (C): 0.0% (0/18)
- Benign ALLOW rate (D): 100.0% (18/18)
- Decision compliance (E): 100.0% (59/59)
- Fail-secure rate (G): 100.0% (9/9)
- CDR recovery rate (I, Phase 11B only): 100.0% (2/2)

### Finding-level recall by category (B)

| Category | Recall |
| --- | --- |
| BENIGN_ARCHIVE | not applicable (0 evaluable cases) |
| BENIGN_OFFICE | not applicable (0 evaluable cases) |
| BENIGN_PDF | not applicable (0 evaluable cases) |
| FILE_IDENTITY | 100.0% (6/6) |
| RISKY_ARCHIVE | 100.0% (17/17) |
| RISKY_OFFICE | 100.0% (27/27) |
| RISKY_PDF | 100.0% (17/17) |
| YARA | 100.0% (5/5) |

### Analysis completeness counts (F)

| Class | Count |
| --- | ---: |
| COMPLETE | 44 |
| INTENTIONAL_PARTIAL | 10 |
| OTHER_FAIL_CLOSED | 1 |
| PARSER_FAILURE | 3 |
| RESOURCE_LIMIT_FAILURE | 1 |

### Latency (H)

- count: 59
- mean: 228.2 ms
- median: 252.0 ms
- min / max: 115 / 452 ms
- p95: 300 ms

Real benchmark values are pending Phase 11B execution against the isolated Bubblewrap worker and trusted policy engine; nothing above was fabricated.
