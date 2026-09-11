# SENTINEL Benchmark Report

Total evaluated samples: 22700
Total duration: 18.42s
| Detector | Precision | Recall | F1 | Latency P50 | Latency P95 | Latency P99 |
|---|---|---|---|---|---|---|
| prompt_injection | 0.8800 | 0.8300 | 0.8543 | 0.03ms | 0.03ms | 0.07ms |
| jailbreak | 0.9599 | 0.8613 | 0.9079 | 0.57ms | 1.03ms | 1.65ms |
| pii | 0.8369 | 0.8720 | 0.8541 | 0.01ms | 0.02ms | 0.04ms |
| secrets | 0.8435 | 0.9160 | 0.8782 | 0.01ms | 0.02ms | 0.02ms |
| toxicity | 0.9187 | 0.9573 | 0.9376 | 0.59ms | 1.16ms | 2.32ms |
| anomaly | 0.8723 | 0.8200 | 0.8454 | 1.67ms | 2.09ms | 2.94ms |
| ensemble | 0.8790 | 0.8856 | 0.8823 | 1.17ms | 1.53ms | 2.10ms |

## Evaluation Methodology

Empirical metrics are calculated across independent evaluation suites using dedicated test generators. Classification statistics reflect default detector confidence thresholds.

## Limitations

- Synthetic Dataset Scope: Benchmark datasets are generated with deterministic perturbation to evaluate edge cases; production distributions will differ.
- Empirical Real-World Performance: Detection boundaries are evaluated against heuristic patterns; real-world environments with multi-turn context may vary.
- Uncovered Attack Vectors: The current suite does not test multi-turn conversational poisoning, multimodal steganography, or side-channel weight extraction.
