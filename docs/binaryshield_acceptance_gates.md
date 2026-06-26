# BinaryShield Acceptance Gates

Acceptance gates are dataset-specific. Do not reuse Dike thresholds blindly for PEMML.

## Dike Gates

Dike currently preserves the accepted `byte_histogram_logistic` detector as the benchmark.

Recommended Dike gates:

- clean macro F1 at least `0.95`
- append transformed macro F1 at least `0.85`
- slack transformed macro F1 at least `0.70`
- append prediction stability at least `0.85`
- slack prediction stability at least `0.85`
- append attack success rate no more than `0.70`
- slack attack success rate no more than `0.70`
- validation JSON coverage `1.0` for evaluated transformations
- transformed PE parse success at least `0.98` for append
- transformed PE parse success at least `0.90` for slack
- entry point unchanged rate `1.0`
- executable sections unchanged rate `1.0`
- benign-class recall reported explicitly
- worst-class F1 reported explicitly
- candidate beats strongest baseline on at least two robustness metrics

The accepted Dike logistic detector satisfies the imported gate report with overall status `PASS`.

## PEMML Gates

PEMML should use cautious gates until its local split, labels, and sample distribution are verified.

Initial PEMML gates:

- clean macro F1 should beat the strongest centroid baseline, not a hard Dike threshold.
- append transformed macro F1 should remain within an agreed drop from clean macro F1.
- slack transformed macro F1 should be reported separately because slack availability varies by PE layout.
- prediction stability should be high, but the threshold should be set after a first subset smoke run.
- attack success rate should be low relative to centroid baselines.
- validation coverage must be reported for append and slack separately.
- benign-class recall must be reported and should not collapse under transformations.
- worst-class F1 must be reported.
- candidate should beat the strongest baseline on at least two robustness metrics before it is called the PEMML winner.

Do not claim PEMML family-level robustness unless family labels are verified. Do not claim Level 3 behavior preservation unless approved isolated sandbox evidence exists.

## Metrics Required In Judge Reports

- clean confusion matrix
- append-transformed confusion matrix
- slack-transformed confusion matrix
- per-class precision, recall, and F1
- prediction stability table
- attack success rate table
- validation coverage table
- detector comparison table
- accepted-vs-baseline metric delta table
- coefficient or feature-importance summary when model artifacts are available

## Claim Boundary

Passing acceptance gates means the detector is robust under the evaluated BinaryShield append/slack structural-transformation threat model for that dataset. It does not prove universal malware robustness.
