# BinaryShield Final Narrative

The project began as CenTaD-MalGuard, a malware-image robustness study. That work showed an important cybersecurity lesson: a lightweight malware image classifier can be accurate on clean samples and still fail under adversarial attack. The image pipeline was useful, but image perturbations alone are not the most realistic way to reason about Windows malware files.

BinaryShield is the stronger final direction. It moves the robustness question closer to raw executable files. Instead of perturbing malware images, it audits Windows PE files, identifies mutation regions that should preserve checked PE structure, applies append-overlay and section-slack transformations, validates the transformed files, evaluates detector stability, and exports sanitized evidence.

BinaryShield currently evaluates a bounded threat model:

```text
raw PE file -> append/slack transformation -> structural validation -> detector evaluation -> robustness evidence
```

Append-overlay transformations add bytes after the declared file content. Section-slack transformations modify unused padding inside non-executable sections when such slack exists. These transformations test whether a detector changes predictions when PE structure and executable sections remain unchanged under the project's validation checks.

Validation is deliberately cautious. Level 1 means the original and transformed files parse as PE files, the hash changed, the entry point is unchanged, and section count is unchanged. Level 2 adds executable-section preservation. Level 3 would require approved sandbox behavior validation. BinaryShield does not currently claim Level 3.

The strongest current detector is the DikeDataset `byte_histogram_logistic` detector. It uses 256 normalized byte-frequency bins, class-balanced logistic training, and validation macro-F1 threshold calibration. On the accepted sanitized Dike evidence package, it reaches:

- append robust-min macro F1: `0.9772199119373777`
- append prediction stability: `1.0`
- append attack success rate: `0.0`
- slack robust-min macro F1: `0.9808817438127784`
- slack prediction stability: `1.0`
- slack attack success rate: `0.0`

It also beats the strongest centroid baseline on six robustness metrics in the imported multi-detector comparison.

Transfer-style evaluation matters because a robustness story is weaker if it only works for one detector. BinaryShield therefore compares multiple detector families under the same transformations and checks whether the candidate improves over the strongest baseline.

The claim remains bounded. BinaryShield does not claim universal malware robustness, behavior preservation, or family-level robustness. It claims that, on the accepted Dike evidence package, the class-balanced byte-histogram logistic detector is stable and accurate under validated append/slack transformations.

The next credibility step is second-dataset validation. PEMML is the preferred candidate because it publicly provides raw PE malware and benign files. A successful PEMML subset run would show whether the Dike-winning detector generalizes beyond one dataset distribution.
