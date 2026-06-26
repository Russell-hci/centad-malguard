# BinaryShield Detector Explainer

BinaryShield compares several detector families under the same PE-preserving append and slack transformations.

Centroid detectors are intentionally simple baselines. They compute an average feature vector for each class and classify a new file by whichever average it is closest to. This makes them transparent and easy to reproduce, but it also means they can miss class boundaries that are not well described by one average point per class.

The current strongest Dike detector is a byte-histogram logistic detector. It uses 256 normalized byte-frequency bins and learns a linear decision boundary. This can outperform centroid detectors because it can weight individual byte bins differently instead of treating the whole histogram as a nearest-average problem.

Class balancing matters because Dike is imbalanced: the sanitized manifest summary contains many more malware samples than benign samples. Without balancing, a detector can optimize overall accuracy while treating the minority class poorly. The accepted logistic detector uses inverse-frequency sample weights during training and calibrates its threshold on validation macro F1.

The strong Dike result should still be interpreted cautiously. A byte histogram can capture real malware/benign signal, but it can also capture dataset-specific collection artifacts such as packing style, compiler/runtime conventions, file sizes, padding, or source-specific byte distributions. That is why PEMML validation is the next credibility step.

BinaryShield does not claim universal malware robustness. It claims detector stability under a defined audit threat model:

```text
raw PE file -> append/slack transformation -> structural validation -> detector comparison -> sanitized robustness evidence
```

Level 1 and Level 2 validation support structural PE-preservation claims. They do not prove runtime behavioral equivalence. Level 3 would require approved isolated sandbox validation and has not been claimed here.
