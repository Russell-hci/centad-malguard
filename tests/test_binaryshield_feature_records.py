from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class BinaryShieldFeatureRecordTests(unittest.TestCase):
    def test_feature_record_training_and_eval_scripts(self) -> None:
        try:
            import numpy as np
        except ImportError:
            self.skipTest("numpy unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            features = root / "features.npz"
            np.savez(
                features,
                X=np.asarray(
                    [
                        [0.0, 0.0],
                        [0.1, 0.0],
                        [4.9, 5.0],
                        [5.0, 5.1],
                        [0.05, 0.0],
                        [5.1, 5.0],
                    ],
                    dtype=float,
                ),
                y=np.asarray([0, 0, 1, 1, 0, 1], dtype=int),
            )
            manifest = root / "manifest.csv"
            manifest.write_text(
                "\n".join(
                    [
                        "sample_id,record_index,label,family,split,sha256,first_seen",
                        "a0,0,benign,,train,a0,2020-01-01",
                        "a1,1,benign,,train,a1,2020-01-02",
                        "b0,2,malware,fam,train,b0,2020-01-03",
                        "b1,3,malware,fam,val,b1,2020-01-04",
                        "a2,4,benign,,test,a2,2020-01-05",
                        "b2,5,malware,fam,test,b2,2020-01-06",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            train_dir = root / "train"
            eval_dir = root / "eval"
            subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_train_feature_records.py",
                    "--manifest",
                    str(manifest),
                    "--features-npz",
                    str(features),
                    "--output-dir",
                    str(train_dir),
                ],
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "scripts/binaryshield_eval_feature_records.py",
                    "--manifest",
                    str(manifest),
                    "--features-npz",
                    str(features),
                    "--model",
                    str(train_dir / "feature_record_centroid.json"),
                    "--output-dir",
                    str(eval_dir),
                ],
                check=True,
            )
            metrics = json.loads((eval_dir / "metrics.json").read_text(encoding="utf-8"))
        self.assertEqual(metrics["accuracy"], 1.0)
        self.assertEqual(metrics["macro_f1"], 1.0)


if __name__ == "__main__":
    unittest.main()
