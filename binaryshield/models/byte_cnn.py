from __future__ import annotations

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
except ImportError:  # pragma: no cover - exercised only when torch is absent
    torch = None
    nn = None
    F = None


if nn is not None:

    class RawByteCNN(nn.Module):
        """Compact raw-byte baseline for PE bytes.

        This is intentionally small enough for first-pass experiments. It provides
        a second detector family for BinaryShield generalizability checks.
        """

        def __init__(self, num_classes: int, embed_dim: int = 16, channels: int = 64) -> None:
            super().__init__()
            self.embedding = nn.Embedding(257, embed_dim, padding_idx=256)
            self.conv1 = nn.Conv1d(embed_dim, channels, kernel_size=7, padding=3)
            self.conv2 = nn.Conv1d(channels, channels, kernel_size=5, padding=2)
            self.conv3 = nn.Conv1d(channels, channels * 2, kernel_size=3, padding=1)
            self.classifier = nn.Sequential(
                nn.LayerNorm(channels * 2),
                nn.Linear(channels * 2, channels),
                nn.ReLU(inplace=True),
                nn.Linear(channels, num_classes),
            )

        def forward(self, byte_tokens):
            x = self.embedding(byte_tokens.clamp(0, 256)).transpose(1, 2)
            x = F.relu(self.conv1(x))
            x = F.relu(self.conv2(x))
            x = F.relu(self.conv3(x))
            pooled = F.adaptive_max_pool1d(x, 1).squeeze(-1)
            return self.classifier(pooled)

else:

    class RawByteCNN:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs) -> None:
            raise ImportError("torch is required for RawByteCNN")
