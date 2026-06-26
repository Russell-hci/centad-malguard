from __future__ import annotations

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
except ImportError:  # pragma: no cover
    torch = None
    nn = None
    F = None


if nn is not None:

    class HybridBinaryShield(nn.Module):
        """Hybrid raw-byte + PE-feature detector.

        The model accepts padded byte tokens and a numeric PE-feature vector. It is
        the proposed BinaryShield detector family for comparison against PE-only
        and raw-byte-only baselines.
        """

        def __init__(
            self,
            num_classes: int,
            pe_feature_dim: int,
            byte_embed_dim: int = 16,
            hidden_dim: int = 128,
        ) -> None:
            super().__init__()
            self.byte_embedding = nn.Embedding(257, byte_embed_dim, padding_idx=256)
            self.byte_encoder = nn.Sequential(
                nn.Conv1d(byte_embed_dim, 64, kernel_size=7, padding=3),
                nn.ReLU(inplace=True),
                nn.Conv1d(64, hidden_dim, kernel_size=5, padding=2),
                nn.ReLU(inplace=True),
            )
            self.pe_encoder = nn.Sequential(
                nn.LayerNorm(pe_feature_dim),
                nn.Linear(pe_feature_dim, hidden_dim),
                nn.ReLU(inplace=True),
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(inplace=True),
            )
            self.mutation_risk_head = nn.Sequential(
                nn.Linear(hidden_dim * 2, hidden_dim),
                nn.ReLU(inplace=True),
                nn.Linear(hidden_dim, 1),
            )
            self.classifier = nn.Sequential(
                nn.LayerNorm(hidden_dim * 2),
                nn.Linear(hidden_dim * 2, hidden_dim),
                nn.ReLU(inplace=True),
                nn.Linear(hidden_dim, num_classes),
            )

        def forward(self, byte_tokens, pe_features, return_aux: bool = False):
            byte_x = self.byte_embedding(byte_tokens.clamp(0, 256)).transpose(1, 2)
            byte_x = self.byte_encoder(byte_x)
            byte_embedding = F.adaptive_max_pool1d(byte_x, 1).squeeze(-1)
            pe_embedding = self.pe_encoder(pe_features.float())
            embedding = torch.cat([byte_embedding, pe_embedding], dim=1)
            logits = self.classifier(embedding)
            if not return_aux:
                return logits
            return {
                "logits": logits,
                "embedding": embedding,
                "mutation_risk_logit": self.mutation_risk_head(embedding).squeeze(-1),
            }

else:

    class HybridBinaryShield:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs) -> None:
            raise ImportError("torch is required for HybridBinaryShield")
