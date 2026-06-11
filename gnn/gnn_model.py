"""
gnn_model.py
────────────
Graph Attention Network (GAT) for cybersecurity attack path prediction.

Architecture rationale:
  • GAT over GCN: attention weights let the model learn WHICH neighboring
    nodes contribute most to risk — critical for finding pivot points in
    an attack graph (e.g., a jump server that connects many segments).
  • Multi-head (8 heads): captures multiple risk propagation patterns
    simultaneously (e.g., one head learns network-based paths, another
    learns credential-based escalation).
  • BatchNorm + ELU: stabilizes training on variable-size graphs.
  • Residual connection: prevents gradient vanishing on deeper graphs.
  • Global mean pool: summarizes node-level risk into graph-level prediction.

Input:
  x           : [N, 16] node feature matrix
  edge_index  : [2, E]  directed edge list
  edge_attr   : [E, 1]  edge attack cost
  batch       : [N]     batch assignment vector

Output:
  [B, 1] sigmoid probability of the graph representing an attack scenario
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import (
    GATConv,
    BatchNorm,
    global_mean_pool,
    global_max_pool,
)


class AttackPathGAT(nn.Module):
    """
    Graph Attention Network for attack path risk classification.

    Args:
        in_channels:      Node feature dimensions (default: 16)
        hidden_channels:  Hidden embedding size (default: 64)
        out_channels:     Output size, 1 for binary classification
        heads:            Number of attention heads in first layer
        dropout:          Dropout rate applied before attention layers
    """

    def __init__(
        self,
        in_channels: int = 16,
        hidden_channels: int = 64,
        out_channels: int = 1,
        heads: int = 8,
        dropout: float = 0.3,
    ):
        super().__init__()
        self.dropout = dropout

        # Layer 1: Multi-head GAT
        # Output: [N, hidden_channels * heads]
        self.conv1 = GATConv(
            in_channels,
            hidden_channels,
            heads=heads,
            dropout=dropout,
            concat=True,
        )
        self.bn1 = BatchNorm(hidden_channels * heads)

        # Layer 2: Single-head GAT (aggregation)
        # Output: [N, hidden_channels]
        self.conv2 = GATConv(
            hidden_channels * heads,
            hidden_channels,
            heads=1,
            dropout=dropout,
            concat=False,
        )
        self.bn2 = BatchNorm(hidden_channels)

        # Residual projection: match dimensions for skip connection
        self.residual = nn.Linear(in_channels, hidden_channels)

        # Graph-level classifier
        # Input: mean_pool + max_pool concatenated → 2 * hidden_channels
        self.classifier = nn.Sequential(
            nn.Linear(hidden_channels * 2, hidden_channels),
            nn.ELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels, 32),
            nn.ELU(),
            nn.Linear(32, out_channels),
        )

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        edge_attr: torch.Tensor = None,
    ) -> torch.Tensor:
        """
        Forward pass.

        Returns:
            Tensor of shape [B] with logits (apply sigmoid for probabilities).
        """
        # Residual baseline
        x_res = self.residual(x)

        # Layer 1
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.conv1(x, edge_index)
        x = self.bn1(x)
        x = F.elu(x)

        # Layer 2 + residual
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.conv2(x, edge_index)
        x = self.bn2(x)
        x = F.elu(x + x_res)  # residual skip connection

        # Graph-level readout: concatenate mean and max pooling
        x_mean = global_mean_pool(x, batch)
        x_max = global_max_pool(x, batch)
        x_graph = torch.cat([x_mean, x_max], dim=1)

        return self.classifier(x_graph).squeeze(-1)

    def get_node_embeddings(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> torch.Tensor:
        """
        Extract node-level embeddings (useful for per-node risk scoring).

        Returns:
            Tensor of shape [N, hidden_channels]
        """
        x_res = self.residual(x)
        x = self.conv1(x, edge_index)
        x = self.bn1(x)
        x = F.elu(x)
        x = self.conv2(x, edge_index)
        x = self.bn2(x)
        return F.elu(x + x_res)

    def count_parameters(self) -> int:
        return sum(p.numel() for p in self.parameters() if p.requires_grad)


def load_model(
    path: str,
    in_channels: int = 16,
    hidden_channels: int = 64,
    heads: int = 8,
    device: str = "cpu",
) -> AttackPathGAT:
    """Load a saved model checkpoint."""
    model = AttackPathGAT(
        in_channels=in_channels,
        hidden_channels=hidden_channels,
        heads=heads,
    ).to(device)
    checkpoint = torch.load(path, map_location=device)
    # Support both raw state_dict and wrapped checkpoint formats
    if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint:
        model.load_state_dict(checkpoint["model_state_dict"])
    else:
        model.load_state_dict(checkpoint)
    model.eval()
    return model
