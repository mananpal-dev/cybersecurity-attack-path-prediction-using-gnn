"""
graph/prepare_gnn_data.py
──────────────────────────
Convert NetworkX graphs to PyTorch Geometric Data objects for GNN training.

This module is the bridge between the graph layer (NetworkX) and the
ML layer (PyTorch Geometric). It handles:
  • Feature matrix construction from node attributes
  • Edge index construction from directed edges
  • Edge attribute extraction (attack cost)
  • Graph-level label assignment
  • Dataset splitting (train / val / test)
  • DataLoader creation

Usage:
    from graph.prepare_gnn_data import graphs_to_dataset, make_loaders

    dataset = graphs_to_dataset(graph_list, label_list)
    train_loader, val_loader, test_loader = make_loaders(dataset)
"""

import sys
from pathlib import Path
from typing import List, Optional, Tuple

import networkx as nx
import torch
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import GNN_CONFIG


# ── Single-graph converter ────────────────────────────────────────────────────

def graph_to_data(G: nx.DiGraph, label: Optional[int] = None) -> Data:
    """
    Convert a single NetworkX DiGraph to a PyG Data object.

    Node features are taken from the 'features' attribute (16-dim list).
    If missing, a zero vector is used as fallback.

    Args:
        G:     Directed NetworkX graph with node/edge attributes
        label: Graph-level label (1=attack, 0=benign). None if unknown.

    Returns:
        torch_geometric.data.Data
    """
    n = G.number_of_nodes()
    feat_dim = GNN_CONFIG.in_channels  # 16

    # ── Node features ─────────────────────────────────────────────────────────
    node_features = []
    for i in range(n):
        raw = G.nodes[i].get("features", None)
        if raw is not None:
            feats = [float(x) for x in raw[:feat_dim]]
            # Pad if shorter than expected
            if len(feats) < feat_dim:
                feats += [0.0] * (feat_dim - len(feats))
        else:
            # Fallback: build from raw attributes
            feats = _attrs_to_features(G.nodes[i], feat_dim)
        node_features.append(feats)

    x = torch.tensor(node_features, dtype=torch.float)

    # ── Edge index ────────────────────────────────────────────────────────────
    edges = list(G.edges())
    if edges:
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)

    # ── Edge attributes (attack cost scalar) ──────────────────────────────────
    if edges:
        edge_attr = torch.tensor(
            [G.edges[u, v].get("attack_cost", 0.5) for (u, v) in edges],
            dtype=torch.float,
        ).unsqueeze(1)
    else:
        edge_attr = torch.zeros((0, 1), dtype=torch.float)

    # ── Graph label ───────────────────────────────────────────────────────────
    y = torch.tensor([float(label)], dtype=torch.float) if label is not None else None

    data = Data(
        x=x,
        edge_index=edge_index,
        edge_attr=edge_attr,
        num_nodes=n,
    )
    if y is not None:
        data.y = y

    return data


def _attrs_to_features(attrs: dict, feat_dim: int) -> List[float]:
    """
    Build a feature vector from raw node attribute dict.
    Used as fallback when 'features' key is absent.
    """
    cvss       = float(attrs.get("cvss_score", 5.0)) / 10.0
    criticality = float(attrs.get("asset_criticality", 0.5))
    segment    = str(attrs.get("segment", "internal"))

    feats = [
        cvss,
        cvss * 0.8,                                  # exploitability proxy
        1.0,                                          # patch_available (assume)
        float(segment == "internet"),                 # internet_facing
        0.3,                                          # days_unpatched_norm
        0.0,                                          # auth_required
        0.5,                                          # privilege_level
        criticality,                                  # asset_criticality
        float(segment == "internet"),                 # seg_internet
        float(segment == "dmz"),                      # seg_dmz
        float(segment in ("internal", "restricted")), # seg_internal
        0.5, 0.3, 0.2,                               # os one-hot
        0.3,                                          # vuln_count_norm
        0.4,                                          # detection_coverage
    ]
    return feats[:feat_dim]


# ── Batch converter ───────────────────────────────────────────────────────────

def graphs_to_dataset(
    graphs: List[nx.DiGraph],
    labels: Optional[List[int]] = None,
) -> List[Data]:
    """
    Convert a list of NetworkX graphs to a PyG dataset.

    Args:
        graphs: List of directed NetworkX graphs
        labels: Optional list of integer labels (1=attack, 0=benign)
                If None, labels are read from node attribute 'label'

    Returns:
        List of PyG Data objects
    """
    dataset = []
    for i, G in enumerate(graphs):
        if labels is not None:
            label = labels[i]
        else:
            # Infer from first node's label attribute
            label = G.nodes[0].get("label", 0) if G.number_of_nodes() > 0 else 0

        dataset.append(graph_to_data(G, label))

    return dataset


# ── Dataset splitting ─────────────────────────────────────────────────────────

def split_dataset(
    dataset: List[Data],
    train_ratio: float = 0.70,
    val_ratio:   float = 0.15,
    seed:        int   = 42,
) -> Tuple[List[Data], List[Data], List[Data]]:
    """
    Split a PyG dataset into train / val / test subsets.

    Args:
        dataset:     Full list of Data objects
        train_ratio: Fraction for training (default 0.70)
        val_ratio:   Fraction for validation (default 0.15)
        seed:        Random seed for shuffle

    Returns:
        (train_data, val_data, test_data)
    """
    torch.manual_seed(seed)
    perm    = torch.randperm(len(dataset)).tolist()
    shuffled = [dataset[i] for i in perm]

    n       = len(shuffled)
    n_train = int(n * train_ratio)
    n_val   = int(n * val_ratio)

    return (
        shuffled[:n_train],
        shuffled[n_train: n_train + n_val],
        shuffled[n_train + n_val:],
    )


# ── DataLoader factory ────────────────────────────────────────────────────────

def make_loaders(
    dataset:    List[Data],
    batch_size: int   = GNN_CONFIG.batch_size,
    seed:       int   = 42,
    train_ratio: float = 0.70,
    val_ratio:   float = 0.15,
) -> Tuple[DataLoader, DataLoader, DataLoader]:
    """
    Create DataLoaders for train / val / test.

    Args:
        dataset:     Full PyG dataset
        batch_size:  Batch size (default from GNN_CONFIG)
        seed:        Split seed
        train_ratio: Fraction for training
        val_ratio:   Fraction for validation

    Returns:
        (train_loader, val_loader, test_loader)
    """
    train_data, val_data, test_data = split_dataset(
        dataset, train_ratio, val_ratio, seed
    )

    train_loader = DataLoader(train_data, batch_size=batch_size, shuffle=True)
    val_loader   = DataLoader(val_data,   batch_size=batch_size, shuffle=False)
    test_loader  = DataLoader(test_data,  batch_size=batch_size, shuffle=False)

    return train_loader, val_loader, test_loader
