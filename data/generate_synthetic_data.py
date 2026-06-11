"""
generate_synthetic_data.py
──────────────────────────
Generates realistic enterprise network graphs for GNN training.

Key improvements over naive random generation:
  • Barabási–Albert scale-free topology (matches real enterprise networks)
  • CVSS v3.1-inspired node feature vectors (16 dimensions)
  • MITRE ATT&CK technique annotations on edges
  • Realistic node type taxonomy (internet-facing → DMZ → internal → restricted)
  • Privilege escalation modeling on edges
  • Stratified attack/benign graph split (35/65)

Usage:
    python data/generate_synthetic_data.py --graphs 500 --nodes 40 --seed 42
"""

import argparse
import json
import random
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx
import numpy as np
import torch
from torch_geometric.data import Data

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import (
    DATA_CONFIG, MITRE_TECHNIQUES, NODE_TYPES,
    CVSS_AV_WEIGHTS, CVSS_AC_WEIGHTS,
)


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class NodeFeatures:
    """16-dimensional node feature vector aligned with CVSS v3.1 components."""
    cvss_score: float           # 0.0–10.0
    exploitability: float       # 0.0–1.0
    patch_available: float      # 0/1
    internet_facing: float      # 0/1
    days_unpatched_norm: float  # 0.0–1.0 (normalized, 1.0 = >365 days)
    auth_required: float        # 0/1
    privilege_level: float      # 0=none / 0.5=user / 1.0=admin
    asset_criticality: float    # 0.0–1.0
    # network segment one-hot (3 dims)
    seg_internet: float
    seg_dmz: float
    seg_internal: float
    # OS type one-hot (3 dims)
    os_windows: float
    os_linux: float
    os_other: float
    # vulnerability count (normalized)
    vuln_count_norm: float
    # detection coverage
    detection_coverage: float

    def to_tensor(self):
        """Convert to PyTorch tensor (list of 16 float values)."""
        return torch.tensor(list(asdict(self).values()), dtype=torch.float)


# ── CVSS score calculator ─────────────────────────────────────────────────────

def calculate_cvss_base_score(
    av: str = "NETWORK",
    ac: str = "LOW",
    pr: str = "NONE",
    ui: str = "NONE",
    scope: str = "UNCHANGED",
    conf: float = 0.56,
    integ: float = 0.56,
    avail: float = 0.56,
) -> float:
    """
    Compute CVSS v3.1 Base Score.
    Returns float in [0.0, 10.0].
    """
    iss_base = 1.0 - (1.0 - conf) * (1.0 - integ) * (1.0 - avail)
    if scope == "UNCHANGED":
        iss = 6.42 * iss_base
    else:
        iss = 7.52 * (iss_base - 0.029) - 3.25 * ((iss_base - 0.02) ** 15)

    av_w = CVSS_AV_WEIGHTS.get(av, 0.85)
    ac_w = CVSS_AC_WEIGHTS.get(ac, 0.77)
    pr_table = {"NONE": {"UNCHANGED": 0.85, "CHANGED": 0.85},
                "LOW":  {"UNCHANGED": 0.62, "CHANGED": 0.68},
                "HIGH": {"UNCHANGED": 0.27, "CHANGED": 0.50}}
    pr_w = pr_table.get(pr, pr_table["NONE"])[scope]
    ui_w = 0.85 if ui == "NONE" else 0.62

    exploitability = 8.22 * av_w * ac_w * pr_w * ui_w

    if iss <= 0:
        return 0.0

    if scope == "UNCHANGED":
        base = min(iss + exploitability, 10.0)
    else:
        base = min(1.08 * (iss + exploitability), 10.0)

    # Round up to nearest 0.1
    return round(float(np.ceil(base * 10) / 10), 1)


# ── Node builder ─────────────────────────────────────────────────────────────

def _random_choice(items: list, rng: random.Random) -> Any:
    return rng.choice(items)


def build_node_features(node_type: str, rng: random.Random) -> NodeFeatures:
    """
    Generate a realistic feature vector for a given node type.
    Parameter distributions are calibrated against NVD CVE statistics.
    """
    meta = NODE_TYPES[node_type]
    segment = meta["segment"]
    criticality = meta["criticality"]

    # Internet-facing raises CVSS attack vector probability
    is_internet = float(segment == "internet")
    is_dmz = float(segment == "dmz")

    # CVSS parameters correlated with node exposure
    av = "NETWORK" if segment in ("internet", "dmz") else _random_choice(
        ["NETWORK", "ADJACENT", "LOCAL"], rng)
    ac = _random_choice(["LOW", "LOW", "LOW", "HIGH"], rng)  # 75% LOW
    pr = _random_choice(["NONE", "LOW", "HIGH"], rng)
    ui = _random_choice(["NONE", "NONE", "REQUIRED"], rng)  # 66% NONE
    scope = _random_choice(["UNCHANGED", "UNCHANGED", "CHANGED"], rng)

    # CIA impact — restricted assets have higher impact scores
    impact_scale = 0.4 + 0.6 * criticality
    conf  = min(1.0, rng.gauss(0.56 * impact_scale, 0.1))
    integ = min(1.0, rng.gauss(0.56 * impact_scale, 0.1))
    avail = min(1.0, rng.gauss(0.56 * impact_scale, 0.1))

    cvss = calculate_cvss_base_score(av, ac, pr, ui, scope, conf, integ, avail)
    exploitability = min(1.0, max(0.0, cvss / 10.0 + rng.gauss(0.0, 0.05)))

    # Days unpatched — some nodes are neglected (long tail distribution)
    days_unpatched = int(np.clip(rng.lognormvariate(3.5, 1.2), 0, 1000))
    days_norm = min(1.0, days_unpatched / 365.0)

    # OS distribution
    os = _random_choice(["windows", "windows", "linux", "other"], rng)
    patch_available = float(rng.random() > 0.25)  # 75% have a patch
    auth_required = float(pr != "NONE")
    priv_level = {"NONE": 0.0, "LOW": 0.5, "HIGH": 1.0}[pr]
    vuln_count = int(np.clip(rng.lognormvariate(1.5, 0.8), 0, 50))
    detection_cov = min(1.0, max(0.0, rng.gauss(0.4, 0.2)))

    # Segment one-hot
    seg_net = float(segment == "internet")
    seg_dmz = float(segment == "dmz")
    seg_int = float(segment in ("internal", "restricted"))

    return NodeFeatures(
        cvss_score=cvss / 10.0,  # normalize to [0,1]
        exploitability=exploitability,
        patch_available=patch_available,
        internet_facing=is_internet,
        days_unpatched_norm=days_norm,
        auth_required=auth_required,
        privilege_level=priv_level,
        asset_criticality=criticality,
        seg_internet=seg_net,
        seg_dmz=seg_dmz,
        seg_internal=seg_int,
        os_windows=float(os == "windows"),
        os_linux=float(os == "linux"),
        os_other=float(os == "other"),
        vuln_count_norm=min(1.0, vuln_count / 50.0),
        detection_coverage=detection_cov,
    )


# ── Edge builder ──────────────────────────────────────────────────────────────

# Which ATT&CK techniques are likely on which edge transitions
_TECHNIQUE_POOL_BY_TACTIC = {
    "Initial Access":       ["T1190", "T1133", "T1566"],
    "Lateral Movement":     ["T1021", "T1021.001", "T1021.002"],
    "Privilege Escalation": ["T1068", "T1078"],
    "Credential Access":    ["T1003", "T1110"],
    "Discovery":            ["T1046", "T1083"],
    "Execution":            ["T1059"],
    "Exfiltration":         ["T1041"],
    "Impact":               ["T1486"],
}

_SEGMENT_ORDER = ["internet", "dmz", "internal", "restricted"]


def _infer_tactic(src_segment: str, dst_segment: str) -> str:
    """Heuristically infer the most likely ATT&CK tactic for a graph edge."""
    src_idx = _SEGMENT_ORDER.index(src_segment) if src_segment in _SEGMENT_ORDER else 1
    dst_idx = _SEGMENT_ORDER.index(dst_segment) if dst_segment in _SEGMENT_ORDER else 1

    if src_idx == 0:
        return "Initial Access"
    if dst_idx > src_idx:
        return "Lateral Movement"
    if dst_idx == len(_SEGMENT_ORDER) - 1:
        return "Privilege Escalation"
    return "Discovery"


def build_edge_attributes(
    src_type: str, dst_type: str, rng: random.Random
) -> Dict[str, Any]:
    """Construct realistic edge attributes with ATT&CK annotations."""
    src_segment = NODE_TYPES[src_type]["segment"]
    dst_segment = NODE_TYPES[dst_type]["segment"]

    tactic = _infer_tactic(src_segment, dst_segment)
    technique_id = rng.choice(_TECHNIQUE_POOL_BY_TACTIC.get(tactic, ["T1021"]))
    technique = MITRE_TECHNIQUES.get(technique_id, {})

    src_crit = NODE_TYPES[src_type]["criticality"]
    dst_crit = NODE_TYPES[dst_type]["criticality"]

    # Attack cost: lower = more attractive to attacker
    # Inverted CVSS-like: high dst criticality lowers cost (attacker motivated)
    base_cost = rng.uniform(0.2, 0.9)
    cost = base_cost * (1.0 - 0.4 * dst_crit)

    return {
        "technique_id": technique_id,
        "technique_name": technique.get("name", "Unknown"),
        "tactic": tactic,
        "attack_complexity": rng.choice(["Low", "Low", "High"]),
        "detection_probability": round(rng.uniform(0.1, 0.8), 2),
        "lateral_movement": tactic == "Lateral Movement",
        "privilege_escalation": tactic == "Privilege Escalation",
        "src_segment": src_segment,
        "dst_segment": dst_segment,
        "attack_cost": round(cost, 3),
        "cvss_contribution": round(rng.uniform(3.0, 9.5), 1),
    }


# ── Graph builder ─────────────────────────────────────────────────────────────

def _assign_node_types(n_nodes: int, rng: random.Random) -> List[str]:
    """
    Assign node types to simulate a realistic enterprise network.
    Topology: internet edge(s) → DMZ → internal → restricted (DC/DB at leaf)
    """
    node_type_list = list(NODE_TYPES.keys())
    weights = [
        1,   # INTERNET_EDGE
        2,   # DMZ_WEB
        1,   # DMZ_MAIL
        1,   # JUMP_SERVER
        8,   # WORKSTATION  (most common)
        4,   # APP_SERVER
        3,   # FILE_SERVER
        2,   # DATABASE
        1,   # DOMAIN_CONTROLLER
        1,   # BACKUP_SERVER
    ]
    return rng.choices(node_type_list, weights=weights, k=n_nodes)


def build_enterprise_graph(
    n_nodes: int,
    is_attack: bool,
    rng: random.Random,
    ba_edges: int = 3,
) -> Tuple[nx.DiGraph, Dict]:
    """
    Build one enterprise network graph.

    Returns:
        G: directed NetworkX graph with node/edge attributes
        meta: metadata dict for serialization
    """
    # Scale-free topology via Barabási–Albert
    G_undirected = nx.barabasi_albert_graph(n_nodes, ba_edges, seed=rng.randint(0, 99999))
    G = nx.DiGraph()
    G.add_nodes_from(G_undirected.nodes())

    # Directed edges: from lower to higher criticality (attack direction)
    node_types = _assign_node_types(n_nodes, rng)
    criticalities = [NODE_TYPES[t]["criticality"] for t in node_types]

    for (u, v) in G_undirected.edges():
        # Direct edge toward higher-criticality node (attacker's preferred direction)
        if criticalities[u] <= criticalities[v]:
            src, dst = u, v
        else:
            src, dst = v, u
        G.add_edge(src, dst)

    # Assign node features
    for i in range(n_nodes):
        ntype = node_types[i]
        feats = build_node_features(ntype, rng)
        G.nodes[i].update({
            "node_type": ntype,
            "segment": NODE_TYPES[ntype]["segment"],
            "asset_criticality": NODE_TYPES[ntype]["criticality"],
            "cvss_score": feats.cvss_score * 10.0,  # store raw for display
            "features": list(asdict(feats).values()),
            "label": int(is_attack),
        })

    # Assign edge attributes
    for (u, v) in G.edges():
        attrs = build_edge_attributes(node_types[u], node_types[v], rng)
        G.edges[u, v].update(attrs)

    meta = {
        "is_attack": is_attack,
        "n_nodes": n_nodes,
        "n_edges": G.number_of_edges(),
        "node_types": node_types,
    }
    return G, meta


# ── PyG converter ─────────────────────────────────────────────────────────────

def graph_to_pyg(G: nx.DiGraph, label: int) -> Data:
    """Convert a NetworkX graph to a PyTorch Geometric Data object."""
    node_features = torch.tensor(
        [G.nodes[i]["features"] for i in range(G.number_of_nodes())],
        dtype=torch.float,
    )

    edges = list(G.edges())
    if edges:
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)

    edge_cost = torch.tensor(
        [G.edges[u, v]["attack_cost"] for (u, v) in edges],
        dtype=torch.float,
    ).unsqueeze(1) if edges else torch.zeros((0, 1))

    return Data(
        x=node_features,
        edge_index=edge_index,
        edge_attr=edge_cost,
        y=torch.tensor([label], dtype=torch.float),
        num_nodes=G.number_of_nodes(),
    )


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_dataset(
    num_graphs: int = DATA_CONFIG.num_graphs,
    min_nodes: int = DATA_CONFIG.min_nodes,
    max_nodes: int = DATA_CONFIG.max_nodes,
    attack_ratio: float = DATA_CONFIG.attack_ratio,
    seed: int = DATA_CONFIG.seed,
    ba_edges: int = DATA_CONFIG.ba_edges,
    output_dir: Path = None,
) -> List[Data]:
    """
    Generate a full dataset of enterprise network graphs.

    Returns list of PyG Data objects, also saves JSON metadata
    and the .pt dataset file.
    """
    if output_dir is None:
        output_dir = Path(__file__).parent / "synthetic_data"
    output_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(seed)
    np.random.seed(seed)

    dataset: List[Data] = []
    metadata = []
    n_attack = int(num_graphs * attack_ratio)
    labels = [1] * n_attack + [0] * (num_graphs - n_attack)
    rng.shuffle(labels)

    print(f"Generating {num_graphs} graphs "
          f"({n_attack} attack / {num_graphs - n_attack} benign)...")

    for i, label in enumerate(labels):
        n_nodes = rng.randint(min_nodes, max_nodes)
        G, meta = build_enterprise_graph(n_nodes, bool(label), rng, ba_edges)
        pyg_data = graph_to_pyg(G, label)
        dataset.append(pyg_data)
        metadata.append(meta)

        if (i + 1) % 100 == 0:
            print(f"  {i + 1}/{num_graphs} graphs generated")

    # Save PyG dataset
    dataset_path = output_dir.parent.parent / "gnn_dataset.pt"
    torch.save(dataset, dataset_path)
    print(f"Dataset saved → {dataset_path}")

    # Save metadata as JSON
    meta_path = output_dir / "metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved → {meta_path}")

    # Print summary stats
    attack_count = sum(1 for d in dataset if d.y.item() == 1)
    avg_nodes = sum(d.num_nodes for d in dataset) / len(dataset)
    avg_edges = sum(d.edge_index.shape[1] for d in dataset) / len(dataset)
    print(f"\nDataset Summary:")
    print(f"  Total graphs  : {len(dataset)}")
    print(f"  Attack graphs : {attack_count} ({100*attack_count/len(dataset):.1f}%)")
    print(f"  Avg nodes     : {avg_nodes:.1f}")
    print(f"  Avg edges     : {avg_edges:.1f}")
    print(f"  Feature dims  : {dataset[0].x.shape[1]}")

    return dataset


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic enterprise network graphs")
    parser.add_argument("--graphs",     type=int,   default=500,  help="Number of graphs to generate")
    parser.add_argument("--min-nodes",  type=int,   default=20,   help="Min nodes per graph")
    parser.add_argument("--max-nodes",  type=int,   default=80,   help="Max nodes per graph")
    parser.add_argument("--attack-ratio", type=float, default=0.35)
    parser.add_argument("--seed",       type=int,   default=42)
    parser.add_argument("--ba-edges",   type=int,   default=3)
    args = parser.parse_args()

    generate_dataset(
        num_graphs=args.graphs,
        min_nodes=args.min_nodes,
        max_nodes=args.max_nodes,
        attack_ratio=args.attack_ratio,
        seed=args.seed,
        ba_edges=args.ba_edges,
    )
