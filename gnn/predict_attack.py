"""
predict_attack.py
──────────────────
GNN-powered inference engine for attack path prediction.

Builds on top of graph.find_attack_path primitives, adding:
  • GAT node embeddings → per-node risk scores
  • Graph-level attack probability (sigmoid output)
  • Structured AttackReport dataclass

Usage (requires trained model):
    python gnn/predict_attack.py --model gnn_model.pt
"""

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import networkx as nx
import torch

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import (
    MITRE_TECHNIQUES, TACTIC_ORDER, get_risk_tier, MODEL_PATH,
)
from graph.find_attack_path import (
    find_critical_attack_paths,
    find_attack_entry_nodes,
    find_high_value_targets,
)
from gnn.gnn_model import AttackPathGAT, load_model


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class AttackReport:
    """Full analysis report produced by GNN-assisted inference."""
    graph_risk_probability: float
    risk_tier: str
    total_nodes: int
    total_edges: int
    critical_nodes: List[Dict]
    attack_paths: List[Dict]
    mitre_techniques: List[str]
    top_tactic: str
    network_exposure_score: float
    executive_summary: str


# ── GNN inference ─────────────────────────────────────────────────────────────

def _graph_to_tensors(G: nx.DiGraph, device: str = "cpu"):
    """Convert NetworkX graph to tensors for GNN inference."""
    n = G.number_of_nodes()
    features = torch.tensor(
        [G.nodes[i].get("features", [0.5] * 16) for i in range(n)],
        dtype=torch.float,
    ).to(device)

    edges = list(G.edges())
    if edges:
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous().to(device)
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long).to(device)

    batch = torch.zeros(n, dtype=torch.long).to(device)
    return features, edge_index, batch


def compute_node_risk_scores(
    G: nx.DiGraph,
    model: AttackPathGAT,
    device: str = "cpu",
) -> Dict[int, float]:
    """
    Use GAT embeddings to assign per-node risk scores.
    Blends GNN embedding norm (60%) with raw CVSS (40%).
    """
    features, edge_index, _ = _graph_to_tensors(G, device)

    with torch.no_grad():
        embeddings = model.get_node_embeddings(features, edge_index)
        norms = torch.norm(embeddings, dim=1)
        norms_norm = (norms - norms.min()) / (norms.max() - norms.min() + 1e-8)
        gnn_scores = norms_norm.cpu().tolist()

    risk_scores = {}
    for i in range(G.number_of_nodes()):
        cvss = G.nodes[i].get("cvss_score", 5.0) / 10.0
        risk_scores[i] = round(0.6 * gnn_scores[i] + 0.4 * cvss, 3)

    return risk_scores


def get_graph_risk_probability(
    G: nx.DiGraph,
    model: AttackPathGAT,
    device: str = "cpu",
) -> float:
    """Run graph-level binary classification. Returns sigmoid probability."""
    features, edge_index, batch = _graph_to_tensors(G, device)
    with torch.no_grad():
        logit = model(features, edge_index, batch, None)
        return float(torch.sigmoid(logit).item())


# ── Report builder ────────────────────────────────────────────────────────────

def _executive_summary(prob: float, paths: List[Dict], critical_nodes: List[Dict]) -> str:
    tier     = get_risk_tier(prob * 10)
    top_tech = paths[0]["techniques"][0] if paths and paths[0]["techniques"] else "N/A"
    top_name = MITRE_TECHNIQUES.get(top_tech, {}).get("name", "Unknown")
    return (
        f"Network assessed as {tier} risk (confidence: {prob:.0%}). "
        f"Identified {len(paths)} exploitable attack path(s) and "
        f"{len(critical_nodes)} critical asset(s) at risk. "
        f"Primary attack vector: {top_name} ({top_tech}). "
        f"Immediate remediation recommended for internet-facing assets with CVSS ≥ 7.0."
    )


def analyze_graph(
    G: nx.DiGraph,
    model: AttackPathGAT,
    top_k: int = 5,
    device: str = "cpu",
) -> AttackReport:
    """
    Full GNN-assisted attack path analysis.

    1. Computes per-node risk scores via GAT embeddings
    2. Finds top-K paths weighted by GNN scores
    3. Returns structured AttackReport
    """
    node_risk  = compute_node_risk_scores(G, model, device)
    graph_prob = get_graph_risk_probability(G, model, device)

    # Annotate nodes with GNN scores for downstream use
    for n, score in node_risk.items():
        G.nodes[n]["_gnn_risk"] = score

    paths = find_critical_attack_paths(G, top_k=top_k, node_risk_scores=node_risk)

    critical_nodes = sorted(
        [
            {
                "node_id":        n,
                "node_type":      G.nodes[n].get("node_type", "UNKNOWN"),
                "cvss_score":     G.nodes[n].get("cvss_score", 0),
                "risk_score":     node_risk.get(n, 0),
                "segment":        G.nodes[n].get("segment", "unknown"),
            }
            for n in G.nodes()
            if G.nodes[n].get("cvss_score", 0) >= 7.0
        ],
        key=lambda x: x["risk_score"],
        reverse=True,
    )

    internet_cvss = [
        G.nodes[n].get("cvss_score", 5.0)
        for n in G.nodes()
        if G.nodes[n].get("segment") == "internet"
    ]
    exposure = round(sum(internet_cvss) / max(1, len(internet_cvss)), 1)

    all_techniques = list({t for p in paths for t in p.get("techniques", [])})
    tactic_counts: Dict[str, int] = {}
    for p in paths:
        for t in p.get("tactics", []):
            tactic_counts[t] = tactic_counts.get(t, 0) + 1
    top_tactic = max(tactic_counts, key=tactic_counts.get) if tactic_counts else "N/A"

    return AttackReport(
        graph_risk_probability=round(graph_prob, 3),
        risk_tier=get_risk_tier(graph_prob * 10),
        total_nodes=G.number_of_nodes(),
        total_edges=G.number_of_edges(),
        critical_nodes=critical_nodes,
        attack_paths=paths,
        mitre_techniques=all_techniques,
        top_tactic=top_tactic,
        network_exposure_score=exposure,
        executive_summary=_executive_summary(graph_prob, paths, critical_nodes),
    )


def print_report(report: AttackReport) -> None:
    w = 68
    print("╔" + "═" * w + "╗")
    print(f"║{'ATTACK PATH ANALYSIS REPORT':^{w}}║")
    print("╠" + "═" * w + "╣")
    print(f"║  Risk Tier    : {report.risk_tier:<{w-17}}║")
    print(f"║  Probability  : {report.graph_risk_probability:.1%}{'':<{w-26}}║")
    print(f"║  Nodes/Edges  : {report.total_nodes} / {report.total_edges:<{w-26}}║")
    print(f"║  Exposure     : {report.network_exposure_score:.1f}/10{'':<{w-23}}║")
    print(f"║  Critical Nodes: {len(report.critical_nodes):<{w-18}}║")
    print("╠" + "═" * w + "╣")
    for ap in report.attack_paths:
        tier   = ap.get("risk_tier", "LOW")
        score  = ap.get("risk_score", 0)
        hops   = len(ap.get("nodes", []))
        print(f"║  Path #{ap['path_id']} │ {tier:8s} │ Score:{score:4.1f} │ {hops} hops{'':<{w-44}}║")
        techs = ", ".join(ap.get("techniques", [])[:3])
        print(f"║    Techniques: {techs:<{w-16}}║")
    print("╚" + "═" * w + "╝")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model",  default=str(MODEL_PATH))
    parser.add_argument("--top-k",  type=int, default=5)
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args()

    import random
    from data.generate_synthetic_data import build_enterprise_graph

    model = load_model(args.model, device=args.device)
    rng   = random.Random(1337)
    G, _  = build_enterprise_graph(n_nodes=40, is_attack=True, rng=rng)
    report = analyze_graph(G, model, top_k=args.top_k, device=args.device)
    print_report(report)
