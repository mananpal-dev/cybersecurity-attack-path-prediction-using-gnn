"""
find_attack_path.py
────────────────────
Graph analysis, attack path enumeration, and network risk utilities.

This module is the single source of truth for pathfinding primitives.
Both the dashboard (graph-only, no model) and gnn/predict_attack.py
(model-assisted) import from here — preventing circular imports.

Public API:
  find_critical_attack_paths   — top-K paths, no GNN required
  score_node_criticality       — per-node composite risk
  build_threat_matrix          — MITRE ATT&CK coverage dict
  compute_network_risk_metrics — aggregated KPIs for dashboard
  find_attack_entry_nodes      — internet/DMZ entry points
  find_high_value_targets      — DC/DB/critical targets
  edge_attack_cost             — edge traversal cost (attacker perspective)
  score_path                   — composite path risk scorer
  build_attack_path_dict       — serialize path to dict
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import (
    MITRE_TECHNIQUES, NODE_TYPES, TACTIC_ORDER, get_risk_tier
)


# ── Node scoring ──────────────────────────────────────────────────────────────

def score_node_criticality(G: nx.DiGraph, node: int) -> float:
    """
    Composite criticality score for a graph node (0–10 scale).

    Factors:
      • CVSS score              (35%)
      • Asset criticality       (35%)
      • Betweenness centrality  (20%)
      • Out-degree (blast proxy)(10%)
    """
    cvss        = G.nodes[node].get("cvss_score", 5.0)
    asset_crit  = G.nodes[node].get("asset_criticality", 0.3) * 10.0

    if "_betweenness" not in G.graph:
        try:
            G.graph["_betweenness"] = nx.betweenness_centrality(G)
        except Exception:
            G.graph["_betweenness"] = {}
    betweenness = G.graph["_betweenness"].get(node, 0.0) * 10.0

    n = max(1, G.number_of_nodes())
    out_deg_norm = min(1.0, G.out_degree(node) / max(1, n * 0.1)) * 10.0

    score = (0.35 * cvss + 0.35 * asset_crit +
             0.20 * betweenness + 0.10 * out_deg_norm)
    return round(min(10.0, score), 2)


# ── Graph topology helpers ────────────────────────────────────────────────────

def find_attack_entry_nodes(G: nx.DiGraph) -> List[int]:
    """Internet-facing / DMZ nodes that are likely attacker entry points."""
    # Prefer zero-in-degree internet/dmz nodes (true entry points)
    entries = [
        n for n in G.nodes()
        if G.nodes[n].get("segment") in ("internet", "dmz")
        and G.in_degree(n) == 0
    ]
    if not entries:
        entries = [
            n for n in G.nodes()
            if G.nodes[n].get("segment") in ("internet", "dmz")
        ]
    if not entries:
        # Fallback: highest-out-degree nodes
        sorted_nodes = sorted(G.nodes(), key=lambda n: G.out_degree(n), reverse=True)
        entries = sorted_nodes[:max(1, len(sorted_nodes) // 10)]
    return entries


def find_high_value_targets(G: nx.DiGraph) -> List[int]:
    """High-value nodes: DC, DB, backup, or criticality ≥ 0.85."""
    targets = [
        n for n in G.nodes()
        if G.nodes[n].get("asset_criticality", 0) >= 0.85
        or G.nodes[n].get("node_type") in (
            "DOMAIN_CONTROLLER", "DATABASE", "BACKUP_SERVER"
        )
    ]
    if not targets:
        targets = sorted(
            G.nodes(),
            key=lambda n: G.nodes[n].get("asset_criticality", 0),
            reverse=True,
        )[:max(1, G.number_of_nodes() // 10)]
    return targets


# ── Edge cost (attacker's traversal cost) ─────────────────────────────────────

def edge_attack_cost(G: nx.DiGraph, u: int, v: int) -> float:
    """
    Attacker's traversal cost for edge u → v.

    Lower cost = attacker prefers this edge.
    Inversely proportional to CVSS and exploitability.
    """
    data = G.edges[u, v]
    cvss_contrib      = data.get("cvss_contribution", 5.0) / 10.0
    attack_complexity = 0.3 if data.get("attack_complexity") == "Low" else 0.7
    detection         = data.get("detection_probability", 0.4)

    cost = (1.0 - cvss_contrib) * attack_complexity * (1.0 - 0.3 * (1.0 - detection))
    return max(0.01, round(cost, 4))


# ── Path scoring ──────────────────────────────────────────────────────────────

def score_path(
    G: nx.DiGraph,
    path: List[int],
    node_risk_scores: Dict[int, float],
) -> float:
    """
    Composite risk score for a path (0–10 scale).

    Factors:
      • Max target criticality  (35%)
      • Avg GNN/structural risk (30%)
      • Avg edge CVSS           (35%)
      • Length penalty
    """
    if len(path) < 2:
        return 0.0

    node_crit  = [G.nodes[n].get("asset_criticality", 0.3) for n in path]
    gnn_scores = [node_risk_scores.get(n, 0.5) for n in path]
    edge_cvss  = [
        G.edges[path[i], path[i + 1]].get("cvss_contribution", 5.0)
        for i in range(len(path) - 1)
    ]

    length_penalty = 1.0 / (1.0 + 0.05 * len(path))
    composite = (
        0.35 * max(node_crit) * 10.0 +
        0.30 * (sum(gnn_scores) / len(gnn_scores)) * 10.0 +
        0.35 * (sum(edge_cvss) / len(edge_cvss))
    ) * length_penalty
    return round(min(10.0, composite), 2)


# ── Path object builder ───────────────────────────────────────────────────────

def build_attack_path_dict(
    G: nx.DiGraph,
    path_nodes: List[int],
    risk_score: float,
    path_id: int,
) -> Dict[str, Any]:
    """
    Build a serializable dict for a single attack path.
    Used by both dashboard (graph-only) and predict_attack (model-assisted).
    """
    steps      = []
    techniques = []
    tactics    = []

    for i, node in enumerate(path_nodes):
        ndata = G.nodes[node]
        tech_id = tech_name = tactic = ""
        priv_change = "NONE"

        if i > 0:
            edata    = G.edges[path_nodes[i - 1], node]
            tech_id  = edata.get("technique_id", "T1021")
            tech_name = edata.get("technique_name", "Remote Services")
            tactic    = edata.get("tactic", "Lateral Movement")
            if edata.get("privilege_escalation"):
                priv_change = "ESCALATION"
            elif edata.get("lateral_movement"):
                priv_change = "LATERAL"
            if tech_id and tech_id not in techniques:
                techniques.append(tech_id)
            if tactic and tactic not in tactics:
                tactics.append(tactic)

        steps.append({
            "node_id":      node,
            "node_type":    ndata.get("node_type", "UNKNOWN"),
            "segment":      ndata.get("segment", "internal"),
            "cvss_score":   ndata.get("cvss_score", 5.0),
            "risk_score":   ndata.get("_gnn_risk", 0.5),
            "technique_id": tech_id,
            "technique_name": tech_name,
            "tactic":       tactic,
            "privilege_change": priv_change,
        })

    # Kill-chain coverage
    covered       = sum(1 for t in TACTIC_ORDER if t in tactics)
    kill_chain_cov = round(covered / max(1, len(TACTIC_ORDER)), 3)

    # Blast radius
    central = path_nodes[len(path_nodes) // 2]
    try:
        blast = len(nx.descendants(G, central))
    except Exception:
        blast = 0

    # Detection difficulty
    det_diffs = []
    for i in range(len(path_nodes) - 1):
        p = G.edges[path_nodes[i], path_nodes[i + 1]].get("detection_probability", 0.3)
        det_diffs.append(1.0 - p)
    det_diff = round(sum(det_diffs) / max(1, len(det_diffs)), 3)

    return {
        "path_id":              path_id,
        "nodes":                path_nodes,
        "risk_score":           risk_score,
        "risk_tier":            get_risk_tier(risk_score),
        "techniques":           techniques,
        "tactics":              tactics,
        "blast_radius":         blast,
        "detection_difficulty": det_diff,
        "kill_chain_coverage":  kill_chain_cov,
        "steps":                steps,
    }


# ── Main API ──────────────────────────────────────────────────────────────────

def find_critical_attack_paths(
    G: nx.DiGraph,
    top_k: int = 5,
    max_depth: int = 8,
    node_risk_scores: Optional[Dict[int, float]] = None,
) -> List[Dict[str, Any]]:
    """
    Find top-K attack paths ranked by composite risk score.

    Args:
        G:                NetworkX directed graph with node/edge attributes
        top_k:            Number of paths to return
        max_depth:        Max hops per path
        node_risk_scores: Optional pre-computed per-node scores (e.g. from GNN).
                          If None, uses structural scoring only.

    Returns:
        List of path dicts, sorted by risk_score descending.
    """
    if node_risk_scores is None:
        node_risk_scores = {n: score_node_criticality(G, n) / 10.0 for n in G.nodes()}

    # Set edge weights (attacker's cost)
    for u, v in G.edges():
        G.edges[u, v]["_cost"] = edge_attack_cost(G, u, v)

    entries = find_attack_entry_nodes(G)
    targets = find_high_value_targets(G)

    seen:  set          = set()
    paths: List[Tuple]  = []

    for src in entries:
        for dst in targets:
            if src == dst:
                continue
            try:
                path = nx.dijkstra_path(G, src, dst, weight="_cost")
                if len(path) > max_depth:
                    continue
                key = tuple(path)
                if key in seen:
                    continue
                seen.add(key)
                s = score_path(G, path, node_risk_scores)
                paths.append((path, s))
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

    # Sort and build top-K
    paths.sort(key=lambda x: x[1], reverse=True)
    result = []
    for rank, (path_nodes, risk_score) in enumerate(paths[:top_k], start=1):
        result.append(build_attack_path_dict(G, path_nodes, risk_score, rank))
    return result


def build_threat_matrix(paths: List[Dict]) -> Dict[str, Dict[str, int]]:
    """MITRE ATT&CK coverage matrix from detected paths: {tactic: {tech_id: count}}."""
    matrix: Dict[str, Dict[str, int]] = {t: {} for t in TACTIC_ORDER}
    for path in paths:
        for tech_id in path.get("techniques", []):
            info   = MITRE_TECHNIQUES.get(tech_id, {})
            tactic = info.get("tactic", "Unknown")
            if tactic in matrix:
                matrix[tactic][tech_id] = matrix[tactic].get(tech_id, 0) + 1
    return matrix


def compute_network_risk_metrics(
    G: nx.DiGraph,
    paths: List[Dict],
) -> Dict[str, Any]:
    """Aggregated security KPIs for the executive dashboard."""
    all_cvss    = [G.nodes[n].get("cvss_score", 0) for n in G.nodes()]
    critical_n  = [n for n in G.nodes() if G.nodes[n].get("cvss_score", 0) >= 9.0]
    high_n      = [n for n in G.nodes() if 7.0 <= G.nodes[n].get("cvss_score", 0) < 9.0]
    medium_n    = [n for n in G.nodes() if 4.0 <= G.nodes[n].get("cvss_score", 0) < 7.0]
    low_n       = [n for n in G.nodes() if G.nodes[n].get("cvss_score", 0) < 4.0]
    internet_n  = [n for n in G.nodes() if G.nodes[n].get("segment") == "internet"]

    # Unpatched: feature index 2 = patch_available (0.0 = no patch)
    unpatched = [
        n for n in G.nodes()
        if (G.nodes[n].get("features") or [1.0, 1.0, 1.0])[2] == 0.0
    ]

    avg_cvss       = round(sum(all_cvss) / max(1, len(all_cvss)), 1)
    max_path_risk  = max((p["risk_score"] for p in paths), default=0.0)
    unique_techs   = len({t for p in paths for t in p.get("techniques", [])})
    avg_blast      = round(
        sum(p.get("blast_radius", 0) for p in paths) / max(1, len(paths)), 1
    )

    return {
        "total_assets":        G.number_of_nodes(),
        "total_connections":   G.number_of_edges(),
        "critical_vuln_count": len(critical_n),
        "high_vuln_count":     len(high_n),
        "medium_vuln_count":   len(medium_n),
        "low_vuln_count":      len(low_n),
        "internet_exposed":    len(internet_n),
        "unpatched_assets":    len(unpatched),
        "avg_cvss":            avg_cvss,
        "max_path_risk":       round(max_path_risk, 1),
        "attack_paths_found":  len(paths),
        "unique_techniques":   unique_techs,
        "avg_blast_radius":    avg_blast,
        "network_risk_tier":   get_risk_tier(max_path_risk),
    }
