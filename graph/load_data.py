"""
graph/load_data.py
───────────────────
Multi-source data loading for the Attack Path Prediction platform.

Supports:
  • In-memory synthetic generation (default, no dependencies)
  • JSON files exported by export_graph.py
  • Neo4j graph database (optional)

All loaders return a NetworkX DiGraph with standardised node/edge attributes.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import networkx as nx

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import NODE_TYPES

logger = logging.getLogger(__name__)


# ── Synthetic loader (primary, no external deps) ──────────────────────────────

def load_synthetic_graph(
    n_nodes: int = 40,
    is_attack: bool = True,
    seed: int = 42,
) -> nx.DiGraph:
    """
    Generate a fresh synthetic enterprise network graph.

    This is the primary data source when no real network data is available.
    Returns a graph immediately with no I/O, suitable for the dashboard.

    Args:
        n_nodes:   Number of network assets
        is_attack: Whether to bias topology toward attack scenarios
        seed:      Random seed for reproducibility

    Returns:
        nx.DiGraph with CVSS node features and ATT&CK edge annotations
    """
    import random
    from data.generate_synthetic_data import build_enterprise_graph

    rng = random.Random(seed)
    G, meta = build_enterprise_graph(n_nodes=n_nodes, is_attack=is_attack, rng=rng)
    logger.debug(
        "Synthetic graph: %d nodes, %d edges, attack=%s",
        meta["n_nodes"], meta["n_edges"], meta["is_attack"],
    )
    return G


# ── JSON file loader ──────────────────────────────────────────────────────────

def load_graph_from_json(path: str) -> nx.DiGraph:
    """
    Load a previously exported graph from a JSON file.

    Expected format: node-link JSON produced by export_graph.py.

    Args:
        path: Path to the JSON file

    Returns:
        nx.DiGraph
    """
    fpath = Path(path)
    if not fpath.exists():
        raise FileNotFoundError(f"Graph file not found: {path}")

    with open(fpath) as f:
        data = json.load(f)

    G = nx.node_link_graph(data, directed=True, multigraph=False)
    logger.info("Loaded graph from %s: %d nodes, %d edges",
                path, G.number_of_nodes(), G.number_of_edges())
    return G


# ── Neo4j loader (optional) ───────────────────────────────────────────────────

def load_graph_from_neo4j() -> nx.DiGraph:
    """
    Load network graph from Neo4j graph database.

    Requires NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD in .env

    Returns:
        nx.DiGraph populated from Neo4j Asset nodes and CONNECTS_TO relationships

    Raises:
        RuntimeError: if Neo4j is not available
    """
    from graph.connection import get_driver, is_neo4j_available

    if not is_neo4j_available():
        raise RuntimeError(
            "Neo4j is not available. "
            "Use load_synthetic_graph() or load_graph_from_json() instead."
        )

    G = nx.DiGraph()
    driver = get_driver()

    with driver.session() as session:
        # Load nodes
        result = session.run("""
            MATCH (a:Asset)
            RETURN a.asset_id AS id,
                   a.node_type AS node_type,
                   a.segment AS segment,
                   a.cvss_score AS cvss_score,
                   a.asset_criticality AS asset_criticality,
                   a.risk_tier AS risk_tier,
                   a.internet_facing AS internet_facing,
                   a.patch_available AS patch_available,
                   a.days_unpatched AS days_unpatched
        """)
        for record in result:
            nid = record["id"]
            G.add_node(nid, **{
                k: v for k, v in record.items() if k != "id" and v is not None
            })
            # Build feature vector for GNN compatibility
            G.nodes[nid]["features"] = _build_feature_vector(dict(record))

        # Load edges
        result = session.run("""
            MATCH (a:Asset)-[r:CONNECTS_TO]->(b:Asset)
            RETURN a.asset_id AS src,
                   b.asset_id AS dst,
                   r.technique_id AS technique_id,
                   r.technique_name AS technique_name,
                   r.tactic AS tactic,
                   r.attack_complexity AS attack_complexity,
                   r.cvss_contribution AS cvss_contribution,
                   r.detection_probability AS detection_probability,
                   r.lateral_movement AS lateral_movement,
                   r.privilege_escalation AS privilege_escalation,
                   r.attack_cost AS attack_cost
        """)
        for record in result:
            G.add_edge(record["src"], record["dst"], **{
                k: v for k, v in record.items()
                if k not in ("src", "dst") and v is not None
            })

    logger.info(
        "Loaded graph from Neo4j: %d nodes, %d edges",
        G.number_of_nodes(), G.number_of_edges(),
    )
    return G


def _build_feature_vector(record: dict) -> list:
    """Build a 16-float feature vector from a Neo4j node record."""
    cvss        = float(record.get("cvss_score") or 5.0)
    criticality = float(record.get("asset_criticality") or 0.5)
    internet    = float(bool(record.get("internet_facing")))
    patched     = float(bool(record.get("patch_available", True)))
    days        = min(1.0, float(record.get("days_unpatched") or 0) / 365.0)
    segment     = str(record.get("segment") or "internal")

    return [
        cvss / 10.0,            # cvss_score (normalized)
        cvss / 10.0 * 0.8,      # exploitability (proxy)
        patched,                 # patch_available
        internet,                # internet_facing
        days,                    # days_unpatched_norm
        0.0,                     # auth_required (unknown from Neo4j)
        0.5,                     # privilege_level
        criticality,             # asset_criticality
        float(segment == "internet"),   # seg_internet
        float(segment == "dmz"),        # seg_dmz
        float(segment in ("internal", "restricted")),  # seg_internal
        0.5, 0.3, 0.2,          # os one-hot (unknown)
        0.3,                     # vuln_count_norm
        0.4,                     # detection_coverage
    ]


# ── Smart loader ──────────────────────────────────────────────────────────────

def load_graph(
    source: str = "synthetic",
    json_path: Optional[str] = None,
    n_nodes: int = 40,
    is_attack: bool = True,
    seed: int = 42,
) -> nx.DiGraph:
    """
    Unified graph loader. Selects the appropriate backend.

    Args:
        source:    "synthetic" | "json" | "neo4j"
        json_path: Required when source="json"
        n_nodes:   Used when source="synthetic"
        is_attack: Used when source="synthetic"
        seed:      Used when source="synthetic"

    Returns:
        nx.DiGraph ready for attack path analysis
    """
    if source == "synthetic":
        return load_synthetic_graph(n_nodes=n_nodes, is_attack=is_attack, seed=seed)
    elif source == "json":
        if not json_path:
            raise ValueError("json_path is required when source='json'")
        return load_graph_from_json(json_path)
    elif source == "neo4j":
        return load_graph_from_neo4j()
    else:
        raise ValueError(f"Unknown source: {source!r}. Use 'synthetic', 'json', or 'neo4j'.")
