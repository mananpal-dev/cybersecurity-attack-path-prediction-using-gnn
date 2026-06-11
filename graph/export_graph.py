"""
graph/export_graph.py
──────────────────────
Export attack graphs and analysis results to standard formats.

Supported outputs:
  • JSON  (node-link format — re-importable by load_data.py)
  • GML   (standard graph format for Gephi / yEd)
  • CSV   (node and edge tables for spreadsheet/SIEM)
  • STIX  (basic STIX 2.1 bundle stub for SOC integration)

Usage:
    from graph.export_graph import export_json, export_csv, export_report_json

    export_json(G, "output/network.json")
    export_csv(G, "output/")
    export_report_json(report, "output/report.json")
"""

import csv
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import networkx as nx

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import MITRE_TECHNIQUES


# ── JSON export (round-trip compatible) ───────────────────────────────────────

def export_json(G: nx.DiGraph, path: str) -> None:
    """
    Export graph to node-link JSON format.
    Can be re-loaded with graph.load_data.load_graph_from_json().

    Args:
        G:    NetworkX directed graph
        path: Output file path
    """
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    # nx.node_link_data can't serialise torch tensors — convert features to lists
    G_clean = G.copy()
    for n in G_clean.nodes():
        feats = G_clean.nodes[n].get("features")
        if feats is not None and not isinstance(feats, list):
            G_clean.nodes[n]["features"] = list(feats)
        # Remove internal keys
        G_clean.nodes[n].pop("_betweenness", None)
        G_clean.nodes[n].pop("_gnn_risk", None)

    data = nx.node_link_data(G_clean, edges="links")
    with open(output, "w") as f:
        json.dump(data, f, indent=2, default=_json_serializer)
    print(f"Graph exported → {output}")


def export_gml(G: nx.DiGraph, path: str) -> None:
    """
    Export graph to GML format (compatible with Gephi, yEd, Cytoscape).

    Args:
        G:    NetworkX directed graph
        path: Output file path (.gml)
    """
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    G_clean = G.copy()
    for n in G_clean.nodes():
        # GML only supports str/int/float — remove complex types
        for key in ["features", "_betweenness", "_gnn_risk"]:
            G_clean.nodes[n].pop(key, None)

    nx.write_gml(G_clean, str(output))
    print(f"Graph exported (GML) → {output}")


# ── CSV export ────────────────────────────────────────────────────────────────

def export_csv(G: nx.DiGraph, output_dir: str) -> None:
    """
    Export graph as two CSV files: nodes.csv and edges.csv.
    Useful for spreadsheet analysis or SIEM ingestion.

    Args:
        G:          NetworkX directed graph
        output_dir: Directory to write nodes.csv and edges.csv
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # nodes.csv
    node_rows = []
    for n in G.nodes():
        d = G.nodes[n]
        node_rows.append({
            "node_id":         n,
            "node_type":       d.get("node_type", "UNKNOWN"),
            "segment":         d.get("segment", "unknown"),
            "cvss_score":      d.get("cvss_score", 0.0),
            "asset_criticality": d.get("asset_criticality", 0.0),
            "risk_tier":       d.get("risk_tier", ""),
            "internet_facing": int(d.get("segment") == "internet"),
        })
    _write_csv(out / "nodes.csv", node_rows)

    # edges.csv
    edge_rows = []
    for u, v in G.edges():
        d = G.edges[u, v]
        edge_rows.append({
            "source":              u,
            "target":              v,
            "technique_id":        d.get("technique_id", ""),
            "technique_name":      d.get("technique_name", ""),
            "tactic":              d.get("tactic", ""),
            "attack_complexity":   d.get("attack_complexity", ""),
            "cvss_contribution":   d.get("cvss_contribution", 0.0),
            "detection_probability": d.get("detection_probability", 0.0),
            "lateral_movement":    int(d.get("lateral_movement", False)),
            "privilege_escalation": int(d.get("privilege_escalation", False)),
            "attack_cost":         d.get("attack_cost", 0.0),
        })
    _write_csv(out / "edges.csv", edge_rows)
    print(f"CSV exported → {out}/nodes.csv, {out}/edges.csv")


def _write_csv(path: Path, rows: List[Dict]) -> None:
    if not rows:
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


# ── Report JSON export ────────────────────────────────────────────────────────

def export_report_json(report: Any, path: str) -> None:
    """
    Serialize an AttackReport (or any dict/dataclass) to JSON.
    Suitable for API responses or archiving scan results.

    Args:
        report: AttackReport dataclass or dict
        path:   Output file path
    """
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    if hasattr(report, "__dataclass_fields__"):
        data = asdict(report)
    elif isinstance(report, dict):
        data = report
    else:
        data = {"raw": str(report)}

    data["exported_at"] = datetime.now(timezone.utc).isoformat()

    with open(output, "w") as f:
        json.dump(data, f, indent=2, default=_json_serializer)
    print(f"Report exported → {output}")


# ── STIX 2.1 stub ─────────────────────────────────────────────────────────────

def export_stix_bundle(paths: List[Dict], path: str) -> None:
    """
    Export detected attack paths as a minimal STIX 2.1 bundle.

    Produces: one 'campaign' object + one 'attack-pattern' per unique technique.
    Intended as a starting point for SIEM/SOAR integration.

    Args:
        paths: List of attack path dicts from find_critical_attack_paths()
        path:  Output file path (.json)
    """
    import uuid

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).isoformat()
    objects = []

    # Campaign object
    campaign_id = f"campaign--{uuid.uuid4()}"
    objects.append({
        "type": "campaign",
        "spec_version": "2.1",
        "id": campaign_id,
        "created": now,
        "modified": now,
        "name": "Detected Attack Campaign",
        "description": f"Automated detection: {len(paths)} attack path(s) identified.",
        "first_seen": now,
    })

    # Attack-pattern objects (one per unique ATT&CK technique)
    seen_techs = set()
    for p in paths:
        for tech_id in p.get("techniques", []):
            if tech_id in seen_techs:
                continue
            seen_techs.add(tech_id)
            info = MITRE_TECHNIQUES.get(tech_id, {})
            ap_id = f"attack-pattern--{uuid.uuid4()}"
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now,
                "modified": now,
                "name": info.get("name", tech_id),
                "description": f"MITRE ATT&CK: {tech_id}",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": info.get("tactic", "unknown").lower().replace(" ", "-"),
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                        "external_id": tech_id,
                    }
                ],
            })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }

    with open(output, "w") as f:
        json.dump(bundle, f, indent=2)
    print(f"STIX 2.1 bundle exported → {output}  ({len(objects)} objects)")


# ── Helper ────────────────────────────────────────────────────────────────────

def _json_serializer(obj: Any) -> Any:
    """JSON serializer for non-standard types (tensors, numpy, etc.)."""
    if hasattr(obj, "tolist"):          # torch.Tensor / np.ndarray
        return obj.tolist()
    if hasattr(obj, "item"):            # torch scalar
        return obj.item()
    return str(obj)
