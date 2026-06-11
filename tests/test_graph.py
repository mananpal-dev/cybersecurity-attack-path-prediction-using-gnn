"""
tests/test_graph.py
────────────────────
Unit tests for graph analysis and attack path finding.
These tests run without PyTorch (graph module only).
"""
import sys
from pathlib import Path

import networkx as nx
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import get_risk_tier, MITRE_TECHNIQUES, NODE_TYPES
from graph.find_attack_path import (
    score_node_criticality,
    find_attack_entry_nodes,
    find_high_value_targets,
    edge_attack_cost,
    score_path,
    find_critical_attack_paths,
    build_threat_matrix,
    compute_network_risk_metrics,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_test_graph() -> nx.DiGraph:
    """Build a deterministic 6-node test network."""
    G = nx.DiGraph()
    nodes = [
        (0, "INTERNET_EDGE",    "internet",   6.5, 0.6),
        (1, "DMZ_WEB",          "dmz",        7.8, 0.5),
        (2, "APP_SERVER",       "internal",   5.2, 0.6),
        (3, "DATABASE",         "restricted", 8.9, 0.95),
        (4, "DOMAIN_CONTROLLER","restricted", 9.1, 1.0),
        (5, "WORKSTATION",      "internal",   3.5, 0.3),
    ]
    for nid, ntype, seg, cvss, crit in nodes:
        G.add_node(nid, node_type=ntype, segment=seg,
                   cvss_score=cvss, asset_criticality=crit,
                   features=[0.5] * 16)

    edges = [
        (0, 1, {"technique_id": "T1190", "tactic": "Initial Access",
                "cvss_contribution": 7.8, "attack_complexity": "Low",
                "detection_probability": 0.2, "lateral_movement": False,
                "privilege_escalation": False}),
        (1, 2, {"technique_id": "T1021", "tactic": "Lateral Movement",
                "cvss_contribution": 6.5, "attack_complexity": "Low",
                "detection_probability": 0.3, "lateral_movement": True,
                "privilege_escalation": False}),
        (2, 3, {"technique_id": "T1078", "tactic": "Privilege Escalation",
                "cvss_contribution": 8.9, "attack_complexity": "High",
                "detection_probability": 0.5, "lateral_movement": False,
                "privilege_escalation": True}),
        (2, 4, {"technique_id": "T1068", "tactic": "Privilege Escalation",
                "cvss_contribution": 9.1, "attack_complexity": "High",
                "detection_probability": 0.4, "lateral_movement": False,
                "privilege_escalation": True}),
    ]
    for u, v, attrs in edges:
        G.add_edge(u, v, **attrs)
    return G


# ── Config tests ──────────────────────────────────────────────────────────────

class TestConfig:
    def test_risk_tiers(self):
        assert get_risk_tier(9.5) == "CRITICAL"
        assert get_risk_tier(8.9) == "HIGH"
        assert get_risk_tier(7.0) == "HIGH"
        assert get_risk_tier(5.0) == "MEDIUM"
        assert get_risk_tier(3.9) == "LOW"
        assert get_risk_tier(0.0) == "INFO"

    def test_mitre_techniques_loaded(self):
        assert len(MITRE_TECHNIQUES) >= 10
        assert "T1190" in MITRE_TECHNIQUES
        assert "T1021" in MITRE_TECHNIQUES
        assert "T1078" in MITRE_TECHNIQUES

    def test_node_types_loaded(self):
        assert "DOMAIN_CONTROLLER" in NODE_TYPES
        assert "DATABASE" in NODE_TYPES
        assert NODE_TYPES["DOMAIN_CONTROLLER"]["criticality"] == 1.0

    def test_mitre_technique_structure(self):
        for tid, info in MITRE_TECHNIQUES.items():
            assert "name" in info
            assert "tactic" in info
            assert "severity" in info


# ── Graph analysis tests ──────────────────────────────────────────────────────

class TestGraphAnalysis:
    def setup_method(self):
        self.G = make_test_graph()

    def test_find_entry_nodes(self):
        entries = find_attack_entry_nodes(self.G)
        assert 0 in entries  # INTERNET_EDGE should be entry

    def test_find_targets(self):
        targets = find_high_value_targets(self.G)
        assert 3 in targets or 4 in targets  # DB or DC

    def test_score_node_criticality(self):
        # DC should score higher than workstation
        dc_score = score_node_criticality(self.G, 4)
        ws_score = score_node_criticality(self.G, 5)
        assert dc_score > ws_score
        assert 0 <= dc_score <= 10

    def test_edge_attack_cost(self):
        cost = edge_attack_cost(self.G, 0, 1)
        assert 0 < cost < 1  # valid cost range
        # Low complexity edge should cost less than high
        low_cost = edge_attack_cost(self.G, 0, 1)   # "Low" complexity
        high_cost = edge_attack_cost(self.G, 2, 3)  # "High" complexity
        assert low_cost < high_cost

    def test_score_path_ordering(self):
        risk = {n: score_node_criticality(self.G, n) / 10.0 for n in self.G.nodes()}
        path_to_dc = [0, 1, 2, 4]  # → DOMAIN_CONTROLLER
        path_to_ws = [0, 5]         # → WORKSTATION (not reachable but test scoring)
        # Give workstation path a fake edge
        self.G.add_edge(0, 5, technique_id="T1566", tactic="Initial Access",
                        cvss_contribution=3.5, attack_complexity="Low",
                        detection_probability=0.6, lateral_movement=False,
                        privilege_escalation=False)
        score_dc = score_path(self.G, path_to_dc, risk)
        score_ws = score_path(self.G, path_to_ws, risk)
        assert score_dc > score_ws  # DC path should score higher


# ── Attack path tests ─────────────────────────────────────────────────────────

class TestAttackPaths:
    def setup_method(self):
        self.G = make_test_graph()

    def test_finds_paths(self):
        paths = find_critical_attack_paths(self.G, top_k=5)
        assert len(paths) >= 1

    def test_path_structure(self):
        paths = find_critical_attack_paths(self.G, top_k=3)
        for p in paths:
            assert "path_id" in p
            assert "nodes" in p
            assert "risk_score" in p
            assert "risk_tier" in p
            assert "techniques" in p
            assert "tactics" in p
            assert "steps" in p
            assert p["risk_tier"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_paths_sorted_by_risk(self):
        paths = find_critical_attack_paths(self.G, top_k=5)
        scores = [p["risk_score"] for p in paths]
        assert scores == sorted(scores, reverse=True)

    def test_techniques_are_valid_mitre(self):
        paths = find_critical_attack_paths(self.G, top_k=5)
        for p in paths:
            for t in p["techniques"]:
                assert t in MITRE_TECHNIQUES, f"Unknown technique: {t}"

    def test_path_nodes_connected(self):
        paths = find_critical_attack_paths(self.G, top_k=5)
        for p in paths:
            nodes = p["nodes"]
            for i in range(len(nodes) - 1):
                assert self.G.has_edge(nodes[i], nodes[i + 1]), \
                    f"No edge {nodes[i]} → {nodes[i+1]}"

    def test_threat_matrix(self):
        paths = find_critical_attack_paths(self.G, top_k=5)
        matrix = build_threat_matrix(paths)
        assert isinstance(matrix, dict)
        nonempty = {k: v for k, v in matrix.items() if v}
        assert len(nonempty) >= 1

    def test_metrics(self):
        paths = find_critical_attack_paths(self.G, top_k=5)
        m = compute_network_risk_metrics(self.G, paths)
        assert m["total_assets"] == 6
        assert m["critical_vuln_count"] >= 1   # CVSS 9.1 node
        assert m["internet_exposed"] == 1
        assert m["attack_paths_found"] == len(paths)
        assert m["avg_cvss"] > 0


# ── CVSS tests ────────────────────────────────────────────────────────────────

class TestCVSS:
    def test_cvss_calculation_direct(self):
        """Test CVSS calculation directly (no torch needed)."""
        # Import the function directly using importlib to bypass torch
        import importlib.util, types

        # Pre-install mocks before the module tries to import torch
        torch_mock = types.ModuleType("torch")
        torch_mock.tensor = lambda *a, **k: list(a[0]) if a and hasattr(a[0], '__iter__') else [0.0]*16
        torch_mock.float = float
        torch_mock.long = int
        torch_mock.save = lambda *a, **k: None

        pyg_mock = types.ModuleType("torch_geometric")
        pyg_data_mock = types.ModuleType("torch_geometric.data")
        class FakeData:
            def __init__(self, **kw): pass
        pyg_data_mock.Data = FakeData

        original_modules = {}
        for mod in ["torch", "torch_geometric", "torch_geometric.data", "data", "data.generate_synthetic_data"]:
            if mod in sys.modules:
                original_modules[mod] = sys.modules.pop(mod)

        sys.modules["torch"] = torch_mock
        sys.modules["torch_geometric"] = pyg_mock
        sys.modules["torch_geometric.data"] = pyg_data_mock

        try:
            spec = importlib.util.spec_from_file_location(
                "data.generate_synthetic_data",
                Path(__file__).parent.parent / "data" / "generate_synthetic_data.py"
            )
            mod = importlib.util.module_from_spec(spec)
            sys.modules["data.generate_synthetic_data"] = mod
            spec.loader.exec_module(mod)
            calculate_cvss_base_score = mod.calculate_cvss_base_score

            # High-risk scenario: network-facing, low complexity, no auth
            score_high = calculate_cvss_base_score("NETWORK", "LOW", "NONE", "NONE")
            assert score_high >= 8.0, f"Expected CVSS >= 8.0 for high-risk config, got {score_high}"

            # Low-risk scenario: physical access, high complexity, high priv required
            score_low = calculate_cvss_base_score("PHYSICAL", "HIGH", "HIGH", "REQUIRED")
            assert score_low < score_high, f"Low-risk score {score_low} should be < {score_high}"

            # Score must be in valid range
            assert 0.0 <= score_high <= 10.0
            assert 0.0 <= score_low <= 10.0

        finally:
            # Restore original modules
            for mod in ["torch", "torch_geometric", "torch_geometric.data",
                        "data", "data.generate_synthetic_data"]:
                sys.modules.pop(mod, None)
            sys.modules.update(original_modules)
