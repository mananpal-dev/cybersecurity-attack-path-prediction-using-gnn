"""
Centralized configuration for the Attack Path Prediction platform.
All tunable parameters live here — never scattered across scripts.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List
import os

# ── Paths ────────────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).parent.parent
DATA_DIR = ROOT_DIR / "data" / "synthetic_data"
MODEL_PATH = ROOT_DIR / "gnn_model.pt"
DATASET_PATH = ROOT_DIR / "gnn_dataset.pt"

# ── Neo4j (optional) ─────────────────────────────────────────────────────────
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

# ── GNN Hyperparameters ───────────────────────────────────────────────────────
@dataclass
class GNNConfig:
    in_channels: int = 16          # node feature vector length
    hidden_channels: int = 64
    out_channels: int = 1          # binary: attack / benign
    attention_heads: int = 8
    dropout: float = 0.3
    learning_rate: float = 0.001
    weight_decay: float = 5e-4
    epochs: int = 200
    batch_size: int = 32
    early_stopping_patience: int = 20
    scheduler_step: int = 50
    scheduler_gamma: float = 0.5


# ── Synthetic Data Generation ─────────────────────────────────────────────────
@dataclass
class DataConfig:
    num_graphs: int = 500
    min_nodes: int = 20
    max_nodes: int = 80
    attack_ratio: float = 0.35      # fraction of graphs that are attack scenarios
    seed: int = 42
    ba_edges: int = 3               # Barabási–Albert connectivity param


# ── CVSS v3.1 Attack Vector weights ──────────────────────────────────────────
CVSS_AV_WEIGHTS = {
    "NETWORK":    0.85,
    "ADJACENT":   0.62,
    "LOCAL":      0.55,
    "PHYSICAL":   0.20,
}

CVSS_AC_WEIGHTS = {"LOW": 0.77, "HIGH": 0.44}
CVSS_PR_WEIGHTS = {
    "NONE":  {"UNCHANGED": 0.85, "CHANGED": 0.85},
    "LOW":   {"UNCHANGED": 0.62, "CHANGED": 0.68},
    "HIGH":  {"UNCHANGED": 0.27, "CHANGED": 0.50},
}
CVSS_UI_WEIGHTS = {"NONE": 0.85, "REQUIRED": 0.62}


# ── MITRE ATT&CK technique catalogue (subset — most common in enterprise) ────
MITRE_TECHNIQUES: Dict[str, Dict] = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access",        "severity": "HIGH"},
    "T1133": {"name": "External Remote Services",          "tactic": "Initial Access",        "severity": "MEDIUM"},
    "T1566": {"name": "Phishing",                          "tactic": "Initial Access",        "severity": "MEDIUM"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution",             "severity": "HIGH"},
    "T1053": {"name": "Scheduled Task / Job",              "tactic": "Persistence",           "severity": "MEDIUM"},
    "T1078": {"name": "Valid Accounts",                    "tactic": "Privilege Escalation",  "severity": "HIGH"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "severity": "CRITICAL"},
    "T1021": {"name": "Remote Services",                   "tactic": "Lateral Movement",      "severity": "HIGH"},
    "T1021.001": {"name": "Remote Desktop Protocol",       "tactic": "Lateral Movement",      "severity": "HIGH"},
    "T1021.002": {"name": "SMB / Windows Admin Shares",    "tactic": "Lateral Movement",      "severity": "HIGH"},
    "T1046": {"name": "Network Service Discovery",         "tactic": "Discovery",             "severity": "LOW"},
    "T1083": {"name": "File and Directory Discovery",      "tactic": "Discovery",             "severity": "LOW"},
    "T1005": {"name": "Data from Local System",            "tactic": "Collection",            "severity": "MEDIUM"},
    "T1041": {"name": "Exfiltration Over C2 Channel",      "tactic": "Exfiltration",          "severity": "CRITICAL"},
    "T1486": {"name": "Data Encrypted for Impact",         "tactic": "Impact",                "severity": "CRITICAL"},
    "T1003": {"name": "OS Credential Dumping",             "tactic": "Credential Access",     "severity": "CRITICAL"},
    "T1110": {"name": "Brute Force",                       "tactic": "Credential Access",     "severity": "MEDIUM"},
}

# Tactic ordering (kill-chain sequence)
TACTIC_ORDER: List[str] = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
]

# ── Node types and their base criticality ────────────────────────────────────
NODE_TYPES = {
    "INTERNET_EDGE":    {"criticality": 0.6, "segment": "internet"},
    "DMZ_WEB":          {"criticality": 0.5, "segment": "dmz"},
    "DMZ_MAIL":         {"criticality": 0.5, "segment": "dmz"},
    "JUMP_SERVER":      {"criticality": 0.7, "segment": "dmz"},
    "WORKSTATION":      {"criticality": 0.3, "segment": "internal"},
    "APP_SERVER":       {"criticality": 0.6, "segment": "internal"},
    "FILE_SERVER":      {"criticality": 0.7, "segment": "internal"},
    "DATABASE":         {"criticality": 0.95, "segment": "restricted"},
    "DOMAIN_CONTROLLER": {"criticality": 1.0, "segment": "restricted"},
    "BACKUP_SERVER":    {"criticality": 0.8, "segment": "restricted"},
}

# ── Risk tier thresholds ─────────────────────────────────────────────────────
RISK_TIERS = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0, 8.9),
    "MEDIUM":   (4.0, 6.9),
    "LOW":      (0.1, 3.9),
    "INFO":     (0.0, 0.0),
}

RISK_COLORS = {
    "CRITICAL": "#FF3B3B",
    "HIGH":     "#FF8C00",
    "MEDIUM":   "#FFD700",
    "LOW":      "#22C55E",
    "INFO":     "#64748B",
}


def get_risk_tier(score: float) -> str:
    """Map a 0-10 risk score to a named tier."""
    for tier, (lo, hi) in RISK_TIERS.items():
        if lo <= score <= hi:
            return tier
    return "INFO"


GNN_CONFIG = GNNConfig()
DATA_CONFIG = DataConfig()
