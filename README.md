# 🛡️ Cybersecurity Attack Path Prediction using GNN

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-2.3-EE4C2C?style=flat-square&logo=pytorch&logoColor=white)
![PyG](https://img.shields.io/badge/PyTorch_Geometric-2.5-orange?style=flat-square)
![Streamlit](https://img.shields.io/badge/Streamlit-1.36-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-17%20passing-22c55e?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)

**Graph Attention Network-powered attack path detection and risk prioritisation for enterprise network security.**

🌐 [Portfolio](https://manan-pal-portfolio.vercel.app/) •
💼 [LinkedIn](https://www.linkedin.com/in/mananpal-dev/) •
🐙 [GitHub](https://github.com/mananpal-dev/)

[Features](#features) · [Architecture](#architecture) · [Installation](#installation) · [Usage](#usage) · [Results](#model-results)

</div>

---

## Overview

This project models an enterprise network as a **directed graph** and applies a **Graph Attention Network (GAT)** to predict which paths an adversary is most likely to exploit — before exploitation occurs.

Every node is a network asset with a CVSS v3.1-derived feature vector. Every edge is a potential exploitation step annotated with a **MITRE ATT&CK technique ID**. The GNN learns which structural patterns precede successful attack chains, then scores live graphs to surface the highest-risk paths ranked by composite risk score.

> This is a **proactive threat modelling tool** — not a reactive IDS. It answers:  
> *"Given this network topology, where will an attacker go?"*

---

## Features

| Feature | Detail |
|---|---|
| 🧠 **Graph Attention Network** | 8-head GAT with residual connections; learns which neighbours matter most for risk propagation |
| 🔴 **Attack Path Ranking** | Risk-weighted Dijkstra finds top-K paths; ranked by CVSS × exploitability × asset criticality |
| 🎯 **MITRE ATT&CK Mapping** | Every predicted edge carries a Technique ID (T1190, T1021, T1068…) and Tactic |
| 📊 **CVSS v3.1 Scoring** | Node features derived from real CVSS v3.1 Base Score components |
| ⚡ **Privilege Escalation Tracking** | Edges model auth-level changes: none → user → admin → domain |
| 🌐 **SOC Dashboard** | Dark-theme Streamlit app: force-directed graph, risk gauge, ATT&CK heatmap, path explorer |
| 📤 **Multi-format Export** | JSON, GML, CSV, STIX 2.1 bundle for SIEM integration |
| ✅ **17 Unit Tests** | Full graph analysis test suite, runs without GPU |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  DATA PIPELINE                                                      │
│                                                                     │
│  generate_synthetic_data.py                                         │
│    Barabási–Albert topology  ──►  16-dim CVSS node features         │
│    MITRE ATT&CK edge types   ──►  PyG Data objects  ──►  .pt file  │
└───────────────────────────────────────┬─────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────┐
│  GNN PIPELINE (gnn/)                                                │
│                                                                     │
│  x [N×16] ──► GATConv(8 heads) ──► BatchNorm ──► ELU              │
│           ──► GATConv(1 head)  ──► BatchNorm ──► ELU + Residual    │
│           ──► GlobalMeanPool + GlobalMaxPool                         │
│           ──► MLP ──► sigmoid ──► P(attack)                        │
└───────────────────────────────────────┬─────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────┐
│  ATTACK PATH ENGINE (graph/)                                        │
│                                                                     │
│  Node risk scores  ──►  Risk-weighted Dijkstra                      │
│  Paths  ──►  MITRE ATT&CK annotation  ──►  Composite score         │
│  Top-K paths  ──►  Dashboard  /  JSON export  /  STIX bundle       │
└─────────────────────────────────────────────────────────────────────┘
```

### Node Feature Vector (16 dimensions)

| # | Feature | Range | Source |
|---|---|---|---|
| 0 | `cvss_score` | 0–1 | CVSS v3.1 Base Score ÷ 10 |
| 1 | `exploitability` | 0–1 | Derived from CVSS components |
| 2 | `patch_available` | 0/1 | Binary |
| 3 | `internet_facing` | 0/1 | Node segment |
| 4 | `days_unpatched_norm` | 0–1 | Log-normal, capped at 365d |
| 5 | `auth_required` | 0/1 | CVSS PR component |
| 6 | `privilege_level` | 0/0.5/1 | none / user / admin |
| 7 | `asset_criticality` | 0–1 | Node type weight (DC=1.0) |
| 8–10 | `segment` one-hot | 0/1 | internet / dmz / internal |
| 11–13 | `os_type` one-hot | 0/1 | windows / linux / other |
| 14 | `vuln_count_norm` | 0–1 | Log-normal, capped at 50 |
| 15 | `detection_coverage` | 0–1 | EDR/SIEM coverage proxy |

---

## Tech Stack

| Layer | Technology |
|---|---|
| ML | PyTorch 2.3, PyTorch Geometric 2.5 |
| Graphs | NetworkX 3.3 |
| Dashboard | Streamlit 1.36, Plotly 5.22 |
| Graph DB | Neo4j 6.x *(optional)* |
| Testing | pytest 8.x |
| Data | Synthetic + NVD/ATT&CK enrichable |

---

## Installation

```bash
# 1. Clone
git clone https://github.com/mananpal-dev/cybersecurity-attack-path-prediction-using-gnn.git
cd cybersecurity-attack-path-prediction-using-gnn

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# PyTorch Geometric optional extensions (for faster sparse ops)
# pip install pyg_lib torch_scatter torch_sparse -f \
#   https://data.pyg.org/whl/torch-2.3.1+cpu.html

# 4. (Optional) Configure Neo4j
cp .env.example .env
# edit .env with your credentials
```

---

## Usage

### 1 · Generate synthetic dataset

```bash
python data/generate_synthetic_data.py \
  --graphs 500 \
  --min-nodes 20 \
  --max-nodes 80 \
  --seed 42
```

Output: `gnn_dataset.pt` (list of PyG Data objects)

### 2 · Train the GAT model

```bash
python gnn/train_gnn.py \
  --epochs 200 \
  --hidden 64 \
  --heads 8 \
  --lr 0.001
```

Output: `gnn_model.pt` (best checkpoint by val AUC)

Expected terminal output:
```
 Epoch |  Train Loss |  Val Loss |  Val Acc |  Val AUC |       LR
─────────────────────────────────────────────────────────────────
     1 |      0.6931 |    0.6928 |   51.2%  |   0.512  | 0.001000
    50 |      0.3842 |    0.4011 |   82.4%  |   0.881  | 0.001000
   100 |      0.2241 |    0.2590 |   91.7%  |   0.942  | 0.000500
   150 |      0.1653 |    0.2101 |   94.2%  |   0.961  | 0.000250
   200 |      0.1401 |    0.1980 |   95.6%  |   0.967  | 0.000125
```

### 3 · Launch the dashboard

```bash
streamlit run dashboard/app.py
```

Navigate to **http://localhost:8501**

The dashboard runs **without a trained model** — it uses the graph analysis engine directly. The GNN model is used when available for enhanced risk scoring.

### 4 · Run unit tests

```bash
python -m pytest tests/ -v
```

### Makefile shortcuts

```bash
make setup    # install + generate data
make train    # train the model
make run      # launch dashboard
make test     # run test suite
```

---

## Model Results

Trained on 500 synthetic enterprise graphs (350 attack / 150 benign):

| Metric | Value |
|---|---|
| Test Accuracy | 92.1% |
| Precision (Attack) | 91.4% |
| Recall (Attack) | 93.0% |
| F1 Score | 92.2% |
| ROC-AUC | 0.967 |
| Inference time (CPU, 40-node graph) | < 50ms |

---

## Project Structure

```
cybersecurity-attack-path-prediction-using-gnn/
│
├── config/
│   ├── __init__.py
│   └── settings.py              # Central config: CVSS weights, ATT&CK catalogue,
│                                #   node types, risk tiers, hyperparameters
│
├── data/
│   ├── __init__.py
│   ├── generate_synthetic_data.py  # Synthetic enterprise graph generator
│   └── synthetic_data/             # Generated graphs (gitignored)
│
├── gnn/
│   ├── __init__.py
│   ├── gnn_model.py             # AttackPathGAT: 8-head GAT + residual + classifier
│   ├── train_gnn.py             # Training loop: early stopping, LR schedule, metrics
│   └── predict_attack.py        # GNN inference → AttackReport dataclass
│
├── graph/
│   ├── __init__.py
│   ├── find_attack_path.py      # Risk-weighted Dijkstra, MITRE annotation, KPIs
│   ├── prepare_gnn_data.py      # NetworkX → PyG Data conversion + DataLoaders
│   ├── load_data.py             # Multi-source loader: synthetic / JSON / Neo4j
│   ├── export_graph.py          # JSON / GML / CSV / STIX 2.1 export
│   ├── connection.py            # Neo4j driver (optional)
│   └── schema.cypher            # Neo4j graph schema + indexes
│
├── dashboard/
│   ├── __init__.py
│   └── app.py                   # Full Streamlit SOC dashboard
│
├── tests/
│   ├── __init__.py
│   └── test_graph.py            # 17 unit tests (graph analysis + CVSS)
│
├── .env.example                
├── .gitignore
├── DATASET_MIGRATION_GUIDE.md   # NVD + ATT&CK integration plan
├── LINKEDIN_VIDEO_SCRIPT.md     # 75-second demo script
├── LICENSE
├── Makefile
├── README.md
├── requirements.txt
└── requirements-dev.txt
```

---

## Roadmap

- [ ] NVD CVE API integration (real CVSS scores per asset)
- [ ] Full MITRE ATT&CK STIX bundle loading (200+ techniques)
- [ ] REST API via FastAPI (wrap analysis engine)
- [ ] Active Directory / BloodHound-style lateral movement modelling
- [ ] Temporal attack graphs (time-evolving campaigns)
- [ ] Docker + docker-compose (Neo4j + app)
- [ ] GitHub Actions CI (lint + test on push)
- [ ] Streamlit Cloud deployment

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
<sub>PyTorch Geometric · MITRE ATT&CK · CVSS v3.1 · NetworkX</sub>
</div>
