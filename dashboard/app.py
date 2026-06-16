"""
dashboard/app.py
─────────────────
Professional Cybersecurity Attack Path Analytics Dashboard

Design target: CrowdStrike / Wiz / Microsoft Defender aesthetic
Theme: Deep Navy + Electric Blue + Cyan highlights + MP Amber Gold accents
"""

import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import networkx as nx
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import (
    MITRE_TECHNIQUES, NODE_TYPES, RISK_COLORS, TACTIC_ORDER,
    get_risk_tier, DATA_CONFIG, GNN_CONFIG, MODEL_PATH,
)
from data.generate_synthetic_data import build_enterprise_graph
from graph.find_attack_path import (
    find_critical_attack_paths,
    compute_network_risk_metrics,
    build_threat_matrix,
    score_node_criticality,
)

# ─────────────────────────────────
st.set_page_config(
    page_title="CyberGraph | Attack Path Intelligence",
    page_icon="assets/favicon.png",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  /* ── Base ── */
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  html, body, [class*="css"] {
    font-family: 'Space Grotesk', sans-serif;
    background-color: #060d1a;
    color: #e2e8f4;
  }

  /* ── Sidebar ── */
  [data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0a1628 0%, #060d1a 100%);
    border-right: 1px solid rgba(245, 166, 35, 0.15);
  }
  [data-testid="stSidebar"] * { color: #b8c5d6 !important; }
  [data-testid="stSidebar"] .stSelectbox label,
  [data-testid="stSidebar"] .stSlider label { color: #7aa3cc !important; }

  /* ── Main area ── */
  [data-testid="stMain"] { background: #060d1a; }
  .main .block-container { padding: 1.5rem 2rem 2rem; max-width: 1400px; }

  /* ── Metric cards ── */
  [data-testid="metric-container"] {
    background: rgba(10, 25, 55, 0.85) !important;
    border: 1px solid rgba(30, 200, 255, 0.18) !important;
    border-radius: 12px !important;
    padding: 16px 20px !important;
    backdrop-filter: blur(8px);
    box-shadow: 0 0 24px rgba(30, 200, 255, 0.06);
    transition: box-shadow 0.2s ease;
  }
  [data-testid="metric-container"]:hover {
    box-shadow: 0 0 32px rgba(245, 166, 35, 0.12);
    border-color: rgba(245, 166, 35, 0.3) !important;
  }
  [data-testid="stMetricLabel"] { color: #7aa3cc !important; font-size: 0.78rem !important; text-transform: uppercase; letter-spacing: 0.06em; }
  [data-testid="stMetricValue"] { color: #e8f4ff !important; font-size: 2.1rem !important; font-weight: 600; }
  [data-testid="stMetricDelta"] { font-size: 0.78rem !important; }

  /* ── Section headers ── */
  h1 { color: #1ec8ff !important; font-weight: 700 !important; letter-spacing: -0.02em; }
  h2 { color: #c5d8f0 !important; font-weight: 600 !important; font-size: 1.15rem !important; }
  h3 { color: #8aafd4 !important; font-weight: 500 !important; font-size: 0.95rem !important; }

  /* ── Dividers ── */
  hr { border-color: rgba(245, 166, 35, 0.12) !important; }

  /* ── Plotly chart containers ── */
  .js-plotly-plot { border-radius: 12px; overflow: hidden; }

  /* ── Dataframes ── */
  [data-testid="stDataFrame"] { border: 1px solid rgba(30, 200, 255, 0.12); border-radius: 10px; }

  /* ── Buttons ── */
  .stButton>button {
    background: linear-gradient(135deg, #0f4c8a 0%, #1168c0 100%) !important;
    color: #e8f4ff !important;
    border: 1px solid rgba(245, 166, 35, 0.4) !important;
    border-radius: 8px !important;
    font-weight: 500 !important;
    padding: 8px 20px !important;
    transition: all 0.2s ease !important;
    box-shadow: 0 0 16px rgba(245, 166, 35, 0.15) !important;
  }
  .stButton>button:hover {
    box-shadow: 0 0 28px rgba(245, 166, 35, 0.35) !important;
    border-color: #F5A623 !important;
    transform: translateY(-1px);
  }

  /* ── Alert / expander ── */
  .stAlert { border-radius: 10px !important; }
  .stExpander { border: 1px solid rgba(30, 200, 255, 0.12) !important; border-radius: 10px !important; background: rgba(10, 25, 55, 0.6) !important; }

  /* ── Tabs ── */
  .stTabs [data-baseweb="tab-list"] { background: rgba(10, 22, 45, 0.8); border-radius: 10px; padding: 4px; }
  .stTabs [data-baseweb="tab"] { color: #7aa3cc !important; border-radius: 8px; }
  .stTabs [aria-selected="true"] { background: rgba(245, 166, 35, 0.12) !important; color: #F5A623 !important; }

  /* ── Select/slider ── */
  .stSelectbox>div>div { background: rgba(10, 25, 55, 0.85) !important; border-color: rgba(30, 200, 255, 0.2) !important; color: #e2e8f4 !important; }
  .stSlider [data-testid="stSlider"] { color: #F5A623 !important; }

  /* ── Custom card ── */
  .cyber-card {
    background: rgba(10, 22, 45, 0.85);
    border: 1px solid rgba(30, 200, 255, 0.14);
    border-radius: 14px;
    padding: 20px 24px;
    margin-bottom: 16px;
    box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3);
    backdrop-filter: blur(6px);
  }
  .cyber-card:hover { border-color: rgba(245, 166, 35, 0.25); }

  /* ── Risk badges ── */
  .badge-critical { background:#2d0a0a; border:1px solid #FF3B3B; color:#FF3B3B; padding:3px 10px; border-radius:6px; font-size:0.78rem; font-weight:600; font-family:'JetBrains Mono',monospace; }
  .badge-high     { background:#2d1a00; border:1px solid #FF8C00; color:#FF8C00; padding:3px 10px; border-radius:6px; font-size:0.78rem; font-weight:600; font-family:'JetBrains Mono',monospace; }
  .badge-medium   { background:#2d2700; border:1px solid #FFD700; color:#FFD700; padding:3px 10px; border-radius:6px; font-size:0.78rem; font-weight:600; font-family:'JetBrains Mono',monospace; }
  .badge-low      { background:#0a2d10; border:1px solid #22C55E; color:#22C55E; padding:3px 10px; border-radius:6px; font-size:0.78rem; font-weight:600; font-family:'JetBrains Mono',monospace; }

  /* ── MP Logo sidebar ── */
  .mp-logo-wrap {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 4px 0 2px;
  }
  .mp-logo-wrap img {
    width: 38px;
    height: 38px;
    border-radius: 8px;
    object-fit: cover;
  }
  .mp-logo-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: #F5A623 !important;
    letter-spacing: 0.01em;
    line-height: 1.15;
  }
  .mp-logo-sub {
    font-size: 0.72rem;
    color: #4a6f9a !important;
    letter-spacing: 0.03em;
    margin-top: 1px;
  }

  /* ── Hero logo row ── */
  .hero-logo-row {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 2px;
  }
  .hero-logo-row img {
    width: 46px;
    height: 46px;
    border-radius: 10px;
    object-fit: cover;
    box-shadow: 0 0 18px rgba(245, 166, 35, 0.25);
  }
  .hero-title {
    font-size: 1.75rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    line-height: 1.1;
    color: #1ec8ff;
    margin: 0;
  }
  .hero-title span {
    color: #F5A623;
  }

  /* ── Footer brand mark ── */
  .footer-brand {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 6px;
  }
  .footer-brand img {
    width: 22px;
    height: 22px;
    border-radius: 5px;
    opacity: 0.75;
  }
  .footer-brand span {
    font-size: 0.7rem;
    color: #2e4a6a !important;
    letter-spacing: 0.04em;
  }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: #060d1a; }
  ::-webkit-scrollbar-thumb { background: rgba(245, 166, 35, 0.2); border-radius: 4px; }
</style>
""", unsafe_allow_html=True)

# ── Plot theme ────────────────────────────────────────────────────────────────
PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(6,13,26,0)",
    plot_bgcolor="rgba(10,22,45,0.6)",
    font=dict(family="Space Grotesk, sans-serif", color="#b8c5d6", size=12),
    margin=dict(l=16, r=16, t=36, b=16),
    colorway=["#1ec8ff", "#F5A623", "#0f9acc", "#35d4a8", "#0675a2", "#ff6b6b"],
    xaxis=dict(gridcolor="rgba(30,200,255,0.07)", linecolor="rgba(30,200,255,0.15)", tickcolor="rgba(30,200,255,0.15)"),
    yaxis=dict(gridcolor="rgba(30,200,255,0.07)", linecolor="rgba(30,200,255,0.15)", tickcolor="rgba(30,200,255,0.15)"),
)


def apply_layout(fig: go.Figure, **kwargs) -> go.Figure:
    fig.update_layout(**{**PLOTLY_LAYOUT, **kwargs})
    return fig


# ── Session state helpers ─────────────────────────────────────────────────────

def _init_state():
    defaults = {
        "graph": None,
        "paths": [],
        "metrics": {},
        "threat_matrix": {},
        "last_scan_time": None,
        "scan_count": 0,
        "node_count": 40,
        "seed": 42,
        "is_attack": True,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def _run_analysis(node_count: int, seed: int, is_attack: bool):
    """Generate graph and run full analysis."""
    rng = random.Random(seed)
    G, _ = build_enterprise_graph(
        n_nodes=node_count,
        is_attack=is_attack,
        rng=rng,
        ba_edges=3,
    )
    paths = find_critical_attack_paths(G, top_k=6)
    metrics = compute_network_risk_metrics(G, paths)
    threat_matrix = build_threat_matrix(paths)

    st.session_state.graph = G
    st.session_state.paths = paths
    st.session_state.metrics = metrics
    st.session_state.threat_matrix = threat_matrix
    st.session_state.last_scan_time = time.strftime("%H:%M:%S")
    st.session_state.scan_count += 1


# ── Chart builders ────────────────────────────────────────────────────────────

def build_attack_graph_figure(G: nx.DiGraph, paths: List[Dict]) -> go.Figure:
    """Build interactive Plotly force-directed attack graph."""
    pos = nx.spring_layout(G, seed=7, k=1.8 / max(1, G.number_of_nodes() ** 0.5))

    SEG_COLORS = {
        "internet":   "#FF3B3B",
        "dmz":        "#FF8C00",
        "internal":   "#1ec8ff",
        "restricted": "#FFD700",
    }

    path_nodes = set()
    for p in paths:
        path_nodes.update(p.get("nodes", []))

    edge_traces = []
    for (u, v) in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        on_path = u in path_nodes and v in path_nodes
        color = "rgba(245,166,35,0.55)" if on_path else "rgba(30,200,255,0.15)"
        width = 2.5 if on_path else 0.8
        edge_traces.append(go.Scatter(
            x=[x0, x1, None],
            y=[y0, y1, None],
            mode="lines",
            line=dict(width=width, color=color),
            hoverinfo="none",
        ))

    node_x, node_y, node_colors, node_sizes, node_texts, hover_texts = [], [], [], [], [], []
    for n in G.nodes():
        x, y = pos[n]
        node_x.append(x)
        node_y.append(y)

        ndata = G.nodes[n]
        segment = ndata.get("segment", "internal")
        color = SEG_COLORS.get(segment, "#1ec8ff")
        if n in path_nodes:
            color = SEG_COLORS.get(segment, "#FF3B3B")
            size = 16
        else:
            size = 9

        cvss = ndata.get("cvss_score", 5.0)
        node_colors.append(color)
        node_sizes.append(size)
        ntype = ndata.get("node_type", "UNKNOWN")
        node_texts.append("")
        hover_texts.append(
            f"<b>{ntype}</b><br>"
            f"Segment: {segment.upper()}<br>"
            f"CVSS: {cvss:.1f}<br>"
            f"Criticality: {ndata.get('asset_criticality', 0):.0%}<br>"
            f"{'⚠️ ON ATTACK PATH' if n in path_nodes else ''}"
        )

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        hoverinfo="text",
        text=node_texts,
        hovertext=hover_texts,
        marker=dict(
            size=node_sizes,
            color=node_colors,
            line=dict(width=1.5, color="rgba(245,166,35,0.3)"),
        ),
    )

    fig = go.Figure(data=[*edge_traces, node_trace])
    apply_layout(fig,
        title=dict(text="Network Attack Graph", font=dict(size=14, color="#7aa3cc")),
        showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        hovermode="closest",
        height=480,
    )
    return fig


def build_cvss_histogram(G: nx.DiGraph) -> go.Figure:
    cvss_scores = [G.nodes[n].get("cvss_score", 0) for n in G.nodes()]
    colors = []
    for c in cvss_scores:
        if c >= 9.0:   colors.append("#FF3B3B")
        elif c >= 7.0: colors.append("#FF8C00")
        elif c >= 4.0: colors.append("#FFD700")
        else:           colors.append("#22C55E")

    fig = go.Figure(go.Histogram(
        x=cvss_scores,
        nbinsx=20,
        marker=dict(color=colors, line=dict(width=0.5, color="rgba(0,0,0,0.3)")),
    ))
    apply_layout(fig,
        title=dict(text="CVSS Score Distribution", font=dict(size=13, color="#7aa3cc")),
        xaxis_title="CVSS v3.1 Score",
        yaxis_title="Asset Count",
        height=260,
        bargap=0.05,
    )
    return fig


def build_risk_gauge(risk_score: float) -> go.Figure:
    tier = get_risk_tier(risk_score)
    color = RISK_COLORS.get(tier, "#64748B")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        domain={"x": [0, 1], "y": [0, 1]},
        number={"font": {"size": 40, "color": color, "family": "Space Grotesk"}},
        title={"text": "Network Risk Score", "font": {"size": 13, "color": "#7aa3cc"}},
        gauge={
            "axis": {"range": [0, 10], "tickwidth": 1, "tickcolor": "#334155", "nticks": 6},
            "bar": {"color": color, "thickness": 0.25},
            "bgcolor": "rgba(10,22,45,0.6)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 4],   "color": "rgba(34,197,94,0.15)"},
                {"range": [4, 7],   "color": "rgba(255,215,0,0.12)"},
                {"range": [7, 9],   "color": "rgba(255,140,0,0.12)"},
                {"range": [9, 10],  "color": "rgba(255,59,59,0.15)"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.8,
                "value": risk_score,
            },
        },
    ))
    apply_layout(fig, height=220, margin=dict(l=20, r=20, t=50, b=10))
    return fig


def build_attack_path_sankey(paths: List[Dict], G: nx.DiGraph) -> go.Figure:
    """Build a Sankey diagram showing attack flow through network segments."""
    if not paths:
        return go.Figure()

    segments = ["INTERNET", "DMZ", "INTERNAL", "RESTRICTED"]
    seg_to_idx = {s.lower(): i for i, s in enumerate(segments)}
    flows = {}

    for path in paths:
        for i in range(len(path["nodes"]) - 1):
            u, v = path["nodes"][i], path["nodes"][i+1]
            src_seg = G.nodes[u].get("segment", "internal")
            dst_seg = G.nodes[v].get("segment", "internal")
            src_i = seg_to_idx.get(src_seg, 2)
            dst_i = seg_to_idx.get(dst_seg, 2)
            if src_i != dst_i:
                key = (src_i, dst_i)
                flows[key] = flows.get(key, 0) + path["risk_score"]

    if not flows:
        return go.Figure()

    sources = [k[0] for k in flows]
    targets = [k[1] for k in flows]
    values  = [v for v in flows.values()]

    fig = go.Figure(go.Sankey(
        node=dict(
            pad=20, thickness=24,
            label=segments,
            color=["#FF3B3B", "#FF8C00", "#1ec8ff", "#FFD700"],
            line=dict(color="rgba(0,0,0,0.3)", width=0.5),
        ),
        link=dict(
            source=sources, target=targets, value=values,
            color=["rgba(245,166,35,0.35)"] * len(sources),
        ),
    ))
    apply_layout(fig,
        title=dict(text="Attack Flow — Segment Traversal", font=dict(size=13, color="#7aa3cc")),
        height=300,
    )
    return fig


def build_mitre_heatmap(threat_matrix: Dict) -> go.Figure:
    """Build MITRE ATT&CK tactic × technique coverage heatmap."""
    tactics = [t for t in TACTIC_ORDER if t in threat_matrix]
    if not tactics:
        return go.Figure()

    all_techs = sorted({t for tac in tactics for t in threat_matrix.get(tac, {})})
    if not all_techs:
        return go.Figure()

    z = []
    for tac in tactics:
        row = [threat_matrix.get(tac, {}).get(t, 0) for t in all_techs]
        z.append(row)

    tech_labels = [f"{t}<br><sub>{MITRE_TECHNIQUES.get(t, {}).get('name', '')[:20]}</sub>" for t in all_techs]

    fig = go.Figure(go.Heatmap(
        z=z,
        x=tech_labels,
        y=[t[:18] for t in tactics],
        colorscale=[[0, "rgba(10,22,45,0.9)"], [0.5, "rgba(245,166,35,0.4)"], [1, "#F5A623"]],
        showscale=False,
        hoverongaps=False,
        hovertemplate="Tactic: %{y}<br>Technique: %{x}<br>Occurrences: %{z}<extra></extra>",
    ))
    apply_layout(fig,
        title=dict(text="MITRE ATT&CK Coverage Matrix", font=dict(size=13, color="#7aa3cc")),
        height=280,
        xaxis=dict(tickangle=-30, tickfont=dict(size=9)),
        yaxis=dict(tickfont=dict(size=10)),
    )
    return fig


def build_segment_pie(G: nx.DiGraph) -> go.Figure:
    seg_counts = {}
    for n in G.nodes():
        s = G.nodes[n].get("segment", "internal")
        seg_counts[s] = seg_counts.get(s, 0) + 1

    SEG_COLORS_MAP = {"internet": "#FF3B3B", "dmz": "#FF8C00", "internal": "#1ec8ff", "restricted": "#FFD700"}
    labels = [s.upper() for s in seg_counts]
    values = list(seg_counts.values())
    colors = [SEG_COLORS_MAP.get(s, "#64748B") for s in seg_counts]

    fig = go.Figure(go.Pie(
        labels=labels, values=values,
        marker=dict(colors=colors, line=dict(color="rgba(0,0,0,0.3)", width=1.5)),
        hole=0.55,
        textfont=dict(size=11, family="Space Grotesk"),
        hovertemplate="<b>%{label}</b><br>Assets: %{value}<br>%{percent}<extra></extra>",
    ))
    apply_layout(fig,
        title=dict(text="Assets by Network Segment", font=dict(size=13, color="#7aa3cc")),
        showlegend=True,
        legend=dict(font=dict(size=10), bgcolor="rgba(0,0,0,0)", x=0.85),
        height=260,
    )
    return fig


def build_top_paths_table(paths: List[Dict]) -> go.Figure:
    if not paths:
        return go.Figure()

    tier_colors = {
        "CRITICAL": "#FF3B3B", "HIGH": "#FF8C00",
        "MEDIUM": "#FFD700", "LOW": "#22C55E"
    }
    rows = []
    for p in paths:
        tier = p.get("risk_tier", "LOW")
        rows.append({
            "ID": f"#{p['path_id']}",
            "Risk Score": f"{p['risk_score']:.1f}",
            "Tier": tier,
            "Hops": len(p.get("nodes", [])),
            "Techniques": ", ".join(p.get("techniques", [])[:2]) or "N/A",
            "Primary Tactic": p.get("tactics", ["N/A"])[0] if p.get("tactics") else "N/A",
            "Blast Radius": p.get("blast_radius", 0),
        })

    col_colors = [
        ["rgba(10,22,45,0.7)"] * len(rows),
        [f"rgba({int(c[1:3],16)},{int(c[3:5],16)},{int(c[5:7],16)},0.2)"
         for c in [tier_colors.get(r["Tier"], "#64748B") for r in rows]],
        [tier_colors.get(r["Tier"], "#64748B") for r in rows],
        ["rgba(10,22,45,0.7)"] * len(rows),
        ["rgba(10,22,45,0.7)"] * len(rows),
        ["rgba(10,22,45,0.7)"] * len(rows),
        ["rgba(10,22,45,0.7)"] * len(rows),
    ]

    fig = go.Figure(go.Table(
        header=dict(
            values=["<b>ID</b>", "<b>Score</b>", "<b>Tier</b>", "<b>Hops</b>",
                    "<b>Techniques</b>", "<b>Primary Tactic</b>", "<b>Blast Radius</b>"],
            fill_color="rgba(15,27,45,0.98)",
            align="left",
            font=dict(color="#F5A623", size=11, family="Space Grotesk"),
            line_color="rgba(245,166,35,0.18)",
            height=34,
        ),
        cells=dict(
            values=[
                [r["ID"] for r in rows],
                [r["Risk Score"] for r in rows],
                [r["Tier"] for r in rows],
                [r["Hops"] for r in rows],
                [r["Techniques"] for r in rows],
                [r["Primary Tactic"] for r in rows],
                [r["Blast Radius"] for r in rows],
            ],
            fill_color=col_colors,
            align="left",
            font=dict(color=["#b8c5d6", "#f0a040", "#ffffff", "#b8c5d6", "#7aa3cc", "#7aa3cc", "#b8c5d6"], size=11, family="Space Grotesk"),
            line_color="rgba(245,166,35,0.07)",
            height=30,
        ),
    ))
    apply_layout(fig, height=min(420, 100 + len(rows) * 35))
    return fig


# ── Sidebar ───────────────────────────────────────────────────────────────────

def render_sidebar():
    with st.sidebar:
        # ── Branding: logo + title ──
        st.markdown(
            """
            <div class="mp-logo-wrap">
              <img src="app/static/favicon.png" alt="MP"/>
              <div>
                <div class="mp-logo-title">CyberGraph</div>
                <div class="mp-logo-sub">Attack Path Intelligence</div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.divider()

        st.markdown("### ⚙️ Scan Configuration")
        node_count = st.slider("Network Assets", 15, 120, st.session_state.node_count, 5)
        seed = st.number_input("Scenario Seed", 0, 9999, st.session_state.seed, 1)
        scenario = st.selectbox(
            "Scenario Type",
            ["Attack Scenario", "Benign Network"],
            index=0 if st.session_state.is_attack else 1,
        )
        is_attack = scenario == "Attack Scenario"

        st.markdown("### 🎯 Analysis Mode")
        analysis_mode = st.selectbox("Mode", ["Full Analysis", "Quick Scan", "Deep Dive"])

        top_k = st.slider("Max Attack Paths", 1, 10, 5)

        st.divider()
        run = st.button("🔍 Run Analysis", use_container_width=True)

        if run:
            st.session_state.node_count = node_count
            st.session_state.seed = seed
            st.session_state.is_attack = is_attack
            with st.spinner("Analyzing network topology..."):
                _run_analysis(node_count, seed, is_attack)

        st.divider()
        st.markdown("### 📊 Legend")
        legend_items = [
            ("🔴", "Internet / Entry Point", "#FF3B3B"),
            ("🟠", "DMZ / Perimeter",       "#FF8C00"),
            ("🔵", "Internal Network",       "#1ec8ff"),
            ("🟡", "Restricted / Critical",  "#FFD700"),
        ]
        for icon, label, color in legend_items:
            st.markdown(
                f"<span style='color:{color}; font-size:0.8rem;'>{icon} {label}</span>",
                unsafe_allow_html=True
            )

        st.divider()
        if st.session_state.last_scan_time:
            st.markdown(
                f"<p style='color:#4a6f9a; font-size:0.72rem;'>Last scan: {st.session_state.last_scan_time} "
                f"&nbsp;|&nbsp; Total scans: {st.session_state.scan_count}</p>",
                unsafe_allow_html=True
            )
        # ── Footer brand mark ──
        st.markdown(
            """
            <div class="footer-brand">
              <img src="app/static/favicon.png" alt="MP"/>
              <span>by Manan Pal &nbsp;·&nbsp; GNN Security Research</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    return top_k


# ── Main layout ───────────────────────────────────────────────────────────────

def render_hero():
    col_title, col_status = st.columns([4, 1])
    with col_title:
        # Logo + title inline
        st.markdown(
            """
            <div class="hero-logo-row">
              <img src="app/static/favicon.png" alt="MP logo"/>
              <h1 class="hero-title">
                CyberGraph &mdash; <span>Attack Path</span> Intelligence Platform
              </h1>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            "<p style='color:#4a6f9a; font-size:0.85rem; margin-top:6px; padding-left:60px;'>"
            "Graph Neural Network &nbsp;·&nbsp; MITRE ATT&CK &nbsp;·&nbsp; CVSS v3.1 &nbsp;·&nbsp; Real-Time Risk Scoring"
            "</p>",
            unsafe_allow_html=True
        )
    with col_status:
        if st.session_state.graph is not None:
            m = st.session_state.metrics
            tier = m.get("network_risk_tier", "LOW")
            color = RISK_COLORS.get(tier, "#64748B")
            st.markdown(
                f"<div style='text-align:right; padding-top:10px;'>"
                f"<span style='color:{color}; font-weight:700; font-size:0.85rem;"
                f" border:1px solid {color}; padding:4px 12px; border-radius:6px;"
                f" background: rgba(255,255,255,0.03);'>● {tier} RISK</span></div>",
                unsafe_allow_html=True
            )
    st.markdown("---")


def render_kpi_strip(metrics: Dict):
    """Top-line KPI cards row."""
    cols = st.columns(6)
    kpis = [
        ("🖥 Total Assets",      metrics.get("total_assets", 0),          None),
        ("⚠️ Critical Vulns",    metrics.get("critical_vuln_count", 0),    "inverse"),
        ("🌐 Internet Exposed",  metrics.get("internet_exposed", 0),       "inverse"),
        ("🔴 Attack Paths",      metrics.get("attack_paths_found", 0),     "inverse"),
        ("📊 Avg CVSS",          f"{metrics.get('avg_cvss', 0):.1f}",      None),
        ("🎯 MITRE Techniques",  metrics.get("unique_techniques", 0),      None),
    ]
    for col, (label, value, delta_color) in zip(cols, kpis):
        col.metric(label, value)


def render_main_analysis(G: nx.DiGraph, paths: List[Dict], metrics: Dict, threat_matrix: Dict):
    """Main two-column analysis layout."""
    tab_overview, tab_paths, tab_mitre, tab_details = st.tabs([
        "📊 Overview", "🔴 Attack Paths", "🎯 MITRE ATT&CK", "🔍 Node Details"
    ])

    with tab_overview:
        col_graph, col_right = st.columns([3, 2])
        with col_graph:
            st.plotly_chart(build_attack_graph_figure(G, paths), use_container_width=True)
        with col_right:
            st.plotly_chart(build_risk_gauge(metrics.get("max_path_risk", 0)), use_container_width=True)
            st.plotly_chart(build_segment_pie(G), use_container_width=True)

        col_h, col_cvss = st.columns(2)
        with col_h:
            st.plotly_chart(build_attack_path_sankey(paths, G), use_container_width=True)
        with col_cvss:
            st.plotly_chart(build_cvss_histogram(G), use_container_width=True)

    with tab_paths:
        if not paths:
            st.info("No attack paths detected in this network configuration.")
        else:
            st.markdown(
                f"<div class='cyber-card'>"
                f"<b style='color:#F5A623'>Detected {len(paths)} exploitable attack path(s)</b> "
                f"using risk-weighted graph traversal. Ranked by composite risk score "
                f"(CVSS × exploitability × asset criticality).</div>",
                unsafe_allow_html=True
            )
            st.plotly_chart(build_top_paths_table(paths), use_container_width=True)

            st.markdown("### Path Details")
            for path in paths:
                tier = path.get("risk_tier", "LOW")
                score = path.get("risk_score", 0)
                color = RISK_COLORS.get(tier, "#64748B")
                with st.expander(
                    f"Path #{path['path_id']}  ·  {tier}  ·  Score: {score:.1f}/10  "
                    f"·  {len(path['nodes'])} hops  ·  Blast radius: {path.get('blast_radius',0)}",
                    expanded=(path['path_id'] == 1),
                ):
                    steps = path.get("steps", [])
                    for i, step in enumerate(steps):
                        arrow = " → " if i < len(steps) - 1 else ""
                        seg_c = {"internet": "#FF3B3B", "dmz": "#FF8C00", "internal": "#1ec8ff", "restricted": "#FFD700"}
                        sc = seg_c.get(step.get("segment", ""), "#64748B")
                        st.markdown(
                            f"<span style='color:{sc}; font-family:JetBrains Mono; font-size:0.82rem;'>"
                            f"[{step.get('segment','').upper()}] {step.get('node_type','')}"
                            f"</span>"
                            f"<span style='color:#334155;'> CVSS:{step.get('cvss_score',0):.1f}</span>"
                            + (f"<br><span style='color:#4a6f9a; font-size:0.75rem; padding-left:20px;'>"
                               f"↳ {step.get('tactic','')} · {step.get('technique_id','')} "
                               f"{MITRE_TECHNIQUES.get(step.get('technique_id',''),{}).get('name','')}</span>"
                               if step.get("technique_id") else ""),
                            unsafe_allow_html=True
                        )

    with tab_mitre:
        if not threat_matrix or not any(threat_matrix.values()):
            st.info("No MITRE ATT&CK techniques mapped. Run analysis to populate.")
        else:
            col_hm, col_info = st.columns([3, 1])
            with col_hm:
                st.plotly_chart(build_mitre_heatmap(threat_matrix), use_container_width=True)
            with col_info:
                all_techs = {t for tac in threat_matrix.values() for t in tac}
                st.markdown(f"**{len(all_techs)} techniques** detected across **{len([t for t in threat_matrix if threat_matrix[t]])} tactics**")
                for tech_id in sorted(all_techs):
                    info = MITRE_TECHNIQUES.get(tech_id, {})
                    sev = info.get("severity", "MEDIUM")
                    color = RISK_COLORS.get(sev, "#64748B")
                    st.markdown(
                        f"<div style='margin:3px 0; font-size:0.78rem;'>"
                        f"<code style='color:#F5A623'>{tech_id}</code> "
                        f"<span style='color:#7aa3cc'>{info.get('name','')[:28]}</span></div>",
                        unsafe_allow_html=True
                    )

    with tab_details:
        st.markdown("### High-Risk Node Inventory")
        node_data = []
        for n in G.nodes():
            cvss = G.nodes[n].get("cvss_score", 0)
            if cvss >= 6.0:
                node_data.append({
                    "Node ID": n,
                    "Type": G.nodes[n].get("node_type", "UNKNOWN"),
                    "Segment": G.nodes[n].get("segment", "").upper(),
                    "CVSS Score": round(cvss, 1),
                    "Criticality": f"{G.nodes[n].get('asset_criticality', 0):.0%}",
                    "Risk Score": round(score_node_criticality(G, n), 1),
                    "Tier": get_risk_tier(cvss),
                })
        node_data.sort(key=lambda x: x["CVSS Score"], reverse=True)

        if node_data:
            import pandas as pd
            df = pd.DataFrame(node_data)
            st.dataframe(
                df.style.background_gradient(
                    subset=["CVSS Score", "Risk Score"],
                    cmap="YlOrRd",
                ),
                use_container_width=True,
                height=400,
            )
        else:
            st.info("No high-risk nodes detected.")


def render_executive_summary(metrics: Dict, paths: List[Dict]):
    """Bottom executive summary section."""
    st.markdown("---")
    # Section header with tiny logo
    st.markdown(
        """
        <div style='display:flex; align-items:center; gap:10px; margin-bottom:12px;'>
          <img src="app/static/favicon.png" style="width:24px;height:24px;border-radius:6px;opacity:0.9;" alt="MP"/>
          <span style='color:#8aafd4; font-weight:500; font-size:0.95rem; letter-spacing:0.01em;'>Executive Summary</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("""<div class='cyber-card'>
            <h3 style='color:#F5A623; margin-top:0'>Risk Posture</h3>""",
            unsafe_allow_html=True)
        st.markdown(
            f"Network risk tier: **{metrics.get('network_risk_tier','N/A')}**  \n"
            f"Max path score: **{metrics.get('max_path_risk',0):.1f}/10**  \n"
            f"Avg CVSS: **{metrics.get('avg_cvss',0):.1f}**  \n"
            f"Internet-exposed assets: **{metrics.get('internet_exposed',0)}**"
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        st.markdown("""<div class='cyber-card'>
            <h3 style='color:#FF8C00; margin-top:0'>Vulnerability Stats</h3>""",
            unsafe_allow_html=True)
        st.markdown(
            f"Critical (CVSS ≥ 9.0): **{metrics.get('critical_vuln_count',0)}**  \n"
            f"High (CVSS ≥ 7.0): **{metrics.get('high_vuln_count',0)}**  \n"
            f"Unpatched assets: **{metrics.get('unpatched_assets',0)}**  \n"
            f"Attack paths found: **{metrics.get('attack_paths_found',0)}**"
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with col3:
        st.markdown("""<div class='cyber-card'>
            <h3 style='color:#22C55E; margin-top:0'>Recommended Actions</h3>""",
            unsafe_allow_html=True)
        crit = metrics.get("critical_vuln_count", 0)
        exposed = metrics.get("internet_exposed", 0)
        unpatched = metrics.get("unpatched_assets", 0)
        actions = []
        if crit > 0:    actions.append(f"🔴 Patch {crit} critical-severity assets immediately")
        if exposed > 3: actions.append(f"🟠 Reduce internet attack surface ({exposed} exposed)")
        if unpatched > 0: actions.append(f"🟡 Apply patches to {unpatched} unpatched assets")
        if not actions:   actions.append("✅ Network risk posture is acceptable")
        for a in actions:
            st.markdown(f"- {a}")
        st.markdown("</div>", unsafe_allow_html=True)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    _init_state()
    top_k = render_sidebar()
    render_hero()

    # Auto-run on first load
    if st.session_state.graph is None:
        with st.spinner("Initializing analysis engine..."):
            _run_analysis(
                st.session_state.node_count,
                st.session_state.seed,
                st.session_state.is_attack,
            )

    # Re-apply top_k if changed
    if st.session_state.graph is not None and len(st.session_state.paths) != top_k:
        paths = find_critical_attack_paths(st.session_state.graph, top_k=top_k)
        st.session_state.paths = paths
        st.session_state.metrics = compute_network_risk_metrics(st.session_state.graph, paths)
        st.session_state.threat_matrix = build_threat_matrix(paths)

    G = st.session_state.graph
    paths = st.session_state.paths
    metrics = st.session_state.metrics
    threat_matrix = st.session_state.threat_matrix

    if G is not None:
        render_kpi_strip(metrics)
        st.markdown("<div style='height:12px'/>", unsafe_allow_html=True)
        render_main_analysis(G, paths, metrics, threat_matrix)
        render_executive_summary(metrics, paths)
    else:
        st.info("Click **Run Analysis** in the sidebar to begin.")


if __name__ == "__main__":
    main()