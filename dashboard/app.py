import base64
import random
import sys
import time
from pathlib import Path
from typing import Dict, List

import networkx as nx
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import (
    MITRE_TECHNIQUES,
    RISK_COLORS,
    TACTIC_ORDER,
    get_risk_tier,
)
from data.generate_synthetic_data import build_enterprise_graph
from graph.find_attack_path import (
    find_critical_attack_paths,
    compute_network_risk_metrics,
    build_threat_matrix,
    score_node_criticality,
)

BASE_DIR = Path(__file__).parent
ASSETS_DIR = BASE_DIR / "assets"
FAVICON = ASSETS_DIR / "favicon.png"

st.set_page_config(
    page_title="CyberGraph | Attack Path Intelligence",
    page_icon=str(FAVICON) if FAVICON.exists() else None,
    layout="wide",
    initial_sidebar_state="expanded",
)

def get_base64_image(image_path: Path) -> str:
    if not image_path.exists():
        return ""
    return base64.b64encode(image_path.read_bytes()).decode()


st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Space Grotesk', sans-serif;
    background-color: #060d1a;
    color: #e2e8f4;
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0a1628 0%, #060d1a 100%);
    border-right: 1px solid rgba(245, 166, 35, 0.15);
}

[data-testid="stSidebar"] * {
    color: #b8c5d6 !important;
}

[data-testid="stSidebar"] .stSelectbox label,
[data-testid="stSidebar"] .stSlider label {
    color: #7aa3cc !important;
}

[data-testid="stMain"] {
    background: #060d1a;
}

header[data-testid="stHeader"] {
    background: transparent;
}

div[data-testid="stToolbar"] {
    visibility: hidden;
    height: 0;
}

.main .block-container {
    width: 100%;
    max-width: none;
    padding-top: 1.35rem;
    padding-right: 1.5rem;
    padding-bottom: 2rem;
    padding-left: 1.5rem;
}

/* Fix: prevent any column from overflowing */
[data-testid="stHorizontalBlock"] {
    overflow: hidden !important;
    gap: 1rem !important;
}

[data-testid="stColumn"] {
    overflow: hidden !important;
    min-width: 0 !important;
}

/* Fix: plotly charts must not overflow their column */
.js-plotly-plot, .plotly, .plot-container {
    max-width: 100% !important;
    overflow: hidden !important;
}

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

[data-testid="stMetricLabel"] {
    color: #7aa3cc !important;
    font-size: 0.78rem !important;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}

[data-testid="stMetricValue"] {
    color: #e8f4ff !important;
    font-size: 2.1rem !important;
    font-weight: 600;
}

[data-testid="stMetricDelta"] {
    font-size: 0.78rem !important;
}

h1 { color: #1ec8ff !important; font-weight: 700 !important; letter-spacing: -0.02em; }
h2 { color: #c5d8f0 !important; font-weight: 600 !important; font-size: 1.15rem !important; }
h3 { color: #8aafd4 !important; font-weight: 500 !important; font-size: 0.95rem !important; }
hr { border-color: rgba(245, 166, 35, 0.12) !important; }

.js-plotly-plot { border-radius: 12px; overflow: hidden; }

[data-testid="stDataFrame"] {
    border: 1px solid rgba(30, 200, 255, 0.12);
    border-radius: 10px;
}

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

.stAlert { border-radius: 10px !important; }

.stExpander {
    border: 1px solid rgba(30, 200, 255, 0.12) !important;
    border-radius: 10px !important;
    background: rgba(10, 25, 55, 0.6) !important;
}

.stTabs [data-baseweb="tab-list"] {
    background: rgba(10, 22, 45, 0.8);
    border-radius: 10px;
    padding: 4px;
}

.stTabs [data-baseweb="tab"] { color: #7aa3cc !important; border-radius: 8px; }
.stTabs [aria-selected="true"] { background: rgba(245, 166, 35, 0.12) !important; color: #F5A623 !important; }

.stSelectbox>div>div {
    background: rgba(10, 25, 55, 0.85) !important;
    border-color: rgba(30, 200, 255, 0.2) !important;
    color: #e2e8f4 !important;
}

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

.badge-critical { background:#2d0a0a; border:1px solid #FF3B3B; color:#FF3B3B; padding:3px 10px; border-radius:6px; font-size:0.78rem; font-weight:600; font-family:'JetBrains Mono',monospace; }
.badge-high     { background:#2d1a00; border:1px solid #FF8C00; color:#FF8C00; padding:3px 10px; border-radius:6px; font-size:0.78rem; font-weight:600; font-family:'JetBrains Mono',monospace; }
.badge-medium   { background:#2d2700; border:1px solid #FFD700; color:#FFD700; padding:3px 10px; border-radius:6px; font-size:0.78rem; font-weight:600; font-family:'JetBrains Mono',monospace; }
.badge-low      { background:#0a2d10; border:1px solid #22C55E; color:#22C55E; padding:3px 10px; border-radius:6px; font-size:0.78rem; font-weight:600; font-family:'JetBrains Mono',monospace; }

::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #060d1a; }
::-webkit-scrollbar-thumb { background: rgba(245, 166, 35, 0.2); border-radius: 4px; }
</style>
""",
    unsafe_allow_html=True,
)

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(6,13,26,0)",
    plot_bgcolor="rgba(10,22,45,0.6)",
    font=dict(family="Space Grotesk, sans-serif", color="#b8c5d6", size=12),
    margin=dict(l=16, r=16, t=36, b=16),
    colorway=["#1ec8ff", "#F5A623", "#0f9acc", "#35d4a8", "#0675a2", "#ff6b6b"],
    xaxis=dict(
        gridcolor="rgba(30,200,255,0.07)",
        linecolor="rgba(30,200,255,0.15)",
        tickcolor="rgba(30,200,255,0.15)",
    ),
    yaxis=dict(
        gridcolor="rgba(30,200,255,0.07)",
        linecolor="rgba(30,200,255,0.15)",
        tickcolor="rgba(30,200,255,0.15)",
    ),
)


def apply_layout(fig: go.Figure, **kwargs) -> go.Figure:
    fig.update_layout(**{**PLOTLY_LAYOUT, **kwargs})
    return fig


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
        "top_k": 5,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def _run_analysis(node_count: int, seed: int, is_attack: bool, top_k: int):
    rng = random.Random(seed)
    G, _ = build_enterprise_graph(
        n_nodes=node_count,
        is_attack=is_attack,
        rng=rng,
        ba_edges=3,
    )
    paths = find_critical_attack_paths(G, top_k=top_k)
    metrics = compute_network_risk_metrics(G, paths)
    threat_matrix = build_threat_matrix(paths)

    st.session_state.graph = G
    st.session_state.paths = paths
    st.session_state.metrics = metrics
    st.session_state.threat_matrix = threat_matrix
    st.session_state.last_scan_time = time.strftime("%H:%M:%S")
    st.session_state.scan_count += 1


def build_attack_graph_figure(G: nx.DiGraph, paths: List[Dict]) -> go.Figure:
    pos = nx.spring_layout(G, seed=7, k=1.8 / max(1, G.number_of_nodes() ** 0.5))
    seg_colors = {
        "internet": "#FF3B3B",
        "dmz": "#FF8C00",
        "internal": "#1ec8ff",
        "restricted": "#FFD700",
    }

    path_nodes = {n for p in paths for n in p.get("nodes", [])}
    edge_traces = []

    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        on_path = u in path_nodes and v in path_nodes
        edge_traces.append(
            go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode="lines",
                line=dict(
                    width=2.5 if on_path else 0.8,
                    color="rgba(245,166,35,0.55)" if on_path else "rgba(30,200,255,0.15)",
                ),
                hoverinfo="none",
            )
        )

    node_x, node_y, node_colors, node_sizes, hover_texts = [], [], [], [], []
    for n in G.nodes():
        x, y = pos[n]
        node_x.append(x)
        node_y.append(y)
        ndata = G.nodes[n]
        segment = ndata.get("segment", "internal")
        color = seg_colors.get(segment, "#1ec8ff")
        size = 16 if n in path_nodes else 9
        if n in path_nodes:
            color = seg_colors.get(segment, "#FF3B3B")
        node_colors.append(color)
        node_sizes.append(size)
        hover_texts.append(
            f"<b>{ndata.get('node_type', 'UNKNOWN')}</b><br>"
            f"Segment: {segment.upper()}<br>"
            f"CVSS: {ndata.get('cvss_score', 5.0):.1f}<br>"
            f"Criticality: {ndata.get('asset_criticality', 0):.0%}"
            f"{'<br>⚠️ ON ATTACK PATH' if n in path_nodes else ''}"
        )

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers",
        hoverinfo="text",
        hovertext=hover_texts,
        marker=dict(
            size=node_sizes,
            color=node_colors,
            line=dict(width=1.5, color="rgba(245,166,35,0.3)"),
        ),
    )

    fig = go.Figure(data=[*edge_traces, node_trace])
    apply_layout(
        fig,
        title=dict(text="Network Attack Graph", font=dict(size=14, color="#7aa3cc")),
        showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        hovermode="closest",
        height=460,
    )
    return fig


def build_cvss_histogram(G: nx.DiGraph) -> go.Figure:
    cvss_scores = [G.nodes[n].get("cvss_score", 0) for n in G.nodes()]
    fig = go.Figure(
        go.Histogram(
            x=cvss_scores,
            nbinsx=20,
            marker=dict(color="#1ec8ff", line=dict(width=0.5, color="rgba(0,0,0,0.3)")),
        )
    )
    apply_layout(
        fig,
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
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=risk_score,
            domain={"x": [0, 1], "y": [0, 1]},
            number={"font": {"size": 36, "color": color, "family": "Space Grotesk"}},
            title={"text": "Network Risk Score", "font": {"size": 12, "color": "#7aa3cc"}},
            gauge={
                "axis": {"range": [0, 10], "tickwidth": 1, "tickcolor": "#334155", "nticks": 6},
                "bar": {"color": color, "thickness": 0.25},
                "bgcolor": "rgba(10,22,45,0.6)",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 4],  "color": "rgba(34,197,94,0.15)"},
                    {"range": [4, 7],  "color": "rgba(255,215,0,0.12)"},
                    {"range": [7, 9],  "color": "rgba(255,140,0,0.12)"},
                    {"range": [9, 10], "color": "rgba(255,59,59,0.15)"},
                ],
                "threshold": {
                    "line": {"color": color, "width": 3},
                    "thickness": 0.8,
                    "value": risk_score,
                },
            },
        )
    )
    apply_layout(fig, height=210, margin=dict(l=16, r=16, t=44, b=8))
    return fig


def build_attack_path_sankey(paths: List[Dict], G: nx.DiGraph) -> go.Figure:
    if not paths:
        return go.Figure()

    segments = ["INTERNET", "DMZ", "INTERNAL", "RESTRICTED"]
    seg_to_idx = {s.lower(): i for i, s in enumerate(segments)}
    flows = {}

    for path in paths:
        nodes = path.get("nodes", [])
        for i in range(len(nodes) - 1):
            u, v = nodes[i], nodes[i + 1]
            src_i = seg_to_idx.get(G.nodes[u].get("segment", "internal"), 2)
            dst_i = seg_to_idx.get(G.nodes[v].get("segment", "internal"), 2)
            if src_i != dst_i:
                flows[(src_i, dst_i)] = flows.get((src_i, dst_i), 0) + path.get("risk_score", 0)

    if not flows:
        return go.Figure()

    fig = go.Figure(
        go.Sankey(
            node=dict(
                pad=20,
                thickness=24,
                label=segments,
                color=["#FF3B3B", "#FF8C00", "#1ec8ff", "#FFD700"],
                line=dict(color="rgba(0,0,0,0.3)", width=0.5),
            ),
            link=dict(
                source=[k[0] for k in flows],
                target=[k[1] for k in flows],
                value=list(flows.values()),
                color=["rgba(245,166,35,0.35)"] * len(flows),
            ),
        )
    )
    apply_layout(
        fig,
        title=dict(text="Attack Flow - Segment Traversal", font=dict(size=13, color="#7aa3cc")),
        height=300,
    )
    return fig


def build_mitre_heatmap(threat_matrix: Dict) -> go.Figure:
    tactics = [t for t in TACTIC_ORDER if t in threat_matrix]
    if not tactics:
        return go.Figure()

    all_techs = sorted({t for tac in tactics for t in threat_matrix.get(tac, {})})
    if not all_techs:
        return go.Figure()

    z = [[threat_matrix.get(tac, {}).get(t, 0) for t in all_techs] for tac in tactics]
    tech_labels = [
        f"{t}<br><sub>{MITRE_TECHNIQUES.get(t, {}).get('name', '')[:20]}</sub>"
        for t in all_techs
    ]

    fig = go.Figure(
        go.Heatmap(
            z=z,
            x=tech_labels,
            y=[t[:18] for t in tactics],
            colorscale=[
                [0, "rgba(10,22,45,0.9)"],
                [0.5, "rgba(245,166,35,0.4)"],
                [1, "#F5A623"],
            ],
            showscale=False,
            hoverongaps=False,
            hovertemplate="Tactic: %{y}<br>Technique: %{x}<br>Occurrences: %{z}<extra></extra>",
        )
    )
    apply_layout(
        fig,
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

    seg_colors_map = {
        "internet": "#FF3B3B",
        "dmz": "#FF8C00",
        "internal": "#1ec8ff",
        "restricted": "#FFD700",
    }
    labels = [s.upper() for s in seg_counts]
    values = list(seg_counts.values())
    colors = [seg_colors_map.get(s, "#64748B") for s in seg_counts]

    fig = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            marker=dict(colors=colors, line=dict(color="rgba(0,0,0,0.3)", width=1.5)),
            hole=0.55,
            textfont=dict(size=10, family="Space Grotesk"),
            hovertemplate="<b>%{label}</b><br>Assets: %{value}<br>%{percent}<extra></extra>",
        )
    )
    apply_layout(
        fig,
        title=dict(text="Assets by Network Segment", font=dict(size=13, color="#7aa3cc")),
        showlegend=True,
        legend=dict(font=dict(size=9), bgcolor="rgba(0,0,0,0)", x=0.75, y=0.5),
        height=240,
        margin=dict(l=8, r=8, t=36, b=8),
    )
    return fig


def build_top_paths_table(paths: List[Dict]) -> go.Figure:
    if not paths:
        return go.Figure()

    rows = []
    for p in paths:
        rows.append(
            {
                "ID": f"#{p['path_id']}",
                "Risk Score": f"{p.get('risk_score', 0):.1f}",
                "Tier": p.get("risk_tier", "LOW"),
                "Hops": len(p.get("nodes", [])),
                "Techniques": ", ".join(p.get("techniques", [])[:2]) or "N/A",
                "Primary Tactic": p.get("tactics", ["N/A"])[0] if p.get("tactics") else "N/A",
                "Blast Radius": p.get("blast_radius", 0),
            }
        )

    fig = go.Figure(
        go.Table(
            header=dict(
                values=["<b>ID</b>","<b>Score</b>","<b>Tier</b>","<b>Hops</b>",
                        "<b>Techniques</b>","<b>Primary Tactic</b>","<b>Blast Radius</b>"],
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
                fill_color=[["rgba(10,22,45,0.7)"] * len(rows)] * 7,
                align="left",
                font=dict(color="#b8c5d6", size=11, family="Space Grotesk"),
                line_color="rgba(245,166,35,0.07)",
                height=30,
            ),
        )
    )
    apply_layout(fig, height=min(420, 100 + len(rows) * 35))
    return fig


def render_sidebar():
    with st.sidebar:
        st.markdown(
            f"""
            <div style="display:flex; align-items:center; gap:12px; padding:6px 0 4px 0;">
                <img src="data:image/png;base64,{get_base64_image(FAVICON)}" style="width:42px; height:42px; object-fit:contain; flex-shrink:0;" />
                <div style="line-height:1.15;">
                    <div style="color:#F5A623; font-weight:700; font-size:1.05rem; letter-spacing:0.01em;">CyberGraph</div>
                    <div style="color:#4a6f9a; font-size:0.72rem; letter-spacing:0.03em;">Attack Path Intelligence</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.divider()
        st.markdown("### Scan Configuration")
        node_count = st.slider("Network Assets", 15, 120, st.session_state.node_count, 5)
        seed = st.number_input("Scenario Seed", 0, 9999, st.session_state.seed, 1)
        scenario = st.selectbox(
            "Scenario Type",
            ["Attack Scenario", "Benign Network"],
            index=0 if st.session_state.is_attack else 1,
        )
        is_attack = scenario == "Attack Scenario"

        st.markdown("### Analysis Mode")
        analysis_mode = st.selectbox("Mode", ["Full Analysis", "Quick Scan", "Deep Dive"], index=0)
        top_k = st.slider("Max Attack Paths", 1, 10, st.session_state.top_k)

        st.divider()
        run = st.button("Run Analysis", use_container_width=True)

        if run:
            st.session_state.node_count = node_count
            st.session_state.seed = seed
            st.session_state.is_attack = is_attack
            st.session_state.top_k = top_k
            with st.spinner("Analyzing network topology..."):
                _run_analysis(node_count, seed, is_attack, top_k)

        st.divider()
        st.markdown("### Legend")
        legend_items = [
            ("🔴", "Internet / Entry Point", "#FF3B3B"),
            ("🟠", "DMZ / Perimeter", "#FF8C00"),
            ("🔵", "Internal Network", "#1ec8ff"),
            ("🟡", "Restricted / Critical", "#FFD700"),
        ]
        for icon, label, color in legend_items:
            st.markdown(
                f"<span style='color:{color}; font-size:0.8rem;'>{icon} {label}</span>",
                unsafe_allow_html=True,
            )

        st.divider()
        if st.session_state.last_scan_time:
            st.markdown(
                f"<p style='color:#4a6f9a; font-size:0.72rem;'>Last scan: {st.session_state.last_scan_time} | Total scans: {st.session_state.scan_count}</p>",
                unsafe_allow_html=True,
            )

        st.markdown(
            f"""
            <div style="display:flex; align-items:center; gap:8px; margin-top:6px;">
                <img src="data:image/png;base64,{get_base64_image(FAVICON)}" style="width:22px; height:22px; object-fit:contain; flex-shrink:0;" />
                <div style="color:#2e4a6a; font-size:0.70rem; letter-spacing:0.04em;">
                    by Manan Pal · GNN Security Research
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    return top_k


def render_hero():
    logo_b64 = get_base64_image(FAVICON)
    logo_html = (
        f'<img src="data:image/png;base64,{logo_b64}" style="width:46px;height:46px;object-fit:contain;flex-shrink:0;" />'
        if logo_b64 else ""
    )

    badge_html = ""
    if st.session_state.graph is not None:
        m = st.session_state.metrics
        tier = m.get("network_risk_tier", "LOW")
        color = RISK_COLORS.get(tier, "#64748B")
        badge_html = (
            f"<span style='color:{color};font-weight:700;font-size:0.85rem;"
            f"border:1px solid {color};padding:4px 14px;border-radius:6px;"
            f"background:rgba(255,255,255,0.03);white-space:nowrap;'>&#9679; {tier} RISK</span>"
        )

    st.markdown(
        f"""
        <div style="display:flex;align-items:center;gap:14px;padding:10px 0 8px 0;width:100%;">
            {logo_html}
            <div style="min-width:0;flex:1;">
                <div style="font-size:1.65rem;font-weight:700;letter-spacing:-0.02em;color:#1ec8ff;line-height:1.15;">
                    CyberGraph &mdash; <span style="color:#F5A623;">Attack Path</span> Intelligence Platform
                </div>
                <div style="color:#4a6f9a;font-size:0.83rem;margin-top:4px;">
                    Graph Neural Network &middot; MITRE ATT&amp;CK &middot; CVSS v3.1 &middot; Real-Time Risk Scoring
                </div>
            </div>
            {badge_html}
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("---")


def render_kpi_strip(metrics: Dict):
    cols = st.columns(6)
    kpis = [
        ("Total Assets",     metrics.get("total_assets", 0)),
        ("Critical Vulns",   metrics.get("critical_vuln_count", 0)),
        ("Internet Exposed", metrics.get("internet_exposed", 0)),
        ("Attack Paths",     metrics.get("attack_paths_found", 0)),
        ("Avg CVSS",         f"{metrics.get('avg_cvss', 0):.1f}"),
        ("MITRE Techniques", metrics.get("unique_techniques", 0)),
    ]
    for col, (label, value) in zip(cols, kpis):
        col.metric(label, value)


def render_main_analysis(G: nx.DiGraph, paths: List[Dict], metrics: Dict, threat_matrix: Dict):
    tab_overview, tab_paths, tab_mitre, tab_details = st.tabs(
        ["Overview", "Attack Paths", "MITRE ATT&CK", "Node Details"]
    )

    with tab_overview:
        # KEY FIX: changed [3,2] → [3,1.6] so right column has enough room
        col_graph, col_right = st.columns([3, 1.6], gap="medium")
        with col_graph:
            st.plotly_chart(build_attack_graph_figure(G, paths), use_container_width=True)
        with col_right:
            st.plotly_chart(build_risk_gauge(metrics.get("max_path_risk", 0)), use_container_width=True)
            st.plotly_chart(build_segment_pie(G), use_container_width=True)

        col_h, col_cvss = st.columns(2, gap="medium")
        with col_h:
            st.plotly_chart(build_attack_path_sankey(paths, G), use_container_width=True)
        with col_cvss:
            st.plotly_chart(build_cvss_histogram(G), use_container_width=True)

    with tab_paths:
        if not paths:
            st.info("No attack paths detected in this network configuration.")
        else:
            st.markdown(
                f"<div class='cyber-card'><b style='color:#F5A623'>Detected {len(paths)} exploitable attack path(s)</b> using risk-weighted graph traversal.</div>",
                unsafe_allow_html=True,
            )
            st.plotly_chart(build_top_paths_table(paths), use_container_width=True)

            st.markdown("### Path Details")
            for path in paths:
                tier = path.get("risk_tier", "LOW")
                score = path.get("risk_score", 0)
                with st.expander(
                    f"Path #{path['path_id']} · {tier} · Score: {score:.1f}/10 · "
                    f"{len(path.get('nodes', []))} hops · Blast radius: {path.get('blast_radius', 0)}",
                    expanded=(path.get("path_id") == 1),
                ):
                    for step in path.get("steps", []):
                        st.markdown(
                            f"<span style='color:#7aa3cc; font-family:JetBrains Mono; font-size:0.82rem;'>"
                            f"[{step.get('segment','').upper()}] {step.get('node_type','')}"
                            f"</span> <span style='color:#334155;'>CVSS:{step.get('cvss_score',0):.1f}</span>",
                            unsafe_allow_html=True,
                        )
                        if step.get("technique_id"):
                            st.markdown(
                                f"<span style='color:#4a6f9a; font-size:0.75rem; padding-left:20px;'>"
                                f"↳ {step.get('tactic','')} · {step.get('technique_id','')} "
                                f"{MITRE_TECHNIQUES.get(step.get('technique_id',''), {}).get('name', '')}"
                                f"</span>",
                                unsafe_allow_html=True,
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
                st.markdown(
                    f"**{len(all_techs)} techniques** detected across **{len([t for t in threat_matrix if threat_matrix[t]])} tactics**"
                )
                for tech_id in sorted(all_techs):
                    info = MITRE_TECHNIQUES.get(tech_id, {})
                    st.markdown(
                        f"<div style='margin:3px 0; font-size:0.78rem;'>"
                        f"<code style='color:#F5A623'>{tech_id}</code> "
                        f"<span style='color:#7aa3cc'>{info.get('name','')[:28]}</span></div>",
                        unsafe_allow_html=True,
                    )

    with tab_details:
        st.markdown("### High-Risk Node Inventory")
        import pandas as pd

        node_data = []
        for n in G.nodes():
            cvss = G.nodes[n].get("cvss_score", 0)
            if cvss >= 6.0:
                node_data.append(
                    {
                        "Node ID": n,
                        "Type": G.nodes[n].get("node_type", "UNKNOWN"),
                        "Segment": G.nodes[n].get("segment", "").upper(),
                        "CVSS Score": round(cvss, 1),
                        "Criticality": f"{G.nodes[n].get('asset_criticality', 0):.0%}",
                        "Risk Score": round(score_node_criticality(G, n), 1),
                        "Tier": get_risk_tier(cvss),
                    }
                )
        node_data.sort(key=lambda x: x["CVSS Score"], reverse=True)

        if node_data:
            df = pd.DataFrame(node_data)
            st.dataframe(df, use_container_width=True, height=400)
        else:
            st.info("No high-risk nodes detected.")


def render_executive_summary(metrics: Dict, paths: List[Dict]):
    st.markdown("---")
    col_es_logo, col_es_title = st.columns([1, 16])
    with col_es_logo:
        if FAVICON.exists():
            st.image(str(FAVICON), width=24)
    with col_es_title:
        st.markdown(
            "<span style='color:#8aafd4; font-weight:500; font-size:0.95rem; display:block; padding-top:3px;'>Executive Summary</span>",
            unsafe_allow_html=True,
        )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("<div class='cyber-card'><h3 style='color:#F5A623; margin-top:0'>Risk Posture</h3>", unsafe_allow_html=True)
        st.markdown(
            f"Network risk tier: **{metrics.get('network_risk_tier', 'N/A')}**  \n"
            f"Max path score: **{metrics.get('max_path_risk', 0):.1f}/10**  \n"
            f"Avg CVSS: **{metrics.get('avg_cvss', 0):.1f}**  \n"
            f"Internet-exposed assets: **{metrics.get('internet_exposed', 0)}**"
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        st.markdown("<div class='cyber-card'><h3 style='color:#FF8C00; margin-top:0'>Vulnerability Stats</h3>", unsafe_allow_html=True)
        st.markdown(
            f"Critical (CVSS ≥ 9.0): **{metrics.get('critical_vuln_count', 0)}**  \n"
            f"High (CVSS ≥ 7.0): **{metrics.get('high_vuln_count', 0)}**  \n"
            f"Unpatched assets: **{metrics.get('unpatched_assets', 0)}**  \n"
            f"Attack paths found: **{metrics.get('attack_paths_found', 0)}**"
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with col3:
        st.markdown("<div class='cyber-card'><h3 style='color:#22C55E; margin-top:0'>Recommended Actions</h3>", unsafe_allow_html=True)
        actions = []
        crit    = metrics.get("critical_vuln_count", 0)
        exposed = metrics.get("internet_exposed", 0)
        unpatched = metrics.get("unpatched_assets", 0)

        if crit > 0:      actions.append(f"Patch {crit} critical-severity assets immediately")
        if exposed > 3:   actions.append(f"Reduce internet attack surface ({exposed} exposed)")
        if unpatched > 0: actions.append(f"Apply patches to {unpatched} unpatched assets")
        if not actions:   actions.append("Network risk posture is acceptable")

        for a in actions:
            st.markdown(f"- {a}")
        st.markdown("</div>", unsafe_allow_html=True)


def main():
    _init_state()
    top_k = render_sidebar()
    render_hero()

    if st.session_state.graph is None:
        with st.spinner("Initializing analysis engine..."):
            _run_analysis(
                st.session_state.node_count,
                st.session_state.seed,
                st.session_state.is_attack,
                top_k,
            )
    elif st.session_state.top_k != top_k:
        st.session_state.top_k = top_k
        st.session_state.paths = find_critical_attack_paths(st.session_state.graph, top_k=top_k)
        st.session_state.metrics = compute_network_risk_metrics(st.session_state.graph, st.session_state.paths)
        st.session_state.threat_matrix = build_threat_matrix(st.session_state.paths)

    G = st.session_state.graph
    if G is not None:
        render_kpi_strip(st.session_state.metrics)
        st.markdown("<div style='height:12px'/>", unsafe_allow_html=True)
        render_main_analysis(G, st.session_state.paths, st.session_state.metrics, st.session_state.threat_matrix)
        render_executive_summary(st.session_state.metrics, st.session_state.paths)
    else:
        st.info("Click Run Analysis in the sidebar to begin.")


if __name__ == "__main__":
    main()