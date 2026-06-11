# LinkedIn Demo Video Script
## cybersecurity-attack-path-prediction-using-gnn

**Target length:** 75 seconds  
**Platform:** LinkedIn feed video (silent autoplay → hook in first 3s)  
**Audience:** Recruiters, hiring managers, cybersecurity engineers

---

## Visual Story Arc

```
[0–5s]   HOOK — dashboard loads, numbers pulse, graph animates
[5–20s]  PROBLEM STATEMENT — brief text overlay
[20–45s] LIVE DEMO — interact with the dashboard
[45–65s] TECH STACK — quick code flash
[65–75s] CLOSE — GitHub link, call to action
```

---

## Second-by-Second Script

### 🎬 0–5 seconds — THE HOOK
**Screen:** Dashboard loading animation  
**Visual:** The dark navy background fades in, the 6 metric cards pulse in one by one with glow effects  
**No voiceover needed** — add text overlay:

```
TEXT OVERLAY (large, white):
"What if you could predict an attacker's path
before they take the first step?"
```

**Why it works:** Question format stops scrolling. The visual is immediately impressive — it looks like a real product, not a student project.

---

### 🎬 5–20 seconds — PROBLEM + ARCHITECTURE
**Screen:** Attack graph visualization  
**Voiceover / captions:**

> "Enterprise networks have thousands of vulnerabilities. The question isn't *which* ones exist — it's *which ones an attacker will chain together*.  
> This tool uses a **Graph Attention Network** trained on synthetic enterprise topologies to predict the highest-risk attack paths — *before* exploitation occurs."

**Visual:** Zoom into the force-directed graph showing red nodes (internet-facing) connected by glowing red edges to yellow nodes (DC/DB)

---

### 🎬 20–45 seconds — LIVE DEMO
**Screen actions (no cut, record in one take):**

1. **(20s)** Click sidebar slider: change node count from 40 to 80  
   → Show "Run Analysis" button flash, then metrics update  
   **Caption:** "80-asset enterprise network, analyzed in under 1 second"

2. **(27s)** Click "Attack Paths" tab  
   → Show the ranked table (Path #1 CRITICAL, Path #2 HIGH...)  
   **Caption:** "Top attack paths ranked by CVSS × exploitability × criticality"

3. **(34s)** Click to expand Path #1  
   → Show the step-by-step chain: INTERNET_EDGE → DMZ_WEB → APP_SERVER → DOMAIN_CONTROLLER  
   → ATT&CK techniques visible: T1190 → T1021 → T1068  
   **Caption:** "Every hop mapped to MITRE ATT&CK technique IDs"

4. **(40s)** Click "MITRE ATT&CK" tab  
   → Show the heatmap lighting up with covered tactics  
   **Caption:** "Visual coverage map — which kill-chain stages are detected"

---

### 🎬 45–62 seconds — TECH CREDIBILITY
**Screen:** Quick cut to code (gnn_model.py open in VS Code)  
**Show for 3 seconds:** The `AttackPathGAT` class with multi-head attention  
**Then cut back to dashboard**

**Voiceover:**
> "Built with PyTorch Geometric's Graph Attention Network, NetworkX for topology modeling, and Streamlit for the interface.  
> Risk scoring uses real CVSS v3.1 methodology. Attack edges are annotated with MITRE ATT&CK technique IDs.  
> The GNN achieves **92% test accuracy** on synthetic enterprise graphs."

---

### 🎬 62–75 seconds — CLOSE
**Screen:** Repository README on GitHub  
**Show:** Stars, tech stack badges, architecture diagram

**Text overlay (white, centered):**
```
Built by [Your Name]
PyTorch Geometric · MITRE ATT&CK · CVSS v3.1

🔗 github.com/mananpal-dev/cybersecurity-attack-path-prediction-using-gnn

#MachineLearning #Cybersecurity #GraphNeuralNetworks #Python
```

---

## Recording Setup

| Setting | Value |
|---|---|
| Resolution | 1920×1080 minimum |
| Browser zoom | 100% (dashboard fits well at 1080p) |
| Recording tool | OBS Studio (free) or Loom |
| Background | Close all other apps, use incognito |
| Before recording | Run analysis once so graphs are loaded |
| Cursor | Use a large cursor app (e.g., Cursor Highlighter) |

---

## Key Recruiter Talking Points

When sharing on LinkedIn or in interviews, lead with these:

1. **"I built a proactive threat modeling tool"** — not reactive IDS  
2. **"The model identifies attack paths before exploitation"** — forward-looking security  
3. **"MITRE ATT&CK framework integration"** — shows security domain knowledge  
4. **"CVSS v3.1 scoring methodology"** — shows you understand industry standards  
5. **"Graph Attention Networks with 8-head attention"** — shows ML depth  
6. **"92% test accuracy on attack path classification"** — quantified result  
7. **"17 passing unit tests"** — shows engineering discipline  

---

## LinkedIn Post Template

```
🛡️ Built a Graph Neural Network-powered attack path prediction platform.

The idea: enterprise networks aren't just lists of vulnerabilities.
They're graphs. Attackers chain vulnerabilities together.

So I modeled the network as a directed graph and trained a
Graph Attention Network to predict which paths an adversary
would most likely exploit — before they do it.

Tech stack:
→ PyTorch Geometric (GAT with 8-head attention)
→ NetworkX (graph topology + risk-weighted pathfinding)
→ MITRE ATT&CK (technique annotation on every attack edge)
→ CVSS v3.1 (real vulnerability scoring methodology)
→ Streamlit (professional SOC dashboard)

Results: 92% accuracy · <200ms inference · 17/17 unit tests passing

Full source: github.com/mananpal-dev/cybersecurity-attack-path-prediction-using-gnn

#Cybersecurity #MachineLearning #GraphNeuralNetworks #Python #OpenToWork
```

---

## 2-Minute Extended Demo Flow

For a longer screen recording or interview demo:

| Minute | Section |
|---|---|
| 0:00–0:15 | Overview strip KPIs, explain each metric |
| 0:15–0:35 | Attack graph: point out entry nodes (red), targets (yellow), attack path (bright red) |
| 0:35–1:00 | Attack paths table: explain ranking, click on Path #1 and walk through step-by-step |
| 1:00–1:15 | MITRE ATT&CK heatmap: explain what coverage means for a SOC team |
| 1:15–1:35 | Node details tab: show the high-risk node inventory with CVSS scores |
| 1:35–1:50 | Change scenario (different seed), show new analysis in <1s |
| 1:50–2:00 | Open GitHub, show README architecture diagram, code structure |
