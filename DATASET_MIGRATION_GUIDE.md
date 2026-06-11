# Dataset Migration Guide
## cybersecurity-attack-path-prediction-using-gnn

---

## Current Dataset Assessment

| Property | Current State | Impact |
|---|---|---|
| Type | Synthetic (Barabási–Albert graphs) | Good topology realism |
| Features | 16-dim CVSS-inspired vectors | Realistic feature space |
| Labels | Binary attack/benign per graph | Adequate for classification |
| Size | 500 graphs, 20–80 nodes each | Small but trainable |
| ATT&CK | Technique IDs on edges | ✅ Domain-authentic |
| CVE data | Simulated (parameterized by NVD statistics) | Lacks specific CVE IDs |

**Verdict:** The synthetic generator is *well-designed* — it reproduces realistic CVSS score distributions, realistic network topologies, and MITRE ATT&CK technique annotations. It can be trained and deployed on any laptop with no internet access or licensing concerns.

**The main limitation:** No specific CVE IDs are linked to nodes, so the tool cannot say "Node 7 is vulnerable to CVE-2024-1234 (Log4Shell)". This is a presentation gap more than a technical one.

---

## Recommended Dataset Upgrades

### Option 1: NVD CVE Feeds — STRONGLY RECOMMENDED ✅

**What it is:** NIST National Vulnerability Database — the authoritative source for all public CVEs.  
**Download:** https://nvd.nist.gov/vuln/data-feeds (JSON format)  
**Size:** ~280MB (recent 2 years) or ~2GB (full history since 1999)  
**License:** Public domain, no restrictions  
**Training impact:** No change to GNN training — enriches node feature labels and display only

**What it adds:**
- Real CVE IDs (e.g., CVE-2024-1234) with official CVSS v3.1 scores
- CWE (Common Weakness Enumeration) mappings
- Affected product/version data
- Patch publication dates (enables realistic `days_unpatched`)

**Integration effort:** 3–5 hours

```python
# integration/nvd_enricher.py (add this file)
import json, requests
from pathlib import Path

NVD_FEED_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_recent_cves(days: int = 30) -> list:
    """Fetch CVEs published in the last N days via NVD API 2.0."""
    from datetime import datetime, timedelta, timezone
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   end.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }
    r = requests.get(NVD_FEED_URL, params=params, timeout=30)
    r.raise_for_status()
    return r.json().get("vulnerabilities", [])

def extract_cvss_score(cve_item: dict) -> float:
    """Extract CVSS v3.1 base score from NVD CVE item."""
    metrics = cve_item.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            return metrics[key][0]["cvssData"].get("baseScore", 5.0)
    return 5.0  # default if no score available

def build_cve_lookup(cves: list) -> dict:
    """Build CVE-ID → {score, description, cwe} lookup dict."""
    lookup = {}
    for item in cves:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        lookup[cve_id] = {
            "cvss": extract_cvss_score(item),
            "description": (cve_data.get("descriptions", [{}])[0].get("value", ""))[:200],
            "cwe": (cve_data.get("weaknesses", [{}])[0]
                    .get("description", [{}])[0].get("value", "CWE-Unknown")),
        }
    return lookup
```

**How to use in dashboard:**
```python
# When showing a node's details, display its CVE assignments
node_cves = cve_lookup.get(node_data.get("cve_id"), {})
st.metric("CVE", node_data.get("cve_id", "None"))
st.metric("CVSS Score", node_cves.get("cvss", "N/A"))
```

---

### Option 2: MITRE ATT&CK STIX Bundle — STRONGLY RECOMMENDED ✅

**What it is:** Complete MITRE ATT&CK knowledge base in machine-readable STIX 2.1 format.  
**Download:** https://github.com/mitre/cti (Enterprise ATT&CK JSON)  
**Size:** ~50MB  
**License:** Apache 2.0  
**Training impact:** None — adds metadata only

**What it adds:**
- Full technique descriptions
- Detection recommendations per technique
- Mitigation mappings
- Procedure examples (real threat actor TTPs)
- Sub-technique hierarchy

```bash
git clone https://github.com/mitre/cti.git --depth 1 --filter=blob:limit=1m
python -c "
import json
# Load enterprise ATT&CK
with open('cti/enterprise-attack/enterprise-attack.json') as f:
    stix = json.load(f)
techniques = {
    obj['external_references'][0]['external_id']: {
        'name': obj['name'],
        'tactic': [p['phase_name'] for p in obj.get('kill_chain_phases', [])],
        'description': obj.get('description', '')[:200],
        'detection': obj.get('x_mitre_detection', '')[:200],
    }
    for obj in stix['objects']
    if obj['type'] == 'attack-pattern' and not obj.get('revoked')
    and obj.get('external_references')
}
print(f'Loaded {len(techniques)} ATT&CK techniques')
# Save compact lookup
with open('config/mitre_full.json', 'w') as f:
    json.dump(techniques, f)
"
```

---

### Option 3: UNSW-NB15 — OPTIONAL ⚠️

**What it is:** Network intrusion detection dataset, 2.5M records.  
**Download:** https://research.unsw.edu.au/projects/unsw-nb15-dataset  
**Size:** ~600MB CSV  
**License:** Free for research  
**Training impact:** Significant — replaces synthetic graphs with real network flow graphs

**Feasibility Analysis:**

| Factor | Assessment |
|---|---|
| Storage | ✅ 600MB is fine |
| Memory | ✅ 16GB RAM sufficient (process in chunks) |
| Training time | ⚠️ 2–4 hours on GPU, 8–16 hours CPU |
| Preprocessing | ❌ Complex: aggregate flows → graph → PyG Data |
| Value for this project | MEDIUM — adds real network traffic patterns |

**Migration steps (if desired):**
```python
# preprocessing/unsw_to_graph.py
import pandas as pd
import networkx as nx

def flows_to_graph(df: pd.DataFrame) -> nx.DiGraph:
    """
    Convert UNSW-NB15 rows to a network graph.
    Each unique (src_ip, dst_ip) pair becomes an edge.
    Node features: aggregated flow statistics.
    Edge label: attack category (DoS/Fuzzers/etc.)
    """
    G = nx.DiGraph()
    for (src, dst), group in df.groupby(['srcip', 'dstip']):
        # Node features from aggregated flows
        G.add_node(src, packet_count=len(group), avg_bytes=group['sbytes'].mean())
        G.add_node(dst, packet_count=len(group), avg_bytes=group['dbytes'].mean())
        # Edge label: is any flow an attack?
        is_attack = (group['Label'] == 1).any()
        G.add_edge(src, dst, is_attack=is_attack,
                   avg_duration=group['dur'].mean(),
                   proto=group['proto'].mode()[0])
    return G
```

**Verdict:** UNSW-NB15 is the best real-dataset upgrade for this project *if* you want to extend it with an IDS component. For the current attack path prediction focus, NVD + ATT&CK enrichment provides higher value per hour of work.

---

### Option 4: CICIDS2017 — NOT RECOMMENDED FOR THIS PROJECT ❌

**Size:** 6GB+  
**Issue:** Too large for casual deployment; preprocessing to graph format requires 20+ hours; the data models network intrusion detection (IDS), not attack path prediction. The project architectures are fundamentally different.

---

### Option 5: TON_IoT — OPTIONAL FOR FUTURE EXTENSION ⚠️

Best suited for adding an IoT/OT segment to the network graph. Consider if you extend the project with IoT device modeling.

---

## Recommended Migration Plan

### Phase 1 — Immediate (2–3 hours)
```bash
# 1. Add NVD API enricher
cp integration/nvd_enricher.py .  # (create the file above)

# 2. Enrich synthetic nodes with real CVE IDs
python -c "
from integration.nvd_enricher import fetch_recent_cves, build_cve_lookup
cves = fetch_recent_cves(days=90)
lookup = build_cve_lookup(cves)
print(f'Loaded {len(lookup)} CVEs from NVD')
# Save for dashboard use
import json
with open('config/cve_cache.json', 'w') as f:
    json.dump(lookup, f)
"
```

### Phase 2 — Weekend (4–6 hours)
```bash
# 1. Clone ATT&CK STIX
git clone https://github.com/mitre/cti --depth 1

# 2. Parse and save compact technique database
python integration/parse_attack_stix.py

# 3. Update config/settings.py to load from mitre_full.json
# 4. Update dashboard to show technique descriptions and detection tips
```

### Phase 3 — Optional (20+ hours)
```bash
# If you want to validate on real network data:
# 1. Download UNSW-NB15 from research.unsw.edu.au
# 2. Run preprocessing/unsw_to_graph.py
# 3. Train a separate model: python gnn/train_gnn.py --dataset unsw
# 4. Compare metrics: real vs synthetic
```

---

## Storage & Memory Budget

| Dataset | Raw Size | Processed | RAM Needed | GPU? |
|---|---|---|---|---|
| NVD (2yr) | 280MB | 15MB JSON | 512MB | No |
| ATT&CK STIX | 50MB | 2MB JSON | 128MB | No |
| UNSW-NB15 | 600MB | 200MB PyG | 8GB | Recommended |
| CICIDS2017 | 6GB | 2GB PyG | 32GB | Required |

**For a laptop/cloud developer machine (16GB RAM, no GPU):**  
NVD + ATT&CK = ✅ Runs easily  
UNSW-NB15 = ⚠️ Possible with patience  
CICIDS2017 = ❌ Not practical  
