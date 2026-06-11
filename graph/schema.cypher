// ─────────────────────────────────────────────────────────────────────────────
// schema.cypher
// Neo4j graph schema for Attack Path Prediction platform
//
// Node labels:   Asset, AttackPath, Vulnerability, Technique
// Relationship types: CONNECTS_TO, EXPLOITS, PART_OF, MAPS_TO
//
// Usage:
//   cat graph/schema.cypher | cypher-shell -u neo4j -p password
// ─────────────────────────────────────────────────────────────────────────────

// ── Constraints (uniqueness + indexed lookup) ─────────────────────────────────

CREATE CONSTRAINT asset_id_unique IF NOT EXISTS
  FOR (a:Asset) REQUIRE a.asset_id IS UNIQUE;

CREATE CONSTRAINT technique_id_unique IF NOT EXISTS
  FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE;

CREATE CONSTRAINT vuln_cve_unique IF NOT EXISTS
  FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE;

CREATE CONSTRAINT path_id_unique IF NOT EXISTS
  FOR (p:AttackPath) REQUIRE p.path_id IS UNIQUE;

// ── Indexes ───────────────────────────────────────────────────────────────────

CREATE INDEX asset_segment_idx IF NOT EXISTS FOR (a:Asset) ON (a.segment);
CREATE INDEX asset_cvss_idx    IF NOT EXISTS FOR (a:Asset) ON (a.cvss_score);
CREATE INDEX asset_type_idx    IF NOT EXISTS FOR (a:Asset) ON (a.node_type);
CREATE INDEX path_risk_idx     IF NOT EXISTS FOR (p:AttackPath) ON (p.risk_score);

// ── Asset node properties ─────────────────────────────────────────────────────
//
// (:Asset {
//   asset_id:          STRING   -- unique identifier (e.g. "host-001")
//   node_type:         STRING   -- INTERNET_EDGE | DMZ_WEB | ... | DOMAIN_CONTROLLER
//   segment:           STRING   -- internet | dmz | internal | restricted
//   hostname:          STRING   -- optional hostname
//   ip_address:        STRING   -- optional IP
//   os_type:           STRING   -- windows | linux | other
//   cvss_score:        FLOAT    -- CVSS v3.1 Base Score (0.0–10.0)
//   exploitability:    FLOAT    -- 0.0–1.0
//   asset_criticality: FLOAT    -- 0.0–1.0 (DC=1.0, workstation=0.3)
//   patch_available:   BOOLEAN
//   days_unpatched:    INTEGER
//   risk_score:        FLOAT    -- GNN-computed composite score
//   risk_tier:         STRING   -- CRITICAL | HIGH | MEDIUM | LOW
//   internet_facing:   BOOLEAN
//   scan_timestamp:    DATETIME
// })

// ── Relationship: CONNECTS_TO ─────────────────────────────────────────────────
//
// (:Asset)-[:CONNECTS_TO {
//   technique_id:          STRING  -- MITRE ATT&CK ID (e.g. "T1021.001")
//   technique_name:        STRING
//   tactic:                STRING  -- ATT&CK tactic name
//   attack_complexity:     STRING  -- Low | High
//   cvss_contribution:     FLOAT   -- CVSS score for this exploitability path
//   detection_probability: FLOAT   -- 0.0–1.0
//   lateral_movement:      BOOLEAN
//   privilege_escalation:  BOOLEAN
//   attack_cost:           FLOAT   -- pathfinding edge weight (lower = attacker prefers)
// }]->(:Asset)

// ── Vulnerability node ────────────────────────────────────────────────────────
//
// (:Vulnerability {
//   cve_id:       STRING  -- e.g. "CVE-2024-1234"
//   cvss_score:   FLOAT
//   cvss_vector:  STRING  -- CVSS v3.1 vector string
//   description:  STRING
//   cwe_id:       STRING  -- e.g. "CWE-79"
//   published:    DATE
//   patch_url:    STRING
// })

// ── Relationship: EXPLOITS ────────────────────────────────────────────────────
//
// (:Asset)-[:EXPLOITS]->(:Vulnerability)

// ── ATT&CK Technique node ─────────────────────────────────────────────────────
//
// (:Technique {
//   technique_id: STRING  -- "T1190"
//   name:         STRING  -- "Exploit Public-Facing Application"
//   tactic:       STRING  -- "Initial Access"
//   severity:     STRING  -- CRITICAL | HIGH | MEDIUM | LOW
//   description:  STRING
//   detection:    STRING  -- detection recommendation from ATT&CK
// })

// ── AttackPath node ───────────────────────────────────────────────────────────
//
// (:AttackPath {
//   path_id:        INTEGER
//   risk_score:     FLOAT    -- 0.0–10.0
//   risk_tier:      STRING
//   hop_count:      INTEGER
//   blast_radius:   INTEGER
//   kill_chain_cov: FLOAT    -- 0.0–1.0
//   scan_timestamp: DATETIME
// })

// ── Relationship: PART_OF ─────────────────────────────────────────────────────
//
// (:Asset)-[:PART_OF { step_index: INTEGER }]->(:AttackPath)

// ── Example seed data (for testing) ──────────────────────────────────────────

// MERGE (entry:Asset {asset_id: 'inet-001', node_type: 'INTERNET_EDGE',
//   segment: 'internet', cvss_score: 6.5, asset_criticality: 0.6,
//   internet_facing: true, patch_available: true, risk_tier: 'MEDIUM'});
//
// MERGE (dc:Asset {asset_id: 'dc-001', node_type: 'DOMAIN_CONTROLLER',
//   segment: 'restricted', cvss_score: 9.1, asset_criticality: 1.0,
//   internet_facing: false, patch_available: false, risk_tier: 'CRITICAL'});
//
// MATCH (a:Asset {asset_id: 'inet-001'}), (b:Asset {asset_id: 'dc-001'})
// MERGE (a)-[:CONNECTS_TO {
//   technique_id: 'T1190', tactic: 'Initial Access',
//   attack_complexity: 'Low', cvss_contribution: 8.1,
//   detection_probability: 0.25, lateral_movement: false,
//   privilege_escalation: false, attack_cost: 0.12
// }]->(b);
