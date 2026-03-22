/**
 * Seed the CSI Malta database with sample guidance and advisories.
 * Usage: npx tsx scripts/seed-sample.ts [--force]
 */
import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["CSIMALTA_DB_PATH"] ?? "data/csi-malta.db";
const force = process.argv.includes("--force");
const dir = dirname(DB_PATH);
if (!existsSync(dir)) { mkdirSync(dir, { recursive: true }); }
if (force && existsSync(DB_PATH)) { unlinkSync(DB_PATH); console.log(`Deleted ${DB_PATH}`); }
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);
console.log(`Database initialised at ${DB_PATH}`);

// --- Frameworks ---
const frameworks = [
  { id: "nis2-mt", name: "NIS2 Implementation in Malta", name_en: "NIS2 Implementation in Malta", description: "Malta's implementation of EU NIS2 Directive. Covers essential and important entities, incident reporting, minimum measures. MITA and MFSA jointly supervise. Transposed via Legal Notice 2023.", document_count: 3 },
  { id: "national-cyber-strategy-mt", name: "Malta National Cybersecurity Strategy 2023-2027", name_en: "Malta National Cybersecurity Strategy 2023-2027", description: "Malta five-year cybersecurity strategy covering critical infrastructure protection, cyber skills development, and international cooperation.", document_count: 2 },
  { id: "mita-standards", name: "MITA Technical Standards", name_en: "MITA Technical Standards", description: "Malta Information Technology Agency technical standards and guidelines for ICT security in the Maltese public sector.", document_count: 5 },
];
const insF = db.prepare("INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)");
for (const f of frameworks) insF.run(f.id, f.name, f.name_en, f.description, f.document_count);
console.log(`Inserted ${frameworks.length} frameworks`);

// --- Guidance ---
const guidance = [
  {
    reference: "MITA-CS-2024-01", title: "NIS2 Compliance Guide for Maltese Essential Entities", title_en: "NIS2 Compliance Guide for Maltese Essential Entities",
    date: "2024-01-20", type: "directive", series: "NIS2",
    summary: "Practical NIS2 compliance guidance for Maltese essential entities covering risk assessment, incident reporting, and minimum cybersecurity measures.",
    full_text: "Malta transposed NIS2 Directive (2022/2555) via Legal Notice published in October 2023. Essential entities in Malta include energy, transport, banking, financial market infrastructure, health, digital infrastructure, and public administration. Key obligations: (1) Cybersecurity risk management — entities must implement appropriate technical and organisational measures; (2) Incident reporting — significant incidents to MITA CSIRT within 24 hours (early warning), full notification within 72 hours; (3) Supply chain security — assess ICT supply chain risks; (4) Encryption — use appropriate encryption for data at rest and in transit; (5) Multi-factor authentication — mandatory for administrative access. Supervisory authorities: MITA for most sectors, MFSA for financial sector entities. Fines: essential entities up to EUR 10 million or 2% of global turnover.",
    topics: JSON.stringify(["NIS2", "essential entities", "incident reporting", "Malta"]), status: "current",
  },
  {
    reference: "MITA-CS-2023-03", title: "Cybersecurity Standards for Maltese Public Sector ICT Systems", title_en: "Cybersecurity Standards for Maltese Public Sector ICT Systems",
    date: "2023-05-15", type: "standard", series: "MITA-standard",
    summary: "MITA mandatory cybersecurity baseline standards for all Maltese government entities, covering network security, identity management, and incident response.",
    full_text: "MITA mandates cybersecurity baseline standards for all Maltese government entities and agencies. Standards apply to all ICT systems processing government data regardless of hosting location. Baseline requirements: (1) Identity and access management — MFA for all administrative accounts, privileged access workstations for admin tasks, quarterly access reviews; (2) Network security — network segmentation, firewall policy review every six months, encrypted remote access only; (3) Vulnerability management — monthly vulnerability scans, critical patches within 7 days, high patches within 30 days; (4) Logging and monitoring — centralised logging for 12 months, security event monitoring, SIEM deployment for critical systems; (5) Incident response — documented IR plan tested annually, MITA CSIRT notification for significant incidents. Government entities must demonstrate compliance through annual self-assessment submitted to MITA.",
    topics: JSON.stringify(["public sector", "ICT security", "MITA", "baseline standards"]), status: "current",
  },
  {
    reference: "MT-NCSS-2023", title: "Malta National Cybersecurity Strategy 2023-2027", title_en: "Malta National Cybersecurity Strategy 2023-2027",
    date: "2023-02-01", type: "standard", series: "national-strategy",
    summary: "Malta five-year national cybersecurity strategy with six strategic pillars: governance, protection, response, awareness, innovation, and international cooperation.",
    full_text: "The Malta National Cybersecurity Strategy 2023-2027 outlines six strategic pillars: (1) Governance — strengthening national cybersecurity governance with clear authority structures and coordination mechanisms; (2) Protection — implementing risk-based cybersecurity measures for critical infrastructure and essential services; (3) Response — enhancing national incident response capabilities through MITA CSIRT and public-private partnerships; (4) Awareness — building cybersecurity skills at all levels from primary school to professional certification; (5) Innovation — supporting research and development in cybersecurity technologies and services; (6) International cooperation — active participation in EU, NATO, and Commonwealth cybersecurity initiatives. Malta has joined the EU Cyber Reserve initiative and is enhancing its Joint Cybersecurity Unit participation.",
    topics: JSON.stringify(["national strategy", "critical infrastructure", "governance", "Malta"]), status: "current",
  },
  {
    reference: "MITA-CS-2024-02", title: "Zero Trust Architecture Guidance for Maltese Organisations", title_en: "Zero Trust Architecture Guidance for Maltese Organisations",
    date: "2024-03-01", type: "recommendation", series: "MITA-standard",
    summary: "MITA guidance on adopting zero trust security principles for Maltese public and private sector organisations.",
    full_text: "Zero Trust Architecture (ZTA) principles: never trust, always verify, assume breach. MITA recommends ZTA adoption aligned with NIST SP 800-207. Key components: (1) Identity verification — strong MFA for all users, device health attestation; (2) Device security — endpoint protection, compliance checks before access; (3) Network access — micro-segmentation, software-defined perimeter; (4) Application access — application-layer controls regardless of network location; (5) Data protection — classify data, apply controls at data level, not just perimeter. Implementation roadmap: Phase 1 (0-6 months) — identity modernisation, MFA everywhere; Phase 2 (6-18 months) — device compliance, privileged access management; Phase 3 (18-36 months) — micro-segmentation, application-level controls. MITA offers free ZTA maturity assessments for government entities.",
    topics: JSON.stringify(["zero trust", "network security", "identity", "access control"]), status: "current",
  },
  {
    reference: "MITA-CS-2022-01", title: "Information Security Policy Framework for Government Entities", title_en: "Information Security Policy Framework for Government Entities",
    date: "2022-06-01", type: "standard", series: "MITA-standard",
    summary: "MITA information security policy framework — previous version, partially superseded by 2023 standards update.",
    full_text: "MITA Information Security Policy Framework 2022 established baseline information security requirements aligned with ISO 27001:2013. Framework covered: policy governance, risk management, asset management, access control, cryptography, physical security, operations security, communications security, supplier relationships, incident management, business continuity, compliance. Updated in 2023 to align with ISO 27001:2022 and NIS2 requirements.",
    topics: JSON.stringify(["information security", "policy", "MITA", "ISO 27001"]), status: "superseded",
  },
];

const insG = db.prepare("INSERT OR IGNORE INTO guidance (reference, title, title_en, date, type, series, summary, full_text, topics, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
const insGAll = db.transaction(() => { for (const g of guidance) insG.run(g.reference, g.title, g.title_en, g.date, g.type, g.series, g.summary, g.full_text, g.topics, g.status); });
insGAll();
console.log(`Inserted ${guidance.length} guidance documents`);

// --- Advisories ---
const advisories = [
  {
    reference: "MITA-ADV-2024-001", title: "Critical Vulnerabilities in Palo Alto Networks PAN-OS",
    date: "2024-04-12", severity: "critical",
    affected_products: JSON.stringify(["Palo Alto Networks PAN-OS", "GlobalProtect"]),
    summary: "MITA CSIRT alerts on critical zero-day command injection vulnerability in Palo Alto PAN-OS enabling unauthenticated remote code execution.",
    full_text: "MITA CSIRT issues critical alert for CVE-2024-3400, a command injection vulnerability in Palo Alto Networks PAN-OS GlobalProtect feature (CVSS 10.0). Unauthenticated attackers can execute arbitrary code with root privileges. Affected: PAN-OS 10.2, 11.0, 11.1 with GlobalProtect gateway or portal enabled. Active exploitation confirmed targeting government and financial sector in multiple EU countries including Malta. Immediate mitigations: (1) Apply PAN-OS hotfix immediately (10.2.9-h1, 11.0.4-h1, 11.1.2-h3); (2) If patching delayed, disable GlobalProtect gateway; (3) Enable Threat Prevention (Threat ID 95187) if licensed; (4) Review logs for exploitation indicators; (5) Contact MITA CSIRT if compromise suspected: csirt@gov.mt.",
    cve_references: JSON.stringify(["CVE-2024-3400"]),
  },
  {
    reference: "MITA-ADV-2023-008", title: "iGaming Sector Targeted by DDoS and Extortion Campaign",
    date: "2023-08-20", severity: "high",
    affected_products: JSON.stringify(["Online gaming platforms", "Payment processing systems"]),
    summary: "MITA CSIRT warns Maltese iGaming operators of coordinated DDoS attacks combined with ransom extortion demands.",
    full_text: "MITA CSIRT has observed a coordinated campaign targeting Malta's iGaming sector, which hosts a significant concentration of licensed online gaming operators. Attack profile: (1) Initial DDoS volumetric attack (peak 180 Gbps) to demonstrate capability; (2) Extortion demand for cryptocurrency payment to cease attacks; (3) Follow-up DDoS with application-layer attacks if ransom not paid; (4) Simultaneous phishing attacks against operator staff. Six Maltese iGaming operators confirmed affected. Protective measures: engage DDoS mitigation provider (scrubbing centre or cloud-based); implement traffic filtering at network edge; coordinate with MITA CSIRT and MGA (Malta Gaming Authority) for regulatory reporting. Do not pay ransom — it does not guarantee cessation of attacks.",
    cve_references: null,
  },
  {
    reference: "MITA-ADV-2024-003", title: "Supply Chain Attack via Compromised Software Update Mechanism",
    date: "2024-01-25", severity: "high",
    affected_products: JSON.stringify(["3CX Desktop App", "Supply chain software"]),
    summary: "MITA CSIRT warning on supply chain attack affecting organisations using trojanised software updates — several Maltese organisations potentially affected.",
    full_text: "MITA CSIRT identified that several Maltese organisations may have been exposed to a supply chain attack via compromised software updates. The attack pattern follows the XZ Utils and 3CX supply chain compromise methodology. Indicators of compromise include: unexpected outbound connections to unknown C2 infrastructure, abnormal process execution from legitimate software, modified system libraries. Affected organisations should: (1) Inventory all third-party software with automatic update mechanisms; (2) Verify software integrity via vendor-published hashes; (3) Review network flows for anomalous outbound connections; (4) Apply principle of least privilege to software update processes; (5) Report confirmed compromise to MITA CSIRT: csirt@gov.mt or +356 2200 0000.",
    cve_references: null,
  },
];

const insA = db.prepare("INSERT OR IGNORE INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
const insAAll = db.transaction(() => { for (const a of advisories) insA.run(a.reference, a.title, a.date, a.severity, a.affected_products, a.summary, a.full_text, a.cve_references); });
insAAll();
console.log(`Inserted ${advisories.length} advisories`);

const gCnt = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const aCnt = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const fCnt = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;
console.log(`\nSummary: ${fCnt} frameworks, ${gCnt} guidance, ${aCnt} advisories`);
console.log(`Done. Database ready at ${DB_PATH}`);
db.close();
