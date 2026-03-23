/**
 * CSIRTMalta Ingestion Crawler
 *
 * Scrapes the CSIRTMalta website (csirtmalta.org) and related Maltese
 * cybersecurity portals to populate the SQLite database with guidance
 * documents, security advisories, and framework definitions.
 *
 * Data sources:
 *   1. csirtmalta.org        — primary: advisories, news, publications
 *   2. maltacip.gov.mt       — CIP Directorate: CSIRT Malta pages, strategy docs
 *   3. ncc-mita.gov.mt       — NCC MITA: national coordination centre resources
 *   4. mfsa.mt               — joint communications on cyber threats
 *
 * The crawler is resilient to csirtmalta.org being intermittently unreachable
 * (common for government CSIRT sites) — it falls back to the maltacip.gov.mt
 * and ncc-mita.gov.mt mirrors for the same content.
 *
 * Usage:
 *   npx tsx scripts/ingest-csirt-mt.ts                   # full crawl
 *   npx tsx scripts/ingest-csirt-mt.ts --resume           # resume from last checkpoint
 *   npx tsx scripts/ingest-csirt-mt.ts --dry-run          # log what would be inserted
 *   npx tsx scripts/ingest-csirt-mt.ts --force            # drop and recreate DB first
 *   npx tsx scripts/ingest-csirt-mt.ts --advisories-only  # only crawl advisories
 *   npx tsx scripts/ingest-csirt-mt.ts --guidance-only    # only crawl guidance
 */

import Database from "better-sqlite3";
import * as cheerio from "cheerio";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["CSIMALTA_DB_PATH"] ?? "data/csi-malta.db";
const PROGRESS_FILE = resolve(dirname(DB_PATH), "ingest-progress.json");

const CSIRT_BASE = "https://csirtmalta.org";
const CIP_BASE = "https://maltacip.gov.mt";
const NCC_BASE = "https://ncc-mita.gov.mt";
const MFSA_BASE = "https://www.mfsa.mt";

const RATE_LIMIT_MS = 1500;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 2000;
const REQUEST_TIMEOUT_MS = 30_000;
const USER_AGENT =
  "AnsvarCSIRTMaltaCrawler/1.0 (+https://ansvar.eu; compliance research)";

// CLI flags
const args = process.argv.slice(2);
const force = args.includes("--force");
const dryRun = args.includes("--dry-run");
const resume = args.includes("--resume");
const advisoriesOnly = args.includes("--advisories-only");
const guidanceOnly = args.includes("--guidance-only");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null;
  summary: string;
  full_text: string;
  cve_references: string | null;
}

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string | null;
  description: string;
  document_count: number;
}

interface Progress {
  completed_guidance_urls: string[];
  completed_advisory_urls: string[];
  completed_cip_urls: string[];
  completed_ncc_urls: string[];
  completed_mfsa_urls: string[];
  last_updated: string;
}

// ---------------------------------------------------------------------------
// Utility: rate-limited fetch with retry
// ---------------------------------------------------------------------------

let lastRequestTime = 0;

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function rateLimitedFetch(
  url: string,
  opts?: RequestInit,
): Promise<Response> {
  const now = Date.now();
  const elapsed = now - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }

  let lastError: Error | null = null;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      lastRequestTime = Date.now();
      const resp = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          Accept:
            "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
        },
        redirect: "follow",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        ...opts,
      });
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} for ${url}`);
      }
      return resp;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      console.warn(
        `  [retry ${attempt}/${MAX_RETRIES}] ${url}: ${lastError.message}`,
      );
      if (attempt < MAX_RETRIES) {
        await sleep(RETRY_BACKOFF_MS * attempt);
      }
    }
  }
  throw lastError!;
}

async function fetchHtml(url: string): Promise<string | null> {
  try {
    const resp = await rateLimitedFetch(url);
    return await resp.text();
  } catch (err) {
    console.warn(
      `  Failed to fetch ${url}: ${err instanceof Error ? err.message : err}`,
    );
    return null;
  }
}

// ---------------------------------------------------------------------------
// Cheerio helpers
// ---------------------------------------------------------------------------

/**
 * Extract the main content text from an HTML page using Cheerio.
 * Strips navigation, scripts, styles, and footers.
 */
function extractMainContent($: cheerio.CheerioAPI): string {
  // Remove non-content elements
  $("script, style, nav, footer, header, iframe, noscript").remove();
  $('[role="navigation"]').remove();
  $(".menu, .sidebar, .breadcrumb, .nav").remove();

  // Try specific content containers first
  const selectors = [
    "main",
    "article",
    '[role="main"]',
    "#content",
    ".content",
    ".page-content",
    ".entry-content",
    ".post-content",
    ".article-body",
  ];

  for (const sel of selectors) {
    const el = $(sel);
    if (el.length > 0) {
      const text = el.text().replace(/\s+/g, " ").trim();
      if (text.length > 200) {
        return text;
      }
    }
  }

  // Fallback: body text
  const bodyText = $("body").text().replace(/\s+/g, " ").trim();
  return bodyText;
}

/**
 * Extract all links from a page matching an optional href pattern.
 */
function extractLinks(
  $: cheerio.CheerioAPI,
  hrefPattern?: RegExp,
): Array<{ href: string; text: string }> {
  const results: Array<{ href: string; text: string }> = [];
  $("a[href]").each((_, el) => {
    const href = $(el).attr("href") ?? "";
    const text = $(el).text().replace(/\s+/g, " ").trim();
    if (!hrefPattern || hrefPattern.test(href)) {
      results.push({ href, text });
    }
  });
  return results;
}

/**
 * Extract date in YYYY-MM-DD format from text.
 * Handles: DD/MM/YYYY, DD.MM.YYYY, DD-MM-YYYY, YYYY-MM-DD, "Month DD, YYYY".
 */
function extractDate(text: string): string | null {
  // DD/MM/YYYY or DD.MM.YYYY or DD-MM-YYYY
  const euMatch = text.match(
    /(\d{1,2})[./\-](\d{1,2})[./\-](\d{4})/,
  );
  if (euMatch) {
    const d = euMatch[1]!.padStart(2, "0");
    const m = euMatch[2]!.padStart(2, "0");
    const y = euMatch[3]!;
    return `${y}-${m}-${d}`;
  }

  // YYYY-MM-DD
  const isoMatch = text.match(/(\d{4})-(\d{2})-(\d{2})/);
  if (isoMatch) {
    return `${isoMatch[1]}-${isoMatch[2]}-${isoMatch[3]}`;
  }

  // "Month DD, YYYY" or "DD Month YYYY"
  const months: Record<string, string> = {
    january: "01", february: "02", march: "03", april: "04",
    may: "05", june: "06", july: "07", august: "08",
    september: "09", october: "10", november: "11", december: "12",
  };

  const namedMatch = text.match(
    /(\d{1,2})\s+(january|february|march|april|may|june|july|august|september|october|november|december)\s+(\d{4})/i,
  );
  if (namedMatch) {
    const d = namedMatch[1]!.padStart(2, "0");
    const m = months[namedMatch[2]!.toLowerCase()]!;
    const y = namedMatch[3]!;
    return `${y}-${m}-${d}`;
  }

  const namedMatch2 = text.match(
    /(january|february|march|april|may|june|july|august|september|october|november|december)\s+(\d{1,2}),?\s+(\d{4})/i,
  );
  if (namedMatch2) {
    const m = months[namedMatch2[1]!.toLowerCase()]!;
    const d = namedMatch2[2]!.padStart(2, "0");
    const y = namedMatch2[3]!;
    return `${y}-${m}-${d}`;
  }

  return null;
}

/**
 * Extract CVE references from text.
 */
function extractCves(text: string): string[] {
  const cveRe = /CVE-\d{4}-\d{4,}/g;
  const cves: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = cveRe.exec(text)) !== null) {
    if (!cves.includes(match[0])) {
      cves.push(match[0]);
    }
  }
  return cves;
}

/**
 * Normalise severity strings to standard values.
 */
function normaliseSeverity(raw: string): string {
  const lower = raw.toLowerCase().trim();
  if (/critical|very\s*high|kritisch/i.test(lower)) return "critical";
  if (/high|hoch|important|severe/i.test(lower)) return "high";
  if (/medium|moderate|mittel/i.test(lower)) return "medium";
  if (/low|niedrig|minor|informational/i.test(lower)) return "low";
  return lower;
}

/**
 * Detect topics from content text for guidance documents.
 */
function detectTopics(text: string, reference: string): string[] {
  const topics: string[] = [];
  const lower = (text + " " + reference).toLowerCase();

  const topicPatterns: Array<[RegExp, string]> = [
    [/nis\s*2|nis2/i, "NIS2"],
    [/critical\s*infrastructure|essential\s*(entities|services)/i, "critical infrastructure"],
    [/incident\s*(report|response|handling|management)/i, "incident response"],
    [/risk\s*(assess|manage|analy)/i, "risk management"],
    [/supply\s*chain/i, "supply chain security"],
    [/encrypt|cryptograph|tls|ssl/i, "encryption"],
    [/multi.?factor|mfa|2fa|two.?factor/i, "authentication"],
    [/vulnerabilit|patch|cve/i, "vulnerability management"],
    [/ransomware/i, "ransomware"],
    [/phishing|social\s*engineer/i, "phishing"],
    [/ddos|denial.of.service/i, "DDoS"],
    [/malware|trojan|virus/i, "malware"],
    [/igaming|gaming|gambling/i, "iGaming sector"],
    [/financial|banking|fintech|mfsa/i, "financial sector"],
    [/health|medical|hospital/i, "healthcare"],
    [/gdpr|data\s*protect/i, "data protection"],
    [/zero\s*trust/i, "zero trust"],
    [/cloud\s*secur/i, "cloud security"],
    [/iot|internet\s*of\s*things/i, "IoT security"],
    [/scada|ics|industrial\s*control|ot\s*secur/i, "industrial security"],
    [/identity|access\s*(control|manage)/i, "identity and access management"],
    [/logging|monitoring|siem/i, "logging and monitoring"],
    [/network\s*secur|firewall|segmentat/i, "network security"],
    [/awareness|training|education|skills/i, "awareness and training"],
    [/iso\s*27001|isms/i, "ISO 27001"],
    [/governance|strategy|policy/i, "governance"],
    [/public\s*sector|government/i, "public sector"],
    [/mita/i, "MITA"],
    [/malta/i, "Malta"],
    [/eu\s*cyber|european/i, "EU cooperation"],
  ];

  for (const [pattern, topic] of topicPatterns) {
    if (pattern.test(lower) && !topics.includes(topic)) {
      topics.push(topic);
    }
  }

  return topics.length > 0 ? topics : ["cybersecurity"];
}

/**
 * Resolve a potentially relative URL against a base URL.
 */
function resolveUrl(href: string, base: string): string {
  if (href.startsWith("http://") || href.startsWith("https://")) {
    return href;
  }
  if (href.startsWith("//")) {
    return "https:" + href;
  }
  if (href.startsWith("/")) {
    const origin = new URL(base).origin;
    return origin + href;
  }
  return new URL(href, base).href;
}

// ---------------------------------------------------------------------------
// Progress tracking
// ---------------------------------------------------------------------------

function loadProgress(): Progress {
  if (resume && existsSync(PROGRESS_FILE)) {
    try {
      const raw = readFileSync(PROGRESS_FILE, "utf-8");
      const p = JSON.parse(raw) as Progress;
      console.log(
        `Resuming from checkpoint (${p.last_updated}): ` +
          `${p.completed_guidance_urls.length} guidance, ` +
          `${p.completed_advisory_urls.length} advisories, ` +
          `${p.completed_cip_urls.length} CIP pages, ` +
          `${p.completed_ncc_urls.length} NCC pages, ` +
          `${p.completed_mfsa_urls.length} MFSA docs`,
      );
      return p;
    } catch {
      console.warn("Could not parse progress file, starting fresh");
    }
  }
  return {
    completed_guidance_urls: [],
    completed_advisory_urls: [],
    completed_cip_urls: [],
    completed_ncc_urls: [],
    completed_mfsa_urls: [],
    last_updated: new Date().toISOString(),
  };
}

function saveProgress(progress: Progress): void {
  progress.last_updated = new Date().toISOString();
  writeFileSync(PROGRESS_FILE, JSON.stringify(progress, null, 2));
}

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

function initDatabase(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  if (force && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    console.log(`Deleted existing database at ${DB_PATH}`);
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  console.log(`Database initialised at ${DB_PATH}`);
  return db;
}

// ---------------------------------------------------------------------------
// Framework definitions (static, updated infrequently)
// ---------------------------------------------------------------------------

const FRAMEWORKS: FrameworkRow[] = [
  {
    id: "nis2-mt",
    name: "NIS2 Implementation in Malta",
    name_en: "NIS2 Implementation in Malta",
    description:
      "Malta's transposition of EU NIS2 Directive (2022/2555) via Legal Notice 71 of 2025. " +
      "Covers essential and important entities, incident reporting to CSIRT Malta within 24 hours " +
      "(early warning) and 72 hours (full notification), minimum cybersecurity measures, and supply " +
      "chain security requirements. Supervisory authorities: MITA for most sectors, MFSA for financial " +
      "sector entities. Penalties for essential entities: up to EUR 10 million or 2% of global turnover.",
    document_count: 0,
  },
  {
    id: "national-cyber-strategy-mt",
    name: "Malta National Cybersecurity Strategy 2023-2026",
    name_en: "Malta National Cybersecurity Strategy 2023-2026",
    description:
      "Malta's national cybersecurity strategy built on four domains: (1) Governance Capacity — " +
      "legislative, regulatory, and policy frameworks; (2) Defence Capacity — operational measures " +
      "and multi-stakeholder coordination for reactive and proactive cybersecurity; (3) Competence " +
      "and Culture — human resources, academic training, National Coordination Centre for research " +
      "and innovation; (4) International Cooperation — bilateral, multilateral, and EU-level engagement. " +
      "Overseen by the National Cybersecurity Steering Committee.",
    document_count: 0,
  },
  {
    id: "mita-standards",
    name: "MITA Technical Standards",
    name_en: "MITA Technical Standards",
    description:
      "Malta Information Technology Agency technical standards and guidelines for ICT security " +
      "in the Maltese public sector. Covers identity and access management, network security, " +
      "vulnerability management, logging and monitoring, and incident response. Government entities " +
      "must demonstrate compliance through annual self-assessment submitted to MITA.",
    document_count: 0,
  },
  {
    id: "csirt-malta-advisories",
    name: "CSIRT Malta Security Advisories",
    name_en: "CSIRT Malta Security Advisories",
    description:
      "Security advisories issued by CSIRT Malta (csirtmalta@gov.mt) covering cyber threats, " +
      "vulnerabilities, and incident alerts relevant to Maltese critical infrastructure and " +
      "essential service operators. Disseminated via mailing list and social media (@CSIRTMalta).",
    document_count: 0,
  },
  {
    id: "mfsa-cyber",
    name: "MFSA Cybersecurity Communications",
    name_en: "MFSA Cybersecurity Communications",
    description:
      "Joint communications by the Malta Financial Services Authority (MFSA) and CSIRT Malta " +
      "on cyber threats and vulnerabilities affecting the financial sector in Malta. Covers " +
      "regulatory obligations for financial entities under NIS2 and DORA.",
    document_count: 0,
  },
];

// ---------------------------------------------------------------------------
// 1. Crawl csirtmalta.org
// ---------------------------------------------------------------------------

/**
 * Known page paths on csirtmalta.org. The site has been intermittently
 * unreachable (government CSIRT sites often have limited uptime), so we
 * attempt each path and gracefully skip on failure.
 */
const CSIRT_PATHS = [
  "/",
  "/news",
  "/news/",
  "/advisories",
  "/advisories/",
  "/publications",
  "/publications/",
  "/services",
  "/services/",
  "/about",
  "/about/",
  "/alerts",
  "/alerts/",
  "/resources",
  "/resources/",
];

interface DiscoveredPage {
  url: string;
  title: string;
  date: string | null;
  content: string;
  source: string;
}

async function crawlCsirtMalta(): Promise<DiscoveredPage[]> {
  console.log("\n--- Crawling csirtmalta.org ---");
  const pages: DiscoveredPage[] = [];
  const visitedUrls = new Set<string>();

  // Try each known path
  for (const path of CSIRT_PATHS) {
    const url = CSIRT_BASE + path;
    if (visitedUrls.has(url)) continue;
    visitedUrls.add(url);

    const html = await fetchHtml(url);
    if (!html) {
      console.log(`  Skipped ${url} (unreachable)`);
      continue;
    }

    const $ = cheerio.load(html);
    const mainText = extractMainContent($);

    if (mainText.length < 100) {
      console.log(`  Skipped ${url} (insufficient content: ${mainText.length} chars)`);
      continue;
    }

    const title = $("title").text().trim() || $("h1").first().text().trim() || path;
    const dateStr = extractDate(mainText);

    pages.push({
      url,
      title,
      date: dateStr,
      content: mainText,
      source: "csirtmalta.org",
    });
    console.log(`  Fetched: ${title} (${mainText.length} chars)`);

    // Discover linked articles from listing pages
    const articleLinks = extractLinks($, /\/(news|advisories|alerts|publications)\//i);
    for (const link of articleLinks) {
      const articleUrl = resolveUrl(link.href, url);
      if (visitedUrls.has(articleUrl)) continue;
      if (!articleUrl.startsWith(CSIRT_BASE)) continue;
      visitedUrls.add(articleUrl);

      const articleHtml = await fetchHtml(articleUrl);
      if (!articleHtml) continue;

      const $article = cheerio.load(articleHtml);
      const articleText = extractMainContent($article);
      if (articleText.length < 100) continue;

      const articleTitle =
        $article("title").text().trim() ||
        $article("h1").first().text().trim() ||
        link.text;
      const articleDate = extractDate(articleText);

      pages.push({
        url: articleUrl,
        title: articleTitle,
        date: articleDate,
        content: articleText,
        source: "csirtmalta.org",
      });
      console.log(`  Fetched article: ${articleTitle.slice(0, 80)} (${articleText.length} chars)`);
    }
  }

  console.log(`  Total pages from csirtmalta.org: ${pages.length}`);
  return pages;
}

// ---------------------------------------------------------------------------
// 2. Crawl maltacip.gov.mt (CIP Directorate — CSIRT Malta section)
// ---------------------------------------------------------------------------

const CIP_CSIRT_PATHS = [
  "/en/the-department/csirtmalta/",
  "/en/CIP_Structure/Pages/CSIRTMalta.aspx",
  "/en/the-department/",
  "/en/Pages/home.aspx",
  "/en/news/",
];

async function crawlCipDirectorate(): Promise<DiscoveredPage[]> {
  console.log("\n--- Crawling maltacip.gov.mt ---");
  const pages: DiscoveredPage[] = [];
  const visitedUrls = new Set<string>();

  for (const path of CIP_CSIRT_PATHS) {
    const url = CIP_BASE + path;
    if (visitedUrls.has(url)) continue;
    visitedUrls.add(url);

    const html = await fetchHtml(url);
    if (!html) {
      console.log(`  Skipped ${url} (unreachable)`);
      continue;
    }

    const $ = cheerio.load(html);
    const mainText = extractMainContent($);

    if (mainText.length < 100) {
      console.log(`  Skipped ${url} (insufficient content: ${mainText.length} chars)`);
      continue;
    }

    const title = $("title").text().trim() || $("h1").first().text().trim() || path;
    const dateStr = extractDate(mainText);

    pages.push({
      url,
      title,
      date: dateStr,
      content: mainText,
      source: "maltacip.gov.mt",
    });
    console.log(`  Fetched: ${title.slice(0, 80)} (${mainText.length} chars)`);

    // Follow internal links related to cybersecurity / CSIRT
    const relatedLinks = extractLinks(
      $,
      /\/(csirt|cyber|security|nis|incident|alert)/i,
    );
    for (const link of relatedLinks) {
      const linkedUrl = resolveUrl(link.href, url);
      if (visitedUrls.has(linkedUrl)) continue;
      if (
        !linkedUrl.startsWith(CIP_BASE) &&
        !linkedUrl.startsWith("https://maltacip.gov.mt")
      ) {
        continue;
      }
      visitedUrls.add(linkedUrl);

      const linkedHtml = await fetchHtml(linkedUrl);
      if (!linkedHtml) continue;

      const $linked = cheerio.load(linkedHtml);
      const linkedText = extractMainContent($linked);
      if (linkedText.length < 100) continue;

      const linkedTitle =
        $linked("title").text().trim() ||
        $linked("h1").first().text().trim() ||
        link.text;
      const linkedDate = extractDate(linkedText);

      pages.push({
        url: linkedUrl,
        title: linkedTitle,
        date: linkedDate,
        content: linkedText,
        source: "maltacip.gov.mt",
      });
      console.log(`  Fetched linked: ${linkedTitle.slice(0, 80)} (${linkedText.length} chars)`);
    }
  }

  console.log(`  Total pages from maltacip.gov.mt: ${pages.length}`);
  return pages;
}

// ---------------------------------------------------------------------------
// 3. Crawl ncc-mita.gov.mt (National Coordination Centre)
// ---------------------------------------------------------------------------

const NCC_PATHS = [
  "/",
  "/strategy/",
  "/news/",
  "/resources/",
  "/publications/",
  "/events/",
];

async function crawlNccMita(): Promise<DiscoveredPage[]> {
  console.log("\n--- Crawling ncc-mita.gov.mt ---");
  const pages: DiscoveredPage[] = [];
  const visitedUrls = new Set<string>();

  for (const path of NCC_PATHS) {
    const url = NCC_BASE + path;
    if (visitedUrls.has(url)) continue;
    visitedUrls.add(url);

    const html = await fetchHtml(url);
    if (!html) {
      console.log(`  Skipped ${url} (unreachable)`);
      continue;
    }

    const $ = cheerio.load(html);
    const mainText = extractMainContent($);

    if (mainText.length < 100) {
      console.log(`  Skipped ${url} (insufficient content: ${mainText.length} chars)`);
      continue;
    }

    const title = $("title").text().trim() || $("h1").first().text().trim() || path;
    const dateStr = extractDate(mainText);

    pages.push({
      url,
      title,
      date: dateStr,
      content: mainText,
      source: "ncc-mita.gov.mt",
    });
    console.log(`  Fetched: ${title.slice(0, 80)} (${mainText.length} chars)`);

    // Follow article/news links
    const articleLinks = extractLinks(
      $,
      /\/(news|article|post|publication|resource|strategy)\//i,
    );
    for (const link of articleLinks) {
      const articleUrl = resolveUrl(link.href, url);
      if (visitedUrls.has(articleUrl)) continue;
      if (!articleUrl.startsWith(NCC_BASE)) continue;
      visitedUrls.add(articleUrl);

      const articleHtml = await fetchHtml(articleUrl);
      if (!articleHtml) continue;

      const $article = cheerio.load(articleHtml);
      const articleText = extractMainContent($article);
      if (articleText.length < 100) continue;

      const articleTitle =
        $article("title").text().trim() ||
        $article("h1").first().text().trim() ||
        link.text;
      const articleDate = extractDate(articleText);

      pages.push({
        url: articleUrl,
        title: articleTitle,
        date: articleDate,
        content: articleText,
        source: "ncc-mita.gov.mt",
      });
      console.log(`  Fetched article: ${articleTitle.slice(0, 80)} (${articleText.length} chars)`);
    }
  }

  console.log(`  Total pages from ncc-mita.gov.mt: ${pages.length}`);
  return pages;
}

// ---------------------------------------------------------------------------
// 4. Crawl MFSA joint communications
// ---------------------------------------------------------------------------

const MFSA_CYBER_URLS = [
  `${MFSA_BASE}/our-work/supervisory-ict-risk-and-cybersecurity/`,
  `${MFSA_BASE}/wp-content/uploads/2021/06/Joint-Communication-by-MFSA-and-CSIRTMalta-on-Cyber-Threats-and-Vulnerabilities.pdf`,
];

async function crawlMfsaCyber(): Promise<DiscoveredPage[]> {
  console.log("\n--- Crawling MFSA cybersecurity communications ---");
  const pages: DiscoveredPage[] = [];
  const visitedUrls = new Set<string>();

  for (const url of MFSA_CYBER_URLS) {
    if (visitedUrls.has(url)) continue;
    visitedUrls.add(url);

    // Skip PDFs — we only process HTML pages
    if (url.endsWith(".pdf")) {
      console.log(`  Skipped PDF: ${url} (PDF ingestion not supported)`);
      continue;
    }

    const html = await fetchHtml(url);
    if (!html) {
      console.log(`  Skipped ${url} (unreachable)`);
      continue;
    }

    const $ = cheerio.load(html);
    const mainText = extractMainContent($);

    if (mainText.length < 100) {
      console.log(`  Skipped ${url} (insufficient content: ${mainText.length} chars)`);
      continue;
    }

    const title = $("title").text().trim() || $("h1").first().text().trim() || url;
    const dateStr = extractDate(mainText);

    pages.push({
      url,
      title,
      date: dateStr,
      content: mainText,
      source: "mfsa.mt",
    });
    console.log(`  Fetched: ${title.slice(0, 80)} (${mainText.length} chars)`);

    // Follow links to cybersecurity-related pages
    const cyberLinks = extractLinks(
      $,
      /cyber|ict.*risk|csirt|nis|dora|incident/i,
    );
    for (const link of cyberLinks) {
      const linkedUrl = resolveUrl(link.href, url);
      if (visitedUrls.has(linkedUrl)) continue;
      if (!linkedUrl.startsWith(MFSA_BASE)) continue;
      if (linkedUrl.endsWith(".pdf")) continue;
      visitedUrls.add(linkedUrl);

      const linkedHtml = await fetchHtml(linkedUrl);
      if (!linkedHtml) continue;

      const $linked = cheerio.load(linkedHtml);
      const linkedText = extractMainContent($linked);
      if (linkedText.length < 100) continue;

      const linkedTitle =
        $linked("title").text().trim() ||
        $linked("h1").first().text().trim() ||
        link.text;
      const linkedDate = extractDate(linkedText);

      pages.push({
        url: linkedUrl,
        title: linkedTitle,
        date: linkedDate,
        content: linkedText,
        source: "mfsa.mt",
      });
      console.log(`  Fetched linked: ${linkedTitle.slice(0, 80)} (${linkedText.length} chars)`);
    }
  }

  console.log(`  Total pages from mfsa.mt: ${pages.length}`);
  return pages;
}

// ---------------------------------------------------------------------------
// Page classification: advisory vs guidance
// ---------------------------------------------------------------------------

/**
 * Determine whether a crawled page is an advisory (security alert, threat
 * warning, vulnerability notice) or guidance (policy, standard, strategy,
 * best practice).
 */
function classifyPage(page: DiscoveredPage): "advisory" | "guidance" {
  const lower = (page.title + " " + page.content.slice(0, 1000)).toLowerCase();

  const advisorySignals = [
    /advisory/i,
    /alert\b/i,
    /warning\b/i,
    /vulnerabilit/i,
    /cve-\d{4}/i,
    /exploit/i,
    /zero.?day/i,
    /patch\s*(now|immediately|urgently)/i,
    /security\s*incident/i,
    /threat\s*(actor|campaign|intelligence)/i,
    /ddos\s*attack/i,
    /ransomware\s*attack/i,
    /malware\s*campaign/i,
    /phishing\s*campaign/i,
    /data\s*breach/i,
    /critical\s*update/i,
    /security\s*update/i,
  ];

  let advisoryScore = 0;
  for (const pattern of advisorySignals) {
    if (pattern.test(lower)) advisoryScore++;
  }

  return advisoryScore >= 2 ? "advisory" : "guidance";
}

/**
 * Infer severity from advisory text.
 */
function inferSeverity(text: string): string {
  const lower = text.toLowerCase();
  if (/critical|cvss\s*(score\s*)?[:\s]*(?:9|10)/i.test(lower)) return "critical";
  if (/zero.?day|active(?:ly)?\s*exploit/i.test(lower)) return "critical";
  if (/high|cvss\s*(score\s*)?[:\s]*[78]/i.test(lower)) return "high";
  if (/medium|moderate|cvss\s*(score\s*)?[:\s]*[456]/i.test(lower)) return "medium";
  if (/low|informational|cvss\s*(score\s*)?[:\s]*[0-3]/i.test(lower)) return "low";
  return "medium";
}

/**
 * Infer the guidance type from content.
 */
function inferGuidanceType(text: string, title: string): string {
  const combined = (title + " " + text.slice(0, 1000)).toLowerCase();
  if (/directive|legal\s*notice|transpos/i.test(combined)) return "directive";
  if (/standard|baseline|requirements?\s*for/i.test(combined)) return "standard";
  if (/strategy|strategic\s*pillar/i.test(combined)) return "strategy";
  if (/guideline|guidance|best\s*practice|recommendation/i.test(combined)) return "recommendation";
  if (/framework|policy/i.test(combined)) return "framework";
  if (/awareness|training|education/i.test(combined)) return "awareness";
  if (/report|assessment|audit/i.test(combined)) return "report";
  return "guidance";
}

/**
 * Infer the guidance series from content.
 */
function inferSeries(text: string, title: string, source: string): string {
  const combined = (title + " " + text.slice(0, 1000)).toLowerCase();
  if (/nis\s*2|nis2/i.test(combined)) return "NIS2";
  if (/national\s*(cyber)?security\s*strategy/i.test(combined)) return "national-strategy";
  if (/mita.*standard|standard.*mita|public\s*sector\s*ict/i.test(combined)) return "MITA-standard";
  if (/mfsa|financial\s*sector/i.test(combined)) return "MFSA-cyber";
  if (/dora|digital\s*operational\s*resilience/i.test(combined)) return "DORA";
  if (/incident\s*response|csirt/i.test(combined)) return "incident-response";
  if (source === "ncc-mita.gov.mt") return "NCC";
  return "CSIRT-MT";
}

// ---------------------------------------------------------------------------
// Generate unique reference IDs
// ---------------------------------------------------------------------------

let guidanceCounter = 0;
let advisoryCounter = 0;

function generateGuidanceRef(page: DiscoveredPage): string {
  guidanceCounter++;
  const year = page.date?.slice(0, 4) ?? new Date().getFullYear().toString();
  const num = String(guidanceCounter).padStart(3, "0");

  // Source-based prefix
  if (page.source === "ncc-mita.gov.mt") return `NCC-MT-${year}-${num}`;
  if (page.source === "mfsa.mt") return `MFSA-CS-${year}-${num}`;
  if (page.source === "maltacip.gov.mt") return `CIP-MT-${year}-${num}`;
  return `CSIRT-MT-G-${year}-${num}`;
}

function generateAdvisoryRef(page: DiscoveredPage): string {
  advisoryCounter++;
  const year = page.date?.slice(0, 4) ?? new Date().getFullYear().toString();
  const num = String(advisoryCounter).padStart(3, "0");
  return `CSIRT-MT-ADV-${year}-${num}`;
}

// ---------------------------------------------------------------------------
// Convert pages to DB rows
// ---------------------------------------------------------------------------

function pageToGuidanceRow(page: DiscoveredPage): GuidanceRow {
  const reference = generateGuidanceRef(page);
  const topics = detectTopics(page.content, reference);
  const guidanceType = inferGuidanceType(page.content, page.title);
  const series = inferSeries(page.content, page.title, page.source);

  // Truncate full_text to 50K chars to avoid bloating the DB
  const fullText = page.content.slice(0, 50_000);

  // Build a summary from the first paragraph or first 500 chars
  const summary = page.content
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 2000);

  return {
    reference,
    title: page.title,
    title_en: page.title, // CSIRTMalta content is in English
    date: page.date,
    type: guidanceType,
    series,
    summary,
    full_text: fullText,
    topics: JSON.stringify(topics),
    status: "current",
  };
}

function pageToAdvisoryRow(page: DiscoveredPage): AdvisoryRow {
  const reference = generateAdvisoryRef(page);
  const cves = extractCves(page.content);
  const severity = inferSeverity(page.content);

  // Try to extract affected products from text
  const productPatterns = [
    /affected\s*(?:products?|software|systems?)\s*[:\-]\s*([^\n.]{5,200})/i,
    /impact(?:ed|s)?\s*(?:products?|software|systems?)\s*[:\-]\s*([^\n.]{5,200})/i,
  ];
  let affectedProducts: string[] = [];
  for (const pattern of productPatterns) {
    const match = page.content.match(pattern);
    if (match?.[1]) {
      affectedProducts = match[1]
        .split(/[,;]/)
        .map((p) => p.trim())
        .filter((p) => p.length > 2 && p.length < 200);
      if (affectedProducts.length > 0) break;
    }
  }

  const fullText = page.content.slice(0, 50_000);
  const summary = page.content
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 2000);

  return {
    reference,
    title: page.title,
    date: page.date,
    severity,
    affected_products:
      affectedProducts.length > 0 ? JSON.stringify(affectedProducts) : null,
    summary,
    full_text: fullText,
    cve_references: cves.length > 0 ? JSON.stringify(cves) : null,
  };
}

// ---------------------------------------------------------------------------
// Database insert helpers
// ---------------------------------------------------------------------------

function createInsertStatements(db: Database.Database) {
  const insertGuidance = db.prepare(`
    INSERT OR REPLACE INTO guidance
      (reference, title, title_en, date, type, series, summary, full_text, topics, status)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertAdvisory = db.prepare(`
    INSERT OR REPLACE INTO advisories
      (reference, title, date, severity, affected_products, summary, full_text, cve_references)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertFramework = db.prepare(
    "INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
  );

  const updateFrameworkCount = db.prepare(
    "UPDATE frameworks SET document_count = (SELECT count(*) FROM guidance WHERE series = ?) WHERE id = ?",
  );

  return {
    insertGuidance,
    insertAdvisory,
    insertFramework,
    updateFrameworkCount,
  };
}

// ---------------------------------------------------------------------------
// Main orchestrator
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("CSIRTMalta Ingestion Crawler");
  console.log("============================");
  console.log(`  Database:       ${DB_PATH}`);
  console.log(
    `  Flags:          ${
      [
        force && "--force",
        dryRun && "--dry-run",
        resume && "--resume",
        advisoriesOnly && "--advisories-only",
        guidanceOnly && "--guidance-only",
      ]
        .filter(Boolean)
        .join(", ") || "(none)"
    }`,
  );
  console.log(`  Rate limit:     ${RATE_LIMIT_MS}ms between requests`);
  console.log(`  Max retries:    ${MAX_RETRIES}`);
  console.log(`  Sources:        ${CSIRT_BASE}, ${CIP_BASE}, ${NCC_BASE}, ${MFSA_BASE}`);
  console.log();

  const db = dryRun ? null : initDatabase();
  const stmts = db ? createInsertStatements(db) : null;
  const progress = loadProgress();

  let guidanceInserted = 0;
  let advisoriesInserted = 0;
  let pagesSkipped = 0;

  // ── Frameworks ──────────────────────────────────────────────────────────

  if (!advisoriesOnly && stmts && db) {
    console.log("\n=== Inserting frameworks ===");
    const insertFrameworks = db.transaction(() => {
      for (const f of FRAMEWORKS) {
        stmts.insertFramework.run(
          f.id,
          f.name,
          f.name_en,
          f.description,
          f.document_count,
        );
      }
    });
    insertFrameworks();
    console.log(`  Inserted ${FRAMEWORKS.length} frameworks`);
  }

  // ── Crawl all sources ──────────────────────────────────────────────────

  const allPages: DiscoveredPage[] = [];

  // Source 1: csirtmalta.org (primary)
  const csirtPages = await crawlCsirtMalta();
  allPages.push(...csirtPages);

  // Source 2: maltacip.gov.mt (CIP Directorate)
  const cipPages = await crawlCipDirectorate();
  allPages.push(...cipPages);

  // Source 3: ncc-mita.gov.mt (National Coordination Centre)
  if (!advisoriesOnly) {
    const nccPages = await crawlNccMita();
    allPages.push(...nccPages);
  }

  // Source 4: MFSA cybersecurity communications
  const mfsaPages = await crawlMfsaCyber();
  allPages.push(...mfsaPages);

  // Deduplicate by URL
  const seenUrls = new Set<string>();
  const uniquePages: DiscoveredPage[] = [];
  for (const page of allPages) {
    if (!seenUrls.has(page.url)) {
      seenUrls.add(page.url);
      uniquePages.push(page);
    }
  }

  console.log(
    `\n=== Processing ${uniquePages.length} unique pages (${allPages.length} total, ${allPages.length - uniquePages.length} duplicates removed) ===`,
  );

  // ── Classify and insert ──────────────────────────────────────────────

  for (let i = 0; i < uniquePages.length; i++) {
    const page = uniquePages[i]!;
    const classification = classifyPage(page);
    const isCompleted =
      progress.completed_guidance_urls.includes(page.url) ||
      progress.completed_advisory_urls.includes(page.url) ||
      progress.completed_cip_urls.includes(page.url) ||
      progress.completed_ncc_urls.includes(page.url) ||
      progress.completed_mfsa_urls.includes(page.url);

    if (isCompleted) {
      console.log(
        `  [${i + 1}/${uniquePages.length}] ${page.title.slice(0, 60)} — skipped (already completed)`,
      );
      pagesSkipped++;
      continue;
    }

    if (classification === "advisory" && guidanceOnly) {
      pagesSkipped++;
      continue;
    }
    if (classification === "guidance" && advisoriesOnly) {
      pagesSkipped++;
      continue;
    }

    console.log(
      `  [${i + 1}/${uniquePages.length}] [${classification}] ${page.title.slice(0, 70)}`,
    );

    if (classification === "advisory") {
      const row = pageToAdvisoryRow(page);
      if (dryRun) {
        console.log(
          `    [dry-run] Would insert advisory: ${row.reference} (${row.full_text.length} chars, severity: ${row.severity})`,
        );
      } else if (stmts) {
        stmts.insertAdvisory.run(
          row.reference,
          row.title,
          row.date,
          row.severity,
          row.affected_products,
          row.summary,
          row.full_text,
          row.cve_references,
        );
        advisoriesInserted++;
      }
      progress.completed_advisory_urls.push(page.url);
    } else {
      const row = pageToGuidanceRow(page);
      if (dryRun) {
        console.log(
          `    [dry-run] Would insert guidance: ${row.reference} (${row.full_text.length} chars, type: ${row.type}, series: ${row.series})`,
        );
      } else if (stmts) {
        stmts.insertGuidance.run(
          row.reference,
          row.title,
          row.title_en,
          row.date,
          row.type,
          row.series,
          row.summary,
          row.full_text,
          row.topics,
          row.status,
        );
        guidanceInserted++;
      }
      progress.completed_guidance_urls.push(page.url);
    }

    // Track source-specific progress
    if (page.source === "maltacip.gov.mt") {
      progress.completed_cip_urls.push(page.url);
    } else if (page.source === "ncc-mita.gov.mt") {
      progress.completed_ncc_urls.push(page.url);
    } else if (page.source === "mfsa.mt") {
      progress.completed_mfsa_urls.push(page.url);
    }

    // Save progress every 5 pages
    if ((i + 1) % 5 === 0) {
      saveProgress(progress);
    }
  }
  saveProgress(progress);

  // ── Update framework document counts ────────────────────────────────────

  if (stmts && db && !dryRun) {
    const seriesFrameworkMap: Array<[string, string]> = [
      ["NIS2", "nis2-mt"],
      ["national-strategy", "national-cyber-strategy-mt"],
      ["MITA-standard", "mita-standards"],
      ["CSIRT-MT", "csirt-malta-advisories"],
      ["incident-response", "csirt-malta-advisories"],
      ["MFSA-cyber", "mfsa-cyber"],
    ];

    for (const [series, frameworkId] of seriesFrameworkMap) {
      stmts.updateFrameworkCount.run(series, frameworkId);
    }

    // Also count advisories for the CSIRT Malta framework
    const advisoryCount = (
      db.prepare("SELECT count(*) as cnt FROM advisories").get() as {
        cnt: number;
      }
    ).cnt;
    db.prepare("UPDATE frameworks SET document_count = ? WHERE id = ?").run(
      advisoryCount,
      "csirt-malta-advisories",
    );

    console.log("\n  Updated framework document counts");
  }

  // ── Summary ─────────────────────────────────────────────────────────────

  if (db && !dryRun) {
    const guidanceCount = (
      db.prepare("SELECT count(*) as cnt FROM guidance").get() as {
        cnt: number;
      }
    ).cnt;
    const advisoryCount = (
      db.prepare("SELECT count(*) as cnt FROM advisories").get() as {
        cnt: number;
      }
    ).cnt;
    const frameworkCount = (
      db.prepare("SELECT count(*) as cnt FROM frameworks").get() as {
        cnt: number;
      }
    ).cnt;
    const guidanceFtsCount = (
      db.prepare("SELECT count(*) as cnt FROM guidance_fts").get() as {
        cnt: number;
      }
    ).cnt;
    const advisoryFtsCount = (
      db.prepare("SELECT count(*) as cnt FROM advisories_fts").get() as {
        cnt: number;
      }
    ).cnt;

    console.log("\n============================");
    console.log("Database summary:");
    console.log(`  Frameworks:      ${frameworkCount}`);
    console.log(
      `  Guidance docs:   ${guidanceCount} (FTS entries: ${guidanceFtsCount}) [+${guidanceInserted} this run]`,
    );
    console.log(
      `  Advisories:      ${advisoryCount} (FTS entries: ${advisoryFtsCount}) [+${advisoriesInserted} this run]`,
    );
    console.log(`  Pages skipped:   ${pagesSkipped}`);
    console.log(`\nDatabase ready at ${DB_PATH}`);

    db.close();
  } else if (dryRun) {
    console.log("\n============================");
    console.log("[dry-run] No database changes made");
    console.log(
      `  Crawled ${uniquePages.length} pages from ${new Set(uniquePages.map((p) => p.source)).size} sources`,
    );
    console.log(`  Skipped: ${pagesSkipped}`);
  }

  // Clean up progress file on successful full run (not resume)
  if (!resume && !dryRun && existsSync(PROGRESS_FILE)) {
    unlinkSync(PROGRESS_FILE);
    console.log("Cleaned up progress file");
  }

  console.log("\nDone.");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
