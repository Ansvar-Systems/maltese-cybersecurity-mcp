#!/usr/bin/env node

/**
 * HTTP Server Entry Point for Docker Deployment
 *
 * Provides Streamable HTTP transport for remote MCP clients.
 * Use src/index.ts for local stdio-based usage.
 *
 * Endpoints:
 *   GET  /health  — liveness probe
 *   POST /mcp     — MCP Streamable HTTP (session-aware)
 */

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
  getLatestDataDate,
} from "./db.js";
import { buildCitation } from "./utils/citation.js";
import { responseMeta } from "./utils/meta.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = parseInt(process.env["PORT"] ?? "3000", 10);
const SERVER_NAME = "maltese-cybersecurity-mcp";

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback
}

// --- Tool definitions (shared with index.ts) ---------------------------------

const TOOLS = [
  {
    name: "mt_cyber_search_guidance",
    description:
      "Full-text search across CSI Malta cybersecurity guidelines, technical standards, and policy documents. Covers national cybersecurity strategy, NIS2 implementation guidance, MITA technical standards, and critical infrastructure protection frameworks. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query (e.g., 'NIS2 compliance', 'incident response', 'critical infrastructure security')" },
        type: {
          type: "string",
          enum: ["directive", "guideline", "standard", "recommendation"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["NIS2", "MITA-standard", "national-strategy"],
          description: "Filter by series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Optional.",
        },
        limit: { type: "number", description: "Max results (default 20)." },
      },
      required: ["query"],
    },
  },
  {
    name: "mt_cyber_get_guidance",
    description:
      "Get a specific CSI Malta guidance document by reference (e.g., 'MITA-CS-2024-01', 'MT-NIS2-2024').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: { type: "string", description: "CSI Malta document reference (e.g., 'MITA-CS-2024-01')" },
      },
      required: ["reference"],
    },
  },
  {
    name: "mt_cyber_search_advisories",
    description:
      "Search CSI Malta security advisories and incident alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query (e.g., 'critical vulnerability', 'ransomware', 'data breach')" },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: { type: "number", description: "Max results (default 20)." },
      },
      required: ["query"],
    },
  },
  {
    name: "mt_cyber_get_advisory",
    description: "Get a specific CSI Malta security advisory by reference (e.g., 'MITA-ADV-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: { type: "string", description: "CSI Malta advisory reference (e.g., 'MITA-ADV-2024-001')" },
      },
      required: ["reference"],
    },
  },
  {
    name: "mt_cyber_list_frameworks",
    description:
      "List all CSI Malta cybersecurity frameworks covered in this MCP, including national cybersecurity strategy and NIS2 implementation framework.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "mt_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "mt_cyber_list_sources",
    description: "List all data sources ingested into this MCP, including official CSI Malta and MITA portals.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "mt_cyber_check_data_freshness",
    description: "Check the freshness of the underlying data: returns the most recent record date, source, and a status of 'ok', 'stale', or 'empty'.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
];

// --- Zod schemas -------------------------------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["directive", "guideline", "standard", "recommendation"]).optional(),
  series: z.enum(["NIS2", "MITA-standard", "national-strategy"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- MCP server factory ------------------------------------------------------

function createMcpServer(): Server {
  const server = new Server(
    { name: SERVER_NAME, version: pkgVersion },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    function textContent(data: unknown) {
      const payload =
        typeof data === "object" && data !== null
          ? { ...(data as object), _meta: responseMeta(SERVER_NAME, pkgVersion) }
          : { data, _meta: responseMeta(SERVER_NAME, pkgVersion) };
      return {
        content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
      };
    }

    function errorContent(message: string, errorType = "tool_error") {
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                _meta: responseMeta(SERVER_NAME, pkgVersion),
                _error_type: errorType,
                message,
              },
              null,
              2,
            ),
          },
        ],
        isError: true as const,
      };
    }

    try {
      switch (name) {
        case "mt_cyber_search_guidance": {
          const parsed = SearchGuidanceArgs.parse(args);
          const results = searchGuidance({
            query: parsed.query,
            type: parsed.type,
            series: parsed.series,
            status: parsed.status,
            limit: parsed.limit,
          });
          const resultsWithCitation = results.map((doc) => ({
            ...doc,
            _citation: buildCitation(
              doc.reference,
              doc.title || doc.reference,
              "mt_cyber_get_guidance",
              { reference: doc.reference },
            ),
          }));
          return textContent({ results: resultsWithCitation, count: results.length });
        }

        case "mt_cyber_get_guidance": {
          const parsed = GetGuidanceArgs.parse(args);
          const doc = getGuidance(parsed.reference);
          if (!doc) {
            return errorContent(
              `Guidance document not found: ${parsed.reference}`,
              "not_found",
            );
          }
          const d = doc as Record<string, unknown>;
          return textContent({
            ...doc,
            _citation: buildCitation(
              String(d["reference"] || parsed.reference),
              String(d["title"] || d["reference"] || parsed.reference),
              "mt_cyber_get_guidance",
              { reference: parsed.reference },
              d["source_url"] as string | undefined,
            ),
          });
        }

        case "mt_cyber_search_advisories": {
          const parsed = SearchAdvisoriesArgs.parse(args);
          const results = searchAdvisories({
            query: parsed.query,
            severity: parsed.severity,
            limit: parsed.limit,
          });
          const resultsWithCitation = results.map((adv) => ({
            ...adv,
            _citation: buildCitation(
              adv.reference,
              adv.title || adv.reference,
              "mt_cyber_get_advisory",
              { reference: adv.reference },
            ),
          }));
          return textContent({ results: resultsWithCitation, count: results.length });
        }

        case "mt_cyber_get_advisory": {
          const parsed = GetAdvisoryArgs.parse(args);
          const advisory = getAdvisory(parsed.reference);
          if (!advisory) {
            return errorContent(
              `Advisory not found: ${parsed.reference}`,
              "not_found",
            );
          }
          const a = advisory as Record<string, unknown>;
          return textContent({
            ...advisory,
            _citation: buildCitation(
              String(a["reference"] || parsed.reference),
              String(a["title"] || a["reference"] || parsed.reference),
              "mt_cyber_get_advisory",
              { reference: parsed.reference },
              a["source_url"] as string | undefined,
            ),
          });
        }

        case "mt_cyber_list_frameworks": {
          const frameworks = listFrameworks();
          return textContent({ frameworks, count: frameworks.length });
        }

        case "mt_cyber_about": {
          return textContent({
            name: SERVER_NAME,
            version: pkgVersion,
            description:
              "CSI Malta (Cybersecurity Intelligence Malta / MITA) MCP server. Provides access to Maltese national cybersecurity guidelines, MITA technical standards, NIS2 implementation documents, and security advisories.",
            data_source: "CSI Malta / MITA (https://csimalta.gov.mt/)",
            tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
          });
        }

        case "mt_cyber_list_sources": {
          return textContent({
            sources: [
              {
                name: "CSI Malta",
                url: "https://csimalta.gov.mt/",
                description:
                  "Cybersecurity Intelligence Malta — national cybersecurity guidance, advisories, and incident alerts published by the government of Malta.",
              },
              {
                name: "MITA",
                url: "https://mita.gov.mt/",
                description:
                  "Malta Information Technology Agency — technical standards, IT governance frameworks, and NIS2 implementation guidance.",
              },
            ],
          });
        }

        case "mt_cyber_check_data_freshness": {
          const lastUpdated = getLatestDataDate();
          let status: "ok" | "stale" | "empty" = "ok";
          if (!lastUpdated) {
            status = "empty";
          } else {
            const daysSince = Math.floor(
              (Date.now() - new Date(lastUpdated).getTime()) / (1000 * 60 * 60 * 24),
            );
            if (daysSince > 90) status = "stale";
          }
          return textContent({
            last_updated: lastUpdated,
            source: "csimalta.gov.mt",
            status,
          });
        }

        default:
          return errorContent(`Unknown tool: ${name}`, "unknown_tool");
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return errorContent(`Error executing ${name}: ${message}`, "execution_error");
    }
  });

  return server;
}

// --- HTTP server -------------------------------------------------------------

async function main(): Promise<void> {
  const sessions = new Map<
    string,
    { transport: StreamableHTTPServerTransport; server: Server }
  >();

  const httpServer = createServer((req, res) => {
    handleRequest(req, res, sessions).catch((err) => {
      console.error(`[${SERVER_NAME}] Unhandled error:`, err);
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal server error" }));
      }
    });
  });

  async function handleRequest(
    req: import("node:http").IncomingMessage,
    res: import("node:http").ServerResponse,
    activeSessions: Map<
      string,
      { transport: StreamableHTTPServerTransport; server: Server }
    >,
  ): Promise<void> {
    const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", server: SERVER_NAME, version: pkgVersion }));
      return;
    }

    if (url.pathname === "/mcp") {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      if (sessionId && activeSessions.has(sessionId)) {
        const session = activeSessions.get(sessionId)!;
        await session.transport.handleRequest(req, res);
        return;
      }

      const mcpServer = createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- SDK type mismatch with exactOptionalPropertyTypes
      await mcpServer.connect(transport as any);

      transport.onclose = () => {
        if (transport.sessionId) {
          activeSessions.delete(transport.sessionId);
        }
        mcpServer.close().catch(() => {});
      };

      await transport.handleRequest(req, res);

      if (transport.sessionId) {
        activeSessions.set(transport.sessionId, { transport, server: mcpServer });
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  }

  httpServer.listen(PORT, () => {
    console.error(`${SERVER_NAME} v${pkgVersion} (HTTP) listening on port ${PORT}`);
    console.error(`MCP endpoint:  http://localhost:${PORT}/mcp`);
    console.error(`Health check:  http://localhost:${PORT}/health`);
  });

  process.on("SIGTERM", () => {
    console.error("Received SIGTERM, shutting down...");
    httpServer.close(() => process.exit(0));
  });
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
