/**
 * Response metadata helper for the Maltese Cybersecurity MCP.
 *
 * Every tool response includes a _meta block so callers can inspect the
 * server version and the vintage of the underlying data without needing to
 * call mt_cyber_check_data_freshness explicitly.
 */

import { getLatestDataDate } from "../db.js";

export interface ResponseMeta {
  server: string;
  version: string;
  data_date: string | null;
  generated_at: string;
}

export function responseMeta(serverName: string, version: string): ResponseMeta {
  return {
    server: serverName,
    version,
    data_date: getLatestDataDate(),
    generated_at: new Date().toISOString(),
  };
}
