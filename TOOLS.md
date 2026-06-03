# Tools

All tools exposed by the Maltese Cybersecurity MCP. Tool prefix: `mt_cyber_`.

---

## mt_cyber_search_guidance

Full-text search across CSI Malta cybersecurity guidelines, technical standards, and policy documents.

**Input**

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `query` | `string` | yes | Free-text search query |
| `type` | `"directive" \| "guideline" \| "standard" \| "recommendation"` | no | Filter by document type |
| `series` | `"NIS2" \| "MITA-standard" \| "national-strategy"` | no | Filter by document series |
| `status` | `"current" \| "superseded" \| "draft"` | no | Filter by document status |
| `limit` | `number` | no | Max results (default 20, max 100) |

**Output**

```json
{
  "results": [
    {
      "id": 1,
      "reference": "MITA-CS-2024-01",
      "title": "...",
      "title_en": "...",
      "date": "2024-03-01",
      "type": "guideline",
      "series": "NIS2",
      "summary": "...",
      "full_text": "...",
      "topics": "...",
      "status": "current",
      "_citation": { "canonical_ref": "MITA-CS-2024-01", "..." }
    }
  ],
  "count": 1,
  "_meta": { "server": "maltese-cybersecurity-mcp", "version": "0.1.0", "data_date": "2024-03-01", "generated_at": "..." }
}
```

---

## mt_cyber_get_guidance

Retrieve a single guidance document by reference.

**Input**

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `reference` | `string` | yes | CSI Malta document reference (e.g. `MITA-CS-2024-01`) |

**Output**

Full `Guidance` record plus `_citation` and `_meta` blocks.

---

## mt_cyber_search_advisories

Search CSI Malta security advisories and incident alerts.

**Input**

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `query` | `string` | yes | Free-text search query |
| `severity` | `"critical" \| "high" \| "medium" \| "low"` | no | Filter by severity level |
| `limit` | `number` | no | Max results (default 20, max 100) |

**Output**

```json
{
  "results": [
    {
      "id": 1,
      "reference": "MITA-ADV-2024-001",
      "title": "...",
      "date": "2024-01-15",
      "severity": "critical",
      "affected_products": "...",
      "summary": "...",
      "full_text": "...",
      "cve_references": "CVE-2024-1234",
      "_citation": { "canonical_ref": "MITA-ADV-2024-001", "..." }
    }
  ],
  "count": 1,
  "_meta": { "..." }
}
```

---

## mt_cyber_get_advisory

Retrieve a single advisory by reference.

**Input**

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `reference` | `string` | yes | CSI Malta advisory reference (e.g. `MITA-ADV-2024-001`) |

**Output**

Full `Advisory` record plus `_citation` and `_meta` blocks.

---

## mt_cyber_list_frameworks

List all cybersecurity frameworks covered in the database.

**Input:** none

**Output**

```json
{
  "frameworks": [
    { "id": "nis2-mt", "name": "...", "name_en": "...", "description": "...", "document_count": 12 }
  ],
  "count": 3,
  "_meta": { "..." }
}
```

---

## mt_cyber_about

Return server metadata.

**Input:** none

**Output**

```json
{
  "name": "maltese-cybersecurity-mcp",
  "version": "0.1.0",
  "description": "...",
  "data_source": "CSI Malta / MITA (https://csimalta.gov.mt/)",
  "coverage": { "..." },
  "tools": [ { "name": "...", "description": "..." } ],
  "_meta": { "..." }
}
```

---

## mt_cyber_list_sources

List all ingested data sources.

**Input:** none

**Output**

```json
{
  "sources": [
    { "name": "CSI Malta", "url": "https://csimalta.gov.mt/", "description": "..." },
    { "name": "MITA", "url": "https://mita.gov.mt/", "description": "..." }
  ],
  "_meta": { "..." }
}
```

---

## mt_cyber_check_data_freshness

Check the freshness of the underlying database.

**Input:** none

**Output**

```json
{
  "last_updated": "2024-03-01",
  "source": "csimalta.gov.mt",
  "status": "ok",
  "_meta": { "..." }
}
```

`status` values: `"ok"` (data ≤ 90 days old), `"stale"` (data > 90 days old), `"empty"` (no records in DB).

---

## Error Responses

All errors return `isError: true` with a JSON body:

```json
{
  "_meta": { "server": "maltese-cybersecurity-mcp", "version": "0.1.0", "data_date": null, "generated_at": "..." },
  "_error_type": "not_found | tool_error | unknown_tool | execution_error",
  "message": "Human-readable error message"
}
```
