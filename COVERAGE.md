# Coverage

Documents the completeness of the CSI Malta corpus ingested into this MCP.

## Data Sources

| Source | URL | Type |
| ------ | --- | ---- |
| CSI Malta | https://csimalta.gov.mt/ | Guidance, advisories |
| MITA | https://mita.gov.mt/ | Technical standards |

## Corpus Coverage

### Guidance Documents

| Series | Description | Status |
| ------ | ----------- | ------ |
| `national-strategy` | Malta National Cybersecurity Strategy documents | Ingested |
| `NIS2` | NIS2 Directive implementation guidance for Malta | Ingested |
| `MITA-standard` | MITA technical standards for government IT systems | Ingested |

Document types covered: `directive`, `guideline`, `standard`, `recommendation`.

Document statuses: `current`, `superseded`, `draft`.

### Security Advisories

CSI Malta security advisories and incident alerts, including CVE references and affected product information where published.

Severity levels: `critical`, `high`, `medium`, `low`.

### Frameworks

| ID | Name |
| -- | ---- |
| `nis2-mt` | Malta NIS2 Implementation Framework |
| `national-cyber-strategy-mt` | Malta National Cybersecurity Strategy |
| `mita-standards` | MITA Technical Standards Series |

## Freshness

Data is ingested monthly via the `ingest.yml` workflow. Use the `mt_cyber_check_data_freshness` tool to query the date of the most recent record in the database.

## Known Gaps

- Full text of documents may not always be available if the source publishes only summaries.
- Historical advisories prior to 2020 may be incomplete.
- Documents published in Maltese only (no English translation) are indexed but may have empty `title_en`.

## data/coverage.json

Machine-readable coverage metadata is stored in [`data/coverage.json`](data/coverage.json).
