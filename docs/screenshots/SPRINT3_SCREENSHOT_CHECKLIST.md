# Sprint 3 evidence checklist

Capture only genuine executions. Redact webhook URLs, tokens, cookies, private channel names, and
any sensitive controller details.

## Local (captured)

| Figure | File | Shows |
|---|---|---|
| 1 | `sprint3-local-tests-and-reports.png` | 28 passing tests, scanner exits `0`/`1`, one-command report generation |
| 2 | `sprint3-scan-artifact-schema.png` | Schema 1.0 artifact fields, summary vs policy, real findings |
| 3 | `sprint3-notification-policy.png` | Below-threshold skip, non-Slack host rejection, missing secret |
| 4 | `sprint3-report-manifest.png` | Manifest with media types, sizes, and SHA-256 checksums |
| 5 | `sprint3-html-report.png` | Rendered multi-image HTML report |
| 6 | `sprint3-pdf-report.png` | Rendered multipage PDF report |

## GitHub Actions (pending)

| Figure | Shows |
|---|---|
| 7 | Green run with the report generation step passing |
| 8 | Run summary showing uploaded JSON/HTML/PDF evidence artifacts |
| 9 | Report artifact contents expanded in the run page |
| 10 | Manual `daily` dispatch of the scheduled summary workflow |
| 11 | Manual `weekly` dispatch of the scheduled summary workflow |
| 12 | Secret name `SLACK_WEBHOOK_URL` configured with the value hidden |

## Jenkins (pending)

| Figure | Shows |
|---|---|
| 13 | Sprint 3 pipeline job configuration (branch, Script Path, parameters) |
| 14 | `Notify Slack` parameter and `slack-webhook-url` credential with value hidden |
| 15 | Green build with Generate Reports and Notify Slack stages passing |
| 16 | Blocked build that still archived JSON/HTML/PDF reports |
| 17 | Archived artifacts list with the report manifest |
| 18 | Daily and weekly summary jobs with their UTC cron triggers |
| 19 | Completed daily summary build with archived outputs |

## Slack (pending)

| Figure | Shows |
|---|---|
| 20 | Clean daily summary message |
| 21 | HIGH severity alert with orange styling and counts |
| 22 | CRITICAL severity alert with red styling and counts |
| 23 | Daily heading and weekly heading in the same channel |

For every live run, record the image reference or digest, Trivy version, scan timestamp, threshold,
report ID or checksum, and the final status so evidence stays traceable.
