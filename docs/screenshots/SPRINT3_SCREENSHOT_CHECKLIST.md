# Sprint 3 evidence checklist

Capture only genuine executions. Redact webhook URLs, tokens, cookies, private channel names, and
any sensitive controller details.

## Live Slack delivery evidence (29 October 2026)

Original UTC console excerpts and verified artifact inventories are embedded directly in
`../Sprint3_Reporting_and_Notifications_Report.html`, sections 12.1 through 12.6.
These are source-text evidence, not screenshots of Slack messages.

| Case | Jenkins run | Verified result | Report identifier | Archived files |
|---|---|---|---|---|
| HIGH alert | Main #4 | Delivered in 1 attempt; expected policy FAILURE; 28 tests passed | `vulnerability-run-4db7171c` | 5 |
| CRITICAL alert | Main #5 | Delivered in 1 attempt; expected policy FAILURE; 28 tests passed | `vulnerability-run-4dfa0116` | 5 |
| Daily summary | Daily #16 | Delivered in 1 attempt; SUCCESS | `vulnerability-daily-54236362` | 8 |
| Weekly summary | Weekly #4 | Delivered in 1 attempt; SUCCESS | `vulnerability-weekly-26dc6136` | 8 |

Both summaries freshly scanned all four configured images with `NOTIFY=true`.
The report includes the exact console timestamps, current severity counts, and direct links to
the archived JSON, HTML, PDF, and SHA-256 manifests. Manual delivery success does not establish
that scheduled notification defaults are enabled.

Browser screenshot export was blank/unreliable in this session. The blank output was removed;
no fabricated screenshots were added. Channel-side HIGH, CRITICAL, daily, and weekly screenshots
remain pending and must be captured from the Capstone workspace without showing webhook values.

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
