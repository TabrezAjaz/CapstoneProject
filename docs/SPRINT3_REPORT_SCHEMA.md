# Sprint 3 report and notification contracts

## Normalized scan artifact 1.0

Required fields: `schema_version`, `scan_id`, `scanned_at`, `image`, five-key `summary`, `findings`, `policy`, `scan_options`, `scanner`, and optional sanitized `source`. Summary counts must equal findings.

## Canonical report 1.0

A report contains one or more explicit normalized artifacts, a report ID, generation time, cadence (`run`, `daily`, or `weekly`), aggregate totals, overall status, image details, and source context. JSON, HTML, and PDF are generated from this same model. The adjacent manifest records media types, sizes, and SHA-256 checksums.

## Security

Raw Trivy and legacy artifacts are rejected. HTML is autoescaped. Slack webhooks are read only from `SLACK_WEBHOOK_URL`, validated as Slack HTTPS endpoints, never logged, and retried only for transient failures.
