# Capstone Submission

**Student:** Tabrez Ajaz

**Project:** Container Image Vulnerability Scanner with Reporting

## Vlearn Upload

The submission instructions request the GitHub repository link in a text,
Word or PDF file. Upload [Repository_Link.txt](Repository_Link.txt) for that
requirement. The project code is published on the repository's `main` branch.

Upload [Final_Project_Report.pdf](Final_Project_Report.pdf) as supporting
documentation when the portal permits an additional attachment. It contains
the Sprint 1-5 implementation, deployment architecture, verification results,
21 figures, including actual Slack-channel alerts, summaries and scheduled-run evidence,
reproduction steps and limitations.

[Final_Project_Report.html](Final_Project_Report.html) is an optional browser
edition with embedded images. It does not need an adjacent image folder.
Original artifact and source links open the public GitHub repository and
require internet access; academic Jenkins links may require authentication.

## Verification Scope

The evidence covers clean and blocked scans, passing and blocked CI builds,
generated reports, Jenkins notification delivery, summary jobs, dashboard,
Prometheus, Grafana, exception approval/expiry and rescan lineage. The final
integrated test run has 77 passing tests.

Slack-channel receipt is verified by the HIGH/CRITICAL and daily/weekly
screenshots captured on 31 October 2026. Final main GitHub run #34 and scheduled
run #2 passed, but their Slack steps were skipped. The final settings check
showed no repository secrets: GitHub notification credential setup remains
pending. Webhook rotation requires separate confirmation. GitHub scheduled run #2
completed successfully with event type `schedule`; the documented Jenkins
default-parameter checks were manual. Live registry outage recovery is not
claimed. These limits are retained in Section 13 of the report.

## Upload Files

- Required: Repository_Link.txt.
- Supporting attachment, if permitted: Final_Project_Report.pdf.
- Optional local reference: Final_Project_Report.html and this README.

The portal instructions accept the repository link in a text, Word or PDF
file. Do not assume that the portal accepts folders or ZIP archives.

Do not upload credentials, virtual environments, local databases or unrelated
workspace files. The repository-link file is the required portal deliverable;
this folder has not been submitted to Vlearn automatically.