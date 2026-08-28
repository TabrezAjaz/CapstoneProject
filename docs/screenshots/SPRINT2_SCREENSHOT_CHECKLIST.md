# Sprint 2 evidence checklist

Capture only genuine executions and redact credentials.

## Local
- Pytest suite passing.
- Policy pass showing exit code 0 and JSON artifact.
- Policy block showing exit code 1 and JSON artifact.
- Invalid configuration showing exit code 2.
- Scanner/registry failure showing exit code 3.

## GitHub Actions
- Workflow trigger and least-privilege permissions.
- Green passing workflow.
- Red policy-blocked workflow.
- JSON and JUnit artifacts retained on the blocked run.
- Required branch-protection check, if enabled.

## Jenkins
- Pipeline parameters and Script Path `ci/Jenkinsfile`.
- Green Stage View.
- Red policy-blocked Stage View.
- Console policy summary and archived JSON/JUnit evidence.

For every live scan, retain the image reference/digest, Trivy version, scan date, threshold, and final status.
