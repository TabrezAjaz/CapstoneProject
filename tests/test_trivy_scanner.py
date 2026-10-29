import argparse
import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from scanner import trivy_scanner as scanner
from scanner.models import ScanResult
from scanner.exceptions import ExceptionPolicyError, apply_allowlist, load_allowlist
from datetime import date


FIXTURES = Path(__file__).parent / "fixtures"


def completed(fixture: str, returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    stdout = (FIXTURES / fixture).read_text(encoding="utf-8") if fixture else ""
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


def test_blocking_count_respects_threshold():
    summary = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "UNKNOWN": 5}
    assert scanner.blocking_count(summary, "CRITICAL") == 1
    assert scanner.blocking_count(summary, "HIGH") == 3
    assert scanner.blocking_count(summary, "MEDIUM") == 6
    assert scanner.blocking_count(summary, "LOW") == 10


def test_model_uses_configurable_threshold():
    result = ScanResult(image="demo", summary={"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3})
    assert result.blocking("HIGH") == 3
    assert result.blocking("CRITICAL") == 1


def test_scan_parses_findings_and_builds_safe_command(monkeypatch):
    run_mock = Mock(return_value=completed("trivy-fail.json"))
    monkeypatch.setattr(scanner.subprocess, "run", run_mock)
    result = scanner.scan_image("demo:1", ["HIGH", "CRITICAL"], True, ["os"], "5m")
    assert result["summary"]["HIGH"] == 1
    assert result["summary"]["CRITICAL"] == 1
    assert len(result["findings"]) == 2
    command = run_mock.call_args.args[0]
    assert command[-1] == "demo:1"
    assert "--ignore-unfixed" in command
    assert run_mock.call_args.kwargs["check"] is False


def test_scan_handles_null_vulnerabilities(monkeypatch):
    monkeypatch.setattr(scanner.subprocess, "run", Mock(return_value=completed("trivy-empty.json")))
    assert sum(scanner.scan_image("empty:1")["summary"].values()) == 0


def test_scan_reports_missing_executable(monkeypatch):
    monkeypatch.setattr(scanner.subprocess, "run", Mock(side_effect=FileNotFoundError()))
    with pytest.raises(scanner.ScannerError, match="not found"):
        scanner.scan_image("demo:1")


def test_scan_reports_process_and_json_failures(monkeypatch):
    monkeypatch.setattr(scanner.subprocess, "run", Mock(return_value=completed("", 2, "registry failed")))
    with pytest.raises(scanner.ScannerError, match="registry failed"):
        scanner.scan_image("demo:1")
    bad = subprocess.CompletedProcess([], 0, stdout="not-json", stderr="")
    monkeypatch.setattr(scanner.subprocess, "run", Mock(return_value=bad))
    with pytest.raises(scanner.ScannerError, match="invalid JSON"):
        scanner.scan_image("demo:1")


def test_cli_environment_yaml_precedence(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("scanner:\n  fail_on: MEDIUM\n  timeout: 2m\noutput:\n  dir: yaml-results\n", encoding="utf-8")
    parser = scanner.build_parser()
    args = parser.parse_args(["demo:1", "--config", str(config), "--fail-on", "CRITICAL"])
    settings = scanner.resolve_settings(args, {"SCANNER_FAIL_ON": "HIGH", "SCANNER_TIMEOUT": "3m"})
    assert settings["fail_on"] == "CRITICAL"
    assert settings["timeout"] == "3m"
    assert settings["output_dir"] == "yaml-results"


def test_environment_image_and_boolean_are_resolved():
    args = scanner.build_parser().parse_args([])
    settings = scanner.resolve_settings(args, {"SCAN_IMAGE": "demo:1", "SCANNER_IGNORE_UNFIXED": "yes"})
    assert settings["images"] == ["demo:1"]
    assert settings["ignore_unfixed"] is True


@pytest.mark.parametrize("arguments,environment", [
    (["demo:1", "--fail-on", "UNKNOWN"], {}),
    (["demo:1", "--severity", "EXTREME"], {}),
    (["demo:1", "--timeout", "forever"], {}),
    ([], {"SCAN_IMAGE": "demo:1", "SCANNER_IGNORE_UNFIXED": "perhaps"}),
])
def test_invalid_configuration_returns_exit_2(arguments, environment):
    assert scanner.run(arguments, environment) == 2


def test_policy_pass_writes_artifact_and_returns_0(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.subprocess, "run", Mock(return_value=completed("trivy-pass.json")))
    code = scanner.run(["safe:1", "--output-dir", str(tmp_path)], {})
    assert code == 0
    artifacts = list(tmp_path.glob("*.json"))
    assert len(artifacts) == 1
    payload = json.loads(artifacts[0].read_text(encoding="utf-8"))
    assert payload["policy"]["passed"] is True


def test_policy_block_writes_artifact_and_returns_1(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.subprocess, "run", Mock(return_value=completed("trivy-fail.json")))
    code = scanner.run(["vulnerable:1", "--output-dir", str(tmp_path)], {})
    assert code == 1
    payload = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert payload["policy"]["blocking_findings"] == 2
    assert payload["policy"]["passed"] is False


def test_operational_failure_returns_exit_3(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.subprocess, "run", Mock(side_effect=FileNotFoundError()))
    assert scanner.run(["demo:1", "--output-dir", str(tmp_path)], {}) == 3


def test_all_configured_continues_and_prioritizes_operational_failure(monkeypatch, tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("images: [first:1, second:1]\noutput:\n  dir: results\n", encoding="utf-8")
    monkeypatch.setattr(scanner, "scan_image", Mock(side_effect=[
        {"image": "first:1", "summary": {"HIGH": 1}, "findings": []},
        scanner.ScannerError("network error"),
    ]))
    assert scanner.run(["--config", str(config), "--all-configured", "--output-dir", str(tmp_path / "out")], {}) == 3


def test_allowlist_preserves_audit_and_scopes_exactly(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.subprocess, "run", Mock(return_value=completed("trivy-fail.json")))
    result = scanner.scan_image("demo:1")
    path = tmp_path / "allowlist.yaml"
    path.write_text("exceptions:\n  - id: CVE-TEST-HIGH\n    reason: Approved test risk\n    expires: 2026-10-29\n    image: demo:1\n    pkg: openssl\n")
    policy = load_allowlist(path)
    filtered = apply_allowlist(result, policy, date(2026, 10, 29))
    assert filtered["summary"]["HIGH"] == 0
    assert filtered["raw_summary"]["HIGH"] == 1
    assert filtered["suppressed_findings"][0]["exception"]["reason"] == "Approved test risk"
    assert len(filtered["exception_policy"]["sha256"]) == 64
    assert len(result["findings"]) == 2
    other = apply_allowlist({**result, "image": "other:1"}, policy, date(2026, 10, 29))
    assert other["suppressed_findings"] == []
    expired = apply_allowlist(result, policy, date(2026, 10, 30))
    assert expired["summary"]["HIGH"] == 1
    assert expired["exception_policy"]["expired"][0]["id"] == "CVE-TEST-HIGH"


@pytest.mark.parametrize("content", [
    "exceptions: null", "exceptions: {}", "other: []", "exceptions: [bad]",
    "exceptions: [{id: '*', reason: approved, expires: 2027-01-01}]",
    "exceptions: [{id: CVE-TEST, reason: '', expires: 2027-01-01}]",
    "exceptions: [{id: CVE-TEST, reason: approved, expires: forever}]",
    "exceptions: [{id: CVE-TEST, reason: approved, expires: 20261030}]",
    "exceptions: [{id: CVE-TEST, reason: approved}]",
    "exceptions: [{id: CVE-TEST, reason: approved, expires: 2027-01-01, image: '*'}]",
    "exceptions: [{id: CVE-TEST, reason: approved, expires: 2027-01-01, typo: true}]",
    "exceptions: [{id: CVE-TEST, reason: approved, expires: 2027-01-01}, {id: CVE-TEST, reason: duplicate, expires: 2027-01-01}]",
])
def test_invalid_allowlists_fail_closed(tmp_path, content):
    path = tmp_path / "allowlist.yaml"
    path.write_text(content)
    with pytest.raises(ExceptionPolicyError):
        load_allowlist(path)


def test_missing_allowlist_is_not_silently_ignored(tmp_path):
    with pytest.raises(ExceptionPolicyError):
        load_allowlist(tmp_path / "missing.yaml")
    assert load_allowlist(None)["rules"] == []


def test_allowlist_changes_gate_and_keeps_raw_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.subprocess, "run", Mock(return_value=completed("trivy-fail.json")))
    policy = tmp_path / "approved.yaml"
    policy.write_text("exceptions:\n  - {id: CVE-TEST-HIGH, reason: Approved fixture, expires: 2099-01-01}\n  - {id: CVE-TEST-CRITICAL, reason: Approved fixture, expires: 2099-01-01}\n")
    assert scanner.run(["demo:1", "--exceptions-file", str(policy), "--output-dir", str(tmp_path / "out")], {}) == 0
    artifact = json.loads(next((tmp_path / "out").glob("*.json")).read_text())
    assert artifact["policy"]["blocking_findings"] == 0
    assert len(artifact["suppressed_findings"]) == 2
    assert sum(artifact["raw_summary"].values()) == 2
    assert artifact["findings"] == []


def test_invalid_exception_file_prevents_scanner_execution(monkeypatch, tmp_path):
    process = Mock()
    monkeypatch.setattr(scanner.subprocess, "run", process)
    assert scanner.run(["demo:1", "--exceptions-file", str(tmp_path / "missing")], {}) == 2
    process.assert_not_called()


def test_yaml_exception_path_is_relative_to_config_file(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.subprocess, "run", Mock(return_value=completed("trivy-pass.json")))
    (tmp_path / "approved.yaml").write_text("exceptions: []\n")
    config = tmp_path / "custom.yaml"
    config.write_text("exceptions_file: approved.yaml\n")
    assert scanner.run(["demo:1", "--config", str(config), "--output-dir", str(tmp_path / "out")], {}) == 0


def test_transient_failure_retries_but_permanent_failure_does_not(monkeypatch):
    sleep = Mock()
    process = Mock(side_effect=[completed("", 1, "registry: 503 Service Unavailable"), completed("trivy-pass.json")])
    monkeypatch.setattr(scanner.time, "sleep", sleep)
    monkeypatch.setattr(scanner.subprocess, "run", process)
    assert scanner.scan_image("demo:1")["image"] == "demo:1"
    assert process.call_count == 2
    sleep.assert_called_once_with(1)
    process.reset_mock(side_effect=True)
    process.side_effect = None
    process.return_value = completed("", 1, "unauthorized: 503")
    with pytest.raises(scanner.ScannerError, match="unauthorized"):
        scanner.scan_image("demo:1")
    assert process.call_count == 1


def test_retry_exhaustion_and_timeout_fail_closed(monkeypatch, tmp_path):
    process = Mock(return_value=completed("", 1, "connection reset"))
    monkeypatch.setattr(scanner.subprocess, "run", process)
    monkeypatch.setattr(scanner.time, "sleep", Mock())
    assert scanner.run(["demo:1", "--retries", "2", "--output-dir", str(tmp_path)], {}) == 3
    assert process.call_count == 3
    assert list(tmp_path.glob("*.json")) == []
    process.side_effect = subprocess.TimeoutExpired("trivy", 30)
    with pytest.raises(scanner.ScannerError, match="timed out"):
        scanner.scan_image("demo:1", retries=0)


def test_fresh_rescan_preserves_lineage_and_refreshes_database(monkeypatch, tmp_path):
    process = Mock(return_value=completed("trivy-pass.json"))
    monkeypatch.setattr(scanner.subprocess, "run", process)
    prior = FIXTURES / "normalized-scan-v1.json"
    assert scanner.run(["--rescan-artifact", str(prior), "--refresh-db", "--output-dir", str(tmp_path)], {}) == 0
    artifact = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert artifact["rescan_of"] == json.loads(prior.read_text())["scan_id"]
    assert artifact["scan_id"] != artifact["rescan_of"]
    assert process.call_args_list[0].args[0] == ["trivy", "image", "--download-db-only"]
    assert process.call_args_list[1].args[0][-1] == "example/app:1"


@pytest.mark.parametrize("arguments", [["--retries", "-1"], ["--retries", "6"], ["--retry-backoff", "nan"], ["--retry-backoff", "31"], ["--timeout", "0m"]])
def test_invalid_retry_configuration(arguments):
    assert scanner.run(["demo:1", *arguments], {}) == 2


@pytest.mark.parametrize("payload", ["", "{}", "[]", '{"Results": {"bad": true}}',
    '{"Results": {}}', '{"Results": false}', '{"Results": 0}', '{"ArtifactName": "incomplete"}',
    '{"Results": [{"Vulnerabilities": {}}]}',
    '{"Results": [null]}', '{"Results": [{"Vulnerabilities": [null]}]}',
    '{"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "test", "Severity": "EXTREME"}]}]}'])
def test_malformed_trivy_output_never_becomes_a_clean_scan(monkeypatch, tmp_path, payload):
    monkeypatch.setattr(scanner.subprocess, "run", Mock(return_value=subprocess.CompletedProcess([], 0, stdout=payload, stderr="")))
    assert scanner.run(["demo:1", "--output-dir", str(tmp_path)], {}) == 3
    assert list(tmp_path.glob("*.json")) == []


def test_blank_configured_images_fail_closed(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text('images: [" "]\n')
    assert scanner.run(["--config", str(config), "--all-configured"], {}) == 2
    assert scanner.run([], {"SCAN_IMAGE": "--clear-cache"}) == 2


def test_artifact_write_failure_is_operational_and_leaves_no_partial_file(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.subprocess, "run", Mock(return_value=completed("trivy-pass.json")))
    monkeypatch.setattr(scanner.os, "replace", Mock(side_effect=PermissionError("write denied")))
    assert scanner.run(["demo:1", "--output-dir", str(tmp_path)], {}) == 3
    assert list(tmp_path.iterdir()) == []


def test_real_scratch_image_metadata_can_have_no_results(monkeypatch):
    process = subprocess.CompletedProcess([], 0, stdout='{"SchemaVersion": 2, "ArtifactName": "hello-world:latest"}', stderr="")
    monkeypatch.setattr(scanner.subprocess, "run", Mock(return_value=process))
    assert sum(scanner.scan_image("hello-world:latest")["summary"].values()) == 0
