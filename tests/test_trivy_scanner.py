import argparse
import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from scanner import trivy_scanner as scanner
from scanner.models import ScanResult


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
