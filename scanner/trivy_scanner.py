"""Trivy image scanner and policy-aware CI/CD gate.

Exit codes: 0=policy passed, 1=policy blocked, 2=invalid configuration,
3=scanner or artifact failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from .exceptions import ExceptionPolicyError, apply_allowlist, load_allowlist

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("trivy_scanner")

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ARTIFACT_SCHEMA_VERSION = "1.0"
WRAPPER_VERSION = "0.5.0"
DEFAULT_CONFIG: dict[str, Any] = {
    "scanner": {
        "severities": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        "fail_on": "HIGH",
        "ignore_unfixed": False,
        "pkg_types": ["os"],
        "timeout": "15m",
        "retries": 2,
        "retry_backoff": 1,
    },
    "output": {"dir": "./scan-results"},
    "images": ["nginx:latest"],
}


class ConfigurationError(ValueError):
    """Raised when scanner configuration is invalid."""


class ScannerError(RuntimeError):
    """Raised when Trivy or artifact generation fails."""


def _parse_list(value: Any, name: str, allowed: set[str] | None = None) -> list[str]:
    items = value if isinstance(value, list) else str(value).split(",")
    normalized = list(dict.fromkeys(str(item).strip().upper() for item in items if str(item).strip()))
    if not normalized:
        raise ConfigurationError(f"{name} cannot be empty")
    invalid = set(normalized) - allowed if allowed else set()
    if invalid:
        raise ConfigurationError(f"Invalid {name}: {', '.join(sorted(invalid))}")
    return normalized


def _parse_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


def load_config(path: str = "config.yaml", required: bool = False) -> dict[str, Any]:
    """Load YAML configuration and merge it over safe defaults."""
    config = {
        "scanner": dict(DEFAULT_CONFIG["scanner"]),
        "output": dict(DEFAULT_CONFIG["output"]),
        "images": list(DEFAULT_CONFIG["images"]),
    }
    config_path = Path(path)
    if not config_path.exists():
        if required:
            raise ConfigurationError(f"Configuration file not found: {path}")
        logger.info("Config not found; using defaults: %s", path)
        return config
    try:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Cannot read configuration {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigurationError("Configuration root must be a mapping")
    if isinstance(loaded.get("scanner"), dict):
        config["scanner"].update(loaded["scanner"])
    if isinstance(loaded.get("output"), dict):
        config["output"].update(loaded["output"])
    if "images" in loaded:
        config["images"] = loaded["images"]
    if "exceptions_file" in loaded:
        config["exceptions_file"] = loaded["exceptions_file"]
    return config


def resolve_settings(args: argparse.Namespace, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Resolve CLI > environment > YAML > defaults and validate values."""
    env = os.environ if env is None else env
    config_path = args.config or env.get("SCANNER_CONFIG") or "config.yaml"
    config = load_config(config_path, required=bool(args.config or env.get("SCANNER_CONFIG")))
    scanner = config["scanner"]

    def choose(cli_value: Any, env_name: str, yaml_value: Any) -> Any:
        return cli_value if cli_value is not None else env.get(env_name, yaml_value)

    severities = _parse_list(
        choose(args.severity, "SCANNER_SEVERITIES", scanner.get("severities")),
        "severities",
        set(SEVERITIES),
    )
    fail_on = str(choose(args.fail_on, "SCANNER_FAIL_ON", scanner.get("fail_on"))).strip().upper()
    if fail_on not in SEVERITY_RANK or fail_on == "UNKNOWN":
        raise ConfigurationError("fail_on must be LOW, MEDIUM, HIGH, or CRITICAL")
    ignore_unfixed = _parse_bool(
        choose(args.ignore_unfixed, "SCANNER_IGNORE_UNFIXED", scanner.get("ignore_unfixed")),
        "ignore_unfixed",
    )
    pkg_types = [item.lower() for item in _parse_list(
        choose(args.pkg_types, "SCANNER_PKG_TYPES", scanner.get("pkg_types")), "pkg_types"
    )]
    timeout = str(choose(args.timeout, "SCANNER_TIMEOUT", scanner.get("timeout"))).strip()
    if not re.fullmatch(r"[1-9]\d*(ms|s|m|h)", timeout):
        raise ConfigurationError("timeout must use Trivy duration syntax, for example 5m")
    try:
        retries = int(choose(args.retries, "SCANNER_RETRIES", scanner.get("retries")))
        retry_backoff = float(choose(args.retry_backoff, "SCANNER_RETRY_BACKOFF", scanner.get("retry_backoff")))
    except (ValueError, TypeError) as exc:
        raise ConfigurationError("retries and retry_backoff must be numeric") from exc
    if not 0 <= retries <= 5 or not 0 <= retry_backoff <= 30:
        raise ConfigurationError("retries must be 0..5 and retry_backoff must be 0..30 seconds")
    exception_path = choose(args.exceptions_file, "SCANNER_EXCEPTIONS_FILE", config.get("exceptions_file"))
    if exception_path is not None:
        if not isinstance(exception_path, str) or not exception_path.strip():
            raise ConfigurationError("exceptions_file must be a non-empty path")
        if args.exceptions_file is None and "SCANNER_EXCEPTIONS_FILE" not in env:
            exception_path = str(Path(config_path).parent / exception_path)
    try:
        exception_policy = load_allowlist(exception_path)
    except ExceptionPolicyError as exc:
        raise ConfigurationError(str(exc)) from exc
    output_dir = str(choose(args.output_dir, "SCANNER_OUTPUT_DIR", config["output"].get("dir"))).strip()
    if not output_dir:
        raise ConfigurationError("output_dir cannot be empty")
    image = args.image or env.get("SCAN_IMAGE")
    images = config.get("images")
    rescan_of = ""
    if args.rescan_artifact:
        if args.all_configured or args.image:
            raise ConfigurationError("--rescan-artifact cannot be combined with IMAGE or --all-configured")
        from reporters.service import ReportError, load_artifacts
        try:
            previous = load_artifacts([args.rescan_artifact])[0]
        except ReportError as exc:
            raise ConfigurationError(str(exc)) from exc
        selected_images = [previous["image"]]
        rescan_of = previous["scan_id"]
    elif args.all_configured:
        if (not isinstance(images, list) or not images
                or any(not isinstance(item, str) or not item.strip() for item in images)):
            raise ConfigurationError("images must be a non-empty list for --all-configured")
        selected_images = [str(item).strip() for item in images if str(item).strip()]
    elif image:
        selected_images = [image.strip()]
    else:
        raise ConfigurationError("Provide IMAGE, set SCAN_IMAGE, or use --all-configured")
    if any(not isinstance(item, str) or not item or item.startswith("-")
           or any(character.isspace() for character in item) or "://" in item
           for item in selected_images):
        raise ConfigurationError("Image references must be non-empty OCI references without whitespace or URL schemes")
    return {
        "images": selected_images,
        "severities": severities,
        "fail_on": fail_on,
        "ignore_unfixed": ignore_unfixed,
        "pkg_types": pkg_types,
        "timeout": timeout,
        "output_dir": output_dir,
        "exception_policy": exception_policy,
        "retries": retries,
        "retry_backoff": retry_backoff,
        "refresh_db": args.refresh_db,
        "rescan_of": rescan_of,
    }


def _run_trivy(command: list[str], retries: int, backoff: float,
               timeout_seconds: float) -> subprocess.CompletedProcess:
    transient = ("timeout", "timed out", "connection reset", "connection refused", "temporary failure",
                 "network is unreachable", "too many requests", "429", "502", "503", "504",
                 "context deadline exceeded", "unexpected eof", "tls handshake")
    permanent = ("unauthorized", "forbidden", "denied", "manifest unknown", "name unknown", "not found")
    for attempt in range(retries + 1):
        try:
            proc = subprocess.run(command, capture_output=True, text=True, check=False,
                                  timeout=timeout_seconds)
        except FileNotFoundError as exc:
            raise ScannerError("Trivy executable was not found") from exc
        except subprocess.TimeoutExpired:
            message = "Trivy execution timed out"
        except OSError as exc:
            raise ScannerError("Unable to start Trivy") from exc
        else:
            if proc.returncode == 0:
                return proc
            message = proc.stderr.strip() or f"Trivy exited with code {proc.returncode}"
        lowered = message.lower()
        retryable = any(marker in lowered for marker in transient) and not any(marker in lowered for marker in permanent)
        if attempt >= retries or not retryable:
            safe_message = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1<redacted>@", message)
            raise ScannerError(safe_message)
        logger.warning("Transient Trivy failure; retry %d of %d", attempt + 1, retries)
        time.sleep(min(backoff * (2 ** attempt), 30))
    raise ScannerError("Trivy retry limit exhausted")


def _timeout_seconds(timeout: str | None) -> float:
    match = re.fullmatch(r"([1-9]\d*)(ms|s|m|h)", timeout or "15m")
    if not match:
        raise ScannerError("Invalid Trivy timeout")
    return int(match[1]) * {"ms": .001, "s": 1, "m": 60, "h": 3600}[match[2]] + 30


def scan_image(
    image: str,
    severities: Sequence[str] | None = None,
    ignore_unfixed: bool = False,
    pkg_types: Sequence[str] | None = None,
    timeout: str | None = None,
    retries: int = 2,
    retry_backoff: float = 1,
) -> dict[str, Any]:
    """Run Trivy and return normalized findings without applying policy."""
    selected = list(severities or SEVERITIES)
    cmd = ["trivy", "image", "--quiet", "--scanners", "vuln", "--format", "json",
            "--severity", ",".join(selected), "--ignorefile", os.devnull]
    if ignore_unfixed:
        cmd.append("--ignore-unfixed")
    if pkg_types:
        cmd.extend(["--pkg-types", ",".join(pkg_types)])
    if timeout:
        cmd.extend(["--timeout", timeout])
    cmd.append(image)
    logger.info("Scanning image=%s severities=%s", image, ",".join(selected))
    proc = _run_trivy(cmd, retries, retry_backoff, _timeout_seconds(timeout))
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ScannerError(f"Trivy returned invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ScannerError("Trivy returned an invalid result object")
    results = data.get("Results")
    valid_empty = (data.get("SchemaVersion") == 2 and isinstance(data.get("ArtifactName"), str)
                   and bool(data["ArtifactName"].strip()))
    if (results is not None and not isinstance(results, list)) or (results is None and not valid_empty):
        raise ScannerError("Trivy returned an invalid result object")
    counts: Counter[str] = Counter()
    findings: list[dict[str, Any]] = []
    for result in results or []:
        if not isinstance(result, dict):
            raise ScannerError("Trivy returned invalid vulnerability results")
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is not None and not isinstance(vulnerabilities, list):
            raise ScannerError("Trivy returned invalid vulnerability results")
        for vuln in vulnerabilities or []:
            if (not isinstance(vuln, dict) or not isinstance(vuln.get("VulnerabilityID"), str)
                    or not isinstance(vuln.get("PkgName"), str)):
                raise ScannerError("Trivy returned an invalid vulnerability finding")
            severity = str(vuln.get("Severity") or "UNKNOWN").upper()
            if severity not in SEVERITY_RANK:
                raise ScannerError("Trivy returned an unsupported severity")
            counts[severity] += 1
            findings.append({
                "id": vuln.get("VulnerabilityID"), "pkg": vuln.get("PkgName"),
                "severity": severity, "installed": vuln.get("InstalledVersion"),
                "fixed": vuln.get("FixedVersion", ""),
            })
    summary = {level: counts.get(level, 0) for level in SEVERITIES}
    logger.info("Done image=%s summary=%s", image, summary)
    return {"image": image, "summary": summary, "findings": findings}


def blocking_count(summary: Mapping[str, int], fail_on: str) -> int:
    """Count findings at or above the configured severity threshold."""
    threshold = SEVERITY_RANK[fail_on]
    return sum(count for severity, count in summary.items()
               if SEVERITY_RANK.get(severity, 0) >= threshold)


def artifact_path(output_dir: str, image: str) -> Path:
    """Return a readable, collision-resistant JSON artifact path."""
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", image).strip("_.") or "image"
    digest = hashlib.sha256(image.encode("utf-8")).hexdigest()[:8]
    return Path(output_dir) / f"{safe}-{digest}.json"


def write_artifact(result: dict[str, Any], settings: Mapping[str, Any]) -> Path:
    """Write a normalized result with effective policy metadata."""
    path = artifact_path(str(settings["output_dir"]), result["image"])
    blocking = blocking_count(result["summary"], str(settings["fail_on"]))
    payload = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "scan_id": str(uuid.uuid4()),
        "scanned_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        **result,
        "policy": {"fail_on": settings["fail_on"], "blocking_findings": blocking,
                   "passed": blocking == 0},
        "scan_options": {key: settings[key] for key in
                         ("severities", "ignore_unfixed", "pkg_types", "timeout")},
        "scanner": {"name": "trivy", "wrapper_version": WRAPPER_VERSION},
        "source": {
            "provider": os.environ.get("GITHUB_ACTIONS") and "github-actions"
                        or os.environ.get("JENKINS_URL") and "jenkins"
                        or "local",
            "repository": os.environ.get("GITHUB_REPOSITORY", ""),
            "commit": os.environ.get("GITHUB_SHA") or os.environ.get("GIT_COMMIT", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID") or os.environ.get("BUILD_NUMBER", ""),
            "run_url": os.environ.get("GITHUB_SERVER_URL") and
                       f"{os.environ.get('GITHUB_SERVER_URL')}/{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/{os.environ.get('GITHUB_RUN_ID')}"
                       or os.environ.get("BUILD_URL", ""),
        },
    }
    if settings.get("rescan_of"):
        payload["rescan_of"] = settings["rescan_of"]
    payload["scan_options"].update({"retries": settings.get("retries", 2),
                                    "retry_backoff": settings.get("retry_backoff", 1)})
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        os.replace(temporary, path)
    except OSError as exc:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)
        raise ScannerError(f"Cannot write artifact {path}: {exc}") from exc
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan images and enforce vulnerability policy")
    parser.add_argument("image", nargs="?", help="container image reference")
    parser.add_argument("--config", help="YAML configuration path")
    parser.add_argument("--severity", help="comma-separated severities to scan")
    parser.add_argument("--fail-on", help="minimum blocking severity")
    fixed = parser.add_mutually_exclusive_group()
    fixed.add_argument("--ignore-unfixed", dest="ignore_unfixed", action="store_true", default=None)
    fixed.add_argument("--include-unfixed", dest="ignore_unfixed", action="store_false")
    parser.add_argument("--pkg-types", help="comma-separated package types")
    parser.add_argument("--timeout", help="Trivy timeout, for example 15m")
    parser.add_argument("--output-dir", help="artifact output directory")
    parser.add_argument("--all-configured", action="store_true", help="scan every configured image")
    parser.add_argument("--exceptions-file", help="approved exception YAML; malformed or missing files fail closed")
    parser.add_argument("--retries", type=int, help="transient Trivy retries after the first attempt (0..5)")
    parser.add_argument("--retry-backoff", type=float, help="initial retry delay in seconds (0..30)")
    parser.add_argument("--rescan-artifact", help="fresh scan of the image in a previous normalized artifact")
    parser.add_argument("--refresh-db", action="store_true", help="refresh the Trivy database before scanning")
    return parser


def run(argv: Sequence[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    """Run the CI gate and return its stable process exit code."""
    try:
        settings = resolve_settings(build_parser().parse_args(argv), env)
    except ConfigurationError as exc:
        logger.error("Configuration error: %s", exc)
        return 2
    blocked = False
    operational_failure = False
    if settings["refresh_db"]:
        try:
            _run_trivy(["trivy", "image", "--download-db-only"], settings["retries"],
                       settings["retry_backoff"], _timeout_seconds(settings["timeout"]))
        except ScannerError as exc:
            logger.error("Database refresh failed: %s", exc)
            return 3
    for image in settings["images"]:
        try:
            result = scan_image(image, settings["severities"], settings["ignore_unfixed"],
                                settings["pkg_types"], settings["timeout"],
                                settings["retries"], settings["retry_backoff"])
            result = apply_allowlist(result, settings["exception_policy"])
            path = write_artifact(result, settings)
            count = blocking_count(result["summary"], settings["fail_on"])
            print(json.dumps({"image": image, "summary": result["summary"],
                              "fail_on": settings["fail_on"], "blocking_findings": count,
                              "artifact": str(path)}, indent=2))
            if count:
                blocked = True
                logger.error("POLICY BLOCKED image=%s blocking_findings=%d", image, count)
            else:
                logger.info("POLICY PASSED image=%s", image)
        except ScannerError as exc:
            operational_failure = True
            logger.error("Scanner error for %s: %s", image, exc)
    if operational_failure:
        return 3
    return 1 if blocked else 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
