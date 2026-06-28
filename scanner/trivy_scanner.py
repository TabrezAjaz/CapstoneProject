"""
Sprint 1 — Core Trivy wrapper.

Runs Trivy against a container image and returns a structured summary
(severity counts + the list of findings). Later sprints build on this:
Sprint 2 adds CI/CD gating, Sprint 3 reporting and notifications.
"""
import json
import logging
import os
import subprocess
import sys
from collections import Counter

try:
    import yaml  # PyYAML — used to read config.yaml
except ImportError:  # keep the wrapper usable even without PyYAML installed
    yaml = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("trivy_scanner")

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
CONFIG_PATH = os.environ.get("SCANNER_CONFIG", "config.yaml")


def load_config(path: str = CONFIG_PATH) -> dict:
    """Load config.yaml if present; fall back to sensible defaults."""
    defaults = {
        "scanner": {"severities": SEVERITIES, "ignore_unfixed": False},
        "output": {"dir": "./scan-results"},
        "images": ["nginx:latest"],
    }
    if yaml is None or not os.path.exists(path):
        logger.info("Config not loaded (using defaults): %s", path)
        return defaults
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    # shallow-merge top-level keys onto defaults
    for key, value in defaults.items():
        cfg.setdefault(key, value)
    return cfg


def scan_image(image: str, severities=None, ignore_unfixed: bool = False) -> dict:
    """Scan a single container image and return parsed results."""
    sev = ",".join(severities or SEVERITIES)
    cmd = ["trivy", "image", "--quiet", "--format", "json", "--severity", sev]
    if ignore_unfixed:
        cmd.append("--ignore-unfixed")
    cmd.append(image)

    logger.info("Scanning image=%s severities=%s", image, sev)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):   # 1 = vulnerabilities found (still valid output)
        logger.error("Trivy failed: %s", proc.stderr.strip())
        raise RuntimeError(proc.stderr.strip())

    data = json.loads(proc.stdout or "{}")
    counts = Counter()
    findings = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []) or []:
            counts[v.get("Severity", "UNKNOWN")] += 1
            findings.append({
                "id": v.get("VulnerabilityID"),
                "pkg": v.get("PkgName"),
                "severity": v.get("Severity"),
                "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion", ""),
            })

    summary = {sev_level: counts.get(sev_level, 0) for sev_level in SEVERITIES}
    logger.info("Done image=%s summary=%s", image, summary)
    return {"image": image, "summary": summary, "findings": findings}


def scan_from_config(path: str = CONFIG_PATH) -> list:
    """Scan every image listed in config.yaml and save each result as JSON."""
    cfg = load_config(path)
    sev = cfg["scanner"].get("severities", SEVERITIES)
    ignore_unfixed = bool(cfg["scanner"].get("ignore_unfixed", False))
    out_dir = cfg["output"].get("dir", "./scan-results")
    os.makedirs(out_dir, exist_ok=True)

    results = []
    for image in cfg.get("images", []):
        result = scan_image(image, severities=sev, ignore_unfixed=ignore_unfixed)
        safe = image.replace(":", "_").replace("/", "_")
        with open(os.path.join(out_dir, f"{safe}.json"), "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        results.append(result)
    return results


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if argv:
        # Scan a single image passed on the command line
        result = scan_image(argv[0])
        print(json.dumps(result["summary"], indent=2))
    else:
        # No argument -> scan every image in config.yaml
        results = scan_from_config()
        for r in results:
            print(f"{r['image']}: {r['summary']}")


if __name__ == "__main__":
    main()
