"""Fail-closed, expiring exception policy with explicit suppression evidence."""
from __future__ import annotations

import hashlib
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml


class ExceptionPolicyError(ValueError):
    """An exception file is unreadable or cannot be safely interpreted."""


def load_allowlist(path: str | Path | None) -> dict[str, Any]:
    if path is None:
        return {"file": "", "sha256": "", "rules": []}
    source = Path(path)
    try:
        content = source.read_bytes()
        data = yaml.safe_load(content)
    except (OSError, yaml.YAMLError, UnicodeError) as exc:
        raise ExceptionPolicyError(f"Cannot load exception policy: {source.name}") from exc
    if not isinstance(data, dict) or set(data) != {"exceptions"} or not isinstance(data["exceptions"], list):
        raise ExceptionPolicyError("Exception policy must contain an exceptions list")
    rules = []
    identities = set()
    for entry in data["exceptions"]:
        if not isinstance(entry, dict) or set(entry) - {"id", "reason", "expires", "image", "pkg"}:
            raise ExceptionPolicyError("Exception entries contain unsupported fields")
        identifier, reason = entry.get("id"), entry.get("reason")
        if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{1,199}", identifier):
            raise ExceptionPolicyError("Exception id must be an exact advisory identifier; wildcards are forbidden")
        if not isinstance(reason, str) or not reason.strip():
            raise ExceptionPolicyError("Every exception requires a non-empty reason")
        expires = entry.get("expires")
        try:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(expires)):
                raise ValueError("ISO date required")
            expires = date.fromisoformat(str(expires))
        except ValueError as exc:
            raise ExceptionPolicyError("Every exception requires an ISO expiry date (YYYY-MM-DD)") from exc
        rule = {"id": identifier, "reason": reason.strip(), "expires": expires.isoformat()}
        for key in ("image", "pkg"):
            if key in entry:
                value = entry[key]
                if not isinstance(value, str) or not value.strip() or any(char in value for char in "*?[]"):
                    raise ExceptionPolicyError(f"Exception {key} must be an exact non-empty value")
                rule[key] = value.strip()
        identity = (identifier, rule.get("image", ""), rule.get("pkg", ""))
        if identity in identities:
            raise ExceptionPolicyError("Duplicate exception id and scope")
        identities.add(identity)
        rules.append(rule)
    return {"file": source.name, "sha256": hashlib.sha256(content).hexdigest(), "rules": rules}


def apply_allowlist(result: dict[str, Any], policy: dict[str, Any],
                    today: date | None = None) -> dict[str, Any]:
    today = today or datetime.now(timezone.utc).date()
    active, suppressed = [], []
    valid_rules = [rule for rule in policy["rules"] if date.fromisoformat(rule["expires"]) >= today]
    for finding in result["findings"]:
        match = next((rule for rule in valid_rules
                      if rule["id"] == finding["id"]
                      and ("image" not in rule or rule["image"] == result["image"])
                      and ("pkg" not in rule or rule["pkg"] == finding["pkg"])), None)
        if match:
            suppressed.append({**finding, "exception": dict(match)})
        else:
            active.append(finding)
    summary = {level: sum(finding["severity"] == level for finding in active)
               for level in result["summary"]}
    return {**result, "summary": summary, "findings": active,
            "raw_summary": dict(result["summary"]), "suppressed_findings": suppressed,
            "exception_policy": {"file": policy["file"], "sha256": policy["sha256"],
                                 "evaluated_on": today.isoformat(),
                                 "expired": [dict(rule) for rule in policy["rules"]
                                             if date.fromisoformat(rule["expires"]) < today]}}