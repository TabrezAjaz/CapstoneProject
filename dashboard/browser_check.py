"""Reproducible browser verification against a running dashboard with real history."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser(description="Verify dashboard interactions and save genuine rendered evidence")
    parser.add_argument("--url", default="http://127.0.0.1:5050")
    parser.add_argument("--executable", help="installed Chrome/Chromium executable; otherwise use Playwright Chromium")
    parser.add_argument("--evidence-dir", default="docs/screenshots")
    parser.add_argument("--audit-scan-id", help="also capture approved-exception details for an existing scan")
    args = parser.parse_args()
    output = Path(args.evidence_dir)
    output.mkdir(parents=True, exist_ok=True)
    result = {"captured_at": datetime.now(timezone.utc).isoformat(), "checks": []}
    with sync_playwright() as playwright:
        launch = {"headless": True}
        if args.executable:
            launch["executable_path"] = args.executable
        browser = playwright.chromium.launch(**launch)
        page = browser.new_page(viewport={"width": 1440, "height": 1080}, device_scale_factor=1)
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(args.url, wait_until="networkidle")
        expect(page.locator("#connection-label")).to_have_text("Connected")
        expect(page.locator("#results")).to_be_visible()
        baseline = page.evaluate("async () => (await fetch('/api/overview')).json()")
        assert baseline["latest"], "Real persisted scan artifacts are required for evidence capture"
        expect(page.locator("#stat-pending")).to_have_text(f"{baseline['totals']['pending']:,}")
        result["checks"].append("API/UI totals agree")
        page.locator("#severity").select_option("HIGH")
        expect(page.locator("#stat-pending")).to_have_text(f"{baseline['summary']['HIGH']:,}")
        result["checks"].append("Severity filter")
        image = baseline["images"][0]
        page.locator("#image").select_option(image)
        expect(page.locator("#image-count")).to_have_text("1")
        result["checks"].append("Image filter")
        page.locator("#start").fill("2099-01-01")
        page.locator("#start").dispatch_event("change")
        expect(page.locator("#empty")).to_be_visible()
        page.locator("#end").fill("2026-01-01")
        page.locator("#end").dispatch_event("change")
        expect(page.locator("#error")).to_have_text("Start must be before end")
        result["checks"].append("Date filter, empty state, invalid-range error")
        page.locator("#filters").evaluate("form => form.reset()")
        expect(page.locator("#stat-pending")).to_have_text(f"{baseline['totals']['pending']:,}")
        expect(page.locator("#error")).to_be_hidden()
        page.locator("[data-scan]").first.click()
        expect(page.locator("#scan-dialog")).to_be_visible()
        expect(page.locator("#detail-body tr")).not_to_have_count(0)
        page.locator("#close-dialog").click()
        result["checks"].append("Scan drilldown and close")
        for name, width, height in (("desktop", 1440, 1080), ("mobile", 390, 844)):
            page.set_viewport_size({"width": width, "height": height})
            page.wait_for_function("document.documentElement.scrollWidth <= window.innerWidth")
            page.wait_for_function("Array.from(document.querySelectorAll('canvas')).every(canvas => canvas.getBoundingClientRect().right <= window.innerWidth)")
            nonblank = page.evaluate("""() => Array.from(document.querySelectorAll('canvas')).every(canvas =>
                Array.from(canvas.getContext('2d').getImageData(0,0,canvas.width,canvas.height).data)
                .some((value,index) => index % 4 === 3 && value > 0))""")
            assert nonblank, f"Blank chart in {name} viewport"
            minimum_control_width = 120 if name == "mobile" else 100
            for selector in ("#image", "#severity", "#start", "#end"):
                assert page.locator(selector).bounding_box()["width"] >= minimum_control_width, f"Unreadable {selector} in {name}"
            page.screenshot(path=str(output / f"sprint4-dashboard-{name}.png"), full_page=True)
            result["checks"].append(f"{width}x{height}: no horizontal overflow; nonblank charts")
        if args.audit_scan_id:
            page.set_viewport_size({"width": 1440, "height": 1080})
            page.goto(args.url + "/?scan=" + args.audit_scan_id, wait_until="networkidle")
            expect(page.locator("#scan-dialog")).to_be_visible()
            page.locator("#show-suppressed").check()
            expect(page.locator("#detail-body tr")).not_to_have_count(0)
            page.screenshot(path=str(output / "sprint5-exception-audit.png"))
            result["checks"].append("Approved exception audit deep link")
        assert not errors, errors
        result["checks"].append("No browser JavaScript errors")
        result["history_scans"] = len(baseline["history"])
        result["totals"] = baseline["totals"]
        browser.close()
    (output / "sprint4-browser-check.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()