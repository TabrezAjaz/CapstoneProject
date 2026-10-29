"""Read-only local dashboard API and Prometheus scrape endpoint."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request
from prometheus_client import CONTENT_TYPE_LATEST

from .history import HistoryStore
from .metrics import render_metrics


def create_app(database: str | Path | None = None) -> Flask:
    app = Flask(__name__)
    store = HistoryStore(database or os.environ.get("SCANNER_HISTORY_DB", "dashboard/data/history.sqlite3"))
    app.extensions["history"] = store

    @app.after_request
    def secure_response(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'")
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/healthz")
    def health():
        with store.connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return jsonify(status="ok")

    @app.get("/api/overview")
    def overview():
        try:
            return jsonify(store.snapshot(**{key: request.args.get(key, "")
                                             for key in ("image", "start", "end", "severity")}))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

    @app.get("/api/scans/<scan_id>")
    def detail(scan_id):
        artifact = store.detail(scan_id)
        return (jsonify(artifact), 200) if artifact else (jsonify(error="Scan not found"), 404)

    @app.get("/metrics")
    def metrics():
        return Response(render_metrics(store), content_type=CONTENT_TYPE_LATEST)

    return app


def main():
    parser = argparse.ArgumentParser(description="Serve read-only scan history and Prometheus metrics")
    parser.add_argument("--database", default=os.environ.get("SCANNER_HISTORY_DB", "dashboard/data/history.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5050)
    args = parser.parse_args()
    create_app(args.database).run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()