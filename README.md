#!/usr/bin/env python3
"""Local interactive web report for selecting individual PE result files to copy."""

from __future__ import annotations

import argparse
import html
import json
import secrets
import shutil
import sys
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from pe_backup_tool import (CHUNK, discover_jobs, hong_kong_now, report,
                            save_report, sha256)


MAX_FORM_BYTES = 1024 * 1024


def safe_copy_file(source: Path, target: Path, source_root: Path, backup_root: Path) -> str:
    source_resolved = source.resolve()
    target_resolved = target.resolve()
    if not source_resolved.is_relative_to(source_root.resolve()):
        raise ValueError(f"Source escapes configured root: {source}")
    if not target_resolved.is_relative_to(backup_root.resolve()):
        raise ValueError(f"Target escapes configured root: {target}")
    if not source.is_file() or source.is_symlink():
        raise ValueError(f"Source file unavailable or unsupported: {source}")
    if target.exists():
        if target.is_file() and not target.is_symlink() and sha256(source) == sha256(target):
            return "already matched"
        return "conflict — existing backup was not overwritten"
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".pe-copy-partial")
    if temporary.exists():
        raise FileExistsError(f"Previous partial copy must be reviewed: {temporary}")
    try:
        shutil.copy2(source, temporary)
        if sha256(source) != sha256(temporary):
            raise IOError(f"Copy verification failed: {source.name}")
        if target.exists():
            temporary.unlink()
            return "conflict — target appeared during copy and was not overwritten"
        temporary.replace(target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return "copied and SHA-256 verified"


class BackupWebApp:
    def __init__(self, config_path: Path):
        config = json.loads(config_path.read_text(encoding="utf-8"))
        self.source_root = Path(config["source_root"]).expanduser()
        self.backup_root = Path(config["backup_root"]).expanduser()
        self.report_dir = Path(config["report_dir"]).expanduser()
        self.csrf_token = secrets.token_urlsafe(32)
        self.manifest: dict[str, dict] = {}
        self.data: dict = {}

    def scan(self) -> dict:
        jobs = discover_jobs(self.source_root, None)
        self.data = report(self.source_root, self.backup_root, jobs, set(), set())
        save_report(self.data, self.report_dir, None)
        manifest: dict[str, dict] = {}
        for row in self.data["jobs"]:
            for item in row["file_results"]:
                if item["source_size_bytes"] is None:
                    continue
                if row["scope"] == "root_file":
                    source = self.source_root / item["path"]
                    target = self.backup_root / item["path"]
                else:
                    source = self.source_root / row["job"] / item["path"]
                    target = self.backup_root / row["job"] / item["path"]
                token = secrets.token_urlsafe(18)
                manifest[token] = {"job": row["job"], "file": item["path"],
                                   "source": source, "target": target,
                                   "source_size": item["source_size_bytes"],
                                   "backup_size": item["backup_size_bytes"],
                                   "size_equal": item["size_equal"],
                                   "content_equal": item["content_equal"],
                                   "status": item["status"]}
        self.manifest = manifest
        return self.data

    def copy_selected(self, tokens: list[str]) -> list[str]:
        messages = []
        for token in tokens:
            entry = self.manifest.get(token)
            if entry is None:
                messages.append("Ignored an expired or invalid selection")
                continue
            result = safe_copy_file(entry["source"], entry["target"],
                                    self.source_root, self.backup_root)
            messages.append(f"{entry['job']} / {entry['file']}: {result}")
        return messages

    def render(self, messages: list[str] | None = None) -> str:
        rows = []
        for token, item in self.manifest.items():
            source_size = f"{item['source_size']:,}"
            backup_size = "—" if item["backup_size"] is None else f"{item['backup_size']:,}"
            size_equal = "—" if item["size_equal"] is None else ("YES" if item["size_equal"] else "NO")
            content_equal = ("—" if item["content_equal"] is None else
                             ("YES" if item["content_equal"] else "NO"))
            checked_disabled = " disabled" if item["status"] == "MATCH" else ""
            checkbox = (f'<input type="checkbox" name="selected" value="{html.escape(token)}"'
                        f'{checked_disabled} aria-label="Select {html.escape(item["file"])}">')
            values = [item["job"], item["file"], source_size, backup_size,
                      size_equal, content_equal, item["status"]]
            rows.append("<tr><td>" + checkbox + "</td>" +
                        "".join(f"<td>{html.escape(value)}</td>" for value in values) + "</tr>")
        notice = ""
        if messages:
            notice = '<div class="notice"><strong>Copy results</strong><ul>' + "".join(
                f"<li>{html.escape(message)}</li>" for message in messages) + "</ul></div>"
        return f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Cache-Control" content="no-store"><title>PE backup interactive report</title>
<style>body{{font:15px system-ui;margin:2rem;color:#18212b}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ccd3da;padding:.55rem;text-align:left}}th{{background:#eaf0f5;position:sticky;top:0}}
tr:nth-child(even){{background:#f8fafb}}button,.button{{padding:.65rem 1rem;border:0;border-radius:5px;
background:#1769aa;color:white;font-weight:650;cursor:pointer;text-decoration:none;display:inline-block}}
.secondary{{background:#5b6770}}.notice{{background:#e9f7ec;border:1px solid #8fc99a;padding:1rem;margin:1rem 0}}
.warning{{background:#fff6da;padding:1rem}}.actions{{display:flex;gap:.7rem;margin:1rem 0}}</style>
<h1>PE results backup status</h1><p>Generated: {html.escape(self.data['created_at'])}<br>
Source: {html.escape(str(self.source_root))}<br>Backup: {html.escape(str(self.backup_root))}</p>
<p class="warning">Select individual files, then click <strong>Copy selected files</strong>.
Matching files are disabled. Existing files with different content are reported as conflicts and are never overwritten.
This tool never deletes files.</p>{notice}
<form method="post" action="/copy"><input type="hidden" name="csrf" value="{html.escape(self.csrf_token)}">
<div class="actions"><button type="submit">Copy selected files</button>
<a class="button secondary" href="/">Refresh scan</a>
<a class="button secondary" href="/file_report.csv">Download file CSV</a></div>
<label><input id="select-all" type="checkbox"> Select all files needing review</label>
<table><thead><tr><th>Copy?</th><th>Job / root filename</th><th>File</th><th>Source bytes</th>
<th>Backup bytes</th><th>Size equal</th><th>Content equal</th><th>Status</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></form>
<script>document.getElementById('select-all').addEventListener('change',function(){{
document.querySelectorAll('input[name="selected"]:not(:disabled)').forEach(x=>x.checked=this.checked);}});</script>
</html>"""


class BackupRequestHandler(BaseHTTPRequestHandler):
    server: "BackupHTTPServer"

    def send_text(self, content: str, content_type: str = "text/html; charset=utf-8",
                  status: int = 200) -> None:
        payload = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            try:
                self.server.app.scan()
                self.send_text(self.server.app.render())
            except Exception as error:
                self.send_text(f"<h1>Scan failed</h1><pre>{html.escape(str(error))}</pre>", status=500)
            return
        downloads = {"/report.csv": "report.csv", "/file_report.csv": "file_report.csv",
                     "/report.json": "report.json"}
        if path in downloads:
            file_path = self.server.app.report_dir / downloads[path]
            if not file_path.is_file():
                self.send_text("Report not generated", "text/plain; charset=utf-8", 404)
                return
            payload = file_path.read_bytes()
            content_type = "application/json" if file_path.suffix == ".json" else "text/csv; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'attachment; filename="{file_path.name}"')
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_text("Not found", "text/plain; charset=utf-8", 404)

    def do_POST(self) -> None:
        if urllib.parse.urlparse(self.path).path != "/copy":
            self.send_text("Not found", "text/plain; charset=utf-8", 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_FORM_BYTES:
                raise ValueError("Invalid form size")
            form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
            if form.get("csrf", [""])[0] != self.server.app.csrf_token:
                self.send_text("Invalid request token", "text/plain; charset=utf-8", 403)
                return
            selected = form.get("selected", [])
            messages = (["No files were selected"] if not selected else
                        self.server.app.copy_selected(selected))
            self.server.app.scan()
            self.send_text(self.server.app.render(messages))
        except Exception as error:
            self.send_text(f"<h1>Copy failed</h1><pre>{html.escape(str(error))}</pre>", status=500)

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}")


class BackupHTTPServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], app: BackupWebApp):
        super().__init__(address, BackupRequestHandler)
        self.app = app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    try:
        app = BackupWebApp(args.config)
        app.scan()
        server = BackupHTTPServer(("127.0.0.1", args.port), app)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    url = f"http://127.0.0.1:{args.port}/"
    print(f"Interactive report: {url}")
    print("Keep this window open while using the report. Press Ctrl+C to stop.")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\nStopped at {hong_kong_now()}")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
