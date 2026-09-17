#!/usr/bin/env python3
"""Inventory, verify and optionally copy PE results between two drives."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


CHUNK = 1024 * 1024
IGNORED_SYSTEM_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}
HONG_KONG_TZ = timezone(timedelta(hours=8), name="HKT")


def is_ignored_file(path: Path) -> bool:
    return path.name in IGNORED_SYSTEM_FILES


@dataclass(frozen=True)
class FileInfo:
    size: int
    modified_ns: int
    accessed_ns: int


@dataclass
class Inventory:
    files: dict[str, FileInfo]
    directories: set[str]
    seconds: float
    folder_modified_ns: int
    folder_accessed_ns: int


def child_path(root: Path, relative: str) -> Path:
    candidate = root.joinpath(*Path(relative).parts)
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes configured root: {relative}")
    return candidate


def inventory(root: Path, recursive: bool = True,
              selected_names: set[str] | None = None) -> Inventory:
    started = time.perf_counter()
    files: dict[str, FileInfo] = {}
    directories: set[str] = set()
    if not root.is_dir():
        raise FileNotFoundError(f"Directory unavailable: {root}")
    root_stat = root.stat()

    def walk_error(error: OSError) -> None:
        raise error

    for current, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        current_path = Path(current)
        relative_dir = current_path.relative_to(root).as_posix()
        if relative_dir != ".":
            directories.add(relative_dir)
        if not recursive:
            dirs.clear()
        for dirname in dirs:
            if (current_path / dirname).is_symlink():
                raise ValueError(f"Directory symlink unsupported: {current_path / dirname}")
        for name in names:
            path = current_path / name
            if is_ignored_file(path):
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Non-regular file unsupported: {path}")
            stat = path.stat()
            relative = path.relative_to(root).as_posix()
            if selected_names is not None and relative not in selected_names:
                continue
            files[relative] = FileInfo(stat.st_size, stat.st_mtime_ns, stat.st_atime_ns)
    if not recursive and len(files) == 1:
        only_file = next(iter(files.values()))
        folder_modified_ns = only_file.modified_ns
        folder_accessed_ns = only_file.accessed_ns
    else:
        folder_modified_ns = root_stat.st_mtime_ns
        folder_accessed_ns = root_stat.st_atime_ns
    return Inventory(files, directories, time.perf_counter() - started,
                     folder_modified_ns, folder_accessed_ns)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compare(source: Path, target: Path, left: Inventory, right: Inventory | None) -> dict:
    if right is None:
        file_results = [{"path": path, "source_size_bytes": info.size,
                         "backup_size_bytes": None, "size_equal": None,
                         "content_equal": None, "status": "MISSING_IN_BACKUP"}
                        for path, info in sorted(left.files.items())]
        return {"status": "NOT_BACKED_UP", "missing_files": len(left.files),
                "extra_files": 0, "different_files": 0, "missing_dirs": len(left.directories),
                "extra_dirs": 0, "differences": [f"missing: {p}" for p in sorted(left.files)],
                "file_results": file_results}
    missing = sorted(left.files.keys() - right.files.keys())
    extra = sorted(right.files.keys() - left.files.keys())
    different = []
    file_results = []
    for relative in missing:
        file_results.append({"path": relative, "source_size_bytes": left.files[relative].size,
                             "backup_size_bytes": None, "size_equal": None,
                             "content_equal": None, "status": "MISSING_IN_BACKUP"})
    for relative in extra:
        file_results.append({"path": relative, "source_size_bytes": None,
                             "backup_size_bytes": right.files[relative].size, "size_equal": None,
                             "content_equal": None, "status": "EXTRA_IN_BACKUP"})
    for relative in sorted(left.files.keys() & right.files.keys()):
        source_size = left.files[relative].size
        backup_size = right.files[relative].size
        size_equal = source_size == backup_size
        content_equal = False
        file_status = "SIZE_DIFFERENT"
        if not size_equal:
            different.append(relative)
        else:
            content_equal = sha256(child_path(source, relative)) == sha256(child_path(target, relative))
            file_status = "MATCH" if content_equal else "CONTENT_DIFFERENT"
            if not content_equal:
                different.append(relative)
        file_results.append({"path": relative, "source_size_bytes": source_size,
                             "backup_size_bytes": backup_size, "size_equal": size_equal,
                             "content_equal": content_equal, "status": file_status})
    file_results.sort(key=lambda item: item["path"].casefold())
    missing_dirs = sorted(left.directories - right.directories)
    extra_dirs = sorted(right.directories - left.directories)
    equal = not (missing or extra or different or missing_dirs or extra_dirs)
    return {"status": "MATCH" if equal else "DIFFERENT", "missing_files": len(missing),
            "extra_files": len(extra), "different_files": len(different),
            "missing_dirs": len(missing_dirs), "extra_dirs": len(extra_dirs),
            "differences": [*[f"missing: {p}" for p in missing],
                            *[f"extra: {p}" for p in extra],
                            *[f"different: {p}" for p in different],
                            *[f"missing directory: {p}" for p in missing_dirs],
                            *[f"extra directory: {p}" for p in extra_dirs]],
            "file_results": file_results}


def format_ns(stamp_ns: int | None) -> str:
    if stamp_ns is None:
        return ""
    stamp = stamp_ns / 1_000_000_000
    return datetime.fromtimestamp(stamp, tz=timezone.utc).astimezone(HONG_KONG_TZ).strftime(
        "%Y-%m-%d %H:%M:%S HKT")


def hong_kong_now() -> str:
    return datetime.now(tz=HONG_KONG_TZ).strftime("%Y-%m-%d %H:%M:%S HKT")


def latest_file_time(inv: Inventory, attribute: str) -> str:
    if not inv.files:
        return ""
    return format_ns(max(getattr(item, attribute) for item in inv.files.values()))


def disk_space(root: Path) -> dict:
    usage = shutil.disk_usage(root)
    return {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free,
            "free_tib": round(usage.free / 1024**4, 3)}


def discover_jobs(source_root: Path, requested: list[str] | None) -> list[str]:
    if not source_root.is_dir():
        raise FileNotFoundError(f"Source unavailable: {source_root}")
    available = {p.name for p in source_root.iterdir() if p.is_dir() and not p.is_symlink()}
    if requested:
        for job in requested:
            if job not in available:
                raise ValueError(f"Job not found in source root: {job}")
        return sorted(set(requested))
    return sorted(available)


def copy_job(source: Path, target: Path, left: Inventory) -> dict:
    """Copy selected job; never remove or overwrite an existing backup file."""
    if target.is_symlink():
        raise ValueError(f"Target job is a symlink: {target}")
    target.mkdir(parents=True, exist_ok=True)
    for relative in sorted(left.directories):
        child_path(target, relative).mkdir(parents=True, exist_ok=True)
    copied = 0
    skipped = 0
    conflicts: list[str] = []
    for relative in sorted(left.files):
        src = child_path(source, relative)
        dst = child_path(target, relative)
        if dst.exists():
            if not dst.is_file() or sha256(src) != sha256(dst):
                conflicts.append(relative)
            else:
                skipped += 1
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        temporary = dst.with_name(dst.name + ".pe-copy-partial")
        if temporary.exists():
            raise FileExistsError(f"Previous partial copy must be reviewed: {temporary}")
        try:
            shutil.copy2(src, temporary)
            if sha256(src) != sha256(temporary):
                raise IOError(f"Copy verification failed: {relative}")
            if dst.exists():
                conflicts.append(relative)
                temporary.unlink()
                continue
            temporary.replace(dst)
            copied += 1
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
    return {"copied": copied, "already_present": skipped, "conflicts": conflicts}


def copy_root_file(source_root: Path, target_root: Path, name: str) -> dict:
    source = child_path(source_root, name)
    target = child_path(target_root, name)
    if not source.is_file() or source.is_symlink() or source.parent != source_root:
        raise ValueError(f"Root file not found or unsupported: {name}")
    if target.exists():
        if target.is_file() and not target.is_symlink() and sha256(source) == sha256(target):
            return {"copied": 0, "already_present": 1, "conflicts": []}
        return {"copied": 0, "already_present": 0, "conflicts": [name]}
    temporary = target.with_name(target.name + ".pe-copy-partial")
    if temporary.exists():
        raise FileExistsError(f"Previous partial copy must be reviewed: {temporary}")
    try:
        shutil.copy2(source, temporary)
        if sha256(source) != sha256(temporary):
            raise IOError(f"Copy verification failed: {name}")
        if target.exists():
            temporary.unlink()
            return {"copied": 0, "already_present": 0, "conflicts": [name]}
        temporary.replace(target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return {"copied": 1, "already_present": 0, "conflicts": []}


def report(source_root: Path, target_root: Path, jobs: list[str],
           copy: bool | set[str], copy_root_files: set[str] | None = None) -> dict:
    if (source_root.resolve().is_relative_to(target_root.resolve()) or
            target_root.resolve().is_relative_to(source_root.resolve())):
        raise ValueError("Source and backup roots must be separate directories")
    if not target_root.is_dir():
        raise FileNotFoundError(f"Backup drive unavailable: {target_root}")
    started = time.perf_counter()
    rows = []
    jobs_to_copy = set(jobs) if copy is True else set() if copy is False else set(copy)
    root_files_to_copy = copy_root_files or set()
    source_root_files = {path.name for path in source_root.iterdir()
                         if (path.is_file() or path.is_symlink()) and not is_ignored_file(path)}
    backup_root_files = {path.name for path in target_root.iterdir()
                         if (path.is_file() or path.is_symlink()) and not is_ignored_file(path)}
    scopes = []
    scopes.extend((name, source_root, target_root, False, {name}, "root_file")
                  for name in sorted(source_root_files | backup_root_files))
    scopes.extend((job, source_root / job, target_root / job, True, None, "job") for job in jobs)
    for job, source, target, recursive, selected_names, scope_type in scopes:
        left = inventory(source, recursive=recursive, selected_names=selected_names)
        copy_result = None
        if recursive and job in jobs_to_copy:
            copy_result = copy_job(source, target, left)
        elif scope_type == "root_file" and job in root_files_to_copy:
            copy_result = copy_root_file(source_root, target_root, job)
        selected_target_missing = (scope_type == "root_file" and
                                   not (target_root / job).is_file() and job in source_root_files)
        right = (inventory(target, recursive=recursive, selected_names=selected_names)
                 if target.exists() and not selected_target_missing else None)
        verify_started = time.perf_counter()
        checked = compare(source, target, left, right)
        verification_seconds = time.perf_counter() - verify_started
        source_display = source / job if scope_type == "root_file" else source
        target_display = target / job if scope_type == "root_file" else target
        rows.append({"job": job, "scope": scope_type,
                     "source": str(source_display), "backup": str(target_display),
                     "file_count": len(left.files), "size_bytes": sum(f.size for f in left.files.values()),
                     "folder_modified": format_ns(left.folder_modified_ns),
                     "folder_accessed": format_ns(left.folder_accessed_ns),
                     "latest_file_modified": latest_file_time(left, "modified_ns"),
                     "latest_file_accessed": latest_file_time(left, "accessed_ns"),
                     "scanned_at": hong_kong_now(),
                     "source_scan_seconds": round(left.seconds, 4),
                     "backup_scan_seconds": round(right.seconds, 4) if right else None,
                     "verification_seconds": round(verification_seconds, 4),
                     **checked, "copy_result": copy_result})
    rows.sort(key=lambda row: (row["scope"] != "root_file", -row["size_bytes"],
                               row["job"].casefold()))
    return {"created_at": hong_kong_now(),
            "source_root": str(source_root), "backup_root": str(target_root),
            "source_disk": disk_space(source_root), "backup_disk": disk_space(target_root),
            "jobs": rows, "total_seconds": round(time.perf_counter() - started, 4),
            "source_scan_seconds": round(sum(r["source_scan_seconds"] for r in rows), 4)}


def save_report(data: dict, output: Path, excel_seconds: float | None) -> None:
    output.mkdir(parents=True, exist_ok=True)
    benchmark = {"python_source_scan_seconds": data["source_scan_seconds"],
                 "excel_scan_seconds": excel_seconds,
                 "comparable_only_if_same_jobs_and_same_scan_scope": True}
    if excel_seconds is not None:
        benchmark["comparison"] = ("PYTHON_FASTER" if data["source_scan_seconds"] < excel_seconds
                                   else "EXCEL_FASTER" if data["source_scan_seconds"] > excel_seconds
                                   else "TIE")
        benchmark["speed_ratio"] = (round(excel_seconds / data["source_scan_seconds"], 2)
                                    if data["source_scan_seconds"] else None)
    data["benchmark"] = benchmark
    (output / "report.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    columns = ["job", "file_count", "size_bytes", "folder_modified", "folder_accessed",
               "latest_file_modified", "latest_file_accessed", "scanned_at", "status",
               "missing_files", "extra_files", "different_files", "missing_dirs", "extra_dirs",
               "source_scan_seconds", "backup_scan_seconds", "verification_seconds", "source", "backup"]
    with (output / "report.csv").open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows({key: row.get(key) for key in columns} for row in data["jobs"])
    file_columns = ["job", "path", "source_size_bytes", "backup_size_bytes", "size_equal",
                    "content_equal", "status"]
    with (output / "file_report.csv").open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=file_columns)
        writer.writeheader()
        for row in data["jobs"]:
            for file_result in row["file_results"]:
                writer.writerow({"job": row["job"], **file_result})
    table_rows = []
    for row in data["jobs"]:
        status = row["status"]
        note = {"MATCH": "Backup matches; team reviews any cleanup",
                "DIFFERENT": "Review differences / backup",
                "NOT_BACKED_UP": "Team to arrange backup"}[status]
        file_rows = []
        for item in row["file_results"]:
            source_size = "—" if item["source_size_bytes"] is None else f"{item['source_size_bytes']:,}"
            backup_size = "—" if item["backup_size_bytes"] is None else f"{item['backup_size_bytes']:,}"
            size_equal = "—" if item["size_equal"] is None else ("YES" if item["size_equal"] else "NO")
            content_equal = ("—" if item["content_equal"] is None else
                             ("YES" if item["content_equal"] else "NO"))
            values = [item["path"], source_size, backup_size, size_equal,
                      content_equal, item["status"]]
            file_rows.append("<tr>" + "".join(f"<td>{html.escape(value)}</td>" for value in values) + "</tr>")
        detail = ("<table class=files><thead><tr><th>File</th><th>Source bytes</th>"
                  "<th>Backup bytes</th><th>Size equal</th><th>Content equal</th><th>Status</th>"
                  f"</tr></thead><tbody>{''.join(file_rows)}</tbody></table>")
        cells = [row["job"], str(row["file_count"]), f"{row['size_bytes'] / 1024**3:.3f}",
                 row["folder_modified"], row["folder_accessed"], row["latest_file_modified"],
                 row["latest_file_accessed"], row["scanned_at"], status, note,
                 f"{row['missing_files']} / {row['extra_files']} / {row['different_files']}"]
        table_rows.append("<tr>" + "".join(f"<td>{html.escape(x)}</td>" for x in cells) +
                          f"<td><details><summary>Show {len(row['file_results'])} files</summary>"
                          f"{detail}</details></td></tr>")
    excel_text = ("Not entered" if excel_seconds is None else
                  f"{excel_seconds:.3f}s; {benchmark['comparison']} (same scope required)")
    page = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<title>PE backup status</title><style>body{{font:16px system-ui;margin:2rem;max-width:1500px}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:.55rem;text-align:left;vertical-align:top}}
th{{background:#eef2f6}}tr:nth-child(even){{background:#f9fafb}}.files{{font-size:.88rem;min-width:700px}}
.files tr:nth-child(even){{background:#f4f6f8}}details{{max-width:900px;overflow:auto}}
.hint{{background:#fff7df;padding:1rem}}</style><h1>PE results backup status</h1>
<p>Generated (Hong Kong time): {html.escape(data['created_at'])}<br>Source: {html.escape(data['source_root'])}<br>
Backup: {html.escape(data['backup_root'])}<br>
Source data scanned: {sum(r['size_bytes'] for r in data['jobs']) / 1024**3:.3f} GiB<br>
Source free space: {data['source_disk']['free_tib']:.3f} TiB;<br>
Backup free space: {data['backup_disk']['free_tib']:.3f} TiB</p>
<p class="hint">This report provides evidence for team members.
It never chooses or deletes files. MATCH means contents and directory structure match at scan time,
not that a job is approved for deletion. This is a static report: rerun the scanner after files change.
Files placed directly under the source root appear as individual rows using their filenames.</p><p>Python source scan: {data['source_scan_seconds']:.3f}s;
Excel scan: {html.escape(excel_text)}. Verification time is excluded from this comparison.</p>
<p>Rows are sorted by source size, largest first. Access times depend on the drive's Windows/server settings
and may be disabled or updated lazily.</p>
<table><thead><tr><th>Job / root filename</th><th>Files</th><th>GiB</th><th>Item modified (HKT)</th>
<th>Item accessed (HKT)</th><th>Latest file modified (HKT)</th><th>Latest file accessed (HKT)</th><th>Scanned at (HKT)</th>
<th>Verification</th><th>Team action prompt</th><th>Missing / extra / different files</th>
<th>Difference details</th></tr></thead><tbody>{''.join(table_rows)}</tbody></table>
<p>Job summary: report.csv. Every file and its size result: file_report.csv. Full data: report.json.</p></html>"""
    (output / "index.html").write_text(page, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="JSON file with source_root, backup_root, report_dir")
    parser.add_argument("--job", action="append", dest="jobs", help="Specific source job; may be repeated")
    parser.add_argument("--file", action="append", dest="files",
                        help="Specific file directly under source root; may be repeated")
    copy_group = parser.add_mutually_exclusive_group()
    copy_group.add_argument("--copy", action="store_true",
                            help="Copy explicitly selected --job/--file items")
    copy_group.add_argument("--copy-all", action="store_true",
                            help="Copy every discovered job and source-root file")
    parser.add_argument("--excel-seconds", type=float, help="Measured Excel scan time for same jobs and scope")
    args = parser.parse_args(argv)
    if args.copy and not (args.jobs or args.files):
        parser.error("--copy requires at least one explicit --job or --file")
    if not (args.copy or args.copy_all) and args.files:
        parser.error("--file is only used with --copy")
    if args.copy_all and (args.jobs or args.files):
        parser.error("--copy-all cannot be combined with --job or --file")
    if args.excel_seconds is not None and args.excel_seconds < 0:
        parser.error("--excel-seconds must be nonnegative")
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        source_root = Path(config["source_root"]).expanduser()
        backup_root = Path(config["backup_root"]).expanduser()
        report_dir = Path(config["report_dir"]).expanduser()
        jobs = discover_jobs(source_root, None if args.copy_all else args.jobs)
        source_root_files = {path.name for path in source_root.iterdir()
                             if path.is_file() and not path.is_symlink() and not is_ignored_file(path)}
        requested_files = set(args.files or [])
        missing_files = sorted(requested_files - source_root_files)
        if missing_files:
            raise ValueError(f"Root file not found: {', '.join(missing_files)}")
        jobs_to_copy = set(jobs) if args.copy_all else set(args.jobs or []) if args.copy else set()
        files_to_copy = source_root_files if args.copy_all else requested_files if args.copy else set()
        data = report(source_root, backup_root, jobs, jobs_to_copy, files_to_copy)
        save_report(data, report_dir, args.excel_seconds)
        print(f"{len(data['jobs'])} scan scope(s) checked; report: {report_dir / 'index.html'}")
        for row in data["jobs"]:
            print(f"{row['job']}: {row['status']}")
        return 0 if all(row["status"] == "MATCH" for row in data["jobs"]) else 2
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
