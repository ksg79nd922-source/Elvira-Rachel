# PE results backup status tool

This tool scans each job folder directly under the PE results source root, checks a corresponding folder on the tier 3 backup drive, and publishes HTML, CSV, and JSON reports. It can also copy a job selected by a team member. It never deletes data or decides which job should be deleted.

The storage fields mirror the supplied `Storage_Tool_v3.1` VBA workflow: recursive folder size, folder modified/accessed times, scan timestamp, descending size order, and free space for both source and backup drives. The Python report also shows the latest modified/accessed time among files inside each job. Folder time and latest-file time are separate because Windows folder metadata does not necessarily change when a nested file changes. Access times may be disabled or updated lazily by Windows or the file server, so they are informational only.

The report is a snapshot, so rerun the scanner after adding or changing files. Expand **Show files** in the HTML report to see every source and backup filename, both byte sizes, `Size equal`, `Content equal`, and the file status. `file_report.csv` contains the same file-level output for Excel. Files placed directly inside the source or backup root, outside a job folder, appear as individual report rows using their filenames. Common operating-system metadata files (`.DS_Store`, `Thumbs.db`, and `desktop.ini`) are excluded from inventory, comparison, and copying. All displayed timestamps use Hong Kong time in the format `YYYY-MM-DD HH:MM:SS HKT`.

Each run produces four complementary files: `index.html` for team viewing, `report.csv` for job/item summary in Excel, `file_report.csv` for one-row-per-file comparison, and `report.json` for the complete machine-readable audit record.

Requires Python 3.9+ and no extra packages. Set the three paths in a copy of `config.example.json`. Drive letters are examples only; use the real shared-drive paths. Run it on a Windows computer that can access both drives. If the backup drive is unavailable, the run fails rather than reporting it as empty.

For a local Mac demonstration, double-click `start_local_demo.command`. It creates a sample `Job001` under `demo/P_PE_results`, automatically discovers every direct child folder as a job, performs a read-only scan, and opens the HTML report. Newly added job folders are included the next time the script runs. The first report should say `NOT_BACKED_UP`; this is expected because the demonstration tier 3 folder starts empty. The script does not copy or delete anything.

```powershell
py pe_backup_tool.py --config config.json
py pe_backup_tool.py --config config.json --job Job123 --job Job124
py pe_backup_tool.py --config config.json --job Job123 --copy
py pe_backup_tool.py --config config.json --job Job123 --excel-seconds 23.4
```

Open `index.html` in the report directory or put the report directory on a team-accessible share. `report.csv` is Excel-readable. The HTML dashboard shows the latest file modification date and backup status. `MATCH` means matching file paths, directory structure, file sizes and SHA-256 contents **at the time of scanning**. Modification timestamps may differ after copying, so they are displayed for planning but are not used as proof of content equality. `NOT_BACKED_UP` and `DIFFERENT` show where team members should review backup work. Even `MATCH` does not authorize cleanup.

Copying requires `--copy` and at least one `--job`. Files already present with matching content are skipped; different existing files are reported as conflicts and never overwritten. New files are copied to a temporary name, checked with SHA-256, then renamed into place. A full post-copy comparison still flags conflicts or extra backup files. The source may change during a run; rerun verification after a job has settled. Empty directories are copied and checked. Directory symlinks and special files are rejected so the run does not silently miss them. Python's `shutil.copy2` does not preserve all Windows metadata, including ACLs; if metadata fidelity is required, coordinate with IT before relying on this copy mode.

For an Excel speed assessment, time the **same source scan** with the current Excel tool on the same computer, same job set, and similarly warm network cache. Enter its elapsed seconds with `--excel-seconds`. The report compares only source inventory scan time, not SHA-256 verification or copying time. Repeat both measurements several times and use the median if the difference is small. The screenshot of `Runlog_Compare_v1.2.xlsb` shows a runlog-table comparator; it is not enough to benchmark PE folder scanning, so this tool does not invent an Excel baseline.

The tool assumes one direct subfolder per job and matching job names under the backup root. If the real P/Q layout differs, adapt the mapping before running on production data. Start with two completed jobs in read-only mode and compare the report with Beyond Compare and the team's existing records.
