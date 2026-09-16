#!/bin/zsh

set -u

SCRIPT_DIR="${0:A:h}"
cd "$SCRIPT_DIR" || exit 1

SOURCE_DIR="$SCRIPT_DIR/demo/P_PE_results"
BACKUP_DIR="$SCRIPT_DIR/demo/Tier3_PE_results"
REPORT_DIR="$SCRIPT_DIR/demo/report"
SAMPLE_JOB_NAME="Job001"

mkdir -p "$SOURCE_DIR/$SAMPLE_JOB_NAME" "$BACKUP_DIR" "$REPORT_DIR"

if [[ ! -f "$SOURCE_DIR/$SAMPLE_JOB_NAME/PE_result_example.txt" ]]; then
  cat > "$SOURCE_DIR/$SAMPLE_JOB_NAME/PE_result_example.txt" <<'EOF'
This is a local PE result example.
It represents a file that would normally be stored on the P drive.
EOF
fi

cat > "$SCRIPT_DIR/config.local-demo.json" <<EOF
{
  "source_root": "$SOURCE_DIR",
  "backup_root": "$BACKUP_DIR",
  "report_dir": "$REPORT_DIR"
}
EOF

echo "Running a read-only scan for every job folder..."
python3 "$SCRIPT_DIR/pe_backup_tool.py" \
  --config "$SCRIPT_DIR/config.local-demo.json"
RESULT=$?

echo
if [[ $RESULT -eq 2 ]]; then
  echo "Scan completed. One or more source/backup differences need review."
elif [[ $RESULT -ne 0 ]]; then
  echo "The tool stopped with an error. Review the message above."
  read "?Press Enter to close..."
  exit $RESULT
else
  echo "Scan completed. The local backup matches the source."
fi

echo "Report: $REPORT_DIR/index.html"
open "$REPORT_DIR/index.html"
echo
read "?Press Enter to close..."
