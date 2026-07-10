#!/usr/bin/env bash
#
# Deletes all uploaded files and the database. Doesn't touch .env or ADMIN_TOKEN.
# An empty database is recreated on next app start. Stop the server first.
#
#   ./scripts/wipe.sh          # prompts for confirmation
#   ./scripts/wipe.sh --yes    # no prompt
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# resolve STORAGE_DIR the same way shred/config.py does
if [[ -z "${STORAGE_DIR:-}" && -f "$ROOT/.env" ]]; then
  STORAGE_DIR="$(grep -E '^[[:space:]]*STORAGE_DIR=' "$ROOT/.env" | tail -1 | cut -d= -f2- | tr -d "\"' " || true)"
fi
STORAGE_DIR="${STORAGE_DIR:-data}"
if [[ "$STORAGE_DIR" = /* ]]; then
  DATA_DIR="$STORAGE_DIR"
else
  DATA_DIR="$ROOT/$STORAGE_DIR"
fi
UPLOAD_DIR="$DATA_DIR/uploads"

FORCE=0
[[ "${1:-}" == "-y" || "${1:-}" == "--yes" ]] && FORCE=1

echo "This will PERMANENTLY delete all user data:"
echo "  database: $DATA_DIR/shred.db (+ -wal / -shm)"
echo "  uploads:  $UPLOAD_DIR/"
echo

if [[ "$FORCE" -ne 1 ]]; then
  read -r -p "Type 'wipe' to confirm: " ans
  if [[ "$ans" != "wipe" ]]; then
    echo "aborted — nothing deleted."
    exit 1
  fi
fi

rm -f "$DATA_DIR/shred.db" "$DATA_DIR/shred.db-wal" "$DATA_DIR/shred.db-shm"

# :? guards against UPLOAD_DIR ever being empty and rm -rf'ing /
if [[ -d "$UPLOAD_DIR" ]]; then
  rm -rf "${UPLOAD_DIR:?}"
fi

echo "done — all user data wiped."
echo "restart the app (or 'python server.py') to recreate an empty database."
