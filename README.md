# shred

A free, open-source, zero-knowledge ephemeral file-sharing service. Files are
encrypted in the browser before they're uploaded — the server never sees your
file contents, filenames, keys, or passwords. Share a link, the recipient
downloads and decrypts, and the file deletes itself on expiry or after download.

## How it works

- **Client-side encryption.** Files are encrypted with AES-256-GCM in the
  browser (chunked, 1 MiB per chunk). The random key is put in the URL fragment
  (`#k=…`), which never reaches the server — the link *is* the key.
- **Encrypted filenames.** The filename is encrypted under the same key, so the
  server only ever stores opaque ciphertext.
- **Password mode (optional).** Instead of putting the key in the link, derive it
  from a passphrase (PBKDF2, 600k iterations, SHA-256) and wrap the content key
  with AES-KW. Leave the passphrase blank to auto-generate a 5-word Diceware one
  (~64 bits, from a CSPRNG).
- **Metadata stripping.** Images are re-encoded via canvas to drop EXIF/GPS.
- **Ephemeral by default.** Pick 1 hour / 1 day / 1 week, or burn-after-reading.
  Expired files are cleaned up automatically; nothing is kept longer than its TTL.

## Stack

Flask + vanilla JS, SQLite for metadata, files sharded on disk. Runs under
gunicorn behind nginx or Caddy. No accounts, no third-party services, no
client-side dependencies to load.

## Running it

```sh
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt 
cp .env.example .env       # edit as needed, please read!!
python server.py            # dev server on http://127.0.0.1:5000
```

For production, run under gunicorn behind a TLS-terminating reverse proxy:

```sh
gunicorn --workers 1 --bind 127.0.0.1:8000 --timeout 3600 server:app
```

Example `nginx`, `Caddy`, and `systemd` configs are in [`deploy/`](deploy/). Set
`TRUSTED_PROXY_COUNT=1` so the app sees the real client IP behind the proxy.

### systemd

Drop [`deploy/shred.service`](deploy/shred.service) into `/etc/systemd/system/`,
adjust the `WorkingDirectory` and `EnvironmentFile` paths, then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now shred
```

## Configuration

All settings are environment variables (loaded from `.env`); see
[`.env.example`](.env.example) for the full list. The ones worth knowing:

| Variable | Purpose |
| --- | --- |
| `STORAGE_DIR` | Where the database and uploads live (default `data`). |
| `MAX_SIZE_BYTES` | Per-file size cap (default 2 GB). |
| `MIN_FREE_DISK_BYTES` | Stop accepting uploads below this much free space (default 1 GB). |
| `TRUSTED_PROXY_COUNT` | Trusted reverse-proxy hops. Set to `1` behind nginx/Caddy. |
| `ABUSE_CONTACT` | Address shown on the `/terms` page. |
| `UPLOAD_TOKEN` | Static secret required to upload. |
| `UPLOAD_IP_ALLOWLIST` | Comma-separated IPs/CIDRs allowed to upload. |
| `UPLOAD_TOKEN_ROTATION` | Rotate the upload token every N seconds (0 = off). |
| `ADMIN_TOKEN` | Secret for the admin panel and token API. |

## Upload gating

By default anyone can upload. For a private instance (e.g. sharing with friends),
gate uploads — this is the single biggest thing that reduces abuse exposure.
Downloads are never gated, since the link itself is the decryption key.

- **Static token** — set `UPLOAD_TOKEN`; the upload page then asks for it.
- **IP allowlist** — set `UPLOAD_IP_ALLOWLIST`.
- **Rotating tokens** — set `UPLOAD_TOKEN_ROTATION` to mint a fresh token every N
  seconds; a leaked token stops working within 2×N. Fetch the current one from
  the admin panel or `GET /api/admin/token`.

## Admin panel

`/admin`, unlocked with `ADMIN_TOKEN`. Shows an overview (uptime, storage, disk
usage, counts), the current upload token (reveal / rotate), the list of stored
files (metadata only — never plaintext), and the abuse-report queue. From here
you can pause, restore, or delete any file.

## Abuse handling

Every file's download page has a **report** button. Reporting *pauses* the file
immediately — downloads are blocked and the page shows "reported, pending review"
— without the operator ever decrypting anything. Reported files land in the admin
queue, where you review them and either restore or delete. Takedown and
law-enforcement contact is on the `/terms` page.

## Wiping data

To permanently delete all uploaded files and the database:

```sh
./scripts/wipe.sh          # prompts for confirmation
./scripts/wipe.sh --yes    # no prompt
```

Your `.env` and `ADMIN_TOKEN` are left alone; an empty database is recreated on
the next start.

## Security notes

- Everything sensitive is encrypted client-side; the server is zero-knowledge by
  design. It cannot read, search, or recover file contents.
- Strict CSP (no inline scripts/styles), `COOP`/`COEP`/`CORP`, `nosniff`,
  `X-Frame-Options: DENY`, and HSTS when served over TLS.
- File IDs are validated against a strict pattern and paths are contained to the
  upload directory, so IDs can't be used for traversal.
- Client-side encryption protects your users' privacy; it does not shield the
  operator from legal responsibility for hosted content. If you run a public
  instance, read `/terms`, set a real `ABUSE_CONTACT`, and understand your
  jurisdiction's obligations.

## License

Licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0). See
[`LICENSE`](LICENSE) for the full text.

    Copyright (C) 2026 btea.dev

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
    for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.
