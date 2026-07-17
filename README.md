# shred

Free, open-source, **zero-knowledge** ephemeral file sharing. Files are encrypted
in the browser before upload — the server only ever stores ciphertext and never
sees your contents, filenames, keys, or passphrases. Share a link, the recipient
downloads and decrypts locally, and the file auto-deletes on expiry or download
limit.

## Features

- **Client-side AES-256-GCM.** Chunked at 1 MiB/plaintext-chunk; the random key
  lives in the URL fragment (`#k=…`) and never reaches the server — the link *is*
  the key.
- **Encrypted filenames.** Stored as opaque ciphertext under the same key.
- **Password mode (optional).** Derive the key from a passphrase (PBKDF2-SHA256,
  600k iterations) wrapping the content key with AES-KW, instead of putting it in
  the link. Blank passphrase auto-generates 5 Diceware words from a 7,776-word
  list (~64.5 bits), generated locally via CSPRNG.
- **Metadata stripping (BETA, imperfect).** Re-encodes images via canvas to drop
  EXIF/GPS. Good practice, not a guarantee — strip sensitive metadata yourself
  before a file leaves your device.
- **Ephemeral.** 5 min → 1 week, or burn-after-reading. A background thread reaps
  expired files; reported files are paused but still auto-delete at their expiry.
- **Multi-file / folder.** One link (`/g/<id>`); recipients grab files
  individually or as a single `.zip` built and streamed client-side.
- **Paste mode.** Share text with the same encryption/expiry/password options.
- **Resumable uploads.** A dropped connection resumes from the last acked chunk.
- **Sender-side deletion.** One-time delete token shown at upload; revoke early
  without admin access.
- **QR codes, named invite tokens, admin panel.** See below.

## Crypto summary

| | |
| --- | --- |
| Content encryption | AES-256-GCM, 1 MiB chunks, per-file random 96-bit base IV + per-chunk counter |
| Key delivery | URL fragment (`#k=`), never sent to server |
| Password mode | PBKDF2-SHA256 (600k) → AES-KW wraps the content key |
| Auto passphrase | 5 Diceware words, 7,776-word list, ~64.5 bits, CSPRNG |
| Filenames | encrypted under the content key |

All encryption/decryption is in-browser via the Web Crypto API. The server is a
dumb ciphertext store.

## Stack

Flask + vanilla JS, SQLite for metadata, blobs sharded on disk. Runs under
gunicorn behind nginx or Caddy. No accounts, no third-party services, no
client-side dependencies to fetch. (`shred/static/fonts/` ships empty — drop
the Redaction `.woff` files in or the serif fallback is used.)

## Quick start (dev)

```sh
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # read it — the defaults matter
python server.py          # http://127.0.0.1:5000
```

## Production

```sh
gunicorn --workers 2 --worker-class gthread --threads 4 \
         --bind 127.0.0.1:8000 --timeout 3600 server:app
```

Run behind a TLS-terminating reverse proxy. Example `nginx`, `Caddy`, and
`systemd` configs are in [`deploy/`](deploy/) — they terminate TLS, set **HSTS**,
disable access logs, and preserve upload streaming. Set `TRUSTED_PROXY_COUNT=1`
so the app sees real client IPs.

**systemd:** drop [`deploy/shred.service`](deploy/shred.service) into
`/etc/systemd/system/`, fix the `WorkingDirectory`/`EnvironmentFile` paths, then
`sudo systemctl enable --now shred`.

## Configuration

All settings are environment variables loaded from `.env`;
[`.env.example`](.env.example) has the full annotated list. Key ones:

| Variable | Default | Purpose |
| --- | --- | --- |
| `STORAGE_DIR` | `data` | Database + uploads location. |
| `MAX_SIZE_BYTES` | 2 GB | Per-file size cap. |
| `MAX_PASTE_SIZE` | 5 MB | Text-paste cap. |
| `MAX_EXPIRY_SECONDS` | 30 d | Longest expiry a client may pick. |
| `MIN_FREE_DISK_BYTES` | 1 GB | Refuse uploads below this free space. |
| `TRUSTED_PROXY_COUNT` | 0 | Reverse-proxy hops to trust for client IP. Set `1` behind nginx/Caddy. |
| `NO_LOGS` | 0 | `1` = keep the admin access log in memory only and never write any request IP to disk. |
| `REPORT_ACTION` | `suspend` | `suspend` pauses reported files; `off` just records the report. |
| `EXPOSE_DOWNLOAD_COUNT` | 0 | Show per-file download count on its page. |
| `ABUSE_CONTACT` | — | Address shown on `/terms`. |
| `ADMIN_TOKEN` | auto | Secret for `/admin` + token API. If blank while rotation is on, one is auto-generated and stored in the DB key-value store — never printed or logged. |

Rate limiting / anti-abuse (all per minute unless noted):

| Variable | Default | Purpose |
| --- | --- | --- |
| `UPLOAD_RATE_LIMIT` / `DOWNLOAD_RATE_LIMIT` | 10 / 30 | Per-IP (in-memory). |
| `REPORT_RATE_LIMIT` / `ADMIN_RATE_LIMIT` | 5 / 30 | Per-IP (in-memory). |
| `CHUNK_RATE_LIMIT` / `CHUNK_RATE_WINDOW` | 1000 / 60 s | Per-upload chunk throttle (DB-backed, shared across workers). |
| `MAX_CONCURRENT_CHUNKS_PER_IP` | 8 | Simultaneous in-flight chunk requests per IP. |
| `MAX_PENDING_UPLOADS` | 0 | Global cap on in-progress uploads (0 = unlimited). |
| `CLEANUP_INTERVAL` / `PENDING_UPLOAD_TTL` | 300 / 3600 s | Reap cadence / abandoned-upload TTL. |
| `REPORTS_RETENTION_SECONDS` | 90 d | Report history retention (0 = forever). |

## Upload gating

Anyone can upload by default. For a private instance, gate uploads — the single
biggest lever on abuse exposure. **Downloads are never gated** (the link is the
key).

- **Static token** — `UPLOAD_TOKEN`; the upload page then asks for it.
- **IP allowlist** — `UPLOAD_IP_ALLOWLIST` (comma-separated IPs/CIDRs).
- **Rotating token** — `UPLOAD_TOKEN_ROTATION=N`; a fresh token every N seconds,
  leaked ones die within 2×N. Fetch the current one from the admin panel or
  `GET /api/admin/token`.
- **Named invite tokens** — per-person, individually revocable, from the admin
  panel. Creating one turns gating on for the whole deployment; revoking your
  last invite won't silently reopen uploads.

## Admin & abuse

`/admin` (unlock with `ADMIN_TOKEN`) shows overview stats, the rotating token
(reveal/rotate), invite tokens (create/revoke), stored files (metadata only), the
report queue, and the in-memory admin access log. Pause, restore, or delete any
file from there.

Every download page has a **report** button, and this behavior — like most of
shred — is operator-configurable (`REPORT_ACTION`).

What reporting actually does: because the server holds only ciphertext, the
operator still cannot see *what* was reported. Reporting is a blind moderation
signal, not content inspection. With the default `REPORT_ACTION=suspend`, a
report flips the file to a paused state so it stops serving (HTTP 451) and lands
in the admin queue — the operator can then delete it or restore it, all without
ever decrypting anything. It exists so anyone holding a link can pull a suspected-
abusive share offline immediately and give the operator a takedown path that
respects the zero-knowledge model, rather than proving the file's contents. With
`REPORT_ACTION=off`, a report is only recorded (no auto-pause). Either way the
reporter's IP is never stored.

Takedown / law-enforcement contact is on `/terms`. That page is the project's
*default* policy — like the report behavior, expiries, gating, and limits, it's
just a starting point each operator sets and is responsible for on their own
instance.

## Privacy & security

- Zero-knowledge by design: the server cannot read, search, or recover contents.
- `NO_LOGS=1` keeps client IPs out of disk entirely (rate limiting stays in
  memory); reporter IPs are never stored regardless. This is aimed at high-risk
  or high-sensitivity deployments — instances serving at-risk users
  (journalists, activists, whistleblowers), operators in hostile jurisdictions,
  or anyone who simply wants the strongest privacy posture and minimal forensic
  footprint. The trade-off is less operational visibility for debugging and
  abuse response, so leave it off if you need those.
- App sets a strict CSP (no inline scripts/styles), `nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP/CORP, and HSTS
  over TLS; the `deploy/` proxies add HSTS too.
- File IDs are pattern-validated and paths contained to the upload dir — no
  traversal.
- The data dir is `0700` and the database `0600` (it holds live tokens); blobs
  are written `0600`. The app sets `umask(077)` at startup.
- The `Server` response header is hidden by the `deploy/` proxy configs (the
  WSGI server emits it below the app layer, so the app can't strip it).
- Client-side encryption protects *users'* privacy; it does **not** shield the
  operator from legal responsibility. Running a public instance? Read `/terms`,
  set a real `ABUSE_CONTACT`, and know your jurisdiction's obligations.

## Wiping data

```sh
./scripts/wipe.sh          # prompts
./scripts/wipe.sh --yes    # no prompt
```

Deletes all uploads and the database (recreated empty on next start); leaves
`.env` / `ADMIN_TOKEN` alone.

## License

**GNU AGPL-3.0.** See [`LICENSE`](LICENSE). Copyright (C) 2026 btea.dev.
</content>
</invoke>
