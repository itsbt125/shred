// download-sw.js — service worker enabling true streaming saves in Firefox/Safari
// (no File System Access API): intercepts a same-origin fetch for a registered
// token and responds with a piped ReadableStream, avoiding a full-file buffer.

const pending = new Map(); // token -> { stream, filename, size }

// filename is untrusted (uploader-chosen); strip header-breaking chars for the ASCII
// fallback and add an RFC 5987 filename* so non-ASCII names still come through.
function buildContentDisposition(filename) {
  const name = String(filename == null ? "download" : filename);
  const asciiFallback = name.replace(/[\x00-\x1f\x7f"\\]/g, "_").replace(/[^\x20-\x7e]/g, "_") || "download";
  const encoded = encodeURIComponent(name).replace(/['()*]/g, function (c) {
    return "%" + c.charCodeAt(0).toString(16).toUpperCase();
  });
  return 'attachment; filename="' + asciiFallback + '"; filename*=UTF-8\'\'' + encoded;
}

self.addEventListener("install", function (event) {
  self.skipWaiting();
});

self.addEventListener("activate", function (event) {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("message", function (event) {
  const data = event.data;
  if (!data || data.type !== "register-stream") return;
  pending.set(data.token, { filename: data.filename, size: data.size, stream: data.stream });
});

self.addEventListener("fetch", function (event) {
  const url = new URL(event.request.url);
  const marker = "/__shred_stream__/";
  const idx = url.pathname.indexOf(marker);
  if (idx === -1) return;

  const token = url.pathname.slice(idx + marker.length);

  event.respondWith(
    (async function () {
      // postMessage and the fetch-triggering navigation fire back-to-back but aren't
      // guaranteed to interleave in order, so give the message a brief window to land.
      let entry = pending.get(token);
      for (let i = 0; i < 50 && !entry; i++) {
        await new Promise(function (r) { setTimeout(r, 20); });
        entry = pending.get(token);
      }
      pending.delete(token);

      if (!entry) {
        return new Response("download not found or expired", { status: 404 });
      }

      // Deliberately no Content-Length: if a declared length drifts from the actual byte
      // count by even one byte, Firefox stalls the download with no error surfaced.
      const headers = {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": buildContentDisposition(entry.filename),
        "Cross-Origin-Resource-Policy": "same-origin",
      };

      return new Response(entry.stream, { headers: headers });
    })()
  );
});
