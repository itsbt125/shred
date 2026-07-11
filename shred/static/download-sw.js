// download-sw.js — minimal service worker enabling true streaming saves.
//
// Firefox and Safari don't support the File System Access API
// (showSaveFilePicker), so without this, a "streamed" decrypt still has to
// be fully buffered in page memory before the browser can save it. This
// worker intercepts a same-origin fetch for a registered token and responds
// with a piped ReadableStream, so the browser's own download writer
// consumes decrypted bytes incrementally instead — no full-file buffer in
// page or worker memory, on any browser that supports service workers.

const pending = new Map(); // token -> { stream, filename, size }

// Build a safe Content-Disposition. The filename is the decrypted, uploader-
// chosen name, so treat it as untrusted: strip anything that could break out
// of the header (control chars, quotes, backslashes) for the ASCII fallback,
// and provide an RFC 5987 filename* so non-ASCII names still come through
// correctly instead of being mangled. (A synthetic Response's Headers
// constructor would throw on a raw CR/LF anyway, which would silently break
// the download — sanitising here keeps it working.)
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
      // The postMessage and the hidden-iframe navigation that triggers this
      // fetch are fired back-to-back on the page, but message delivery and
      // fetch dispatch aren't guaranteed to interleave in that order, so give
      // the message a brief window to land.
      let entry = pending.get(token);
      for (let i = 0; i < 50 && !entry; i++) {
        await new Promise(function (r) { setTimeout(r, 20); });
        entry = pending.get(token);
      }
      pending.delete(token);

      if (!entry) {
        return new Response("download not found or expired", { status: 404 });
      }

      // Deliberately NO Content-Length. This is a *streamed* response whose
      // byte count the browser discovers as it arrives. If we declare a
      // length and the produced count drifts from it by even one byte,
      // Firefox stalls the download waiting for bytes that never come — the
      // user sees network activity but no saved file and no error. Letting
      // the length be unknown (transfer-encoding: chunked semantics) is the
      // robust choice; the download panel just shows an unknown total.
      const headers = {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": buildContentDisposition(entry.filename),
        // Kept even though the page no longer sends COEP: require-corp — a
        // matching CORP header is harmless and future-proofs the response
        // against the download being cancelled under a stricter embedder
        // policy.
        "Cross-Origin-Resource-Policy": "same-origin",
      };

      return new Response(entry.stream, { headers: headers });
    })()
  );
});
