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
      // The postMessage and the anchor click that triggers this fetch are
      // both fired synchronously back-to-back on the page, but message
      // delivery and fetch dispatch aren't guaranteed to interleave in
      // that order, so give the message a brief window to land.
      let entry = pending.get(token);
      for (let i = 0; i < 50 && !entry; i++) {
        await new Promise(function (r) { setTimeout(r, 20); });
        entry = pending.get(token);
      }
      pending.delete(token);

      if (!entry) {
        return new Response("download not found or expired", { status: 404 });
      }

      const headers = {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": 'attachment; filename="' + entry.filename.replace(/"/g, "") + '"',
        // The page sends Cross-Origin-Embedder-Policy: require-corp, which
        // applies to this synthetic response too — without a matching CORP
        // header Chrome silently cancels the download instead of erroring.
        "Cross-Origin-Resource-Policy": "same-origin",
      };
      if (entry.size) headers["Content-Length"] = String(entry.size);

      return new Response(entry.stream, { headers: headers });
    })()
  );
});
