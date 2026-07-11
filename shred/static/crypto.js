// crypto.js — Web Crypto helpers for shred_
// Zero-knowledge: all encryption/decryption happens client-side.
// The server never sees plaintext, keys, or passwords.

const CHUNK_SIZE = 1024 * 1024;       // 1 MiB
const PBKDF2_ITERATIONS = 600000;
const IV_LENGTH = 12;                 // 96-bit GCM nonce
const SALT_LENGTH = 16;
const TAG_LENGTH = 16;                // AES-GCM auth tag

// --- base64url helpers (for URL fragment key) ---

function bytesToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlToBytes(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// --- standard base64 helpers (for API metadata) ---

function bytesToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// --- random ---

function randomBytes(length) {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

// --- key generation / import / export ---

function generateContentKey() {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function exportKey(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return bytesToBase64url(raw);
}

async function importKey(b64url) {
  const raw = base64urlToBytes(b64url);
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// --- PBKDF2 key derivation (password -> KEK) ---

async function deriveKEK(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"]
  );
}

// --- key wrapping (password mode) ---

async function wrapContentKey(kek, contentKey) {
  return crypto.subtle.wrapKey("raw", contentKey, kek, "AES-KW");
}

async function unwrapContentKey(kek, wrappedKeyBytes) {
  return crypto.subtle.unwrapKey(
    "raw",
    wrappedKeyBytes,
    kek,
    "AES-KW",
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// --- chunked AES-GCM ---

// IV per chunk: first 8 bytes of base_iv + 4-byte big-endian counter.
// Guarantees IV uniqueness under the same key for up to 2^32 chunks (4 TB).
function chunkIV(baseIv, index) {
  const iv = new Uint8Array(IV_LENGTH);
  iv.set(baseIv.subarray(0, 8));
  const view = new DataView(iv.buffer);
  view.setUint32(8, index);
  return iv;
}

async function readJsonError(response, fallback) {
  try {
    const body = await response.json();
    return body.error || fallback;
  } catch (e) {
    return fallback;
  }
}

// Encrypts and uploads one ~1MiB chunk at a time — encrypt, POST, release,
// repeat — instead of building the whole ciphertext in memory before a
// single request. This is what actually keeps client memory flat for a
// multi-GB file; without it, removing the double-buffer in the old
// encryptFile() only halved a number that was still O(file size).
//
// init is a single request carrying the file's metadata (rate-limited and
// upload-token-gated server-side, same as the old one-shot endpoint).
// Each chunk after that is authorized purely by possession of the
// (unguessable) upload_id returned from init.
async function chunkedUploadFile(file, key, baseIv, metadata, uploadToken, onProgress) {
  const initForm = new FormData();
  for (const [k, v] of Object.entries(metadata)) initForm.append(k, v);
  if (uploadToken) initForm.append("upload_token", uploadToken);

  const initHeaders = uploadToken ? { "X-Upload-Token": uploadToken } : {};
  const initResp = await fetch("/api/upload/init", { method: "POST", body: initForm, headers: initHeaders });
  if (!initResp.ok) {
    throw new Error(await readJsonError(initResp, "upload init failed (" + initResp.status + ")"));
  }
  const { upload_id } = await initResp.json();

  const totalChunks = Math.ceil(file.size / CHUNK_SIZE) || 1;
  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const chunkBuffer = await file.slice(start, end).arrayBuffer();

    const iv = chunkIV(baseIv, i);
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, chunkBuffer);

    const chunkForm = new FormData();
    chunkForm.append("upload_id", upload_id);
    chunkForm.append("chunk_index", String(i));
    chunkForm.append("chunk", new Blob([encrypted]), "chunk.enc");

    const chunkResp = await fetch("/api/upload/chunk", { method: "POST", body: chunkForm });
    if (!chunkResp.ok) {
      throw new Error(await readJsonError(chunkResp, "chunk upload failed (" + chunkResp.status + ")"));
    }

    if (onProgress) onProgress((i + 1) / totalChunks);
  }

  const finishForm = new FormData();
  finishForm.append("upload_id", upload_id);
  const finishResp = await fetch("/api/upload/finish", { method: "POST", body: finishForm });
  if (!finishResp.ok) {
    throw new Error(await readJsonError(finishResp, "upload finish failed (" + finishResp.status + ")"));
  }
  return finishResp.json();
}

// --- streaming download + decrypt ---
//
// The network response arrives as arbitrary-sized chunks that don't line up
// with our logical (CHUNK_SIZE + TAG_LENGTH) ciphertext chunk boundaries, so
// we can't know a chunk is complete (let alone that it's the *last* one,
// which may be shorter) until we've either buffered a full chunk's worth or
// hit the end of the stream. Buffering just enough to stay one chunk ahead
// keeps memory flat at O(chunk size) regardless of file size.
function createDecryptTransform(key, baseIv, onBytesDecrypted) {
  const fullChunkCtSize = CHUNK_SIZE + TAG_LENGTH;
  let buffer = new Uint8Array(0);
  let chunkIndex = 0;
  let bytesIn = 0;

  function append(next) {
    const combined = new Uint8Array(buffer.length + next.length);
    combined.set(buffer);
    combined.set(next, buffer.length);
    buffer = combined;
  }

  async function decryptChunk(ctBytes) {
    const iv = chunkIV(baseIv, chunkIndex++);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ctBytes);
    return new Uint8Array(decrypted);
  }

  return new TransformStream({
    async transform(chunk, controller) {
      append(chunk);
      bytesIn += chunk.length;
      // Only decrypt once we know more data follows, i.e. the buffered
      // chunk can't be the (possibly short) final one.
      while (buffer.length > fullChunkCtSize) {
        const ctSlice = buffer.subarray(0, fullChunkCtSize);
        const plaintext = await decryptChunk(ctSlice);
        buffer = buffer.slice(fullChunkCtSize);
        controller.enqueue(plaintext);
        if (onBytesDecrypted) onBytesDecrypted(bytesIn);
      }
    },
    async flush(controller) {
      if (buffer.length === 0) return;
      if (buffer.length < TAG_LENGTH) {
        throw new Error("corrupt ciphertext: truncated chunk");
      }
      const plaintext = await decryptChunk(buffer);
      controller.enqueue(plaintext);
      if (onBytesDecrypted) onBytesDecrypted(bytesIn);
    },
  });
}

// Registered once, early, from initViewPage — by the time the user actually
// clicks download the SW has almost always finished activating.
let _downloadSwRegistration = null;

function registerDownloadServiceWorker() {
  if (!("serviceWorker" in navigator) || !window.isSecureContext) return;
  navigator.serviceWorker.register("/static/download-sw.js")
    .then(function (reg) { _downloadSwRegistration = reg; })
    .catch(function () {});
}

// Note: this deliberately does NOT use navigator.serviceWorker.controller.
// A page only becomes "controlled" by a service worker if the page's own
// URL falls within that worker's scope — our view pages live at /f/<id>,
// outside the /static/ scope the download worker registers under, so
// `controller` would be null forever regardless of activation state or
// how long you wait. Messaging the registration's active worker directly
// works from any page: it doesn't require the sender to be controlled,
// only the *download link itself* (/static/__shred_stream__/<token>) to
// fall within the worker's scope, which it does. That in-scope-URL match
// is also what lets the worker intercept the anchor-click download at
// all, independent of this page's controller status — the mechanism
// StreamSaver.js-style techniques rely on.
async function getActiveDownloadServiceWorker() {
  if (!("serviceWorker" in navigator) || !window.isSecureContext) return null;
  try {
    let reg = _downloadSwRegistration || await navigator.serviceWorker.getRegistration("/static/download-sw.js");
    if (!reg) reg = await navigator.serviceWorker.register("/static/download-sw.js");
    if (reg.active) return reg.active;

    const installing = reg.installing || reg.waiting;
    if (!installing) return null;
    return await new Promise(function (resolve) {
      let settled = false;
      const timer = setTimeout(function () {
        if (settled) return;
        settled = true;
        resolve(reg.active || null);
      }, 3000);
      installing.addEventListener("statechange", function onChange() {
        if (settled || installing.state !== "activated") return;
        settled = true;
        clearTimeout(timer);
        installing.removeEventListener("statechange", onChange);
        resolve(reg.active);
      });
    });
  } catch (e) {
    return null;
  }
}

// True streaming save via a same-origin service worker fetch intercept:
// the browser's own download writer consumes the piped stream, so bytes
// never have to sit fully in page memory. Works in Firefox/Safari too,
// unlike the File System Access API. See static/download-sw.js.
//
// Deliberately fire-and-forget after the click, same as the old anchor+blob
// path — there's no reliable way to observe when the browser finishes
// writing to disk. A bad key or tampered ciphertext surfaces as a failed
// download in the browser's own UI, not here (password-protected files
// already validate the key via unwrap before a download is even attempted).
//
// An earlier version of this function used readableStream.tee() to drain a
// second branch just to catch that case — but tee() enqueues into both
// branches whenever either is pulled, not gated by the slower branch's
// buffer, so a drain loop running faster than the SW consumes the stream
// would silently reintroduce full-file buffering. Not worth it for
// marginal error visibility; removed.
function supportsTransferableStreams() {
  // Feature-detect transferable ReadableStreams. Older browsers throw
  // "DataCloneError" when a stream is listed in the transfer array; detecting
  // up front lets the caller pick the blob fallback instead of half-starting
  // an SW download that silently produces nothing.
  try {
    const rs = new ReadableStream();
    const mc = new MessageChannel();
    mc.port1.postMessage(rs, [rs]);
    mc.port1.close();
    mc.port2.close();
    return true;
  } catch (e) {
    return false;
  }
}

async function saveViaServiceWorker(worker, readableStream, filename, plainSize) {
  const token = crypto.randomUUID();

  // Transfer is atomic: if the browser can't transfer a ReadableStream this
  // throws before anything is sent and readableStream is left untouched, so
  // the caller can fall back to a different save strategy with the same
  // stream. (supportsTransferableStreams is checked first by the caller, but
  // keep the try semantics intact.)
  worker.postMessage(
    { type: "register-stream", token: token, filename: filename, size: plainSize, stream: readableStream },
    [readableStream]
  );

  // Trigger the download by navigating a hidden iframe to the SW-scoped URL,
  // NOT a top-level `<a download>` click. A service worker reliably
  // intercepts an iframe's in-scope navigation across browsers — this is the
  // mechanism StreamSaver.js uses — whereas a top-level download navigation
  // is the least reliably intercepted case, particularly in Firefox, which
  // is exactly where the old anchor approach produced "network activity but
  // no saved file". The iframe also means a failure can't blank out or
  // navigate away the page the user is looking at. The filename now rides on
  // the SW response's Content-Disposition, so the iframe needs no download
  // attribute.
  const iframe = document.createElement("iframe");
  iframe.setAttribute("hidden", "");
  iframe.style.display = "none";
  iframe.src = "/static/__shred_stream__/" + token;
  document.body.appendChild(iframe);
  // Once the browser commits the navigation to a download it continues in the
  // download manager independent of the iframe, so cleaning up after a delay
  // is safe and avoids leaking an element per download.
  setTimeout(function () {
    try { document.body.removeChild(iframe); } catch (e) {}
  }, 120000);
}

async function saveViaBlob(readableStream, filename) {
  const reader = readableStream.getReader();
  const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const blob = new Blob(chunks);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
}

// Fetches ciphertext, decrypts it as bytes arrive (never buffering the
// whole file), and saves it.
//
// Priority order is deliberate, not "best API first": File System Access
// (Chromium/Edge) is a mature, directly-observable API — pipeTo() either
// writes the file or throws, so failures are visible. The service worker
// path is the only way to get true streaming saves in Firefox/Safari
// (confirmed working end-to-end, byte-for-byte, via a real test), but
// under browser automation Chrome was observed to silently cancel SW-
// triggered downloads after handoff, with no error surfaced back to the
// page — a fire-and-forget API can't detect that. Since it's unclear
// whether that's an automation-only artifact or a real Chrome behavior,
// Chromium is kept on the API that's been verifiable, and the SW path is
// reserved for browsers that have no other route to a flat-memory save.
// Returns a short string naming the save path actually taken —
// "filesystem" | "service-worker" | "blob" | "aborted" — so the caller can
// show an honest status (e.g. the blob path buffers the whole file in memory
// and the user should be told, and the SW/FS paths save without a further
// prompt in some browsers). Throws on real errors (network, decrypt, expiry).
async function streamDownloadDecrypt(url, plainSize, key, baseIv, filename, onProgress) {
  const response = await fetch(url);
  if (response.status === 410) throw new Error("expired");
  if (response.status === 451) throw new Error("suspended");
  if (!response.ok) throw new Error("download failed (" + response.status + ")");

  const ctLength = Number(response.headers.get("Content-Length")) || 0;
  const transform = createDecryptTransform(key, baseIv, function (bytesIn) {
    if (onProgress && ctLength) onProgress(Math.min(bytesIn / ctLength, 1));
  });
  const decryptedStream = response.body.pipeThrough(transform);

  // 1. File System Access API (Chromium/Edge): mature, directly observable —
  //    pipeTo() resolves on success or throws, so failures are visible.
  if ("showSaveFilePicker" in window) {
    let handle;
    try {
      handle = await window.showSaveFilePicker({ suggestedName: filename });
    } catch (e) {
      if (e.name === "AbortError") {
        await decryptedStream.cancel();
        return "aborted";
      }
      throw e;
    }
    const writable = await handle.createWritable();
    await decryptedStream.pipeTo(writable);
    return "filesystem";
  }

  // 2. Service worker streaming save (Firefox/Safari and any browser without
  //    the FS Access API). Only attempt it when the browser can actually
  //    transfer the stream to the worker AND the worker is active — otherwise
  //    we'd hand off to a path that silently produces nothing. Fall through
  //    to the in-memory blob if either precondition fails.
  if (supportsTransferableStreams()) {
    const swWorker = await getActiveDownloadServiceWorker();
    if (swWorker) {
      await saveViaServiceWorker(swWorker, decryptedStream, filename, plainSize);
      return "service-worker";
    }
  }

  // 3. Last resort: buffer the whole decrypted file in memory as one Blob,
  //    then save. Works everywhere but peak memory ~= file size, so the
  //    caller warns the user for large files.
  await saveViaBlob(decryptedStream, filename);
  return "blob";
}

// --- filename encryption ---

async function encryptFilename(filename, key) {
  const enc = new TextEncoder();
  const iv = randomBytes(IV_LENGTH);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    enc.encode(filename)
  );
  const result = new Uint8Array(IV_LENGTH + encrypted.byteLength);
  result.set(iv);
  result.set(new Uint8Array(encrypted), IV_LENGTH);
  return result;
}

async function decryptFilename(encryptedFilenameBytes, key) {
  const data = new Uint8Array(encryptedFilenameBytes);
  const iv = data.subarray(0, IV_LENGTH);
  const ct = data.subarray(IV_LENGTH);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    ct
  );
  return new TextDecoder().decode(decrypted);
}

// --- image metadata stripping (canvas re-encode) ---

const STRIPPABLE_TYPES = ["image/jpeg", "image/png", "image/webp"];

async function stripImageMetadata(file) {
  if (!STRIPPABLE_TYPES.includes(file.type)) {
    return file;
  }

  try {
    const bitmap = await createImageBitmap(file);
    const canvas = document.createElement("canvas");
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(bitmap, 0, 0);
    bitmap.close();

    const blob = await new Promise(function (resolve) {
      canvas.toBlob(resolve, file.type, 0.95);
    });

    if (!blob || blob.size > file.size * 1.1) {
      return file;
    }

    return new File([blob], file.name, {
      type: file.type,
      lastModified: file.lastModified,
    });
  } catch (e) {
    return file;
  }
}
