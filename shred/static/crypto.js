// crypto.js — Web Crypto helpers for shred_. Zero-knowledge: all
// encryption/decryption happens client-side; the server never sees
// plaintext, keys, or passwords.

const CHUNK_SIZE = 1024 * 1024;       // 1 MiB
const PBKDF2_ITERATIONS = 600000;
const IV_LENGTH = 12;                 // 96-bit GCM nonce
const SALT_LENGTH = 16;
const TAG_LENGTH = 16;                // AES-GCM auth tag

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

function randomBytes(length) {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

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

async function wrapContentKey(kek, contentKey) {
  return crypto.subtle.wrapKey("raw", contentKey, kek, "AES-KW");
}

async function unwrapContentKey(kek, wrappedKeyBytes) {
  // extractable: false — in password mode the content key never leaves memory
  // (only the link-fragment path needs exportKey, and that uses importKey instead).
  return crypto.subtle.unwrapKey(
    "raw",
    wrappedKeyBytes,
    kek,
    "AES-KW",
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// IV per chunk = base_iv[0:8] + 4-byte big-endian counter, unique for up to 2^32 chunks.
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

const CHUNK_RETRY_ATTEMPTS = 5;
const CHUNK_RETRY_BACKOFF_MS = [500, 1000, 2000, 4000];

// Retries transient failures (network error, 429, 5xx) with backoff; other statuses throw immediately.
async function uploadChunkWithRetry(uploadId, chunkIndex, encryptedBuffer) {
  let lastError;
  for (let attempt = 0; attempt < CHUNK_RETRY_ATTEMPTS; attempt++) {
    try {
      const chunkForm = new FormData();
      chunkForm.append("upload_id", uploadId);
      chunkForm.append("chunk_index", String(chunkIndex));
      chunkForm.append("chunk", new Blob([encryptedBuffer]), "chunk.enc");

      const chunkResp = await fetch("/api/upload/chunk", { method: "POST", body: chunkForm });
      if (chunkResp.ok) return;

      const msg = await readJsonError(chunkResp, "chunk upload failed (" + chunkResp.status + ")");
      if (chunkResp.status !== 429 && chunkResp.status < 500) {
        throw new Error(msg);
      }
      lastError = new Error(msg);
    } catch (e) {
      if (e instanceof TypeError) {
        lastError = e; // TypeError from fetch() means a network-level failure — treat as transient.
      } else {
        throw e;
      }
    }
    if (attempt < CHUNK_RETRY_ATTEMPTS - 1) {
      await new Promise(function (resolve) {
        setTimeout(resolve, CHUNK_RETRY_BACKOFF_MS[attempt] || 4000);
      });
    }
  }
  throw lastError;
}

// Encrypts and uploads ~1MiB at a time (encrypt, POST, release) to keep client memory flat for multi-GB files.
// resumeUploadId, if given, asks the server which chunk to resume from instead of re-sending already-received bytes.
async function chunkedUploadFile(file, key, baseIv, metadata, uploadToken, onProgress, resumeUploadId) {
  let upload_id = null;
  let startChunkIndex = 0;

  if (resumeUploadId) {
    try {
      const statusResp = await fetch("/api/upload/status/" + encodeURIComponent(resumeUploadId));
      if (statusResp.ok) {
        const statusBody = await statusResp.json();
        upload_id = resumeUploadId;
        startChunkIndex = statusBody.next_chunk_index || 0;
      }
    } catch (e) {
      // fall through to a fresh init
    }
  }

  if (!upload_id) {
    const initForm = new FormData();
    for (const [k, v] of Object.entries(metadata)) initForm.append(k, v);
    if (uploadToken) initForm.append("upload_token", uploadToken);

    const initHeaders = uploadToken ? { "X-Upload-Token": uploadToken } : {};
    const initResp = await fetch("/api/upload/init", { method: "POST", body: initForm, headers: initHeaders });
    if (!initResp.ok) {
      throw new Error(await readJsonError(initResp, "upload init failed (" + initResp.status + ")"));
    }
    upload_id = (await initResp.json()).upload_id;
    startChunkIndex = 0;
  }

  const totalChunks = Math.ceil(file.size / CHUNK_SIZE) || 1;
  for (let i = startChunkIndex; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const chunkBuffer = await file.slice(start, end).arrayBuffer();

    const iv = chunkIV(baseIv, i);
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, chunkBuffer);

    try {
      await uploadChunkWithRetry(upload_id, i, encrypted);
    } catch (e) {
      const err = new Error(e.message);
      err.uploadId = upload_id;
      throw err;
    }

    if (onProgress) onProgress((i + 1) / totalChunks);
  }

  const finishForm = new FormData();
  finishForm.append("upload_id", upload_id);
  let finishResp;
  try {
    finishResp = await fetch("/api/upload/finish", { method: "POST", body: finishForm });
  } catch (e) {
    const err = new Error("upload finish failed: " + e.message);
    err.uploadId = upload_id;
    throw err;
  }
  if (!finishResp.ok) {
    const err = new Error(await readJsonError(finishResp, "upload finish failed (" + finishResp.status + ")"));
    err.uploadId = upload_id;
    throw err;
  }
  return finishResp.json();
}

// Buffers one ciphertext chunk ahead since the network stream doesn't align with
// CHUNK_SIZE boundaries and we can't tell a chunk is the (possibly short) last one until more data arrives or the stream ends.
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

// Registered early from initViewPage so it's usually already active by the time the user clicks download.
let _downloadSwRegistration = null;

function registerDownloadServiceWorker() {
  if (!("serviceWorker" in navigator) || !window.isSecureContext) return;
  navigator.serviceWorker.register("/static/download-sw.js")
    .then(function (reg) { _downloadSwRegistration = reg; })
    .catch(function () {});
}

// Deliberately not navigator.serviceWorker.controller: /f/<id> pages are outside the
// worker's /static/ scope so controller is always null; messaging reg.active works regardless.
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

// Streams via a service worker fetch intercept (see download-sw.js) so bytes never sit
// fully in page memory; works in Firefox/Safari unlike the File System Access API.
// Fire-and-forget: there's no way to observe when the browser finishes writing to disk.
function supportsTransferableStreams() {
  // Older browsers throw DataCloneError transferring a ReadableStream; feature-detect
  // so the caller can pick the blob fallback instead of a silently-failing SW download.
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

  worker.postMessage(
    { type: "register-stream", token: token, filename: filename, size: plainSize, stream: readableStream },
    [readableStream]
  );

  // A hidden iframe navigation is reliably intercepted by the SW across browsers
  // (notably Firefox); a top-level <a download> click is not.
  const iframe = document.createElement("iframe");
  iframe.setAttribute("hidden", "");
  iframe.style.display = "none";
  iframe.src = "/static/__shred_stream__/" + token;
  document.body.appendChild(iframe);
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

// Fetches ciphertext, returns a ReadableStream of plaintext bytes (decrypted as they arrive,
// never buffering the whole file). Throws "expired"/"suspended" on 410/451.
async function openDecryptedStream(url, key, baseIv, onProgress) {
  const response = await fetch(url);
  if (response.status === 410) throw new Error("expired");
  if (response.status === 451) throw new Error("suspended");
  if (!response.ok) throw new Error("download failed (" + response.status + ")");

  const ctLength = Number(response.headers.get("Content-Length")) || 0;
  const transform = createDecryptTransform(key, baseIv, function (bytesIn) {
    if (onProgress && ctLength) onProgress(Math.min(bytesIn / ctLength, 1));
  });
  return response.body.pipeThrough(transform);
}

// Saves a plaintext ReadableStream to disk, picking the best available strategy.
// Chromium stays on File System Access rather than the SW path: SW-triggered downloads were
// observed to silently cancel under Chrome automation with no error surfaced back to the page.
// Returns "filesystem" | "service-worker" | "blob" | "aborted"; throws on real errors.
async function saveStream(decryptedStream, filename, plainSize) {
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

  if (supportsTransferableStreams()) {
    const swWorker = await getActiveDownloadServiceWorker();
    if (swWorker) {
      await saveViaServiceWorker(swWorker, decryptedStream, filename, plainSize);
      return "service-worker";
    }
  }

  // Last resort: buffers the whole file in memory (peak memory ~= file size).
  await saveViaBlob(decryptedStream, filename);
  return "blob";
}

async function streamDownloadDecrypt(url, plainSize, key, baseIv, filename, onProgress) {
  const decryptedStream = await openDecryptedStream(url, key, baseIv, onProgress);
  return saveStream(decryptedStream, filename, plainSize);
}

// Streams each file's decrypted bytes into a single ZIP via client-zip. Files are opened
// lazily (one fetch at a time) as the zip encoder pulls them, so we never exceed the browser's
// per-host connection cap and never buffer a whole file. Any per-file failure aborts the whole zip.
async function downloadGroupAsZip(files, filenames, contentKey, zipName, onProgress) {
  let totalSize = 0;
  for (const f of files) totalSize += (f.size || 0);

  const doneBytes = new Array(files.length).fill(0);
  function reportProgress() {
    if (!onProgress || !totalSize) return;
    let done = 0;
    for (const b of doneBytes) done += b;
    onProgress(Math.min(done / totalSize, 1));
  }

  const usedNames = Object.create(null);
  // Filenames are uploader-controlled: strip path separators, dot-segments and
  // control chars so a hostile name can't plant zip-slip entries ("../../x")
  // in the client-built archive when the recipient extracts it.
  function safeZipName(name) {
    let n = String(name == null ? "" : name);
    n = n.replace(/[\\/]/g, "_").replace(/[\x00-\x1f\x7f]/g, "_");
    if (n === "" || n === "." || n === "..") n = "file";
    return n;
  }
  function uniqueName(name, index) {
    let n = name ? safeZipName(name) : ("file-" + (index + 1));
    if (usedNames[n]) {
      const dot = n.lastIndexOf(".");
      const base = dot > 0 ? n.slice(0, dot) : n;
      const ext = dot > 0 ? n.slice(dot) : "";
      n = base + "-" + (usedNames[name]++) + ext;
    } else {
      usedNames[n] = 1;
    }
    return n;
  }

  async function* entries() {
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      const idx = i;
      let stream;
      try {
        stream = await openDecryptedStream(f.url, contentKey, f.iv, function (frac) {
          doneBytes[idx] = frac * (f.size || 0);
          reportProgress();
        });
      } catch (e) {
        const err = new Error(e.message);
        err.filename = filenames[i];
        throw err;
      }
      yield { name: uniqueName(filenames[i], i), input: stream, size: f.size };
    }
  }

  const zipResponse = downloadZip(entries());
  return saveStream(zipResponse.body, zipName, totalSize);
}

// Like streamDownloadDecrypt but returns plaintext bytes in memory; fine for paste/text shares (small, from a <textarea>).
async function streamDownloadDecryptToBytes(url, key, baseIv, onProgress) {
  const response = await fetch(url);
  if (response.status === 410) throw new Error("expired");
  if (response.status === 451) throw new Error("suspended");
  if (!response.ok) throw new Error("download failed (" + response.status + ")");

  const ctLength = Number(response.headers.get("Content-Length")) || 0;
  const transform = createDecryptTransform(key, baseIv, function (bytesIn) {
    if (onProgress && ctLength) onProgress(Math.min(bytesIn / ctLength, 1));
  });
  const decryptedStream = response.body.pipeThrough(transform);
  const reader = decryptedStream.getReader();
  const chunks = [];
  let totalLen = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    totalLen += value.length;
  }
  const combined = new Uint8Array(totalLen);
  let offset = 0;
  for (const c of chunks) {
    combined.set(c, offset);
    offset += c.length;
  }
  return combined;
}

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
