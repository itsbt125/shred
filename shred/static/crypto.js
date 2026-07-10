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

async function encryptFile(file, key, baseIv, onProgress) {
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE) || 1;
  const chunks = [];

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const chunkBuffer = await file.slice(start, end).arrayBuffer();

    const iv = chunkIV(baseIv, i);
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      chunkBuffer
    );
    chunks.push(new Uint8Array(encrypted));

    if (onProgress) onProgress((i + 1) / totalChunks);
  }

  const totalLength = chunks.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return new Blob([result]);
}

// Compute chunk boundaries from ciphertext size alone (no original size needed).
function computeChunkLayout(totalCtLength) {
  const fullChunkCtSize = CHUNK_SIZE + TAG_LENGTH;
  const numFullChunks = Math.floor(totalCtLength / fullChunkCtSize);
  const remaining = totalCtLength - numFullChunks * fullChunkCtSize;

  let numChunks, lastChunkCtSize;
  if (remaining === 0) {
    numChunks = numFullChunks;
    lastChunkCtSize = fullChunkCtSize;
  } else {
    if (remaining < TAG_LENGTH) {
      throw new Error("corrupt ciphertext: truncated chunk");
    }
    numChunks = numFullChunks + 1;
    lastChunkCtSize = remaining;
  }

  if (numChunks === 0) {
    throw new Error("corrupt ciphertext: empty");
  }

  return { numChunks, lastChunkCtSize, fullChunkCtSize };
}

// In-memory decryption (for smaller files or browsers without File System Access API).
async function decryptFile(blob, key, baseIv, onProgress) {
  const buffer = await blob.arrayBuffer();
  const data = new Uint8Array(buffer);
  const layout = computeChunkLayout(data.length);

  const plaintextChunks = [];
  let offset = 0;

  for (let i = 0; i < layout.numChunks; i++) {
    const ctSize = i === layout.numChunks - 1 ? layout.lastChunkCtSize : layout.fullChunkCtSize;
    const ctSlice = data.subarray(offset, offset + ctSize);
    const iv = chunkIV(baseIv, i);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      ctSlice
    );
    plaintextChunks.push(new Uint8Array(decrypted));

    offset += ctSize;
    if (onProgress) onProgress((i + 1) / layout.numChunks);
  }

  const totalPtLength = plaintextChunks.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(totalPtLength);
  let ptOffset = 0;
  for (const chunk of plaintextChunks) {
    result.set(chunk, ptOffset);
    ptOffset += chunk.length;
  }

  return new Blob([result]);
}

// Stream decryption to disk via File System Access API (Chrome/Edge).
// Falls back to in-memory blob download otherwise.
async function decryptAndSave(blob, key, baseIv, filename, onProgress) {
  const buffer = await blob.arrayBuffer();
  const data = new Uint8Array(buffer);
  const layout = computeChunkLayout(data.length);

  if ("showSaveFilePicker" in window) {
    let handle;
    try {
      handle = await window.showSaveFilePicker({ suggestedName: filename });
    } catch (e) {
      if (e.name === "AbortError") return;
      throw e;
    }
    const writable = await handle.createWritable();
    try {
      let offset = 0;
      for (let i = 0; i < layout.numChunks; i++) {
        const ctSize = i === layout.numChunks - 1 ? layout.lastChunkCtSize : layout.fullChunkCtSize;
        const ctSlice = data.subarray(offset, offset + ctSize);
        const iv = chunkIV(baseIv, i);

        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: iv },
          key,
          ctSlice
        );
        await writable.write(new Uint8Array(decrypted));

        offset += ctSize;
        if (onProgress) onProgress((i + 1) / layout.numChunks);
      }
    } finally {
      await writable.close();
    }
    return;
  }

  // Fallback: in-memory
  const plaintext = await decryptFile(blob, key, baseIv, onProgress);
  const url = URL.createObjectURL(plaintext);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
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

// --- upload helper (XMLHttpRequest for progress) ---

function uploadCiphertext(blob, metadata, onProgress) {
  return new Promise(function (resolve, reject) {
    const formData = new FormData();
    formData.append("file", blob, "data.enc");
    for (const [k, v] of Object.entries(metadata)) {
      formData.append(k, v);
    }

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/upload");
    xhr.upload.addEventListener("progress", function (e) {
      if (e.lengthComputable && onProgress) {
        onProgress(e.loaded / e.total);
      }
    });
    xhr.addEventListener("load", function () {
      if (xhr.status === 200) {
        try {
          resolve(JSON.parse(xhr.responseText));
        } catch (e) {
          reject(new Error("bad server response"));
        }
      } else {
        try {
          const err = JSON.parse(xhr.responseText);
          reject(new Error(err.error || "upload failed"));
        } catch (e) {
          reject(new Error("upload failed (" + xhr.status + ")"));
        }
      }
    });
    xhr.addEventListener("error", function () {
      reject(new Error("network error during upload"));
    });
    xhr.send(formData);
  });
}

// --- download helper (XMLHttpRequest for progress) ---

function downloadCiphertext(url, onProgress) {
  return new Promise(function (resolve, reject) {
    const xhr = new XMLHttpRequest();
    xhr.open("GET", url);
    xhr.responseType = "blob";
    xhr.addEventListener("progress", function (e) {
      if (e.lengthComputable && onProgress) {
        onProgress(e.loaded / e.total);
      }
    });
    xhr.addEventListener("load", function () {
      if (xhr.status === 200) {
        resolve(xhr.response);
      } else if (xhr.status === 410) {
        reject(new Error("expired"));
      } else if (xhr.status === 451) {
        reject(new Error("suspended"));
      } else {
        reject(new Error("download failed (" + xhr.status + ")"));
      }
    });
    xhr.addEventListener("error", function () {
      reject(new Error("network error during download"));
    });
    xhr.send();
  });
}
