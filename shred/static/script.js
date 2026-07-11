// script.js — UI logic + real encrypt/upload/decrypt/download for shred

var CONFIG = (function () {
  var el = document.getElementById("config-data");
  try { return el ? JSON.parse(el.textContent) : {}; } catch (e) { return {}; }
})();

var EXPIRY_MAP = {};
var DEFAULT_EXPIRY_SECONDS = 86400;
if (CONFIG.expiry_options) {
  CONFIG.expiry_options.forEach(function (opt) {
    EXPIRY_MAP[opt.label] = opt.seconds;
    if (opt.default) DEFAULT_EXPIRY_SECONDS = opt.seconds;
  });
}

var ID_RE = /^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/;

let WORDS = null;
let _wordsPromise = null;

function loadWords() {
  if (WORDS) return Promise.resolve(WORDS);
  if (_wordsPromise) return _wordsPromise;
  _wordsPromise = fetch("/static/words.json")
    .then(function (r) { return r.json(); })
    .then(function (w) { WORDS = w; return w; });
  return _wordsPromise;
}

// Uniform integer in [0, max) from the CSPRNG, using rejection sampling to
// avoid the modulo bias a plain `random % max` would introduce.
function secureRandomInt(max) {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  let x;
  do {
    crypto.getRandomValues(buf);
    x = buf[0];
  } while (x >= limit);
  return x % max;
}

async function randomWord() {
  const words = await loadWords();
  return words[secureRandomInt(words.length)];
}

async function generatePassphrase() {
  const words = await loadWords();
  const parts = [];
  for (let i = 0; i < 5; i++) parts.push(words[secureRandomInt(words.length)]);
  return parts.join("-");
}

function randomizeFilename(originalName) {
  const parts = originalName.split(".");
  const ext = parts.length > 1 ? parts.pop() : null;
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let random = "";
  for (let i = 0; i < 8; i++) {
    random += chars[secureRandomInt(chars.length)];
  }
  return ext ? random + "." + ext : random;
}

function validId(str) {
  return ID_RE.test(str);
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
  return (bytes / 1073741824).toFixed(2) + " GB";
}

function formatExpiry(expiry) {
  var now = Math.floor(Date.now() / 1000);
  var remaining = expiry - now;
  if (remaining < 0) return "expired";
  if (remaining < 3600) return "expires in " + Math.floor(remaining / 60) + " min";
  if (remaining < 86400) return "expires in " + Math.floor(remaining / 3600) + " hours";
  return "expires in " + Math.floor(remaining / 86400) + " days";
}

function formatAgo(created) {
  var now = Math.floor(Date.now() / 1000);
  var ago = now - created;
  if (ago < 60) return "just now";
  if (ago < 3600) return Math.floor(ago / 60) + " min ago";
  if (ago < 86400) return Math.floor(ago / 3600) + " hours ago";
  return Math.floor(ago / 86400) + " days ago";
}

function setProgress(fill, percent) {
  fill.style.width = percent + "%";
}

// --- copy buttons (shared) ---

function initCopyButtons() {
  document.querySelectorAll(".copy-btn").forEach(function (btn) {
    if (btn.dataset.bound) return;
    btn.dataset.bound = "1";
    btn.addEventListener("click", function () {
      var targetId = btn.dataset.copyTarget;
      var valueEl = document.getElementById(targetId);
      if (!valueEl) return;

      var text = valueEl.textContent.trim();
      var finish = function () {
        var original = btn.dataset.label || btn.textContent;
        btn.dataset.label = original;
        btn.textContent = "copied";
        btn.classList.add("copied");
        setTimeout(function () {
          btn.textContent = original;
          btn.classList.remove("copied");
        }, 1400);
      };

      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(finish).catch(finish);
      } else {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); } catch (e) {}
        document.body.removeChild(ta);
        finish();
      }
    });
  });
}

// --- upload page ---

function initUploadPage() {
  var dropzone = document.getElementById("dropzone");
  if (!dropzone) return;

  var fileInput = document.getElementById("file-input");
  var dropzonePrimary = document.getElementById("dropzone-primary");
  var dropzoneSecondary = document.getElementById("dropzone-secondary");
  var uploadBtn = document.getElementById("upload-btn");
  var uploadProgress = document.getElementById("upload-progress");
  var uploadProgressFill = document.getElementById("upload-progress-fill");
  var expirySelect = document.getElementById("expiry-select");
  var stripCheckbox = document.getElementById("strip-metadata");
  var randomizeCheckbox = document.getElementById("randomize-name");
  var passwordToggle = document.getElementById("password-toggle");
  var passphraseRow = document.getElementById("passphrase-row");
  var passwordInput = document.getElementById("password-input");
  var stateUpload = document.getElementById("state-upload");
  var stateResult = document.getElementById("state-result");
  var resetBtn = document.getElementById("reset-btn");
  var shareLink = document.getElementById("share-link");
  var resultMeta = document.getElementById("result-meta");
  var resultStatus = document.getElementById("result-status");
  var resultPassphraseWrap = document.getElementById("result-passphrase-wrap");
  var passphraseEl = document.getElementById("passphrase");
  var warningNote = document.getElementById("warning-note");
  var uploadTokenInput = document.getElementById("upload-token-input");

  // prefill a previously-used upload token, if this instance requires one
  if (uploadTokenInput) {
    try {
      var savedToken = localStorage.getItem("shred_upload_token");
      if (savedToken && !uploadTokenInput.value) uploadTokenInput.value = savedToken;
    } catch (e) {}
  }

  var reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var selectedFile = null;

  function setSelectedFile(file) {
    selectedFile = file;
    if (file) {
      if (CONFIG.max_file_size_bytes && file.size > CONFIG.max_file_size_bytes) {
        selectedFile = null;
        dropzone.classList.remove("has-file");
        dropzonePrimary.textContent = "file too large — max " + CONFIG.max_file_size_display;
        dropzoneSecondary.textContent = "";
        uploadBtn.setAttribute("disabled", "disabled");
        return;
      }
      dropzone.classList.add("has-file");
      dropzonePrimary.textContent = file.name;
      dropzoneSecondary.textContent = formatSize(file.size) + " — click to change";
      uploadBtn.removeAttribute("disabled");
    } else {
      dropzone.classList.remove("has-file");
      dropzonePrimary.textContent = "click to browse or drag a file here";
      dropzoneSecondary.textContent = "max " + CONFIG.max_file_size_display;
      uploadBtn.setAttribute("disabled", "disabled");
    }
  }

  dropzone.addEventListener("click", function () { fileInput.click(); });

  dropzone.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fileInput.click();
    }
  });

  fileInput.addEventListener("change", function () {
    if (fileInput.files && fileInput.files[0]) {
      setSelectedFile(fileInput.files[0]);
    }
  });

  ["dragenter", "dragover"].forEach(function (evt) {
    dropzone.addEventListener(evt, function (e) {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "dragend"].forEach(function (evt) {
    dropzone.addEventListener(evt, function (e) {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", function (e) {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  });

  if (passwordToggle) {
    passwordToggle.addEventListener("change", function () {
      if (passwordToggle.checked) {
        passphraseRow.removeAttribute("hidden");
      } else {
        passphraseRow.setAttribute("hidden", "");
        passwordInput.value = "";
      }
    });
  }

  function showResult(shareUrl, isProtected, pass, expiryOption) {
    shareLink.textContent = shareUrl;

    var isBurn = expiryOption.toLowerCase().startsWith("burn");
    resultMeta.textContent = isBurn ? "expires after 1 read" : "expires in " + expiryOption;

    if (isProtected) {
      resultPassphraseWrap.removeAttribute("hidden");
      passphraseEl.textContent = pass;
      resultStatus.textContent = "done. encrypted.";
      warningNote.textContent = "save this link and passphrase — neither will be shown again.";
    } else {
      resultPassphraseWrap.setAttribute("hidden", "");
      resultStatus.textContent = "done.";
      warningNote.textContent = "save this link — it won't be shown again.";
    }

    stateUpload.setAttribute("hidden", "");
    stateResult.removeAttribute("hidden");
    window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
    initCopyButtons();
  }

  function resetToUpload() {
    stateResult.setAttribute("hidden", "");
    stateUpload.removeAttribute("hidden");
    setSelectedFile(null);
    fileInput.value = "";
    if (uploadProgress) {
      uploadProgress.classList.remove("active");
      uploadProgressFill.style.width = "0%";
    }
    uploadBtn.textContent = "upload";
    uploadBtn.removeAttribute("disabled");
  }

  if (resetBtn) {
    resetBtn.addEventListener("click", resetToUpload);
  }

  if (uploadBtn) {
    uploadBtn.addEventListener("click", async function () {
      if (!selectedFile) return;
      uploadBtn.setAttribute("disabled", "disabled");
      var hasProgress = uploadProgress && uploadProgressFill;
      if (hasProgress) uploadProgress.classList.add("active");

      try {
        // Phase 1: prepare file
        uploadBtn.textContent = "preparing...";
        var file = selectedFile;
        if (stripCheckbox && stripCheckbox.checked) {
          file = await stripImageMetadata(file);
        }

        var filename = file.name;
        if (randomizeCheckbox && randomizeCheckbox.checked) {
          filename = randomizeFilename(filename);
        }

        // Phase 2: keys + filename encryption (fast, done upfront so the
        // full metadata is ready before the chunked upload's init call)
        uploadBtn.textContent = "encrypting...";
        var key = await generateContentKey();
        var baseIv = randomBytes(IV_LENGTH);
        var encryptedFilename = await encryptFilename(filename, key);

        // Phase 3: build metadata
        var expiryOption = expirySelect ? expirySelect.value : "1 day";
        var expirySeconds = EXPIRY_MAP[expiryOption] || DEFAULT_EXPIRY_SECONDS;
        var expiry = Math.floor(Date.now() / 1000) + expirySeconds;
        var maxDownloads = expiryOption.toLowerCase().startsWith("burn") ? 1 : 0;

        var metadata = {
          iv: bytesToBase64(baseIv),
          encrypted_filename: bytesToBase64(encryptedFilename),
          size: file.size,
          expiry: String(expiry),
          max_downloads: String(maxDownloads),
        };

        // Phase 4: password handling
        var isProtected = passwordToggle && passwordToggle.checked;
        var pass = null;
        var keyFragment = null;

        if (isProtected) {
          pass = (passwordInput && passwordInput.value.trim()) || await generatePassphrase();
          metadata.has_password = "1";
          var salt = randomBytes(SALT_LENGTH);
          metadata.salt = bytesToBase64(salt);
          var kek = await deriveKEK(pass, salt);
          var wrappedKey = await wrapContentKey(kek, key);
          metadata.wrapped_key = bytesToBase64(wrappedKey);
        } else {
          metadata.has_password = "0";
          keyFragment = await exportKey(key);
        }

        // Upload token, if this instance requires one — sent once at init,
        // not repeated on every chunk request.
        var uploadToken = null;
        if (uploadTokenInput && uploadTokenInput.value.trim()) {
          uploadToken = uploadTokenInput.value.trim();
          try { localStorage.setItem("shred_upload_token", uploadToken); } catch (e) {}
        }

        // Phase 6: upload — encrypts and POSTs one chunk at a time so
        // memory stays flat regardless of file size
        uploadBtn.textContent = "uploading...";
        var result = await chunkedUploadFile(file, key, baseIv, metadata, uploadToken, function (progress) {
          if (hasProgress) setProgress(uploadProgressFill, progress * 100);
        });

        // Phase 7: show result
        var shareUrl = window.location.origin + "/f/" + result.id;
        if (keyFragment) {
          shareUrl += "#k=" + keyFragment;
        }

        if (hasProgress) setProgress(uploadProgressFill, 100);
        showResult(shareUrl, isProtected, pass, expiryOption);

      } catch (e) {
        if (hasProgress) {
          uploadProgress.classList.remove("active");
          uploadProgressFill.style.width = "0%";
        }
        uploadBtn.textContent = "upload";
        uploadBtn.removeAttribute("disabled");
        dropzonePrimary.textContent = "error: " + e.message;
        dropzoneSecondary.textContent = "click to try again";
      }
    });
  }
}

// --- view page ---

function initViewPage() {
  var downloadBtn = document.getElementById("download-btn");
  if (!downloadBtn) return;

  var pathParts = window.location.pathname.split("/").filter(Boolean);
  var lastPart = pathParts[pathParts.length - 1];
  var fileId = validId(lastPart) ? lastPart : null;

  if (!fileId) return;

  // Registered early so it's almost always already active/controlling by
  // the time the user clicks download, avoiding the controllerchange race.
  registerDownloadServiceWorker();

  var fileNameEl = document.getElementById("file-name");
  var fileMetaEl = document.getElementById("file-meta");
  var passwordGate = document.getElementById("password-gate");
  var passwordInput = document.getElementById("decrypt-password");
  var downloadProgress = document.getElementById("download-progress");
  var downloadProgressFill = document.getElementById("download-progress-fill");
  var downloadStatus = document.getElementById("download-status");

  var fragment = window.location.hash.slice(1);
  var keyMatch = fragment.match(/^k=(.+)$/);
  var fragmentKey = keyMatch ? keyMatch[1] : null;

  var meta = null;
  var contentKey = null;
  var decryptedFilename = null;

  function showExpired() {
    fileNameEl.textContent = "this file has expired";
    fileNameEl.style.fontSize = "20px";
    fileNameEl.style.fontFamily = '"Redaction 35", serif';
    fileMetaEl.textContent = "nothing to recover, nothing to download";
    passwordGate.setAttribute("hidden", "");
    downloadBtn.style.display = "none";
    if (downloadProgress) downloadProgress.classList.remove("active");
  }

  function showError(msg) {
    fileNameEl.textContent = msg;
    fileNameEl.style.fontSize = "20px";
    fileNameEl.style.fontFamily = '"Redaction 35", serif';
    fileMetaEl.textContent = "";
    passwordGate.setAttribute("hidden", "");
    downloadBtn.style.display = "none";
  }

  function showSuspended() {
    fileNameEl.textContent = "this file has been reported";
    fileNameEl.style.fontSize = "20px";
    fileNameEl.style.fontFamily = '"Redaction 35", serif';
    fileMetaEl.textContent = "downloads are paused pending review";
    passwordGate.setAttribute("hidden", "");
    downloadBtn.style.display = "none";
    if (downloadProgress) downloadProgress.classList.remove("active");
  }

  function showFileInfo(m, filename) {
    fileNameEl.textContent = filename;
    fileMetaEl.innerHTML =
      "<span>" + formatSize(m.size) + "</span>" +
      "<span> · </span>" +
      "<span>uploaded " + formatAgo(m.created) + "</span>" +
      "<span> · </span>" +
      "<span>" + formatExpiry(m.expiry) + "</span>";
  }

  async function doDownload(key, baseIv, filename) {
    downloadBtn.setAttribute("disabled", "disabled");
    downloadBtn.textContent = "downloading...";
    if (downloadProgress) downloadProgress.classList.add("active");
    if (downloadStatus) downloadStatus.textContent = "";

    try {
      downloadBtn.textContent = "downloading & decrypting...";
      await streamDownloadDecrypt(
        "/api/file/" + fileId,
        meta ? meta.size : 0,
        key,
        baseIv,
        filename,
        function (progress) {
          if (downloadProgressFill) setProgress(downloadProgressFill, progress * 100);
        }
      );

      if (downloadProgressFill) setProgress(downloadProgressFill, 100);
      downloadBtn.textContent = "done";
      downloadBtn.removeAttribute("disabled");
      if (downloadStatus) downloadStatus.textContent = "decrypted and saved";
    } catch (e) {
      downloadBtn.textContent = "download";
      downloadBtn.removeAttribute("disabled");
      if (downloadProgress) downloadProgress.classList.remove("active");
      if (downloadProgressFill) downloadProgressFill.style.width = "0%";
      if (downloadStatus) {
        if (e.message === "expired") downloadStatus.textContent = "this file has expired";
        else if (e.message === "suspended") downloadStatus.textContent = "this file has been reported — downloads are paused";
        else downloadStatus.textContent = "error: " + e.message;
      }
      if (e.message === "expired") showExpired();
      if (e.message === "suspended") showSuspended();
    }
  }

  async function handlePasswordSubmit() {
    if (!passwordInput.value) return;
    downloadBtn.setAttribute("disabled", "disabled");
    downloadBtn.textContent = "deriving key...";

    try {
      var salt = base64ToBytes(meta.salt);
      var kek = await deriveKEK(passwordInput.value, salt);
      var wrappedKey = base64ToBytes(meta.wrapped_key);
      contentKey = await unwrapContentKey(kek, wrappedKey);

      var encFn = base64ToBytes(meta.encrypted_filename);
      decryptedFilename = await decryptFilename(encFn, contentKey);

      showFileInfo(meta, decryptedFilename);
      passwordGate.setAttribute("hidden", "");
      downloadBtn.textContent = "download";
      downloadBtn.removeAttribute("disabled");

      downloadBtn.onclick = function () {
        doDownload(contentKey, base64ToBytes(meta.iv), decryptedFilename);
      };
    } catch (e) {
      downloadBtn.textContent = "decrypt & download";
      downloadBtn.removeAttribute("disabled");
      if (downloadStatus) downloadStatus.textContent = "wrong passphrase";
    }
  }

  // Fetch meta and set up UI
  (async function () {
    try {
      var response = await fetch("/api/meta/" + fileId);
      if (response.status === 410) {
        showExpired();
        return;
      }
      if (response.status === 451) {
        showSuspended();
        return;
      }
      if (response.status !== 200) {
        showError("file not found");
        return;
      }

      meta = await response.json();

      if (meta.has_password) {
        // Password-protected: show password gate
        fileNameEl.textContent = "encrypted file";
        fileMetaEl.innerHTML =
          "<span>" + formatSize(meta.size) + "</span>" +
          "<span> · </span>" +
          "<span>" + formatExpiry(meta.expiry) + "</span>";
        passwordGate.removeAttribute("hidden");
        downloadBtn.textContent = "decrypt & download";
        downloadBtn.setAttribute("disabled", "disabled");

        if (passwordInput) {
          passwordInput.addEventListener("input", function () {
            if (passwordInput.value.length > 0) {
              downloadBtn.removeAttribute("disabled");
            } else {
              downloadBtn.setAttribute("disabled", "disabled");
            }
          });
          passwordInput.addEventListener("keydown", function (e) {
            if (e.key === "Enter") {
              e.preventDefault();
              handlePasswordSubmit();
            }
          });
        }

        var pwToggle = document.getElementById("password-toggle-btn");
        if (pwToggle && passwordInput) {
          pwToggle.addEventListener("click", function () {
            var isPassword = passwordInput.type === "password";
            passwordInput.type = isPassword ? "text" : "password";
            pwToggle.textContent = isPassword ? "hide" : "show";
          });
        }

        downloadBtn.onclick = handlePasswordSubmit;
        return;
      }

      // No password: need fragment key
      if (!fragmentKey) {
        showError("this link is incomplete — the decryption key is missing from the URL");
        return;
      }

      // Import key from fragment
      contentKey = await importKey(fragmentKey);
      var encFn = base64ToBytes(meta.encrypted_filename);
      decryptedFilename = await decryptFilename(encFn, contentKey);

      showFileInfo(meta, decryptedFilename);
      passwordGate.setAttribute("hidden", "");
      downloadBtn.textContent = "download";
      downloadBtn.removeAttribute("disabled");

      downloadBtn.onclick = function () {
        doDownload(contentKey, base64ToBytes(meta.iv), decryptedFilename);
      };

    } catch (e) {
      showError("failed to load file info");
    }
  })();
}

function initReportLink() {
  var btn = document.getElementById("report-btn");
  if (!btn) return;

  var pathParts = window.location.pathname.split("/").filter(Boolean);
  var lastPart = pathParts[pathParts.length - 1];
  var fileId = validId(lastPart) ? lastPart : null;
  if (!fileId) {
    btn.style.display = "none";
    return;
  }

  var statusEl = document.getElementById("report-status");

  btn.addEventListener("click", function () {
    var reason = window.prompt(
      "Report this file as abusive or illegal?\n\n" +
      "Downloads will be paused pending review. You can optionally describe the issue:"
    );
    if (reason === null) return; // cancelled

    btn.setAttribute("disabled", "disabled");
    var form = new FormData();
    form.append("file_id", fileId);
    form.append("reason", reason || "");

    fetch("/api/report", { method: "POST", body: form })
      .then(function (r) {
        return r.json().then(function (j) { return { ok: r.ok, body: j }; });
      })
      .then(function (res) {
        if (res.ok) {
          if (statusEl) statusEl.textContent = "reported — thank you. downloads are now paused pending review.";
          btn.style.display = "none";
          var dlBtn = document.getElementById("download-btn");
          if (dlBtn) { dlBtn.setAttribute("disabled", "disabled"); dlBtn.style.display = "none"; }
        } else {
          if (statusEl) statusEl.textContent = "error: " + ((res.body && res.body.error) || "could not report");
          btn.removeAttribute("disabled");
        }
      })
      .catch(function () {
        if (statusEl) statusEl.textContent = "network error — please try again";
        btn.removeAttribute("disabled");
      });
  });
}

document.addEventListener("DOMContentLoaded", function () {
  initCopyButtons();
  initUploadPage();
  initViewPage();
  initReportLink();
});
