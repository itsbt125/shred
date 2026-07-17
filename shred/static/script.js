// script.js — UI logic + real encrypt/upload/decrypt/download for shred

// Renders a " · "-separated meta line via DOM nodes only (no innerHTML).
function renderMetaLine(el, parts) {
  el.textContent = "";
  parts.forEach(function (text, i) {
    if (i > 0) {
      var sep = document.createElement("span");
      sep.textContent = " · ";
      el.appendChild(sep);
    }
    var span = document.createElement("span");
    span.textContent = text;
    el.appendChild(span);
  });
}

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

// Surface the instance's privacy posture to uploaders when the operator opted into it.
if (CONFIG.no_logs) {
  var nlBadge = document.getElementById("no-logs-badge");
  if (nlBadge) nlBadge.hidden = false;
}

var ID_RE = /^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/;
var UPLOAD_ID_RE = /^[A-Za-z0-9_-]{16,64}$/; // group_id shape, not the 4-4-4 file-id pattern

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

// Uniform int in [0, max) via rejection sampling, to avoid modulo bias.
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

function validUploadId(str) {
  return UPLOAD_ID_RE.test(str);
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

// Draws a QR code via the vendored qrcode.js module matrix directly to canvas (no innerHTML/SVG string sinks).
function renderQrCode(canvas, text) {
  if (!canvas || typeof qrcode !== "function") return false;
  try {
    var qr = qrcode(0, "M");
    qr.addData(text);
    qr.make();
    var moduleCount = qr.getModuleCount();
    var cellSize = 5;
    var margin = 4;
    var size = (moduleCount + margin * 2) * cellSize;
    canvas.width = size;
    canvas.height = size;
    var ctx = canvas.getContext("2d");
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = "#000";
    for (var row = 0; row < moduleCount; row++) {
      for (var col = 0; col < moduleCount; col++) {
        if (qr.isDark(row, col)) {
          ctx.fillRect((col + margin) * cellSize, (row + margin) * cellSize, cellSize, cellSize);
        }
      }
    }
    return true;
  } catch (e) {
    return false;
  }
}

function initUploadPage() {
  var dropzone = document.getElementById("dropzone");
  if (!dropzone) return;

  var fileInput = document.getElementById("file-input");
  var dropzonePrimary = document.getElementById("dropzone-primary");
  var dropzoneSecondary = document.getElementById("dropzone-secondary");
  var uploadBtn = document.getElementById("upload-btn");
  var uploadProgress = document.getElementById("upload-progress");
  var uploadProgressFill = document.getElementById("upload-progress-fill");
  var uploadStatus = document.getElementById("upload-status");
  var expirySelect = document.getElementById("expiry-select");
  var stripCheckbox = document.getElementById("strip-metadata");
  var randomizeCheckbox = document.getElementById("randomize-name");
  var stripOpt = document.getElementById("strip-metadata-opt");
  var randomizeOpt = document.getElementById("randomize-name-opt");
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
  var modeFileBtn = document.getElementById("mode-file-btn");
  var modePasteBtn = document.getElementById("mode-paste-btn");
  var pasteRow = document.getElementById("paste-row");
  var pasteInput = document.getElementById("paste-input");
  var pasteCount = document.getElementById("paste-count");
  var deleteLinkBtn = document.getElementById("delete-link-btn");
  var resultDeleteStatus = document.getElementById("result-delete-status");
  var qrWrap = document.getElementById("qr-wrap");
  var qrCanvas = document.getElementById("qr-canvas");

  var uploadMode = "file";
  var currentFileId = null;
  var currentDeleteToken = null;
  var currentGroupMembers = null; // group result: [{id, delete_token}, ...], exclusive with currentFileId

  function setMode(mode) {
    uploadMode = mode;
    if (mode === "paste") {
      dropzone.setAttribute("hidden", "");
      pasteRow.removeAttribute("hidden");
      if (stripOpt) stripOpt.setAttribute("hidden", "");
      if (randomizeOpt) randomizeOpt.setAttribute("hidden", "");
      modePasteBtn.classList.add("active");
      modePasteBtn.setAttribute("aria-selected", "true");
      modeFileBtn.classList.remove("active");
      modeFileBtn.setAttribute("aria-selected", "false");
      updatePasteState();
    } else {
      dropzone.removeAttribute("hidden");
      pasteRow.setAttribute("hidden", "");
      if (stripOpt) stripOpt.removeAttribute("hidden");
      if (randomizeOpt) randomizeOpt.removeAttribute("hidden");
      modeFileBtn.classList.add("active");
      modeFileBtn.setAttribute("aria-selected", "true");
      modePasteBtn.classList.remove("active");
      modePasteBtn.setAttribute("aria-selected", "false");
      uploadBtn[selectedFiles.length ? "removeAttribute" : "setAttribute"]("disabled", "disabled");
    }
  }

  if (modeFileBtn && modePasteBtn) {
    modeFileBtn.addEventListener("click", function () { setMode("file"); });
    modePasteBtn.addEventListener("click", function () { setMode("paste"); });
  }

  function pasteByteLength() {
    return new TextEncoder().encode(pasteInput.value).length;
  }

  function updatePasteState() {
    if (uploadMode !== "paste") return;
    var len = pasteByteLength();
    var overLimit = CONFIG.max_paste_size_bytes && len > CONFIG.max_paste_size_bytes;
    if (pasteCount) {
      pasteCount.textContent = overLimit
        ? "too long — max " + CONFIG.max_paste_size_display
        : (pasteInput.value ? len + " bytes / max " + CONFIG.max_paste_size_display : "");
      pasteCount.classList.toggle("paste-count-over", !!overLimit);
    }
    if (pasteInput.value.trim() && !overLimit) uploadBtn.removeAttribute("disabled");
    else uploadBtn.setAttribute("disabled", "disabled");
  }

  if (pasteInput) {
    pasteInput.addEventListener("input", updatePasteState);
  }

  if (uploadTokenInput) {
    try {
      var savedToken = localStorage.getItem("shred_upload_token");
      if (savedToken && !uploadTokenInput.value) uploadTokenInput.value = savedToken;
    } catch (e) {}
  }

  var reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var selectedFiles = []; // one file -> /f/<id> link; 2+ -> shared-key /g/<group_id> link

  function setSelectedFiles(fileList) {
    var arr = fileList ? Array.prototype.slice.call(fileList) : [];
    if (arr.length === 0) {
      selectedFiles = [];
      dropzone.classList.remove("has-file");
      dropzonePrimary.textContent = "click to browse or drag files here";
      dropzoneSecondary.textContent = "max " + CONFIG.max_file_size_display + " each · select multiple for one link";
      uploadBtn.setAttribute("disabled", "disabled");
      return;
    }

    var tooBig = null;
    var totalSize = 0;
    arr.forEach(function (f) {
      totalSize += f.size;
      if (CONFIG.max_file_size_bytes && f.size > CONFIG.max_file_size_bytes) tooBig = f;
    });
    if (tooBig) {
      selectedFiles = [];
      dropzone.classList.remove("has-file");
      dropzonePrimary.textContent = '"' + tooBig.name + '" is too large — max ' + CONFIG.max_file_size_display;
      dropzoneSecondary.textContent = "";
      uploadBtn.setAttribute("disabled", "disabled");
      return;
    }

    selectedFiles = arr;
    dropzone.classList.add("has-file");
    if (arr.length === 1) {
      dropzonePrimary.textContent = arr[0].name;
      dropzoneSecondary.textContent = formatSize(arr[0].size) + " — click to change";
    } else {
      dropzonePrimary.textContent = arr.length + " files selected";
      dropzoneSecondary.textContent = formatSize(totalSize) + " total — click to change";
    }
    uploadBtn.removeAttribute("disabled");
  }

  dropzone.addEventListener("click", function () { fileInput.click(); });

  dropzone.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fileInput.click();
    }
  });

  fileInput.addEventListener("change", function () {
    if (fileInput.files && fileInput.files.length) {
      setSelectedFiles(fileInput.files);
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
    if (e.dataTransfer.files && e.dataTransfer.files.length) {
      setSelectedFiles(e.dataTransfer.files);
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

  function wireVisibilityToggle(btnId, input, label) {
    var btn = document.getElementById(btnId);
    if (!btn || !input) return;
    btn.addEventListener("click", function () {
      var hidden = input.type === "password";
      input.type = hidden ? "text" : "password";
      btn.textContent = hidden ? "hide" : "show";
      btn.setAttribute("aria-label", (hidden ? "hide " : "show ") + label);
    });
  }

  wireVisibilityToggle("password-input-toggle", passwordInput, "passphrase");
  wireVisibilityToggle("upload-token-toggle", uploadTokenInput, "upload token");

  function showResult(shareUrl, isProtected, pass, expiryOption, fileId, deleteToken) {
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

    currentFileId = fileId;
    currentDeleteToken = deleteToken;
    currentGroupMembers = null;
    if (deleteToken) {
      try { localStorage.setItem("shred_delete_" + fileId, deleteToken); } catch (e) {}
    }
    if (deleteLinkBtn) {
      deleteLinkBtn.hidden = false;
      deleteLinkBtn.textContent = "delete this link";
      deleteLinkBtn.removeAttribute("disabled");
    }
    if (resultDeleteStatus) resultDeleteStatus.textContent = "";

    if (qrWrap && qrCanvas) {
      var drew = renderQrCode(qrCanvas, shareUrl);
      qrWrap.hidden = !drew;
    }

    stateUpload.setAttribute("hidden", "");
    stateResult.removeAttribute("hidden");
    window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
    initCopyButtons();
  }

  function showGroupResult(shareUrl, isProtected, pass, expiryOption, members) {
    shareLink.textContent = shareUrl;

    var isBurn = expiryOption.toLowerCase().startsWith("burn");
    resultMeta.textContent =
      (isBurn ? "expires after 1 read" : "expires in " + expiryOption) +
      " · " + members.length + " files";

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

    currentFileId = null;
    currentDeleteToken = null;
    currentGroupMembers = members;
    try {
      members.forEach(function (m) {
        if (m.delete_token) localStorage.setItem("shred_delete_" + m.id, m.delete_token);
      });
    } catch (e) {}

    if (deleteLinkBtn) {
      deleteLinkBtn.hidden = false;
      deleteLinkBtn.textContent = "delete this link";
      deleteLinkBtn.removeAttribute("disabled");
    }
    if (resultDeleteStatus) resultDeleteStatus.textContent = "";

    if (qrWrap && qrCanvas) {
      var drew = renderQrCode(qrCanvas, shareUrl);
      qrWrap.hidden = !drew;
    }

    stateUpload.setAttribute("hidden", "");
    stateResult.removeAttribute("hidden");
    window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
    initCopyButtons();
  }

  if (deleteLinkBtn) {
    deleteLinkBtn.addEventListener("click", function () {
      var isGroup = !!(currentGroupMembers && currentGroupMembers.length);
      if (!isGroup && (!currentFileId || !currentDeleteToken)) return;

      var confirmed = window.confirm(
        isGroup
          ? "Delete this link? All " + currentGroupMembers.length +
            " files will be permanently removed for everyone — this cannot be undone."
          : "Delete this link? The file will be permanently removed for everyone — this cannot be undone."
      );
      if (!confirmed) return;

      deleteLinkBtn.setAttribute("disabled", "disabled");
      deleteLinkBtn.textContent = "deleting...";

      var targets = isGroup
        ? currentGroupMembers.slice()
        : [{ id: currentFileId, delete_token: currentDeleteToken }];

      Promise.all(targets.map(function (t) {
        return fetch("/api/file/" + t.id, {
          method: "DELETE",
          headers: { "X-Delete-Token": t.delete_token },
        })
          .then(function (r) { return { ok: r.ok, target: t }; })
          .catch(function () { return { ok: false, target: t }; });
      })).then(function (results) {
        var failed = results.filter(function (r) { return !r.ok; });
        results.forEach(function (r) {
          if (r.ok) { try { localStorage.removeItem("shred_delete_" + r.target.id); } catch (e) {} }
        });

        if (failed.length === 0) {
          shareLink.textContent = "";
          resultMeta.textContent = "";
          resultPassphraseWrap.setAttribute("hidden", "");
          if (qrWrap) qrWrap.hidden = true;
          resultStatus.textContent = isGroup ? "these files have been deleted." : "this link has been deleted.";
          warningNote.textContent = "";
          deleteLinkBtn.hidden = true;
          if (resultDeleteStatus) resultDeleteStatus.textContent = "";
          currentFileId = null;
          currentDeleteToken = null;
          currentGroupMembers = null;
        } else {
          if (isGroup) {
            currentGroupMembers = failed.map(function (r) { return r.target; });
            if (resultDeleteStatus) {
              resultDeleteStatus.textContent =
                "error: could not delete " + failed.length + " of " + results.length + " files — please retry";
            }
          } else if (resultDeleteStatus) {
            resultDeleteStatus.textContent = "error: could not delete — please retry";
          }
          deleteLinkBtn.removeAttribute("disabled");
          deleteLinkBtn.textContent = "delete this link";
        }
      });
    });
  }

  function resetToUpload() {
    stateResult.setAttribute("hidden", "");
    stateUpload.removeAttribute("hidden");
    setSelectedFiles(null);
    fileInput.value = "";
    if (pasteInput) pasteInput.value = "";
    setMode("file");
    resumeState = null;
    currentFileId = null;
    currentDeleteToken = null;
    currentGroupMembers = null;
    if (uploadProgress) {
      uploadProgress.classList.remove("active");
      uploadProgressFill.style.width = "0%";
    }
    if (uploadStatus) uploadStatus.textContent = "";
    uploadBtn.textContent = "upload";
    uploadBtn.removeAttribute("disabled");
  }

  if (resetBtn) {
    resetBtn.addEventListener("click", resetToUpload);
  }

  var resumeState = null; // set on a failed upload, holds context needed to resume rather than restart

  if (uploadBtn) {
    uploadBtn.addEventListener("click", async function () {
      if (resumeState) {
        await runUpload(resumeState);
        return;
      }
      if (uploadMode === "paste") {
        if (!pasteInput || !pasteInput.value.trim()) return;
      } else if (!selectedFiles.length) {
        return;
      }

      uploadBtn.setAttribute("disabled", "disabled");
      var hasProgress = uploadProgress && uploadProgressFill;
      if (hasProgress) uploadProgress.classList.add("active");
      if (uploadStatus) uploadStatus.textContent = "";

      if (uploadMode === "file" && selectedFiles.length >= 2) {
        try {
          await runGroupUpload(await collectUploadParams(hasProgress));
        } catch (e) {
          failUpload(e, null);
        }
        return;
      }

      try {
        uploadBtn.textContent = "preparing...";
        var file, filename, contentKind;
        if (uploadMode === "paste") {
          var textBytes = new TextEncoder().encode(pasteInput.value);
          file = new Blob([textBytes]);
          filename = "note.txt";
          contentKind = "paste";
        } else {
          file = selectedFiles[0];
          if (stripCheckbox && stripCheckbox.checked) {
            file = await stripImageMetadata(file);
          }
          filename = file.name;
          if (randomizeCheckbox && randomizeCheckbox.checked) {
            filename = randomizeFilename(filename);
          }
          contentKind = "file";
        }

        uploadBtn.textContent = "encrypting...";
        var key = await generateContentKey();
        var baseIv = randomBytes(IV_LENGTH);
        var encryptedFilename = await encryptFilename(filename, key);

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
          content_kind: contentKind,
        };

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

        var uploadToken = null;
        if (uploadTokenInput && uploadTokenInput.value.trim()) {
          uploadToken = uploadTokenInput.value.trim();
          try { localStorage.setItem("shred_upload_token", uploadToken); } catch (e) {}
        }

        await runUpload({
          file: file,
          key: key,
          baseIv: baseIv,
          metadata: metadata,
          uploadToken: uploadToken,
          keyFragment: keyFragment,
          isProtected: isProtected,
          pass: pass,
          expiryOption: expiryOption,
          hasProgress: hasProgress,
          resumeUploadId: null,
        });

      } catch (e) {
        failUpload(e, null);
      }
    });
  }

  // Runs (or resumes) the chunked upload from a prepared context; shared by the initial attempt and a retry.
  async function runUpload(ctx) {
    uploadBtn.setAttribute("disabled", "disabled");
    var hasProgress = ctx.hasProgress;
    if (hasProgress) uploadProgress.classList.add("active");
    if (uploadStatus) uploadStatus.textContent = ctx.resumeUploadId ? "resuming upload..." : "";
    resumeState = null;

    try {
      uploadBtn.textContent = "uploading...";
      var result = await chunkedUploadFile(
        ctx.file, ctx.key, ctx.baseIv, ctx.metadata, ctx.uploadToken,
        function (progress) {
          if (hasProgress) setProgress(uploadProgressFill, progress * 100);
        },
        ctx.resumeUploadId
      );

      var shareUrl = window.location.origin + "/f/" + result.id;
      if (ctx.keyFragment) {
        shareUrl += "#k=" + ctx.keyFragment;
      }

      if (hasProgress) setProgress(uploadProgressFill, 100);
      showResult(shareUrl, ctx.isProtected, ctx.pass, ctx.expiryOption, result.id, result.delete_token);

    } catch (e) {
      failUpload(e, ctx);
    }
  }

  function failUpload(e, ctx) {
    if (uploadProgress && uploadProgressFill) {
      uploadProgress.classList.remove("active");
      uploadProgressFill.style.width = "0%";
    }
    if (ctx && e && e.uploadId) {
      resumeState = Object.assign({}, ctx, { resumeUploadId: e.uploadId });
      uploadBtn.textContent = "retry upload";
      uploadBtn.removeAttribute("disabled");
      if (uploadStatus) uploadStatus.textContent = "upload interrupted: " + e.message;
    } else {
      resumeState = null;
      uploadBtn.textContent = "upload";
      uploadBtn.removeAttribute("disabled");
      if (uploadStatus) uploadStatus.textContent = "error: " + e.message;
    }
  }

  // Gathers upload options shared by every file in a group, applied to each member.
  async function collectUploadParams(hasProgress) {
    var expiryOption = expirySelect ? expirySelect.value : "1 day";
    var expirySeconds = EXPIRY_MAP[expiryOption] || DEFAULT_EXPIRY_SECONDS;
    var expiry = Math.floor(Date.now() / 1000) + expirySeconds;
    var maxDownloads = expiryOption.toLowerCase().startsWith("burn") ? 1 : 0;

    var isProtected = !!(passwordToggle && passwordToggle.checked);
    var pass = null;
    if (isProtected) {
      pass = (passwordInput && passwordInput.value.trim()) || await generatePassphrase();
    }

    var uploadToken = null;
    if (uploadTokenInput && uploadTokenInput.value.trim()) {
      uploadToken = uploadTokenInput.value.trim();
      try { localStorage.setItem("shred_upload_token", uploadToken); } catch (e) {}
    }

    return {
      files: selectedFiles.slice(),
      expiryOption: expiryOption,
      expiry: expiry,
      maxDownloads: maxDownloads,
      isProtected: isProtected,
      pass: pass,
      uploadToken: uploadToken,
      strip: !!(stripCheckbox && stripCheckbox.checked),
      randomize: !!(randomizeCheckbox && randomizeCheckbox.checked),
      hasProgress: hasProgress,
    };
  }

  // 32 random bytes -> 43 base64url chars, matching the server's valid_upload_id shape.
  function generateGroupId() {
    return bytesToBase64url(randomBytes(32));
  }

  // One shared AES-GCM key + group_id for all files, each with its own random baseIv
  // (so sharing the key across files never reuses a GCM nonce).
  async function runGroupUpload(ctx) {
    uploadBtn.setAttribute("disabled", "disabled");
    var hasProgress = ctx.hasProgress;
    if (hasProgress) uploadProgress.classList.add("active");
    resumeState = null;

    uploadBtn.textContent = "encrypting...";
    var key = await generateContentKey();
    var groupId = generateGroupId();

    var keyFragment = null;
    var saltB64 = null;
    var wrappedKeyB64 = null;
    if (ctx.isProtected) {
      var salt = randomBytes(SALT_LENGTH);
      var kek = await deriveKEK(ctx.pass, salt);
      var wrappedKey = await wrapContentKey(kek, key);
      saltB64 = bytesToBase64(salt);
      wrappedKeyB64 = bytesToBase64(wrappedKey);
    } else {
      keyFragment = await exportKey(key);
    }

    var total = ctx.files.length;
    var members = [];

    for (var i = 0; i < total; i++) {
      var f = ctx.files[i];
      if (ctx.strip) f = await stripImageMetadata(f);
      var filename = f.name;
      if (ctx.randomize) filename = randomizeFilename(filename);

      var baseIv = randomBytes(IV_LENGTH);
      var encryptedFilename = await encryptFilename(filename, key);

      var metadata = {
        iv: bytesToBase64(baseIv),
        encrypted_filename: bytesToBase64(encryptedFilename),
        size: f.size,
        expiry: String(ctx.expiry),
        max_downloads: String(ctx.maxDownloads),
        content_kind: "file",
        group_id: groupId,
        group_index: String(i),
        group_count: String(total),
        has_password: ctx.isProtected ? "1" : "0",
      };
      if (ctx.isProtected) {
        metadata.salt = saltB64;
        metadata.wrapped_key = wrappedKeyB64;
      }

      var fileIndex = i;
      uploadBtn.textContent = "uploading " + (i + 1) + " of " + total + "...";
      if (uploadStatus) uploadStatus.textContent = "file " + (i + 1) + " of " + total;

      // Sequential (not concurrent) to respect per-IP rate limits.
      var result = await chunkedUploadFile(
        f, key, baseIv, metadata, ctx.uploadToken,
        function (progress) {
          if (hasProgress) setProgress(uploadProgressFill, ((fileIndex + progress) / total) * 100);
        }
      );
      members.push({ id: result.id, delete_token: result.delete_token });
    }

    var shareUrl = window.location.origin + "/g/" + groupId;
    if (keyFragment) shareUrl += "#k=" + keyFragment;

    if (hasProgress) setProgress(uploadProgressFill, 100);
    showGroupResult(shareUrl, ctx.isProtected, ctx.pass, ctx.expiryOption, members);
  }
}

function initViewPage() {
  var downloadBtn = document.getElementById("download-btn");
  if (!downloadBtn) return;

  var pathParts = window.location.pathname.split("/").filter(Boolean);
  var lastPart = pathParts[pathParts.length - 1];
  var fileId = validId(lastPart) ? lastPart : null;

  if (!fileId) return;

  registerDownloadServiceWorker();

  var fileNameEl = document.getElementById("file-name");
  var fileMetaEl = document.getElementById("file-meta");
  var passwordGate = document.getElementById("password-gate");
  var passwordInput = document.getElementById("decrypt-password");
  var downloadProgress = document.getElementById("download-progress");
  var downloadProgressFill = document.getElementById("download-progress-fill");
  var downloadStatus = document.getElementById("download-status");
  var pasteView = document.getElementById("paste-view");
  var pasteContentEl = document.getElementById("paste-content");
  var pasteCopyBtn = document.getElementById("paste-copy-btn");

  var fragment = window.location.hash.slice(1);
  var keyMatch = fragment.match(/^k=(.+)$/);
  var fragmentKey = keyMatch ? keyMatch[1] : null;

  var meta = null;
  var contentKey = null;
  var decryptedFilename = null;

  function showExpired(neverExisted) {
    fileNameEl.textContent = neverExisted ? "this link doesn't look right" : "this file has expired";
    fileNameEl.style.fontSize = "20px";
    fileNameEl.style.fontFamily = '"Redaction 35", serif';
    fileMetaEl.textContent = neverExisted
      ? "no file was ever found at this link — check for a typo"
      : "nothing to recover, nothing to download";
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

  function metaLineParts(m, includeUploaded) {
    var parts = [formatSize(m.size)];
    if (includeUploaded) parts.push("uploaded " + formatAgo(m.created));
    parts.push(formatExpiry(m.expiry));
    if (m.downloads !== undefined) { // absent unless the operator enabled EXPOSE_DOWNLOAD_COUNT
      parts.push("downloaded " + m.downloads + " time" + (m.downloads === 1 ? "" : "s"));
    }
    return parts;
  }

  function showFileInfo(m, filename) {
    fileNameEl.textContent = m.content_kind === "paste" ? "shared text" : filename;
    renderMetaLine(fileMetaEl, metaLineParts(m, true));
  }

  async function doDecryptPaste(key, baseIv) {
    downloadBtn.setAttribute("disabled", "disabled");
    downloadBtn.textContent = "decrypting...";
    if (downloadProgress) downloadProgress.classList.add("active");
    if (downloadStatus) downloadStatus.textContent = "";

    try {
      var bytes = await streamDownloadDecryptToBytes(
        "/api/file/" + fileId,
        key,
        baseIv,
        function (progress) {
          if (downloadProgressFill) setProgress(downloadProgressFill, progress * 100);
        }
      );
      var text = new TextDecoder().decode(bytes);

      if (pasteContentEl) pasteContentEl.value = text;
      if (pasteView) pasteView.removeAttribute("hidden");
      if (downloadProgressFill) setProgress(downloadProgressFill, 100);
      if (downloadProgress) downloadProgress.classList.remove("active");
      downloadBtn.setAttribute("hidden", "");
      if (downloadStatus) downloadStatus.textContent = "decrypted";

      if (pasteCopyBtn) {
        pasteCopyBtn.addEventListener("click", function () {
          var finish = function () {
            var original = pasteCopyBtn.dataset.label || pasteCopyBtn.textContent;
            pasteCopyBtn.dataset.label = original;
            pasteCopyBtn.textContent = "copied";
            setTimeout(function () { pasteCopyBtn.textContent = original; }, 1400);
          };
          if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(finish).catch(finish);
          } else {
            pasteContentEl.select();
            try { document.execCommand("copy"); } catch (e) {}
            finish();
          }
        });
      }
    } catch (e) {
      downloadBtn.textContent = "view text";
      downloadBtn.removeAttribute("disabled");
      if (downloadProgress) downloadProgress.classList.remove("active");
      if (downloadProgressFill) downloadProgressFill.style.width = "0%";
      if (downloadStatus) {
        if (e.message === "expired") downloadStatus.textContent = "this file has expired";
        else if (e.message === "suspended") downloadStatus.textContent = "this file has been reported — downloads are paused";
        else downloadStatus.textContent = "error: " + e.message;
      }
      try { console.error("shred paste decrypt failed:", e); } catch (_) {}
      if (e.message === "expired") showExpired();
      if (e.message === "suspended") showSuspended();
    }
  }

  async function doDownload(key, baseIv, filename) {
    downloadBtn.setAttribute("disabled", "disabled");
    downloadBtn.textContent = "downloading...";
    if (downloadProgress) downloadProgress.classList.add("active");
    if (downloadStatus) downloadStatus.textContent = "";

    var willBufferInMemory =
      !("showSaveFilePicker" in window) &&
      !(supportsTransferableStreams() && "serviceWorker" in navigator && window.isSecureContext);
    var bigFile = meta && meta.size > 500 * 1024 * 1024;
    if (willBufferInMemory && bigFile && downloadStatus) {
      downloadStatus.textContent =
        "heads up: your browser can't stream this to disk, so it will be held in memory while downloading (" +
        formatSize(meta.size) + "). it may be slow or fail on low-memory devices.";
    }

    try {
      downloadBtn.textContent = "downloading & decrypting...";
      var mode = await streamDownloadDecrypt(
        "/api/file/" + fileId,
        meta ? meta.size : 0,
        key,
        baseIv,
        filename,
        function (progress) {
          if (downloadProgressFill) setProgress(downloadProgressFill, progress * 100);
        }
      );

      if (mode === "aborted") {
        downloadBtn.textContent = "download";
        downloadBtn.removeAttribute("disabled");
        if (downloadProgress) downloadProgress.classList.remove("active");
        if (downloadProgressFill) downloadProgressFill.style.width = "0%";
        if (downloadStatus) downloadStatus.textContent = "";
        return;
      }

      if (downloadProgressFill) setProgress(downloadProgressFill, 100);
      downloadBtn.textContent = "done";
      downloadBtn.removeAttribute("disabled");
      if (downloadStatus) {
        // service-worker/blob paths give no completion signal, so word this as "started" not "saved"
        if (mode === "service-worker" || mode === "blob") {
          downloadStatus.textContent = "decrypted — your download should be saving now (check your browser's downloads)";
        } else {
          downloadStatus.textContent = "decrypted and saved";
        }
      }
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
      try { console.error("shred download failed:", e); } catch (_) {}
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

      if (meta.content_kind === "paste") {
        downloadBtn.textContent = "view text";
        downloadBtn.removeAttribute("disabled");
        downloadBtn.onclick = function () {
          doDecryptPaste(contentKey, base64ToBytes(meta.iv));
        };
      } else {
        downloadBtn.textContent = "download";
        downloadBtn.removeAttribute("disabled");
        downloadBtn.onclick = function () {
          doDownload(contentKey, base64ToBytes(meta.iv), decryptedFilename);
        };
      }
    } catch (e) {
      downloadBtn.textContent = "decrypt & download";
      downloadBtn.removeAttribute("disabled");
      if (downloadStatus) downloadStatus.textContent = "wrong passphrase";
    }
  }

  (async function () {
    try {
      var response = await fetch("/api/meta/" + fileId);
      if (response.status === 410) {
        var body410 = await response.json().catch(function () { return {}; });
        showExpired(body410.error === "not found");
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
        fileNameEl.textContent = "encrypted file";
        renderMetaLine(fileMetaEl, metaLineParts(meta, false));
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

      if (!fragmentKey) {
        showError("this link is incomplete — the decryption key is missing from the URL");
        return;
      }

      contentKey = await importKey(fragmentKey);
      var encFn = base64ToBytes(meta.encrypted_filename);
      decryptedFilename = await decryptFilename(encFn, contentKey);

      showFileInfo(meta, decryptedFilename);
      passwordGate.setAttribute("hidden", "");

      if (meta.content_kind === "paste") {
        downloadBtn.textContent = "view text";
        downloadBtn.removeAttribute("disabled");
        downloadBtn.onclick = function () {
          doDecryptPaste(contentKey, base64ToBytes(meta.iv));
        };
      } else {
        downloadBtn.textContent = "download";
        downloadBtn.removeAttribute("disabled");
        downloadBtn.onclick = function () {
          doDownload(contentKey, base64ToBytes(meta.iv), decryptedFilename);
        };
      }

    } catch (e) {
      showError("failed to load file info");
    }
  })();
}

function initGroupPage() {
  var listEl = document.getElementById("group-list");
  if (!listEl) return;

  registerDownloadServiceWorker();

  var titleEl = document.getElementById("group-title");
  var metaEl = document.getElementById("group-meta");
  var statusEl = document.getElementById("group-status");
  var pwGate = document.getElementById("group-password-gate");
  var pwInput = document.getElementById("group-decrypt-password");
  var pwToggleBtn = document.getElementById("group-password-toggle-btn");
  var unlockBtn = document.getElementById("group-unlock-btn");
  var pwStatus = document.getElementById("group-password-status");
  var zipActions = document.getElementById("group-zip-actions");
  var zipBtn = document.getElementById("group-zip-btn");
  var zipProg = document.getElementById("group-zip-progress");
  var zipProgFill = document.getElementById("group-zip-progress-fill");
  var zipStatus = document.getElementById("group-zip-status");

  var pathParts = window.location.pathname.split("/").filter(Boolean);
  var groupId = pathParts[pathParts.length - 1];

  var fragment = window.location.hash.slice(1);
  var keyMatch = fragment.match(/^k=(.+)$/);
  var fragmentKey = keyMatch ? keyMatch[1] : null;

  var files = null;
  var contentKey = null;

  function showGone(neverExisted) {
    titleEl.textContent = neverExisted ? "this link doesn't look right" : "these files have expired";
    titleEl.style.fontSize = "20px";
    titleEl.style.fontFamily = '"Redaction 35", serif';
    metaEl.textContent = neverExisted
      ? "no files were found at this link — check for a typo"
      : "nothing to recover, nothing to download";
    if (pwGate) pwGate.setAttribute("hidden", "");
  }

  function showError(msg) {
    titleEl.textContent = msg;
    titleEl.style.fontSize = "20px";
    titleEl.style.fontFamily = '"Redaction 35", serif';
    metaEl.textContent = "";
    if (pwGate) pwGate.setAttribute("hidden", "");
  }

  async function downloadOne(file, filename, btn, prog, progFill, st) {
    btn.setAttribute("disabled", "disabled");
    btn.textContent = "downloading...";
    prog.classList.add("active");
    st.textContent = "";

    var willBufferInMemory =
      !("showSaveFilePicker" in window) &&
      !(supportsTransferableStreams() && "serviceWorker" in navigator && window.isSecureContext);
    if (willBufferInMemory && file.size > 500 * 1024 * 1024) {
      st.textContent = "heads up: your browser can't stream this to disk, so it will be held in memory (" +
        formatSize(file.size) + ").";
    }

    try {
      btn.textContent = "downloading & decrypting...";
      var mode = await streamDownloadDecrypt(
        "/api/file/" + file.id,
        file.size,
        contentKey,
        base64ToBytes(file.iv),
        filename,
        function (progress) { setProgress(progFill, progress * 100); }
      );

      if (mode === "aborted") {
        btn.textContent = "download";
        btn.removeAttribute("disabled");
        prog.classList.remove("active");
        progFill.style.width = "0%";
        st.textContent = "";
        return;
      }

      setProgress(progFill, 100);
      btn.textContent = "done";
      btn.removeAttribute("disabled");
      st.textContent = (mode === "service-worker" || mode === "blob")
        ? "decrypted — saving now (check your browser's downloads)"
        : "decrypted and saved";
    } catch (e) {
      btn.textContent = "download";
      btn.removeAttribute("disabled");
      prog.classList.remove("active");
      progFill.style.width = "0%";
      if (e.message === "expired") st.textContent = "this file has expired";
      else if (e.message === "suspended") st.textContent = "reported — downloads paused";
      else st.textContent = "error: " + e.message;
      try { console.error("shred group download failed:", e); } catch (_) {}
    }
  }

  async function renderFiles() {
    if (pwGate) pwGate.setAttribute("hidden", "");
    listEl.textContent = "";

    var totalSize = 0;
    files.forEach(function (f) { totalSize += f.size; });
    titleEl.textContent = files.length + (files.length === 1 ? " shared file" : " shared files");
    renderMetaLine(metaEl, [formatSize(totalSize) + " total", formatExpiry(files[0].expiry)]);

    var decryptedNames = [];

    for (var i = 0; i < files.length; i++) {
      var f = files[i];
      var filename;
      try {
        filename = await decryptFilename(base64ToBytes(f.encrypted_filename), contentKey);
      } catch (e) {
        filename = "file " + (i + 1);
      }
      decryptedNames.push(filename);

      var row = document.createElement("div");
      row.className = "group-file-row";

      var info = document.createElement("div");
      info.className = "group-file-info";
      var nameEl = document.createElement("div");
      nameEl.className = "group-file-name";
      nameEl.textContent = filename;
      var fmeta = document.createElement("div");
      fmeta.className = "group-file-meta";
      var fmetaParts = [formatSize(f.size)];
      if (f.downloads !== undefined) {
        fmetaParts.push("downloaded " + f.downloads + " time" + (f.downloads === 1 ? "" : "s"));
      }
      renderMetaLine(fmeta, fmetaParts);
      info.appendChild(nameEl);
      info.appendChild(fmeta);

      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn group-file-btn";
      btn.textContent = "download";

      var prog = document.createElement("div");
      prog.className = "upload-progress";
      var progFill = document.createElement("div");
      progFill.className = "upload-progress-fill";
      prog.appendChild(progFill);

      var st = document.createElement("div");
      st.className = "download-status";

      row.appendChild(info);
      row.appendChild(btn);
      row.appendChild(prog);
      row.appendChild(st);
      listEl.appendChild(row);

      (function (file, name, b, p, pf, s) {
        b.addEventListener("click", function () { downloadOne(file, name, b, p, pf, s); });
      })(f, filename, btn, prog, progFill, st);
    }

    if (files.length > 1 && zipActions && zipBtn) {
      zipActions.removeAttribute("hidden");
      zipBtn.addEventListener("click", function () { downloadAllZip(decryptedNames); });
    }
  }

  async function downloadAllZip(names) {
    zipBtn.setAttribute("disabled", "disabled");
    zipBtn.textContent = "downloading & zipping...";
    zipProg.classList.add("active");
    zipStatus.textContent = "";

    var entries = files.map(function (f) {
      return { url: "/api/file/" + f.id, iv: base64ToBytes(f.iv), size: f.size };
    });

    try {
      var mode = await downloadGroupAsZip(entries, names, contentKey, "shred-files.zip",
        function (progress) { setProgress(zipProgFill, progress * 100); });

      if (mode === "aborted") {
        zipBtn.textContent = "download all as .zip";
        zipBtn.removeAttribute("disabled");
        zipProg.classList.remove("active");
        zipProgFill.style.width = "0%";
        zipStatus.textContent = "";
        return;
      }

      setProgress(zipProgFill, 100);
      zipBtn.textContent = "done";
      zipBtn.removeAttribute("disabled");
      zipStatus.textContent = (mode === "service-worker" || mode === "blob")
        ? "zipped — saving now (check your browser's downloads)"
        : "zipped and saved";
    } catch (e) {
      zipBtn.textContent = "download all as .zip";
      zipBtn.removeAttribute("disabled");
      zipProg.classList.remove("active");
      zipProgFill.style.width = "0%";
      var which = e.filename ? ' ("' + e.filename + '")' : "";
      if (e.message === "expired") zipStatus.textContent = "a file" + which + " has expired — zip cancelled";
      else if (e.message === "suspended") zipStatus.textContent = "a file" + which + " was reported — zip cancelled";
      else zipStatus.textContent = "error: " + e.message;
      try { console.error("shred group zip failed:", e); } catch (_) {}
    }
  }

  function setupPasswordGate() {
    titleEl.textContent = "encrypted files";
    metaEl.textContent = files.length + (files.length === 1 ? " file" : " files") + " · passphrase required";
    if (pwGate) pwGate.removeAttribute("hidden");

    if (pwInput) {
      pwInput.addEventListener("input", function () {
        if (pwInput.value.length > 0) unlockBtn.removeAttribute("disabled");
        else unlockBtn.setAttribute("disabled", "disabled");
      });
      pwInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") { e.preventDefault(); handleUnlock(); }
      });
    }
    if (pwToggleBtn && pwInput) {
      pwToggleBtn.addEventListener("click", function () {
        var isPassword = pwInput.type === "password";
        pwInput.type = isPassword ? "text" : "password";
        pwToggleBtn.textContent = isPassword ? "hide" : "show";
      });
    }
    if (unlockBtn) unlockBtn.addEventListener("click", handleUnlock);
  }

  async function handleUnlock() {
    if (!pwInput || !pwInput.value) return;
    unlockBtn.setAttribute("disabled", "disabled");
    unlockBtn.textContent = "deriving key...";
    try {
      // Every member shares the same salt + wrapped key.
      var salt = base64ToBytes(files[0].salt);
      var kek = await deriveKEK(pwInput.value, salt);
      contentKey = await unwrapContentKey(kek, base64ToBytes(files[0].wrapped_key));
      await renderFiles();
    } catch (e) {
      unlockBtn.removeAttribute("disabled");
      unlockBtn.textContent = "unlock files";
      if (pwStatus) pwStatus.textContent = "wrong passphrase";
    }
  }

  (async function () {
    if (!validUploadId(groupId)) {
      showGone(true);
      return;
    }
    try {
      var response = await fetch("/api/group/" + encodeURIComponent(groupId));
      if (response.status === 404) {
        showGone(true);
        return;
      }
      if (response.status === 410) {
        showGone(false);
        return;
      }
      if (response.status === 429) {
        showError("too many requests — please wait a moment and reload");
        return;
      }
      if (response.status !== 200) {
        showError("failed to load these files");
        return;
      }

      var body = await response.json();
      files = body.files || [];
      if (files.length === 0) {
        showGone(false);
        return;
      }

      if (files[0].has_password) {
        setupPasswordGate();
        return;
      }

      if (!fragmentKey) {
        showError("this link is incomplete — the decryption key is missing from the URL");
        return;
      }
      contentKey = await importKey(fragmentKey);
      await renderFiles();
    } catch (e) {
      showError("failed to load these files");
      try { console.error("shred group load failed:", e); } catch (_) {}
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
    var pauses = CONFIG.report_action !== "off";
    var reason = window.prompt(
      "Report this file as abusive or illegal?\n\n" +
      (pauses
        ? "Downloads will be paused pending review."
        : "The operator will be notified; downloads are not automatically paused on this instance.") +
      " You can optionally describe the issue:"
    );
    if (reason === null) return;

    btn.setAttribute("disabled", "disabled");
    var form = new FormData();
    form.append("file_id", fileId);
    form.append("reason", reason || "");

    fetch("/api/report", {
      method: "POST",
      body: form,
      headers: { "X-Requested-With": "XMLHttpRequest" },
    })
      .then(function (r) {
        return r.json().then(function (j) { return { ok: r.ok, body: j }; });
      })
      .then(function (res) {
        if (res.ok) {
          if (statusEl) {
            statusEl.textContent = pauses
              ? "reported — thank you. downloads are now paused pending review."
              : "reported — thank you. the operator has been notified.";
          }
          btn.style.display = "none";
          if (pauses) {
            var dlBtn = document.getElementById("download-btn");
            if (dlBtn) { dlBtn.setAttribute("disabled", "disabled"); dlBtn.style.display = "none"; }
          }
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
  initGroupPage();
  initReportLink();
});
