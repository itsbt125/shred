// admin.js — operator panel. Token goes in sessionStorage and is sent as
// X-Admin-Token, not a cookie, so it's not exposed to CSRF.

(function () {
  "use strict";

  var TOKEN_KEY = "shred_admin_token";
  var token = null;

  // --- elements ---
  var loginEl = document.getElementById("admin-login");
  var dashEl = document.getElementById("admin-dashboard");
  var tokenInput = document.getElementById("admin-token-input");
  var loginBtn = document.getElementById("admin-login-btn");
  var loginError = document.getElementById("admin-login-error");

  // --- helpers ---

  function adminFetch(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign({}, opts.headers || {}, { "X-Admin-Token": token });
    return fetch(path, opts);
  }

  function fmtBytes(b) {
    if (b == null) return "--";
    if (b < 1024) return b + " B";
    if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
    if (b < 1073741824) return (b / 1048576).toFixed(1) + " MB";
    return (b / 1073741824).toFixed(2) + " GB";
  }

  function fmtDuration(sec) {
    if (sec == null) return "--";
    if (sec < 60) return sec + "s";
    if (sec < 3600) return Math.floor(sec / 60) + "m";
    if (sec < 86400) return Math.floor(sec / 3600) + "h";
    return Math.floor(sec / 86400) + "d";
  }

  function fmtAgo(created, now) {
    var ago = now - created;
    if (ago < 60) return "just now";
    if (ago < 3600) return Math.floor(ago / 60) + "m ago";
    if (ago < 86400) return Math.floor(ago / 3600) + "h ago";
    return Math.floor(ago / 86400) + "d ago";
  }

  function fmtExpiry(expiry, now) {
    var rem = expiry - now;
    if (rem < 0) return "expired";
    if (rem < 3600) return "in " + Math.floor(rem / 60) + "m";
    if (rem < 86400) return "in " + Math.floor(rem / 3600) + "h";
    return "in " + Math.floor(rem / 86400) + "d";
  }

  // Build a stat card via DOM (no innerHTML with dynamic values).
  function statCard(value, label) {
    var card = document.createElement("div");
    card.className = "stat-card";
    var v = document.createElement("div");
    v.className = "stat-value";
    v.textContent = value;
    var l = document.createElement("div");
    l.className = "stat-label";
    l.textContent = label;
    card.appendChild(v);
    card.appendChild(l);
    return card;
  }

  // --- rendering ---

  function renderOverview(d) {
    var grid = document.getElementById("admin-overview");
    grid.textContent = "";
    grid.appendChild(statCard(fmtDuration(d.uptime), "uptime"));
    grid.appendChild(statCard(String(d.files_stored), "files stored"));
    grid.appendChild(statCard(fmtBytes(d.total_bytes), "total data"));
    grid.appendChild(statCard(String(d.total_uploads), "uploads"));
    grid.appendChild(statCard(String(d.total_downloads), "downloads"));
    grid.appendChild(statCard(String(d.suspended || 0), "suspended"));
    grid.appendChild(statCard(String(d.reports), "reports"));

    if (d.disk) {
      var usedPct = d.disk.total ? Math.round((d.disk.used / d.disk.total) * 100) : 0;
      grid.appendChild(statCard(fmtBytes(d.disk.free) + " free", "disk (" + usedPct + "% used)"));
    }

    var access = [];
    if (d.gating.token_required) access.push("token");
    if (d.gating.ip_restricted) access.push("ip");
    grid.appendChild(statCard(access.length ? access.join(" + ") : "open", "upload access"));

    // token section only relevant when rotation is enabled
    var rotation = d.gating.rotation;
    var tokenH = document.getElementById("token-section-h");
    var tokenBox = document.getElementById("admin-token-box");
    if (rotation) {
      tokenH.hidden = false;
      tokenBox.hidden = false;
      document.getElementById("admin-token-meta").textContent =
        "rotates every " + fmtDuration(rotation.interval_seconds) +
        " · next in " + fmtDuration(rotation.next_rotation_seconds);
    } else {
      tokenH.hidden = true;
      tokenBox.hidden = true;
    }
  }

  // offset is how many rows have been loaded so far (also the next page's
  // offset param); total comes from the server's COUNT(*) each response.
  var filesState = { offset: 0, total: 0 };
  var reportsState = { offset: 0, total: 0 };

  function renderFiles(list, now, append) {
    var body = document.getElementById("files-body");
    var empty = document.getElementById("files-empty");
    if (!append) body.textContent = "";
    document.getElementById("files-count").textContent =
      filesState.offset ? "(" + filesState.offset + (filesState.total > filesState.offset ? " of " + filesState.total : "") + ")" : "";
    empty.hidden = filesState.offset > 0;
    document.getElementById("files-load-more").hidden = filesState.offset >= filesState.total;

    list.forEach(function (f) {
      var tr = document.createElement("tr");
      if (f.suspended) tr.className = "row-suspended";
      var maxDl = f.max_downloads > 0 ? "/" + f.max_downloads : "";
      appendCells(tr, [
        f.id,
        fmtBytes(f.size),
        fmtAgo(f.created, now),
        fmtExpiry(f.expiry, now),
        f.downloads + maxDl,
        f.has_password ? "yes" : "",
      ]);

      var statusTd = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = f.suspended ? "badge badge-suspended" : "badge badge-active";
      badge.textContent = f.suspended ? "paused" : "active";
      statusTd.appendChild(badge);
      tr.appendChild(statusTd);

      var actionTd = document.createElement("td");
      actionTd.className = "action-cell";
      if (f.suspended) {
        actionTd.appendChild(actionButton("restore", f.id, "restore", null));
      } else {
        actionTd.appendChild(actionButton("pause", f.id, "suspend", null));
      }
      actionTd.appendChild(actionButton("delete", f.id, "delete",
        "Delete file " + f.id + "? This removes it permanently."));
      tr.appendChild(actionTd);
      body.appendChild(tr);
    });
  }

  function renderReports(list, now, append) {
    var body = document.getElementById("reports-body");
    var empty = document.getElementById("reports-empty");
    if (!append) body.textContent = "";
    document.getElementById("reports-count").textContent =
      reportsState.offset ? "(" + reportsState.offset + (reportsState.total > reportsState.offset ? " of " + reportsState.total : "") + ")" : "";
    empty.hidden = reportsState.offset > 0;
    document.getElementById("reports-load-more").hidden = reportsState.offset >= reportsState.total;

    list.forEach(function (rep) {
      var tr = document.createElement("tr");
      var status = rep.existed ? "" : " (file already gone)";
      appendCells(tr, [
        fmtAgo(rep.created, now) + status,
        rep.file_id,
        rep.reason || "—",
        rep.ip || "—",
      ]);

      var actionTd = document.createElement("td");
      actionTd.className = "action-cell";
      actionTd.appendChild(actionButton("restore", rep.file_id, "restore", null));
      actionTd.appendChild(actionButton("delete", rep.file_id, "delete",
        "Delete file " + rep.file_id + "? This removes it permanently."));
      tr.appendChild(actionTd);
      body.appendChild(tr);
    });
  }

  function appendCells(tr, values) {
    values.forEach(function (v) {
      var td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
  }

  // action: "delete" (DELETE), or "suspend" / "restore" (POST).
  function fileAction(fileId, action) {
    var path = "/api/admin/files/" + encodeURIComponent(fileId);
    var method = "DELETE";
    if (action !== "delete") { path += "/" + action; method = "POST"; }
    return adminFetch(path, { method: method })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); });
  }

  // Build a small action button that runs a file action then refreshes.
  function actionButton(label, fileId, action, confirmMsg) {
    var b = document.createElement("button");
    b.className = "link-danger";
    if (action === "restore") b.className = "link-action";
    b.textContent = label;
    b.addEventListener("click", function () {
      if (confirmMsg && !window.confirm(confirmMsg)) return;
      b.disabled = true;
      fileAction(fileId, action)
        .then(function (res) {
          if (res.ok) { refresh(); }
          else { b.disabled = false; window.alert("error: " + (res.j.error || "action failed")); }
        })
        .catch(function () { b.disabled = false; window.alert("network error"); });
    });
    return b;
  }

  // --- token actions ---

  function initTokenActions() {
    var valueEl = document.getElementById("admin-token-value");
    var copyBtn = document.getElementById("token-copy");
    var revealBtn = document.getElementById("token-reveal");
    var rotateBtn = document.getElementById("token-rotate");
    var revealed = false;

    function showToken(data) {
      valueEl.textContent = data.token;
      valueEl.classList.add("revealed");
      copyBtn.hidden = false;
      revealBtn.textContent = "hide current";
      revealed = true;
      document.getElementById("admin-token-meta").textContent =
        "expires in " + fmtDuration(data.expires_in) +
        " · rotates every " + fmtDuration(data.rotation_interval);
    }

    function hideToken() {
      valueEl.textContent = "hidden";
      valueEl.classList.remove("revealed");
      copyBtn.hidden = true;
      revealBtn.textContent = "reveal current";
      revealed = false;
    }

    revealBtn.addEventListener("click", function () {
      if (revealed) { hideToken(); return; }
      revealBtn.disabled = true;
      adminFetch("/api/admin/token")
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          revealBtn.disabled = false;
          if (res.ok) showToken(res.j);
          else window.alert("error: " + (res.j.error || "could not fetch token"));
        })
        .catch(function () { revealBtn.disabled = false; window.alert("network error"); });
    });

    copyBtn.addEventListener("click", function () {
      var text = valueEl.textContent;
      var done = function () {
        copyBtn.textContent = "copied";
        setTimeout(function () { copyBtn.textContent = "copy"; }, 1500);
      };
      if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, done);
    });

    rotateBtn.addEventListener("click", function () {
      if (!window.confirm("Rotate the upload token now? Every token shared so far stops working immediately.")) return;
      rotateBtn.disabled = true;
      adminFetch("/api/admin/token/rotate", { method: "POST" })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          rotateBtn.disabled = false;
          if (res.ok) { showToken(res.j); window.alert("Rotated. New token revealed below."); }
          else window.alert("error: " + (res.j.error || "rotate failed"));
        })
        .catch(function () { rotateBtn.disabled = false; window.alert("network error"); });
    });
  }

  // --- load / auth ---

  function refresh() {
    filesState = { offset: 0, total: 0 };
    reportsState = { offset: 0, total: 0 };
    Promise.all([
      adminFetch("/api/admin/overview").then(function (r) { return r.json(); }),
      adminFetch("/api/admin/files").then(function (r) { return r.json(); }),
      adminFetch("/api/admin/reports").then(function (r) { return r.json(); }),
    ]).then(function (results) {
      document.getElementById("admin-refresh-error").textContent = "";
      var now = results[1].now || Math.floor(Date.now() / 1000);
      renderOverview(results[0]);
      var files = results[1].files || [];
      filesState.total = results[1].total || 0;
      filesState.offset = files.length;
      renderFiles(files, now, false);
      var reports = results[2].reports || [];
      reportsState.total = results[2].total || 0;
      reportsState.offset = reports.length;
      renderReports(reports, now, false);
    }).catch(function () {
      document.getElementById("admin-refresh-error").textContent = "could not refresh — network error";
    });
  }

  function loadMoreFiles() {
    var btn = document.getElementById("files-load-more");
    btn.disabled = true;
    adminFetch("/api/admin/files?offset=" + filesState.offset)
      .then(function (r) { return r.json(); })
      .then(function (d) {
        btn.disabled = false;
        var files = d.files || [];
        filesState.total = d.total || filesState.total;
        filesState.offset += files.length;
        renderFiles(files, d.now || Math.floor(Date.now() / 1000), true);
      })
      .catch(function () { btn.disabled = false; });
  }

  function loadMoreReports() {
    var btn = document.getElementById("reports-load-more");
    btn.disabled = true;
    adminFetch("/api/admin/reports?offset=" + reportsState.offset)
      .then(function (r) { return r.json(); })
      .then(function (d) {
        btn.disabled = false;
        var reports = d.reports || [];
        reportsState.total = d.total || reportsState.total;
        reportsState.offset += reports.length;
        renderReports(reports, Math.floor(Date.now() / 1000), true);
      })
      .catch(function () { btn.disabled = false; });
  }

  function enterDashboard() {
    loginEl.hidden = true;
    dashEl.hidden = false;
    refresh();
  }

  function attemptLogin(candidate) {
    loginError.textContent = "checking...";
    var prev = token;
    token = candidate;
    adminFetch("/api/admin/overview")
      .then(function (r) {
        if (r.ok) {
          try { sessionStorage.setItem(TOKEN_KEY, candidate); } catch (e) {}
          loginError.textContent = "";
          enterDashboard();
        } else {
          token = prev;
          loginError.textContent = r.status === 401 ? "invalid token" : "error (" + r.status + ")";
        }
      })
      .catch(function () { token = prev; loginError.textContent = "network error"; });
  }

  loginBtn.addEventListener("click", function () {
    if (tokenInput.value) attemptLogin(tokenInput.value.trim());
  });
  tokenInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && tokenInput.value) attemptLogin(tokenInput.value.trim());
  });

  document.getElementById("admin-refresh").addEventListener("click", refresh);
  document.getElementById("files-load-more").addEventListener("click", loadMoreFiles);
  document.getElementById("reports-load-more").addEventListener("click", loadMoreReports);
  document.getElementById("admin-logout").addEventListener("click", function () {
    try { sessionStorage.removeItem(TOKEN_KEY); } catch (e) {}
    token = null;
    dashEl.hidden = true;
    loginEl.hidden = false;
    tokenInput.value = "";
  });

  initTokenActions();

  // Auto-login if a token is already in this session.
  var saved = null;
  try { saved = sessionStorage.getItem(TOKEN_KEY); } catch (e) {}
  if (saved) attemptLogin(saved);
})();
