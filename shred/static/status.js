(async function () {
  try {
    var r = await fetch("/api/status");
    if (!r.ok) throw new Error("fetch failed");
    var s = await r.json();

    var dots = document.querySelectorAll(".dot");
    dots.forEach(function (d) { d.classList.remove("operational"); });
    document.getElementById("status-text").textContent = s.status;
    document.getElementById("stat-uptime").textContent = formatDuration(s.uptime);
    document.getElementById("stat-files").textContent = s.files_stored.toLocaleString();
    document.getElementById("stat-data").textContent = formatBytes(s.total_bytes);
    document.getElementById("stat-uploads").textContent = s.total_uploads_total.toLocaleString();
    document.getElementById("stat-downloads").textContent = s.total_downloads_total.toLocaleString();
    document.getElementById("stat-limits").textContent = s.limits.uploads_per_minute + "/min · " + s.limits.downloads_per_minute + "/min";

    var uploads = s.uploads || {};
    var accessEl = document.getElementById("stat-access");
    if (accessEl) {
      var bits = [];
      if (uploads.token_required) bits.push("token");
      if (uploads.ip_restricted) bits.push("ip allowlist");
      accessEl.textContent = bits.length ? bits.join(" + ") : "open";
    }
    var rotEl = document.getElementById("stat-rotation");
    if (rotEl) {
      if (uploads.rotation) {
        rotEl.textContent = "every " + formatDuration(uploads.rotation.interval_seconds)
          + " · next " + formatDuration(uploads.rotation.next_rotation_seconds);
      } else {
        rotEl.textContent = "off";
      }
    }
  } catch (e) {
    document.getElementById("status-text").textContent = "unreachable";
  }

  function formatDuration(sec) {
    if (sec < 60) return sec + "s";
    if (sec < 3600) return Math.floor(sec / 60) + "m";
    if (sec < 86400) return Math.floor(sec / 3600) + "h";
    return Math.floor(sec / 86400) + "d";
  }

  function formatBytes(b) {
    if (b < 1024) return b + " B";
    if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
    if (b < 1073741824) return (b / 1048576).toFixed(1) + " MB";
    return (b / 1073741824).toFixed(2) + " GB";
  }
})();
