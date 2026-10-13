/*
 * Sovereign webapp — vanilla JS only, no build step, no external requests.
 *
 * Three responsibilities live here:
 *   1. Chip rendering — wraps `[PLACEHOLDER_ab12cd]` / `[CATEGORY_REDACTED]` style
 *      tokens in any element marked `data-chips` so they read as a distinct token,
 *      not prose. Always escapes first, then wraps matches — see chipify().
 *   2. The dashboard "Explorer" — selection, sorting, sidebar filters, breadcrumb,
 *      status bar, and the two toolbar bulk actions. Multi-document actions POST to
 *      the existing single-document routes sequentially via fetch(); see
 *      runBulkAction(). A single selected document instead submits a real HTML form
 *      so the browser navigates to the route's normal result page (e.g. release.html)
 *      instead of being hidden behind a bulk-progress reload.
 *   3. Client-side status/metadata memory (localStorage). `GET /dashboard` only ever
 *      returns {doc_id, title} per document (see UI-NOTES.md) — there is no
 *      server-provided signal for per-document Status/Identifiers/Size, and the
 *      release action in particular writes nothing server-side by design. Every
 *      write here is wrapped in try/catch and degrades to a neutral default if
 *      storage is unavailable (e.g. inside a restrictive iframe embed).
 */
(function () {
  "use strict";

  // ---------------------------------------------------------------- chips ----

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  var TOKEN_RE = /\[[A-Za-z0-9_]+\]/g;
  var ADVANCED_SUFFIX_RE = /_REDACTED\]$/;

  function chipify(text) {
    var escaped = escapeHtml(text);
    return escaped.replace(TOKEN_RE, function (match) {
      var cls = ADVANCED_SUFFIX_RE.test(match) ? "chip chip-advanced" : "chip";
      return '<span class="' + cls + '">' + match + "</span>";
    });
  }

  function initChips() {
    var nodes = document.querySelectorAll("[data-chips]");
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      el.innerHTML = chipify(el.textContent);
    }
  }

  // ------------------------------------------------------- confirm guards ----

  function initConfirmForms() {
    var forms = document.querySelectorAll("form[data-confirm]");
    forms.forEach(function (form) {
      form.addEventListener("submit", function (e) {
        if (!window.confirm(form.getAttribute("data-confirm"))) {
          e.preventDefault();
        }
      });
    });
  }

  // ------------------------------------------------------ totp input feel ----

  function initTotpInputs() {
    document.querySelectorAll("[data-totp-input]").forEach(function (input) {
      input.addEventListener("input", function () {
        input.value = input.value.replace(/\D/g, "").slice(0, 6);
      });
    });
  }

  // ------------------------------------------------- client-side status ----
  // See UI-NOTES.md: the dashboard route has no per-document status/size/identifier
  // signal to give the template. This is a browser-local stand-in, not shared across
  // devices, and never a substitute for real server state.

  var STATUS_RANK = { original: 0, deidentified: 1, summarised: 2, released: 3 };
  var STATUS_LABEL = {
    original: "Original",
    deidentified: "De-identified",
    summarised: "Summarised",
    released: "Released",
  };
  var STATUS_PILL_CLASS = {
    original: "pill-review",
    deidentified: "pill-progress",
    summarised: "pill-summarised",
    released: "pill-released",
  };

  function statusKey(docId) { return "sovereign:status:" + docId; }
  function metaKey(docId) { return "sovereign:meta:" + docId; }
  function lastActionKey(docId) { return "sovereign:lastaction:" + docId; }

  function getStatus(docId) {
    try {
      return localStorage.getItem(statusKey(docId)) || "original";
    } catch (e) {
      return "original";
    }
  }

  function setLastAction(docId, label) {
    try {
      localStorage.setItem(lastActionKey(docId), JSON.stringify({ label: label, ts: Date.now() }));
    } catch (e) { /* storage unavailable */ }
  }

  function getLastAction(docId) {
    try {
      var raw = localStorage.getItem(lastActionKey(docId));
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function formatRelative(ts) {
    var diff = Date.now() - ts;
    if (diff < 60000) return "just now";
    var mins = Math.floor(diff / 60000);
    if (mins < 60) return mins + "m ago";
    var hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + "h ago";
    return Math.floor(hrs / 24) + "d ago";
  }

  function setStatusAtLeast(docId, status) {
    // Monotonic: never let the UI silently regress from "Released" to an earlier
    // stage just because the document happened to be re-opened or re-run.
    try {
      var current = getStatus(docId);
      if ((STATUS_RANK[status] || 0) > (STATUS_RANK[current] || 0)) {
        localStorage.setItem(statusKey(docId), status);
        setLastAction(docId, STATUS_LABEL[status] || status);
      }
    } catch (e) { /* storage unavailable — degrade to default silently */ }
  }

  function getMeta(docId) {
    try {
      var raw = localStorage.getItem(metaKey(docId));
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function setMeta(docId, meta) {
    try {
      localStorage.setItem(metaKey(docId), JSON.stringify(meta));
    } catch (e) { /* storage unavailable */ }
  }

  // Called from document.html: that page has real, server-derived signals
  // (has_map / summary_deid / summary_identified, plus the full doc for size and
  // identifier count) even though the dashboard list does not. Reconciling here
  // means the dashboard gets more accurate once a document has actually been opened.
  function reconcileFromDocumentPage(docId, info) {
    setMeta(docId, { identifiers: info.identifiers, size: info.size });
    var trueStatus = "original";
    if (info.hasSummaryDeid) trueStatus = "summarised";
    else if (info.hasMap) trueStatus = "deidentified";
    setStatusAtLeast(docId, trueStatus);
  }

  // Called from release.html on load: reaching that page IS the ground truth that a
  // release just happened, which is the one state the server never records anywhere
  // the UI can read back (advanced_deid.release() writes no map by design).
  function markReleased(docId) {
    setStatusAtLeast(docId, "released");
  }

  function formatSize(chars) {
    if (typeof chars !== "number") return "—";
    if (chars < 1000) return chars + " ch";
    return (chars / 1000).toFixed(1) + "k ch";
  }

  // ------------------------------------------------------------- explorer ----

  function initExplorer() {
    var table = document.getElementById("doc-table");
    if (!table) return; // not the dashboard

    var tbody = document.getElementById("doc-tbody");
    var selectAllBox = document.getElementById("select-all");
    var btnSummarise = document.getElementById("btn-summarise");
    var btnRelease = document.getElementById("btn-release");
    var progressWrap = document.getElementById("toolbar-progress");
    var progressText = document.getElementById("toolbar-progress-text");
    var statusbarText = document.getElementById("statusbar-text");

    var selected = new Set();
    var anchorIndex = null;
    var activeFilter = "all";
    var sortState = { key: null, dir: "asc" };
    var collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

    function allRows() { return Array.prototype.slice.call(tbody.querySelectorAll(".doc-row")); }
    function visibleRows() { return allRows().filter(function (r) { return !r.classList.contains("is-hidden-by-filter"); }); }

    // Status, identifier count, size and last action are rendered SERVER-side, from the
    // audit log (see app/audit.py::document_status). There used to be a localStorage
    // hydration pass here that overwrote those cells on load.
    //
    // It had to go. It defaulted to "original" for any document this browser had not
    // opened, so a fresh browser - which is exactly what a demo to a clinician is -
    // showed every released document as untouched, and two people looking at the same
    // record saw different states. Status is a fact about what was done to a document,
    // so it belongs to the server and specifically to the audited history.
    //
    // Sorting and filtering read row.dataset.*, which the template now fills from the
    // same server values, so both still work with nothing client-side behind them.

    function updateCounts() {
      var counts = { all: 0, "needs-review": 0, summarised: 0, released: 0 };
      allRows().forEach(function (r) {
        counts.all++;
        var s = r.dataset.status;
        if (s === "summarised") counts.summarised++;
        else if (s === "released") counts.released++;
        else counts["needs-review"]++;
      });
      setText("count-all", counts.all);
      setText("count-needs-review", counts["needs-review"]);
      setText("count-summarised", counts.summarised);
      setText("count-released", counts.released);
    }
    function setText(id, val) {
      var el = document.getElementById(id);
      if (el) el.textContent = String(val);
    }

    var FILTER_LABEL = {
      all: "Documents",
      "needs-review": "Documents — Needs review",
      summarised: "Documents — Summarised",
      released: "Documents — Released",
    };

    function applyFilter(filter) {
      activeFilter = filter;
      selected.clear(); // changing the view resets selection, same as changing folders
      anchorIndex = null;
      document.querySelectorAll(".sidebar-item").forEach(function (btn) {
        var isActive = btn.dataset.filter === filter;
        btn.classList.toggle("is-active", isActive);
      });
      allRows().forEach(function (row) {
        var status = row.dataset.status;
        var show =
          filter === "all" ||
          (filter === "needs-review" && status !== "summarised" && status !== "released") ||
          (filter === "summarised" && status === "summarised") ||
          (filter === "released" && status === "released");
        row.classList.toggle("is-hidden-by-filter", !show);
      });
      var crumb = document.getElementById("crumb-current");
      if (crumb) crumb.textContent = FILTER_LABEL[filter] || FILTER_LABEL.all;
      renderSelection();
    }

    function renderSelection() {
      allRows().forEach(function (row) {
        var isSel = selected.has(row.dataset.docId);
        row.classList.toggle("is-selected", isSel);
        var cb = row.querySelector(".row-check");
        if (cb) cb.checked = isSel;
      });
      var visible = visibleRows();
      var visibleSelectedCount = visible.filter(function (r) { return selected.has(r.dataset.docId); }).length;
      if (selectAllBox) {
        selectAllBox.checked = visible.length > 0 && visibleSelectedCount === visible.length;
        selectAllBox.indeterminate = visibleSelectedCount > 0 && visibleSelectedCount < visible.length;
      }
      if (statusbarText) {
        var n = visible.length, m = visibleSelectedCount;
        statusbarText.textContent = n + " item" + (n === 1 ? "" : "s") + ", " + m + " selected";
      }
      var hasSelection = selected.size > 0;
      if (btnSummarise) btnSummarise.disabled = !hasSelection;
      if (btnRelease) btnRelease.disabled = !hasSelection;
    }

    function toggle(id) {
      if (selected.has(id)) selected.delete(id); else selected.add(id);
    }

    tbody.addEventListener("click", function (e) {
      var row = e.target.closest(".doc-row");
      if (!row) return;
      if (e.target.closest("a")) return; // let the document link navigate normally

      var rows = visibleRows();
      var idx = rows.indexOf(row);
      var id = row.dataset.docId;
      var isCheckboxClick = !!e.target.closest(".row-check");

      if (isCheckboxClick) {
        e.preventDefault(); // we own checked state via renderSelection()
        toggle(id);
        anchorIndex = idx;
      } else if (e.shiftKey && anchorIndex !== null) {
        var lo = Math.min(anchorIndex, idx), hi = Math.max(anchorIndex, idx);
        selected.clear();
        for (var i = lo; i <= hi; i++) selected.add(rows[i].dataset.docId);
      } else if (e.metaKey || e.ctrlKey) {
        toggle(id);
        anchorIndex = idx;
      } else {
        selected.clear();
        selected.add(id);
        anchorIndex = idx;
      }
      renderSelection();
    });

    tbody.addEventListener("keydown", function (e) {
      var row = e.target.closest(".doc-row");
      if (!row) return;
      if (e.key === " " || e.key === "Spacebar") {
        e.preventDefault();
        toggle(row.dataset.docId);
        anchorIndex = visibleRows().indexOf(row);
        renderSelection();
      } else if (e.key === "Enter") {
        var link = row.querySelector(".doc-name-cell a");
        if (link) window.location.href = link.href;
      }
    });

    if (selectAllBox) {
      selectAllBox.addEventListener("change", function () {
        var rows = visibleRows();
        var allSelected = rows.length > 0 && rows.every(function (r) { return selected.has(r.dataset.docId); });
        rows.forEach(function (r) {
          if (allSelected) selected.delete(r.dataset.docId); else selected.add(r.dataset.docId);
        });
        renderSelection();
      });
    }

    document.querySelectorAll(".sidebar-item").forEach(function (btn) {
      btn.addEventListener("click", function () { applyFilter(btn.dataset.filter); });
    });

    table.querySelectorAll("th.sortable").forEach(function (th) {
      th.setAttribute("tabindex", "0");
      th.addEventListener("click", function () { applySort(th.dataset.sort); });
      th.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); applySort(th.dataset.sort); }
      });
    });

    function applySort(key) {
      if (sortState.key === key) {
        sortState.dir = sortState.dir === "asc" ? "desc" : "asc";
      } else {
        sortState = { key: key, dir: "asc" };
      }
      var rows = allRows();
      rows.sort(function (a, b) {
        var av = a.dataset[key] || "";
        var bv = b.dataset[key] || "";
        var an = parseFloat(av), bn = parseFloat(bv);
        var cmp;
        if (av !== "" && bv !== "" && !isNaN(an) && !isNaN(bn)) {
          cmp = an - bn;
        } else {
          cmp = collator.compare(av, bv);
        }
        return sortState.dir === "asc" ? cmp : -cmp;
      });
      rows.forEach(function (r) { tbody.appendChild(r); });

      table.querySelectorAll("th.sortable").forEach(function (th) {
        var arrow = th.querySelector(".sort-arrow");
        if (th.dataset.sort === key) {
          th.setAttribute("aria-sort", sortState.dir === "asc" ? "ascending" : "descending");
          if (arrow) arrow.textContent = sortState.dir === "asc" ? "▲" : "▼";
        } else {
          th.removeAttribute("aria-sort");
          if (arrow) arrow.textContent = "▴";
        }
      });
    }

    // ---- toolbar bulk actions ----

    function setToolbarBusy(busy) {
      if (btnSummarise) btnSummarise.disabled = busy || selected.size === 0;
      if (btnRelease) btnRelease.disabled = busy || selected.size === 0;
      if (selectAllBox) selectAllBox.disabled = busy;
      tbody.querySelectorAll(".row-check").forEach(function (cb) { cb.disabled = busy; });
      if (progressWrap) progressWrap.hidden = !busy;
    }

    function submitRealForm(action) {
      var f = document.createElement("form");
      f.method = "POST";
      f.action = action;
      f.style.display = "none";
      document.body.appendChild(f);
      f.submit();
    }

    function runBulkAction(ids, actionSegment) {
      setToolbarBusy(true);
      var done = 0, failed = 0;
      function step() {
        if (done >= ids.length) {
          if (progressText) {
            progressText.textContent = failed
              ? "Finished with " + failed + " of " + ids.length + " failed."
              : "Done — " + ids.length + " document" + (ids.length === 1 ? "" : "s") + " processed.";
          }
          window.setTimeout(function () { window.location.reload(); }, failed ? 1400 : 700);
          return;
        }
        var id = ids[done];
        if (progressText) progressText.textContent = "Processing " + (done + 1) + " of " + ids.length + "…";
        fetch("/doc/" + encodeURIComponent(id) + "/" + actionSegment, { method: "POST" })
          .then(function (resp) {
            if (resp.ok) {
              setStatusAtLeast(id, actionSegment === "release" ? "released" : "summarised");
            } else {
              failed++;
            }
          })
          .catch(function () { failed++; })
          .then(function () { done++; step(); });
      }
      step();
    }

    function triggerSummarise() {
      var ids = Array.from(selected);
      if (ids.length === 0) return;
      if (ids.length === 1) {
        submitRealForm("/doc/" + encodeURIComponent(ids[0]) + "/summarize");
        return;
      }
      runBulkAction(ids, "summarize");
    }

    function triggerRelease() {
      var ids = Array.from(selected);
      if (ids.length === 0) return;
      var msg = ids.length === 1
        ? "De-identify this document for public release?\n\nThis cannot be undone, and the result cannot be re-identified."
        : "De-identify " + ids.length + " documents for public release?\n\nThis cannot be undone for any of them.";
      if (!window.confirm(msg)) return;
      if (ids.length === 1) {
        submitRealForm("/doc/" + encodeURIComponent(ids[0]) + "/release");
        return;
      }
      runBulkAction(ids, "release");
    }

    if (btnSummarise) btnSummarise.addEventListener("click", triggerSummarise);
    if (btnRelease) btnRelease.addEventListener("click", triggerRelease);

    updateCounts();
    renderSelection();
  }

  // ------------------------------------------------------------------ boot ----

  document.addEventListener("DOMContentLoaded", function () {
    initChips();
    initConfirmForms();
    initTotpInputs();
    initExplorer();
  });

  window.Sovereign = {
    chipify: chipify,
    reconcileFromDocumentPage: reconcileFromDocumentPage,
    markReleased: markReleased,
  };
})();
