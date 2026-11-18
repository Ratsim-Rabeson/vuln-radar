(() => {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const PAGE = 60;
  const store = {
    get(k, d) { try { const v = localStorage.getItem("vr:" + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem("vr:" + k, JSON.stringify(v)); } catch { /* private mode */ } },
  };

  // ---------- theme
  const applyTheme = (t) => { if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme; };
  applyTheme(store.get("theme", null));
  $("#theme").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === "dark"
      : matchMedia("(prefers-color-scheme: dark)").matches;
    const t = dark ? "light" : "dark";
    applyTheme(t); store.set("theme", t);
  });

  // ---------- tabs
  function route() {
    const tab = (location.hash.replace("#", "") || "feed").split("/")[0];
    const known = ["feed", "newsletters", "subscribe"].includes(tab) ? tab : "feed";
    $$(".view").forEach(v => v.hidden = v.id !== "view-" + known);
    $$(".tabs a").forEach(a => {
      if (a.dataset.tab === known) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
    if (known === "newsletters") loadNewsletters();
  }
  window.addEventListener("hashchange", route);

  // ---------- data
  let ALL = [], shown = PAGE;
  const state = Object.assign({ q: "", sevs: [], kev: false, source: "", range: "7", sort: "date" }, store.get("filters", {}));

  const fmtDate = (iso) => {
    if (!iso) return "";
    const d = new Date(iso), diff = (Date.now() - d) / 36e5;
    if (diff < 1) return Math.max(1, Math.round(diff * 60)) + " min ago";
    if (diff < 48) return Math.round(diff) + " h ago";
    return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  };
  const sevLabel = (it) => (it.severity || "UNKNOWN") === "UNKNOWN" ? "UNSCORED" : it.severity + (it.cvss != null ? " " + it.cvss.toFixed(1) : "");

  function filtered() {
    const cutoff = new Date(Date.now() - Number(state.range) * 864e5).toISOString();
    const terms = state.q.toLowerCase().split(/\s+/).filter(Boolean);
    let out = ALL.filter(it => {
      if ((it.date || "") < cutoff) return false;
      if (state.sevs.length && !state.sevs.includes(it.severity || "UNKNOWN")) return false;
      if (state.kev && !it.kev) return false;
      if (state.source && !(it.sources || []).includes(state.source)) return false;
      if (terms.length) {
        const hay = it._hay || (it._hay = [it.id, ...(it.aliases || []), it.title, it.description, it.vendor, it.product,
          ...(it.packages || []), ...(it.cwes || [])].join(" ").toLowerCase());
        if (!terms.every(t => hay.includes(t))) return false;
      }
      return true;
    });
    const key = { date: it => it.date || "", cvss: it => it.cvss ?? -1, epss: it => it.epss ?? -1 }[state.sort];
    out.sort((a, b) => (key(b) > key(a)) - (key(b) < key(a)) || ((b.cvss ?? 0) - (a.cvss ?? 0)));
    return out;
  }

  function renderStats() {
    const day = new Date(Date.now() - 864e5).toISOString(), week = new Date(Date.now() - 7 * 864e5).toISOString();
    const wk = ALL.filter(i => (i.date || "") >= week);
    const cards = [
      ["Last 24 h", ALL.filter(i => (i.date || "") >= day).length, { range: "1", sevs: [], kev: false }],
      ["Critical · 7d", wk.filter(i => i.severity === "CRITICAL").length, { range: "7", sevs: ["CRITICAL"], kev: false }],
      ["High · 7d", wk.filter(i => i.severity === "HIGH").length, { range: "7", sevs: ["HIGH"], kev: false }],
      ["Exploited · 30d", ALL.filter(i => i.kev).length, { range: "30", sevs: [], kev: true }],
      ["Total · 30d", ALL.length, { range: "30", sevs: [], kev: false }],
    ];
    $("#stats").replaceChildren(...cards.map(([label, n, f]) => {
      const b = document.createElement("button");
      b.className = "stat"; b.type = "button";
      b.innerHTML = `<b>${n.toLocaleString()}</b><span>${label}</span>`;
      b.addEventListener("click", () => { Object.assign(state, f); syncControls(); render(); });
      return b;
    }));
  }

  function itemNode(it) {
    const n = $("#tpl-item").content.firstElementChild.cloneNode(true);
    const sev = it.severity || "UNKNOWN";
    n.classList.add("sev-" + sev);
    $(".sev", n).textContent = sevLabel(it);
    const a = $(".vid", n); a.textContent = it.id; a.href = it.url || "#";
    a.addEventListener("click", e => e.stopPropagation());
    const badges = $(".badges", n);
    const badge = (t, cls = "") => { const s = document.createElement("span"); s.className = "badge " + cls; s.textContent = t; badges.append(s); };
    if (it.kev) badge("EXPLOITED", "kev");
    if (it.ransomware) badge("RANSOMWARE", "rw");
    if (it.epss != null && it.epss >= 0.1) badge("EPSS " + (it.epss * 100).toFixed(0) + "%");
    (it.sources || []).forEach(s => badge(s));
    const t = $(".when", n); t.textContent = fmtDate(it.date); t.dateTime = it.date || ""; t.title = it.date || "";
    $(".title", n).textContent = it.title || it.id;
    $(".desc", n).textContent = it.description || "";
    const facts = [
      ["CVSS", it.cvss != null ? `${it.cvss} (v${it.cvss_version || "?"})` : null],
      ["Vector", it.vector], ["EPSS", it.epss != null ? `${(it.epss * 100).toFixed(2)}% (pct ${(100 * (it.epss_percentile || 0)).toFixed(0)})` : null],
      ["Vendor / product", [it.vendor, it.product].filter(Boolean).join(" / ") || null],
      ["Packages", (it.packages || []).join(", ") || null], ["Weakness", (it.cwes || []).join(", ") || null],
      ["Also known as", (it.aliases || []).join(", ") || null],
      ["Published", it.published ? new Date(it.published).toUTCString() : null],
      ["Added to KEV", it.kev_added ? it.kev_added.slice(0, 10) + (it.kev_due ? ` (fix due ${it.kev_due})` : "") : null],
      ["Required action", it.kev_action],
    ].filter(([, v]) => v);
    $(".facts", n).replaceChildren(...facts.flatMap(([k, v]) => {
      const dt = document.createElement("dt"), dd = document.createElement("dd");
      dt.textContent = k; dd.textContent = v; return [dt, dd];
    }));
    $(".refs", n).replaceChildren(...(it.references || []).map(u => {
      const li = document.createElement("li"), l = document.createElement("a");
      l.href = u; l.textContent = u; l.target = "_blank"; l.rel = "noopener"; li.append(l); return li;
    }));
    return n;
  }

  function render() {
    store.set("filters", { q: state.q, sevs: state.sevs, kev: state.kev, source: state.source, range: state.range, sort: state.sort });
    const rows = filtered();
    $("#count").textContent = `${rows.length.toLocaleString()} vulnerabilit${rows.length === 1 ? "y" : "ies"}`;
    $("#list").replaceChildren(...rows.slice(0, shown).map(itemNode));
    $("#more").hidden = rows.length <= shown;
  }

  function syncControls() {
    $("#q").value = state.q; $("#kev-only").checked = state.kev; $("#source").value = state.source;
    $("#range").value = state.range; $("#sort").value = state.sort;
    $$("#sev-chips .chip").forEach(c => c.setAttribute("aria-pressed", state.sevs.includes(c.dataset.sev)));
    shown = PAGE;
  }

  let qTimer;
  $("#q").addEventListener("input", e => { clearTimeout(qTimer); qTimer = setTimeout(() => { state.q = e.target.value; shown = PAGE; render(); }, 150); });
  $("#kev-only").addEventListener("change", e => { state.kev = e.target.checked; shown = PAGE; render(); });
  ["source", "range", "sort"].forEach(id => $("#" + id).addEventListener("change", e => { state[id] = e.target.value; shown = PAGE; render(); }));
  $$("#sev-chips .chip").forEach(c => c.addEventListener("click", () => {
    const s = c.dataset.sev;
    state.sevs = state.sevs.includes(s) ? state.sevs.filter(x => x !== s) : [...state.sevs, s];
    syncControls(); render();
  }));
  $("#more").addEventListener("click", () => { shown += PAGE; render(); });

  fetch("data/vulns.json", { cache: "no-cache" })
    .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(d => {
      ALL = d.items || [];
      const when = d.generated ? new Date(d.generated) : null;
      $("#meta").textContent = `Updated ${when ? when.toLocaleString() : "—"} · refreshed every 3 hours · sources: ${(d.sources_ok || []).join(", ") || "NVD, CISA KEV, GitHub Advisory"}`;
      if (d.repo) {
        const url = "https://github.com/" + d.repo;
        $("#watch-link").href = url;
      }
      renderStats(); syncControls(); render();
    })
    .catch(e => { $("#meta").textContent = "Could not load data (" + e.message + "). The first scheduled update may not have run yet."; });

  // ---------- newsletters
  let nlLoaded = false;
  function loadNewsletters() {
    if (nlLoaded) return; nlLoaded = true;
    fetch("newsletters/index.json", { cache: "no-cache" }).then(r => r.ok ? r.json() : []).catch(() => []).then(list => {
      const ul = $("#nl-list");
      if (!list.length) { ul.innerHTML = '<li class="muted">The first issue is published next Monday.</li>'; $(".nl-frame-wrap").hidden = true; return; }
      const open = (issue, btn) => {
        $("#nl-frame").src = issue.html;
        $$("#nl-list button").forEach(b => b.setAttribute("aria-current", b === btn));
      };
      ul.replaceChildren(...list.map((issue, i) => {
        const li = document.createElement("li"), b = document.createElement("button");
        b.type = "button";
        b.innerHTML = `<strong></strong><small></small>`;
        b.querySelector("strong").textContent = issue.id;
        b.querySelector("small").textContent = `${issue.start.slice(0, 10)} → ${issue.end.slice(0, 10)} · ${issue.counts.CRITICAL} critical · ${issue.counts.KEV} exploited`;
        b.addEventListener("click", () => open(issue, b));
        li.append(b); if (i === 0) setTimeout(() => open(issue, b));
        return li;
      }));
    });
  }

  route();
})();
