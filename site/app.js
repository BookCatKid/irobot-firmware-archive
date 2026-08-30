const state = { catalog: null, platforms: {}, selected: null };

const $ = (q) => document.querySelector(q);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtBytes = (n) => {
  if (n == null) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
};
const archived = (f) => Boolean(f.archive?.manifest);
const pinfo = (f) => state.platforms[f.family] || {};
const modelsFor = (f) => pinfo(f).models || [];
const skusFor = (f) => [...new Set([...(pinfo(f).known_skus || []), ...(f.source_sku ? [f.source_sku] : [])])];
const deviceTitle = (f) => modelsFor(f).length ? modelsFor(f).join(" / ") : (f.source_sku ? `SKU ${f.source_sku}` : "Hardware mapping incomplete");
const label = (f) => `${deviceTitle(f)} · ${f.family} ${f.version}`;
const sourceUrl = (f) => f.archive?.asset_url || f.url;
const kv = (key, value, mono=false) => `<div class="kv"><span class="key">${esc(key)}</span><span class="value${mono?' mono':''}">${value ?? '—'}</span></div>`;

async function load() {
  const [catRes, platformRes] = await Promise.all([
    fetch("data/catalog.json", {cache:"no-store"}),
    fetch("data/platforms.json", {cache:"no-store"})
  ]);
  if (!catRes.ok) throw new Error(`catalog HTTP ${catRes.status}`);
  state.catalog = await catRes.json();
  if (platformRes.ok) state.platforms = (await platformRes.json()).platforms || {};
  renderInitial();
}

function renderInitial() {
  const list = state.catalog.firmwares || [];
  const families = [...new Set(list.map(x => x.family))].sort();
  const knownBytes = list.reduce((sum, x) => sum + Number(x.archive?.size || x.size || 0), 0);
  const archivedCount = list.filter(archived).length;
  $("#summary").textContent = `${list.length} builds · ${families.length} platforms · ${archivedCount} archived · ${fmtBytes(knownBytes)} indexed`;

  $("#platformFilter").innerHTML = `<option value="">All platforms</option>` + families.map(x => `<option value="${esc(x)}">${esc(x)}</option>`).join("");
  const options = list.map((f,i)=>`<option value="${i}">${esc(f.family)} ${esc(f.version)} · ${esc(deviceTitle(f))}${archived(f)?" · archived":""}</option>`).join("");
  $("#leftSelect").innerHTML = options;
  $("#rightSelect").innerHTML = options;
  if (list.length > 1) $("#rightSelect").value = String(list.length - 1);
  if (list.length > 2) $("#leftSelect").value = String(list.length - 2);
  renderCatalog();
}

function filteredCatalog() {
  const list = state.catalog?.firmwares || [];
  const q = $("#search").value.trim().toLowerCase();
  const platform = $("#platformFilter").value;
  const status = $("#statusFilter").value;
  return list.filter(f => {
    if (platform && f.family !== platform) return false;
    if (status === "archived" && !archived(f)) return false;
    if (status === "discovered" && archived(f)) return false;
    if (!q) return true;
    const haystack = [
      f.family, f.version, f.source_sku, f.source, f.release_date,
      ...modelsFor(f), ...skusFor(f), pinfo(f).type, pinfo(f).description
    ].filter(Boolean).join(" ").toLowerCase();
    return haystack.includes(q);
  });
}

function renderCatalog() {
  const filtered = filteredCatalog();
  $("#resultCount").textContent = `${filtered.length} ${filtered.length === 1 ? 'build' : 'builds'}`;
  $("#catalog").innerHTML = filtered.map(f => {
    const sourceSku = f.source_sku || skusFor(f)[0];
    const p = pinfo(f);
    return `<tr data-id="${esc(f.family)}|${esc(f.version)}|${esc(f.url)}">
      <td><span class="model-primary">${esc(deviceTitle(f))}</span><span class="model-secondary">${sourceSku ? `Observed/probed SKU ${esc(sourceSku)}` : 'No exact SKU attached to this discovery'}</span></td>
      <td class="platform-cell"><strong>${esc(f.family)}</strong><small>${esc(p.type || 'firmware family identifier')}</small></td>
      <td class="mono">${esc(f.version)}</td>
      <td>${esc(f.release_date || '—')}</td>
      <td>${esc(fmtBytes(f.archive?.size || f.size))}</td>
      <td><span class="status ${archived(f)?'archived':'discovered'}">${archived(f)?'● archived':'○ discovered'}</span></td>
    </tr>`;
  }).join("") || `<tr><td colspan="6" class="muted">No matching firmware.</td></tr>`;

  $("#catalog").querySelectorAll("tr[data-id]").forEach(row => row.addEventListener("click", () => {
    const id = row.dataset.id;
    const f = (state.catalog.firmwares || []).find(x => `${x.family}|${x.version}|${x.url}` === id);
    if (f) showDetail(f, row);
  }));
}

function showDetail(f, row) {
  $("#catalog").querySelectorAll("tr.selected").forEach(x => x.classList.remove("selected"));
  row.classList.add("selected");
  state.selected = f;
  const p = pinfo(f);
  const archive = f.archive || {};
  const evidence = p.evidence || [];
  const releaseUrl = archive.release_tag ? `https://github.com/BookCatKid/irobot-firmware-archive/releases/tag/${encodeURIComponent(archive.release_tag)}` : null;
  const raw = JSON.stringify(f, null, 2);

  $("#detail").innerHTML = `
    <div class="detail-top">
      <div>
        <h3>${esc(f.family)} ${esc(f.version)}</h3>
        <p class="sub">${esc(deviceTitle(f))}${skusFor(f).length ? ` · ${esc(skusFor(f).join(', '))}` : ''}</p>
      </div>
      <div class="detail-actions">
        <a class="small-button" href="${esc(f.url)}">${f.source === 'app-embedded' ? 'Source app' : 'Original OTA'} ↗</a>
        ${f.metapackage_url ? `<a class="small-button" href="${esc(f.metapackage_url)}">Metapackage ↗</a>` : ''}
        ${releaseUrl ? `<a class="small-button" href="${esc(releaseUrl)}">GitHub release ↗</a>` : ''}
        ${archive.asset_url ? `<a class="small-button" href="${esc(archive.asset_url)}">Archived file ↓</a>` : ''}
      </div>
    </div>
    <div class="detail-grid">
      ${kv("Firmware platform", `<span class="mono">${esc(f.family)}</span>`)}
      ${kv("Platform identifier type", esc(p.type || 'unknown'))}
      ${kv("Hardware mapping", esc(p.confidence || 'unmapped'))}
      ${kv("Version", `<span class="mono">${esc(f.version)}</span>`)}
      ${kv("Release date", esc(f.release_date || '—'))}
      ${kv("Package size", esc(fmtBytes(archive.size || f.size)))}
      ${kv("Discovery method", `<span class="mono">${esc(f.source || '—')}</span>`)}
      ${kv("Discovery SKU", `<span class="mono">${esc(f.source_sku || '—')}</span>`)}
      ${kv("Track / signing", `${esc(f.track || '—')} / ${esc(f.signing || '—')}`)}
      ${kv("SHA-256", archive.sha256 ? `<span class="mono">${esc(archive.sha256)}</span>` : 'not archived yet')}
      ${kv("Source ETag", f.etag ? `<span class="mono">${esc(f.etag)}</span>` : '—')}
      ${kv("Last-Modified", esc(f.last_modified || '—'))}
    </div>
    ${p.description ? `<p class="detail-description">${esc(p.description)}</p>` : ''}
    ${evidence.length ? `<details class="evidence"><summary>Hardware association evidence (${evidence.length})</summary><ul>${evidence.map(e => `<li>${esc(e.kind || 'evidence')}: ${esc([e.model, e.sku, e.software_prefix && `software prefix ${e.software_prefix}`, e.note].filter(Boolean).join(' · '))}${e.url ? ` · <a href="${esc(e.url)}">source ↗</a>` : ''}</li>`).join('')}</ul></details>` : ''}
    <details class="raw"><summary>Raw catalog record</summary><pre>${esc(raw)}</pre></details>`;
  $("#detail").hidden = false;
  $("#detail").scrollIntoView({behavior:"smooth", block:"nearest"});
}

async function loadManifest(f) {
  if (!f.archive?.manifest) return null;
  const res = await fetch(`data/${f.archive.manifest}`, {cache:"no-store"});
  if (!res.ok) throw new Error(`manifest HTTP ${res.status}`);
  return res.json();
}

const compMap = (m) => new Map((m?.components || []).map(x => [x.name || `#${x.index}`, x]));
function squashFiles(m) {
  for (const c of m?.components || []) {
    const files = c.filesystem_analysis?.files;
    if (Array.isArray(files)) return files;
  }
  return [];
}
function fileKey(x){ return `${x.type}|${x.sha256||""}|${x.target||""}|${x.size??""}`; }

async function compare() {
  const list = state.catalog.firmwares || [];
  const a = list[Number($("#leftSelect").value)];
  const b = list[Number($("#rightSelect").value)];
  const out = $("#diffResult");
  if (!a || !b) return;
  out.classList.remove("empty-state");
  out.innerHTML = `<span class="muted">Loading manifests…</span>`;
  try {
    const [ma, mb] = await Promise.all([loadManifest(a), loadManifest(b)]);
    if (!ma || !mb) {
      out.innerHTML = `<p class="diff-title">${esc(label(a))} → ${esc(label(b))}</p><p class="muted">At least one build is only discovered, not archived yet. The full component/filesystem diff appears automatically after both manifests exist.</p>`;
      return;
    }
    const ac = compMap(ma), bc = compMap(mb), names = [...new Set([...ac.keys(),...bc.keys()])].sort();
    const compRows = names.map(name => {
      const x=ac.get(name), y=bc.get(name);
      return {name, status:!x?"added":!y?"removed":x.sha256!==y.sha256?"changed":"same", a:x, b:y};
    });
    const af = new Map(squashFiles(ma).map(x=>[x.path,x])), bf = new Map(squashFiles(mb).map(x=>[x.path,x]));
    const paths=[...new Set([...af.keys(),...bf.keys()])].sort();
    const fileRows=paths.map(path=>{const x=af.get(path),y=bf.get(path);return {path,status:!x?"added":!y?"removed":fileKey(x)!==fileKey(y)?"changed":"same",a:x,b:y};}).filter(x=>x.status!=="same");
    const summary = [
      [compRows.filter(x=>x.status!=="same").length,"components changed"],
      [fileRows.filter(x=>x.status==="added").length,"files added"],
      [fileRows.filter(x=>x.status==="removed").length,"files removed"],
      [fileRows.filter(x=>x.status==="changed").length,"files changed"]
    ];
    const comps = compRows.filter(x=>x.status!=="same").map(x => `<div class="component"><span class="status-${x.status}">${x.status}</span><strong>${esc(x.name)}</strong><code>${esc(x.a?.sha256?.slice(0,16)||'—')} → ${esc(x.b?.sha256?.slice(0,16)||'—')}</code></div>`).join("");
    const rows = fileRows.slice(0,500).map(x=>`<tr><td class="status-${x.status}">${x.status}</td><td class="mono">${esc(x.path)}</td><td>${esc(fmtBytes(x.a?.size))}</td><td>${esc(fmtBytes(x.b?.size))}</td></tr>`).join("");
    out.innerHTML = `
      <p class="diff-title">${esc(label(a))} → ${esc(label(b))}</p>
      <div class="diff-summary">${summary.map(([v,k])=>`<div class="diff-chip"><strong>${v}</strong><span>${k}</span></div>`).join('')}</div>
      ${comps ? `<div class="component-list">${comps}</div>` : '<p class="muted">Top-level signed components are identical.</p>'}
      ${fileRows.length ? `<table class="diff-table"><thead><tr><th>Status</th><th>Path</th><th>A</th><th>B</th></tr></thead><tbody>${rows}</tbody></table>${fileRows.length>500?`<p class="muted">Showing 500 of ${fileRows.length} changed entries.</p>`:''}` : '<p class="muted">No root-filesystem changes detected in the available manifests.</p>'}`;
  } catch (err) {
    out.innerHTML = `<span class="muted">Could not compare: ${esc(err.message)}</span>`;
  }
}

["#search", "#platformFilter", "#statusFilter"].forEach(sel => $(sel).addEventListener(sel === "#search" ? "input" : "change", renderCatalog));
$("#compareButton").addEventListener("click", compare);
$("#swap").addEventListener("click",()=>{const a=$("#leftSelect"),b=$("#rightSelect");[a.value,b.value]=[b.value,a.value];});
load().catch(err => { $("#summary").textContent = `Failed to load catalog: ${err.message}`; });
