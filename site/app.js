const state = { catalog: null };

const fmtBytes = (n) => {
  if (n == null) return "unknown size";
  const units = ["B", "KiB", "MiB", "GiB"];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
};
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const label = (f) => `${f.family} ${f.version}${f.source_sku ? ` · ${f.source_sku}` : ""}`;
const archived = (f) => Boolean(f.archive?.manifest);

async function loadCatalog() {
  const res = await fetch("data/catalog.json", {cache:"no-store"});
  if (!res.ok) throw new Error(`catalog HTTP ${res.status}`);
  state.catalog = await res.json();
  render();
}

function render() {
  const list = state.catalog.firmwares || [];
  const families = new Set(list.map(x => x.family));
  const archivedCount = list.filter(archived).length;
  const bytes = list.reduce((sum,x)=>sum + Number(x.archive?.size || x.size || 0), 0);
  document.querySelector("#stats").innerHTML = [
    [list.length,"known builds"], [families.size,"families"], [archivedCount,"archived + analyzed"], [fmtBytes(bytes),"known package bytes"]
  ].map(([v,k])=>`<div class="stat"><strong>${esc(v)}</strong><span>${esc(k)}</span></div>`).join("");

  const options = list.map((f,i)=>`<option value="${i}">${esc(label(f))}${archived(f)?" ✓":""}</option>`).join("");
  const left = document.querySelector("#leftSelect"), right = document.querySelector("#rightSelect");
  left.innerHTML = options; right.innerHTML = options;
  if (list.length > 1) right.value = String(list.length - 1);
  if (list.length > 2) left.value = String(list.length - 2);
  renderCatalog(list);
}

function renderCatalog(list) {
  const q = document.querySelector("#search").value.trim().toLowerCase();
  const filtered = list.filter(f => JSON.stringify(f).toLowerCase().includes(q));
  document.querySelector("#catalog").innerHTML = filtered.map(f => {
    const archive = f.archive || {};
    const source = archive.asset_url || f.url;
    return `<div class="firmware-row">
      <strong>${esc(f.family)}</strong>
      <span class="version">${esc(f.version)}</span>
      <span><span class="pill ${archived(f)?"ok":""}">${archived(f)?"archived":"discovered"}</span></span>
      <span class="small" title="${esc(f.url)}">${esc(f.source_sku || f.source || "unknown source")} · ${esc(fmtBytes(archive.size || f.size))}${f.release_date ? ` · ${esc(f.release_date)}` : ""}</span>
      <a class="link" href="${esc(source)}">${archive.asset_url ? "download" : "source"} ↗</a>
    </div>`;
  }).join("") || `<div class="muted">No matching firmware.</div>`;
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
  const list = state.catalog.firmwares;
  const a = list[Number(document.querySelector("#leftSelect").value)];
  const b = list[Number(document.querySelector("#rightSelect").value)];
  const out = document.querySelector("#diffResult");
  out.innerHTML = `<span class="muted">Loading manifests…</span>`;
  try {
    const [ma, mb] = await Promise.all([loadManifest(a), loadManifest(b)]);
    const ac = compMap(ma), bc = compMap(mb), names = [...new Set([...ac.keys(),...bc.keys()])].sort();
    const compRows = names.map(name => {
      const x=ac.get(name), y=bc.get(name);
      const status=!x?"added":!y?"removed":x.sha256!==y.sha256?"changed":"same";
      return {name,status,a:x,b:y};
    });
    const af = new Map(squashFiles(ma).map(x=>[x.path,x])), bf = new Map(squashFiles(mb).map(x=>[x.path,x]));
    const paths=[...new Set([...af.keys(),...bf.keys()])].sort();
    const fileRows=paths.map(path=>{const x=af.get(path),y=bf.get(path);return {path,status:!x?"added":!y?"removed":fileKey(x)!==fileKey(y)?"changed":"same",a:x,b:y};}).filter(x=>x.status!=="same");
    const summary = {
      components: compRows.filter(x=>x.status!=="same").length,
      added:fileRows.filter(x=>x.status==="added").length,
      removed:fileRows.filter(x=>x.status==="removed").length,
      changed:fileRows.filter(x=>x.status==="changed").length
    };
    const packageLine = `<p class="muted">${esc(label(a))} → ${esc(label(b))} · ${esc(fmtBytes(ma?.size || a.size))} → ${esc(fmtBytes(mb?.size || b.size))}</p>`;
    const chips = `<div class="diff-summary">${[[summary.components,"components changed"],[summary.added,"files added"],[summary.removed,"files removed"],[summary.changed,"files changed"]].map(([v,k])=>`<div class="diff-chip"><strong>${v}</strong><span>${k}</span></div>`).join("")}</div>`;
    const comps = `<div class="component-grid">${compRows.filter(x=>x.status!=="same").map(x=>`<div class="component"><span class="status-${x.status}">${x.status}</span> · <strong>${esc(x.name)}</strong><br><code>${esc(x.a?.sha256?.slice(0,16)||"—")} → ${esc(x.b?.sha256?.slice(0,16)||"—")}</code></div>`).join("") || `<div class="muted">Top-level components are identical.</div>`}</div>`;
    const rows = fileRows.slice(0,500).map(x=>`<tr><td class="status-${x.status}">${x.status}</td><td>${esc(x.path)}</td><td>${esc(fmtBytes(x.a?.size))}</td><td>${esc(fmtBytes(x.b?.size))}</td></tr>`).join("");
    const table = fileRows.length ? `<table class="diff-table"><thead><tr><th>Status</th><th>Path</th><th>A</th><th>B</th></tr></thead><tbody>${rows}</tbody></table>${fileRows.length>500?`<p class="muted">Showing first 500 of ${fileRows.length} changed filesystem entries.</p>`:""}` : `<p class="muted">No root-filesystem changes detected in available manifests.</p>`;
    if (!ma || !mb) {
      out.innerHTML = `<p><strong>${esc(label(a))}</strong> vs <strong>${esc(label(b))}</strong></p><p class="muted">At least one build has not been archived/analyzed yet, so only catalog metadata is available. Once the archive workflow stores both manifests, this page will automatically expose component and filesystem diffs.</p>`;
      return;
    }
    out.innerHTML = packageLine + chips + comps + table;
  } catch (err) {
    out.innerHTML = `<span class="muted">Could not compare: ${esc(err.message)}</span>`;
  }
}

document.querySelector("#search").addEventListener("input",()=>renderCatalog(state.catalog.firmwares||[]));
document.querySelector("#compareButton").addEventListener("click",compare);
document.querySelector("#swap").addEventListener("click",()=>{const a=document.querySelector("#leftSelect"),b=document.querySelector("#rightSelect");[a.value,b.value]=[b.value,a.value];});
loadCatalog().catch(err => document.body.innerHTML += `<p>Failed to load catalog: ${esc(err.message)}</p>`);
