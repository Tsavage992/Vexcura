/* ---- BOOK: Vexcura NCLEX-RN Review Book, secure reader (v28, NOT deployed) ----
   Inserted INSIDE MOD (uses current, audit, now) immediately BEFORE the line-start "\nglobalThis.__BADGE = BADGE;", then
   `globalThis.__BOOK = BOOK;`. Router hook (outer export default fetch, next to the other /api/ hooks):
     if (u.pathname.startsWith("/api/book/")) return globalThis.__BOOK.api(r, e, c, u);
   Who can read: signed-in users with an active school_members row in a school whose license is current (status active, or pilot
   when cfg.pilot is true; ends not passed; starts not more than a day ahead — same rule as SCHL lic()), plus the site admin.
   Content: KV book:ch:<id> = gzip(chapter JSON, see book/schema.md); KV book:toc = table of contents (built by the upload
   endpoint or book/build.js). Pages are rendered here, one at a time, as HTML fragments, behind short-lived single-use HMAC
   page tokens bound to user + reading session + chapter + page. No endpoint returns a whole chapter, the book, or a file.
   D1 (created on first call): book_sess, book_log (access log; nonce UNIQUE makes tokens single-use), book_marks, book_hl, book_ans.
   Endpoints (writes need X-NCLEX:1):
     GET  /api/book/access                      {ok, reason, admin, name, email}
     GET  /api/book/toc                         units/chapters/sections with page numbers (no content)
     POST /api/book/session                     {sid, wm:{name,email}, limits}
     POST /api/book/tok   {sid, ch, p}          {t, exp}   (rate limited)
     GET  /api/book/page?t=TOKEN                {ch, p, n, kind, sec, html, wm, hl, mark}   (single use, rate limited, logged)
     GET  /api/book/search?q=&ch=               {hits:[{ch, title, p, sec, snip:[before, match, after]}]}  snippets only, max 20
     POST /api/book/answer {ch, q, resp}        {score, max, fb}   (only for a question page the user opened in the last 3 h)
     GET  /api/book/progress                    per-chapter answered counts
     GET|POST|DELETE /api/book/marks            bookmarks       GET|POST /api/book/hl   block highlights
     Admin: GET /api/book/admin/reads?days=N · GET /api/book/admin/reads/<uid> · GET|PUT /api/book/admin/cfg ·
            POST /api/book/admin/chapter {id, gz(base64)} · DELETE /api/book/admin/chapter/<id> · PUT /api/book/admin/toc {toc} ·
            GET /api/book/admin/status   (upload only; there is deliberately no admin download) */
const BOOK = (() => {
  const J = (o, s, h) => new Response(JSON.stringify(o), { status: s || 200, headers: Object.assign({ "Content-Type": "application/json", "Cache-Control": "no-store, private", "X-Robots-Tag": "noindex", "X-Content-Type-Options": "nosniff" }, h || {}) });
  const now_ = () => (typeof now === "function" ? now() : Date.now());
  const LABEL = "AI-assisted; fact-checked against cited sources; RN review in progress";
  const CATN = { MOC: "Management of Care", SIC: "Safety and Infection Prevention and Control", HPM: "Health Promotion and Maintenance", PSY: "Psychosocial Integrity", BCC: "Basic Care and Comfort", PHA: "Pharmacological and Parenteral Therapies", RRP: "Reduction of Risk Potential", PHY: "Physiological Adaptation" };
  const TYPEN = { mc: "Multiple choice", sata: "Select all that apply", order: "Ordered response", calc: "Fill in the blank (calculation)", mx: "Matrix", hl: "Highlight", cloze: "Drop-down cloze", dnd: "Drag and drop", bow: "Bowtie", hs: "Hot spot" };
  const CJN = { RC: "Recognize cues", AC: "Analyze cues", PH: "Prioritize hypotheses", GS: "Generate solutions", TA: "Take action", EO: "Evaluate outcomes" };
  const CFG0 = { enabled: true, pilot: true, perWin: 60, winMin: 10, perDay: 400, searchWin: 30, answerWin: 120, tokTtl: 90, adminX: 5, fp: true, burst: 40 };
  const HLC = ["yellow", "green", "blue", "pink"];
  const BUDGET = 2000;
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const cl = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").trim().slice(0, n);
  const ipOf = r => r.headers.get("CF-Connecting-IP") || "";
  const isAdmin = me => !!(me && me.role === "admin" && !me.must_reset && !me.mustReset);
  const b64u = u8 => btoa(String.fromCharCode(...u8)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const ub64u = s => Uint8Array.from(atob(String(s).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(s).length + 3) % 4)), c => c.charCodeAt(0));
  const hex = n => [...crypto.getRandomValues(new Uint8Array(n))].map(b => b.toString(16).padStart(2, "0")).join("");

  let ready = false;
  async function init(env) {
    if (ready) return;
    await env.DB.batch([
      env.DB.prepare("CREATE TABLE IF NOT EXISTS book_sess (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, created INTEGER NOT NULL, last INTEGER, ua TEXT, ip TEXT)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS book_log (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, user_id TEXT NOT NULL, sid TEXT, kind TEXT NOT NULL, ch TEXT, p INTEGER, q TEXT, nonce TEXT, ip TEXT)"),
      env.DB.prepare("CREATE UNIQUE INDEX IF NOT EXISTS book_log_nonce ON book_log (nonce) WHERE nonce IS NOT NULL"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS book_log_user ON book_log (user_id, kind, at)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS book_log_at ON book_log (at)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS book_marks (user_id TEXT NOT NULL, ch TEXT NOT NULL, p INTEGER NOT NULL, label TEXT, created INTEGER NOT NULL, PRIMARY KEY (user_id, ch, p))"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS book_hl (user_id TEXT NOT NULL, ch TEXT NOT NULL, b TEXT NOT NULL, color TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (user_id, ch, b))"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS book_ans (user_id TEXT NOT NULL, ch TEXT NOT NULL, q TEXT NOT NULL, score REAL NOT NULL, max REAL NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (user_id, ch, q))")]);
    ready = true;
  }

  /* ---------- config + key ---------- */
  let CFG = null, CFGT = 0;
  async function cfg(env) { if (CFG && now_() - CFGT < 60000) return CFG; let c = null; try { c = await env.SITE.get("book:cfg", "json") } catch (e) { } CFG = Object.assign({}, CFG0, c || {}); CFGT = now_(); return CFG }
  let KEY = null;
  async function hkey(env) {
    if (KEY) return KEY; let m = env.BOOK_KEY || env.ADMIN_KEY;
    if (!m) { m = await env.SITE.get("book:key"); if (!m) { m = hex(32); await env.SITE.put("book:key", m) } }
    KEY = await crypto.subtle.importKey("raw", new TextEncoder().encode("vexcura-book-v1|" + m), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]); return KEY }
  const mac = async (env, s) => new Uint8Array(await crypto.subtle.sign("HMAC", await hkey(env), new TextEncoder().encode(s)));

  /* ---------- access ---------- */
  async function access(env, me) {
    if (!me) return { ok: false, code: 401, reason: "Sign in to read the Vexcura Review Book." };
    if (me.must_reset || me.mustReset) return { ok: false, code: 403, reason: "Set a new password first." };
    if (isAdmin(me)) return { ok: true, admin: true, schools: [] };
    const c = await cfg(env); if (!c.enabled) return { ok: false, code: 403, reason: "The review book is not open yet." };
    let rows = []; try { rows = (await env.DB.prepare("SELECT s.id, s.name, s.status, s.starts, s.ends, m.role FROM school_members m JOIN schools s ON s.id=m.school_id WHERE m.user_id=? AND m.status='active'").bind(String(me.id)).all()).results || [] } catch (e) { rows = [] }
    const t = now_(); const ok = rows.filter(s => (s.status === "active" || (c.pilot && s.status === "pilot")) && !(s.ends && s.ends < t) && !(s.starts && s.starts > t + 86400000));
    if (!ok.length) return { ok: false, code: 403, reason: rows.length ? "Your program's license isn't active right now, so the review book is closed. Ask your program to renew it." : "The Vexcura Review Book is included with licensed nursing programs. Join your program with its code to read it." };
    return { ok: true, admin: false, schools: ok.map(s => ({ id: s.id, name: s.name, role: s.role })) };
  }

  /* ---------- content ---------- */
  async function gunzip(buf) { const u = new Uint8Array(buf); if (u[0] === 0x7b) return new TextDecoder().decode(u); const s = new Blob([u]).stream().pipeThrough(new DecompressionStream("gzip")); return await new Response(s).text() }
  async function gzip(str) { const s = new Blob([new TextEncoder().encode(str)]).stream().pipeThrough(new CompressionStream("gzip")); return new Uint8Array(await new Response(s).arrayBuffer()) }
  const CH = new Map();
  async function chapter(env, id) {
    if (!/^[a-z0-9-]{2,40}$/.test(String(id || ""))) return null;
    const c = CH.get(id); if (c && now_() - c.at < 600000) return c;
    const buf = await env.SITE.get("book:ch:" + id, "arrayBuffer"); if (!buf) { CH.delete(id); return null }
    const d = JSON.parse(await gunzip(buf)); const pages = paginate(d);
    const o = { at: now_(), d, pages, text: null }; CH.set(id, o); return o }
  async function toc(env) { let t = null; try { t = await env.SITE.get("book:toc", "json") } catch (e) { } return t || { title: "Vexcura NCLEX-RN Review Book", label: LABEL, units: [] } }
  const readyIds = T => (T.units || []).flatMap(u => (u.chapters || []).filter(c => c.status === "ready").map(c => c.id));

  /* block weight for pagination (characters of reading) */
  function weight(b) {
    const L = v => typeof v === "string" ? v.length : Array.isArray(v) ? v.reduce((a, x) => a + L(x), 0) : v && typeof v === "object" ? Object.values(v).reduce((a, x) => a + L(x), 0) : 0;
    if (b.p) return b.p.length + 20; if (b.h) return 90; if (b.ul || b.ol) return L(b.ul || b.ol) + 30 * (b.ul || b.ol).length;
    if (b.table) return 120 + L(b.table.rows) * 1.25 + 40 * b.table.rows.length; if (b.fig) return 1000;
    if (b.key || b.pri || b.alert) { const x = b.key || b.pri || b.alert; return 140 + L(x.items) + 25 * (x.items || []).length }
    if (b.mn) return 160 + L(b.mn.letters) + 30 * b.mn.letters.length; if (b.ex) return 140 + L(b.ex.steps) + 30 * b.ex.steps.length; return 100 }
  function paginate(d) {
    const P = [{ k: "open" }];
    (d.sections || []).forEach((s, si) => { let a = 0, sz = 0; (s.blocks || []).forEach((b, bi) => {
      if (b.pb) { if (bi > a) P.push({ k: "c", s: si, a, b: bi }); a = bi + 1; sz = 0; return }
      const w = weight(b); if (sz && sz + w > BUDGET && sz >= BUDGET * 0.45) { P.push({ k: "c", s: si, a, b: bi }); a = bi; sz = 0 } sz += w });
      if ((s.blocks || []).length > a) P.push({ k: "c", s: si, a, b: s.blocks.length }) });
    if ((d.questions || []).length || (d.cases || []).length) P.push({ k: "qh" });
    (d.questions || []).forEach((q, i) => P.push({ k: "q", i }));
    (d.cases || []).forEach((c, ci) => c.items.forEach((q, i) => P.push({ k: "cs", c: ci, i })));
    P.push({ k: "src" }); return P }
  const qOf = (d, pg) => pg.k === "q" ? d.questions[pg.i] : pg.k === "cs" ? d.cases[pg.c].items[pg.i] : null;
  const qid = (d, pg) => pg.k === "q" ? d.questions[pg.i].id : pg.k === "cs" ? d.cases[pg.c].id + "-" + (pg.i + 1) : "";
  function pageOfQ(o, id) { return o.pages.findIndex(pg => (pg.k === "q" || pg.k === "cs") && qid(o.d, pg) === id) }
  function secTitle(d, pg) { if (pg.k === "c") return d.sections[pg.s].title; if (pg.k === "open") return "Chapter opening"; if (pg.k === "src") return "Sources"; if (pg.k === "cs") return "Case study: " + d.cases[pg.c].title; return "Chapter questions" }

  /* ---------- rendering ---------- */
  function zw(sid) { if (!sid) return ""; let s = ""; for (const ch of String(sid).slice(0, 8)) { const v = parseInt(ch, 16); if (isNaN(v)) continue; for (let k = 3; k >= 0; k--) s += (v >> k) & 1 ? "‌" : "​" } return "⁠" + s + "⁠" }
  function inl(s, fp) { let h = esc(s).replace(/\*\*([^*\n]+)\*\*/g, "<b>$1</b>").replace(/(^|[^*\w])\*([^*\s][^*\n]*?)\*(?!\w)/g, "$1<i>$2</i>").replace(/\[(S\d{1,3}(?:\s*,\s*S\d{1,3})*)\]/g, (m, x) => `<sup class="bk-cite"><button type="button" data-go="src" aria-label="Sources ${esc(x)}">[${esc(x.replace(/\s+/g, ""))}]</button></sup>`);
    if (fp) { const i = h.indexOf(" "); if (i > 0) h = h.slice(0, i) + fp + h.slice(i) } return h }
  function svgClean(s) { return String(s || "").replace(/<\s*(script|foreignObject|iframe|image|use|a)\b[\s\S]*?(<\/\s*\1\s*>|\/>)/gi, "").replace(/\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "").replace(/\s(xlink:)?href\s*=\s*("[^#"][^"]*"|'[^#'][^']*')/gi, "").replace(/url\(\s*['"]?(?!#)[^)]*\)/gi, "none").replace(/<svg\b/i, '<svg role="img" focusable="false"') }
  function block(b, key, fp, fig) {
    const W = (cls, inner) => `<div class="bk-b ${cls}" data-b="${key}">${inner}</div>`;
    const li = L => L.map(x => `<li>${inl(x)}</li>`).join("");
    if (b.p) return W("bk-p", `<p>${inl(b.p, fp)}</p>`);
    if (b.h) return W("bk-h", `<h3>${inl(b.h)}</h3>`);
    if (b.ul) return W("bk-l", `<ul>${li(b.ul)}</ul>`);
    if (b.ol) return W("bk-l", `<ol>${li(b.ol)}</ol>`);
    if (b.key) return W("bk-box bk-key", `<aside role="note" aria-label="Key points"><h4><span class="bk-tag">Key points</span>${b.key.title ? " " + inl(b.key.title) : ""}</h4><ul>${li(b.key.items)}</ul></aside>`);
    if (b.pri) return W("bk-box bk-pri", `<aside role="note" aria-label="Priority nursing actions"><h4><span class="bk-tag">Priority nursing actions</span>${b.pri.title ? " " + inl(b.pri.title) : ""}</h4><ol>${li(b.pri.items)}</ol></aside>`);
    if (b.alert) return W("bk-box bk-alert", `<aside role="note" aria-label="Safety alert"><h4><span class="bk-tag">Safety alert</span>${b.alert.title ? " " + inl(b.alert.title) : ""}</h4><ul>${li(b.alert.items)}</ul></aside>`);
    if (b.ex) return W("bk-box bk-ex", `<aside role="note" aria-label="Worked example"><h4><span class="bk-tag">Worked example</span> ${inl(b.ex.title)}</h4><ol>${li(b.ex.steps)}</ol>${b.ex.answer ? `<p class="bk-exa"><b>Answer:</b> ${inl(b.ex.answer)}</p>` : ""}</aside>`);
    if (b.mn) return W("bk-box bk-mn", `<aside role="note" aria-label="Memory aid"><h4><span class="bk-tag">Memory aid</span> ${inl(b.mn.name)}</h4><dl>${b.mn.letters.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${inl(v)}</dd></div>`).join("")}</dl>${b.mn.note ? `<p class="bk-note">${inl(b.mn.note)}</p>` : ""}</aside>`);
    if (b.table) { const t = b.table; return W("bk-tblw", `<figure class="bk-tbl"><div class="bk-tsc" role="region" tabindex="0" aria-label="${esc(t.cap)} (scrolls sideways)"><table><caption>${inl(t.cap)}</caption><thead><tr>${t.head.map(h => `<th scope="col">${inl(h)}</th>`).join("")}</tr></thead><tbody>${t.rows.map(r => `<tr>${r.map((c, i) => i === 0 ? `<th scope="row">${inl(c)}</th>` : `<td>${inl(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>${t.note || t.src ? `<figcaption class="bk-src">${t.note ? inl(t.note) + " " : ""}${t.src ? "Sources: " + inl("[" + t.src.join(", ") + "]") : ""}</figcaption>` : ""}</figure>`) }
    if (b.fig) { const f = b.fig; return W("bk-figw", `<figure class="bk-fig"><div class="bk-svg" role="img" aria-label="${esc(f.alt)}">${svgClean(f.svg)}</div><figcaption><b>Figure ${esc(fig)}.</b> ${inl(f.cap)}</figcaption></figure>`) }
    return "" }
  function figNo(d, si, bi) { let n = 0; for (let s = 0; s < d.sections.length; s++) for (let b = 0; b < d.sections[s].blocks.length; b++) { if (d.sections[s].blocks[b].fig) n++; if (s === si && b === bi) return (d.num || "") + "-" + n } return "" }

  /* deterministic per-user shuffles keyed by the server secret, so display order never reveals the key */
  async function perm(env, seed, n) { const h = await mac(env, seed); const a = [...Array(n).keys()]; for (let i = n - 1; i > 0; i--) { const j = h[i % 32] % (i + 1); [a[i], a[j]] = [a[j], a[i]] } return a }
  async function views(env, uid, q, id) {
    const V = {}; const P = (tag, n) => perm(env, "perm|" + uid + "|" + id + "|" + tag, n);
    if (q.t === "mc" || q.t === "sata" || q.t === "order") V.o = await P("o", q.o.length);
    if (q.t === "cloze") { V.dd = []; for (let i = 0; i < q.dd.length; i++) V.dd.push(await P("dd" + i, q.dd[i].length)) }
    if (q.t === "dnd") V.tok = await P("tok", q.tok.length);
    if (q.t === "bow") { V.cond = await P("c", q.cond.length); V.act = await P("a", q.act.length); V.mon = await P("m", q.mon.length) }
    if (q.t === "order") { /* make sure the shown order is not already the answer */ if (V.o.every((v, i) => v === i)) V.o.push(V.o.shift()) }
    return V }
  function exhibits(x) { if (!x || !x.length) return ""; return `<div class="bk-xw"><div class="bk-xt" role="tablist" aria-label="Client record">${x.map((e, i) => `<button type="button" role="tab" id="bkx-t${i}" aria-controls="bkx-p${i}" aria-selected="${i === 0}" tabindex="${i === 0 ? 0 : -1}" data-xt="${i}">${esc(e[0])}</button>`).join("")}</div>${x.map((e, i) => `<div class="bk-xp" role="tabpanel" id="bkx-p${i}" aria-labelledby="bkx-t${i}" tabindex="0" ${i ? "hidden" : ""}>${esc(e[1]).replace(/\n/g, "<br>")}</div>`).join("")}</div>` }
  async function qHTML(env, uid, q, id, meta, fp) {
    const V = await views(env, uid, q, id); const nm = "a_" + id.replace(/[^A-Za-z0-9]/g, "");
    let f = "";
    if (q.t === "mc" || q.t === "sata") { const ty = q.t === "mc" ? "radio" : "checkbox"; f = `<fieldset class="bk-opts"><legend class="bk-sr">Answer options</legend>${V.o.map((oi, di) => `<label class="bk-opt"><input type="${ty}" name="${nm}" value="${di}"><span>${inl(q.o[oi])}</span></label>`).join("")}</fieldset>` }
    else if (q.t === "order") f = `<p class="bk-hint" id="${nm}-h">Use the arrow buttons to put the options in order. The first step goes at the top.</p><ol class="bk-ord" aria-describedby="${nm}-h">${V.o.map((oi, di) => `<li data-v="${di}"><span>${inl(q.o[oi])}</span><span class="bk-ordb"><button type="button" data-mv="-1" aria-label="Move up">&#8593;</button><button type="button" data-mv="1" aria-label="Move down">&#8595;</button></span></li>`).join("")}</ol>`;
    else if (q.t === "calc") f = `<label class="bk-calc"><span>Answer</span><input type="text" inputmode="decimal" autocomplete="off" name="${nm}" aria-describedby="${nm}-u"><span id="${nm}-u">${esc(q.u)}</span></label>${q.rd ? `<p class="bk-hint">${esc(q.rd)}</p>` : ""}`;
    else if (q.t === "mx") f = `<div class="bk-tsc" role="region" tabindex="0" aria-label="Answer grid"><table class="bk-mx"><thead><tr><th scope="col">${esc(q.rh || "Finding")}</th>${q.cols.map(c => `<th scope="col">${esc(c)}</th>`).join("")}</tr></thead><tbody>${q.rows.map((r, ri) => `<tr><th scope="row">${inl(r[0])}</th>${q.cols.map((c, ci) => `<td><input type="radio" name="${nm}_${ri}" value="${ci}" aria-label="${esc(r[0])}: ${esc(c)}"></td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
    else if (q.t === "hl") f = `<p class="bk-hint">Select each part to highlight it. Select it again to remove the highlight.</p><div class="bk-hl">${q.parts.map((p, i) => `<button type="button" class="bk-hlp" aria-pressed="false" data-v="${i}">${inl(p[0])}</button>`).join(" ")}</div>`;
    else if (q.t === "cloze" || q.t === "dnd") { let k = 0; const tpl = esc(q.tpl).replace(/\{(\d+)\}/g, (m, n) => { const i = +n; const opts = q.t === "cloze" ? V.dd[i].map((oi, di) => `<option value="${di}">${esc(q.dd[i][oi])}</option>`).join("") : V.tok.map((oi, di) => `<option value="${di}">${esc(q.tok[oi])}</option>`).join(""); k++; return `<select data-blank="${i}" aria-label="Blank ${i + 1}"><option value="">Select…</option>${opts}</select>` });
      f = (q.t === "dnd" ? `<p class="bk-hint">Choose a word for each blank. Each word can be used once.</p><p class="bk-toks" aria-label="Word choices">${V.tok.map(oi => `<span>${esc(q.tok[oi])}</span>`).join("")}</p>` : "") + `<p class="bk-cloze">${tpl}</p>` }
    else if (q.t === "bow") { const grp = (lab, key, n, ty) => `<fieldset class="bk-bowg bk-bow-${key}"><legend>${lab}</legend>${V[key].map((oi, di) => `<label class="bk-opt"><input type="${ty}" name="${nm}_${key}" value="${di}"><span>${inl(q[key][oi])}</span></label>`).join("")}</fieldset>`;
      f = `<p class="bk-hint">Choose 1 condition the client is most likely experiencing, 2 actions to take, and 2 parameters to monitor.</p><div class="bk-bow">${grp("Actions to take (choose 2)", "act", 2, "checkbox")}${grp("Condition most likely experiencing (choose 1)", "cond", 1, "radio")}${grp("Parameters to monitor (choose 2)", "mon", 2, "checkbox")}</div>` }
    else if (q.t === "hs") f = `<div class="bk-hs"><div class="bk-svg" role="img" aria-label="${esc(q.img.alt)}">${svgClean(q.img.svg)}</div><fieldset class="bk-opts"><legend>Choose the area</legend>${q.img.regions.map((r, i) => `<label class="bk-opt"><input type="radio" name="${nm}" value="${i}"><span>${esc(r)}</span></label>`).join("")}</fieldset></div>`;
    return `<section class="bk-q" data-q="${esc(id)}" data-t="${q.t}" data-n="${nm}"><p class="bk-qmeta">${meta}</p>${exhibits(q.x)}<p class="bk-stem">${inl(q.q, fp)}</p><form class="bk-qf" novalidate>${f}<div class="bk-qa"><button type="submit" class="bk-btn bk-check">Check answer</button></div></form><div class="bk-fb" aria-live="polite"></div></section>` }

  async function renderPage(env, o, p, ctx) {
    const d = o.d, pg = o.pages[p], fp = ctx.fp ? zw(ctx.sid) : "";
    const run = `<p class="bk-run" aria-hidden="true">Unit ${esc(d.unit)} · Chapter ${esc(d.num)} · ${esc(d.title)}</p>`;
    let h = "";
    if (pg.k === "open") {
      const tp = d.testPlan ? Object.entries(d.testPlan).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]) : [];
      h = `<div class="bk-open"><p class="bk-kicker">Unit ${esc(d.unit)}: ${esc(d.unitTitle)}</p><h2 class="bk-h1">Chapter ${esc(d.num)}<span>${esc(d.title)}</span></h2><p class="bk-label" role="note">${esc(d.label || LABEL)}</p>
      ${d.intro ? `<div class="bk-b bk-p" data-b="o.0"><p>${inl(d.intro, fp)}</p></div>` : ""}
      <h3>In this chapter</h3><ol class="bk-toc1">${d.sections.map((s, si) => { const sp = o.pages.findIndex(x => x.k === "c" && x.s === si); return `<li><button type="button" data-go="${sp}">${esc(s.title)}</button> <span class="bk-pn">page ${sp + 1}</span></li>` }).join("")}<li><button type="button" data-go="${o.pages.findIndex(x => x.k === "qh")}">Chapter questions</button></li></ol>
      ${d.objectives && d.objectives.length ? `<h3>Objectives</h3><ul>${d.objectives.map(x => `<li>${inl(x)}</li>`).join("")}</ul>` : ""}
      ${tp.length ? `<h3>NCLEX-RN test plan focus</h3><table class="bk-tp"><caption class="bk-sr">Share of this chapter's questions by Client Needs category</caption><thead><tr><th scope="col">Client Needs category</th><th scope="col">Share of chapter questions</th></tr></thead><tbody>${tp.map(([k, v]) => `<tr><th scope="row">${esc(CATN[k] || k)}</th><td>${esc(v)}%</td></tr>`).join("")}</tbody></table><p class="bk-note">Category names and ranges follow the NCSBN 2026 NCLEX-RN Test Plan (effective April 2026).</p>` : ""}</div>` }
    else if (pg.k === "c") { const s = d.sections[pg.s]; h = (pg.a === 0 ? `<h2 class="bk-sec" id="bk-s${pg.s}">${esc(s.title)}</h2>` : `<p class="bk-cont" aria-hidden="true">${esc(s.title)} (continued)</p>`) + s.blocks.slice(pg.a, pg.b).map((b, i) => block(b, pg.s + "." + (pg.a + i), fp, b.fig ? figNo(d, pg.s, pg.a + i) : "")).join("") }
    else if (pg.k === "qh") { const n = (d.questions || []).length, nc = (d.cases || []).length; h = `<h2 class="bk-sec">Chapter ${esc(d.num)} questions</h2><div class="bk-b bk-p" data-b="q.0"><p>This chapter has ${n} questions${nc ? ` and ${nc} unfolding case stud${nc > 1 ? "ies" : "y"} (6 items each)` : ""}. Answer each one, then choose <b>Check answer</b> to see the rationale for every option and the sources. Your results are saved to your account.</p></div><div class="bk-b bk-p" data-b="q.1"><p>Partial-credit items are scored the way NCSBN describes in general terms: some items give a point for each correct choice and take one away for each incorrect choice (+/-), others give a point for each correct choice (0/1). Practice scores here are a study aid, not a prediction of your result.</p></div>` }
    else if (pg.k === "q" || pg.k === "cs") { const q = qOf(d, pg), id = qid(d, pg); const nq = (d.questions || []).length;
      const meta = pg.k === "q" ? `Question ${pg.i + 1} of ${nq} · ${TYPEN[q.t]} · ${esc(CATN[q.c] || q.c)}${q.trend ? " · Trend" : ""}` : `Case study ${pg.c + 1}: ${esc(d.cases[pg.c].title)} · Item ${pg.i + 1} of ${d.cases[pg.c].items.length} · ${TYPEN[q.t]} · ${esc(CJN[q.j] || "")}`;
      h = (pg.k === "cs" && pg.i === 0 && d.cases[pg.c].intro ? `<div class="bk-b bk-p" data-b="c${pg.c}.0"><p class="bk-csi">${inl(d.cases[pg.c].intro)}</p></div>` : "") + await qHTML(env, ctx.uid, q, id, meta, fp) }
    else if (pg.k === "src") h = `<h2 class="bk-sec">Sources for chapter ${esc(d.num)}</h2><p class="bk-note">${esc(d.label || LABEL)}. Reference ranges vary by laboratory; follow your facility's values and policies.</p><ol class="bk-srcs">${(d.sources || []).map(s => `<li id="bk-${esc(s.id)}"><b>[${esc(s.id)}]</b> ${esc(s.cite)}${s.url ? ` <a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer nofollow">${esc(s.url.replace(/^https:\/\//, "").slice(0, 70))}</a>` : ""}</li>`).join("")}</ol>`;
    return `<article class="bk-page bk-k-${pg.k}" aria-label="Page ${p + 1} of ${o.pages.length}">${run}${h}<p class="bk-folio" aria-hidden="true">${p + 1}</p></article>` }

  /* plain text of a page for search (no keys, no rationales) */
  function pageText(o, p) { const d = o.d, pg = o.pages[p]; const T = []; const W = v => { if (typeof v === "string") T.push(v); else if (Array.isArray(v)) v.forEach(W); else if (v && typeof v === "object") Object.values(v).forEach(W) };
    if (pg.k === "open") { T.push(d.title, d.intro || ""); W(d.objectives || []) }
    else if (pg.k === "c") { const s = d.sections[pg.s]; if (pg.a === 0) T.push(s.title); s.blocks.slice(pg.a, pg.b).forEach(b => { if (b.fig) T.push(b.fig.cap, b.fig.alt); else if (b.table) { T.push(b.table.cap); W(b.table.head); W(b.table.rows) } else if (!b.pb) W(b) }) }
    else if (pg.k === "q" || pg.k === "cs") { const q = qOf(d, pg); T.push(q.q); if (q.tpl) T.push(q.tpl.replace(/\{\d+\}/g, "___")) }
    return T.join(" ").replace(/\*\*|\*/g, "").replace(/\[S\d+(?:,\s*S\d+)*\]/g, "").replace(/\s+/g, " ").trim() }

  /* ---------- grading ---------- */
  async function grade(env, uid, q, id, resp) {
    const V = await views(env, uid, q, id); const A = v => Array.isArray(v) ? v : []; const toO = di => V.o[di];
    let score = 0, max = 1, sel = null;
    if (q.t === "mc") { const di = parseInt(resp, 10); sel = isNaN(di) ? -1 : toO(di); score = sel === 0 ? 1 : 0 }
    else if (q.t === "sata") { sel = [...new Set(A(resp).map(x => toO(parseInt(x, 10))).filter(x => x != null))]; max = q.k; const good = sel.filter(x => x < q.k).length, bad = sel.length - good; score = Math.max(0, good - bad) }
    else if (q.t === "order") { sel = A(resp).map(x => toO(parseInt(x, 10))); score = sel.length === q.o.length && sel.every((v, i) => v === i) ? 1 : 0 }
    else if (q.t === "calc") { const v = parseFloat(String(resp == null ? "" : resp).replace(/,/g, "").trim()); sel = isNaN(v) ? null : v; score = sel != null && Math.abs(sel - q.a) <= (q.tol || 0) + 1e-9 ? 1 : 0 }
    else if (q.t === "mx") { sel = A(resp).map(x => parseInt(x, 10)); max = q.rows.length; score = q.rows.reduce((a, r, i) => a + (sel[i] === r[1] ? 1 : 0), 0) }
    else if (q.t === "hl") { sel = [...new Set(A(resp).map(x => parseInt(x, 10)).filter(i => i >= 0 && i < q.parts.length))]; max = q.parts.filter(p => p[1] === 1).length; const good = sel.filter(i => q.parts[i][1] === 1).length, bad = sel.filter(i => q.parts[i][1] === 0).length; score = Math.max(0, good - bad) }
    else if (q.t === "cloze") { sel = A(resp).map((x, i) => { const di = parseInt(x, 10); return isNaN(di) || !V.dd[i] ? -1 : V.dd[i][di] }); max = q.ans.length; score = q.ans.reduce((a, k, i) => a + (sel[i] === k ? 1 : 0), 0) }
    else if (q.t === "dnd") { sel = A(resp).map(x => { const di = parseInt(x, 10); return isNaN(di) ? -1 : V.tok[di] }); max = q.ans.length; score = q.ans.reduce((a, k, i) => a + (sel[i] === k ? 1 : 0), 0) }
    else if (q.t === "bow") { const r = resp || {}; const c = V.cond[parseInt(r.cond, 10)], a = [...new Set(A(r.act).map(x => V.act[parseInt(x, 10)]))].slice(0, 2), m = [...new Set(A(r.mon).map(x => V.mon[parseInt(x, 10)]))].slice(0, 2); sel = { c, a, m }; max = 5; score = (c === q.ca ? 1 : 0) + a.filter(x => q.aa.indexOf(x) >= 0).length + m.filter(x => q.ma.indexOf(x) >= 0).length }
    else if (q.t === "hs") { sel = parseInt(resp, 10); score = sel === q.a ? 1 : 0 }
    return { score, max, V, sel } }
  function fbHTML(q, g, srcs) {
    const ok = g.score === g.max, part = g.score > 0 && !ok; const V = g.V; const ro = q.ro;
    const row = (txt, keyed, mine, why) => `<li class="${keyed ? "bk-k" : ""}${mine ? " bk-mine" : ""}"><span class="bk-mk">${keyed ? "Correct" : "Incorrect"}${mine ? " · your answer" : ""}</span><b>${inl(txt)}</b><span class="bk-why">${inl(why)}</span></li>`;
    let L = "";
    if (q.t === "mc" || q.t === "sata") L = `<ul class="bk-ro">${V.o.map(oi => row(q.o[oi], q.t === "mc" ? oi === 0 : oi < q.k, q.t === "mc" ? g.sel === oi : g.sel.indexOf(oi) >= 0, ro[oi])).join("")}</ul>`;
    else if (q.t === "order") L = `<p><b>Correct order:</b></p><ol class="bk-ro">${q.o.map((o, i) => `<li class="bk-k"><b>${inl(o)}</b><span class="bk-why">${inl(ro[i])}</span></li>`).join("")}</ol>`;
    else if (q.t === "calc") L = `<p><b>Answer:</b> ${esc(q.a)} ${esc(q.u)}${g.sel != null ? ` · <span>you entered ${esc(g.sel)}</span>` : ""}</p><ol class="bk-ro">${ro.map(x => `<li><span class="bk-why">${inl(x)}</span></li>`).join("")}</ol>`;
    else if (q.t === "mx") L = `<ul class="bk-ro">${q.rows.map((r, i) => `<li class="${g.sel[i] === r[1] ? "bk-k" : "bk-x"}"><span class="bk-mk">${g.sel[i] === r[1] ? "Correct" : "Review"}</span><b>${inl(r[0])} → ${esc(q.cols[r[1]])}</b><span class="bk-why">${inl(ro[i])}</span></li>`).join("")}</ul>`;
    else if (q.t === "hl") L = `<ul class="bk-ro">${q.parts.map((p, i) => row(p[0], p[1] === 1, g.sel.indexOf(i) >= 0, ro[i])).join("")}</ul>`;
    else if (q.t === "cloze") L = q.dd.map((opts, b) => `<p><b>Blank ${b + 1}</b></p><ul class="bk-ro">${V.dd[b].map(oi => row(opts[oi], oi === q.ans[b], g.sel[b] === oi, ro[b][oi])).join("")}</ul>`).join("");
    else if (q.t === "dnd") L = `<ul class="bk-ro">${V.tok.map(oi => { const bl = q.ans.indexOf(oi); return row(q.tok[oi] + (bl >= 0 ? ` (blank ${bl + 1})` : ""), bl >= 0, g.sel.indexOf(oi) >= 0, ro[oi]) }).join("")}</ul>`;
    else if (q.t === "bow") L = [["cond", "Condition", x => x === q.ca, x => g.sel.c === x], ["act", "Actions to take", x => q.aa.indexOf(x) >= 0, x => g.sel.a.indexOf(x) >= 0], ["mon", "Parameters to monitor", x => q.ma.indexOf(x) >= 0, x => g.sel.m.indexOf(x) >= 0]].map(([k, lab, key, mine]) => `<p><b>${lab}</b></p><ul class="bk-ro">${V[k].map(oi => row(q[k][oi], key(oi), mine(oi), ro[k][oi])).join("")}</ul>`).join("");
    else if (q.t === "hs") L = `<ul class="bk-ro">${q.img.regions.map((r, i) => row(r, i === q.a, g.sel === i, ro[i])).join("")}</ul>`;
    return `<div class="bk-res ${ok ? "bk-ok" : part ? "bk-part" : "bk-no"}" role="status"><b>${ok ? "Correct" : part ? "Partly correct" : "Not quite"}</b> · score ${g.score} of ${g.max}</div>${L}<div class="bk-rat"><h4>Rationale</h4><p>${inl(q.r)}</p></div><p class="bk-qs"><b>Sources:</b> ${(srcs || []).map(s => s.url ? `<a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer nofollow">${esc(s.cite)}</a>` : esc(s.cite)).join("; ")}</p>` }

  /* ---------- structural check (upload) ---------- */
  function check(d) { const E = [];
    if (!d || typeof d !== "object") return ["not an object"]; if (!/^[a-z0-9-]{2,40}$/.test(d.id || "")) E.push("id"); if (!d.title) E.push("title");
    if (!Array.isArray(d.sections) || !d.sections.length) E.push("sections"); else d.sections.forEach((s, i) => { if (!s.title || !Array.isArray(s.blocks)) E.push("section " + i) });
    const qs = (d.questions || []).concat(...(d.cases || []).map(c => c.items || []));
    qs.forEach((q, i) => { if (!TYPEN[q.t]) E.push("question " + i + " type"); if (!q.r || !q.ro) E.push("question " + i + " rationale") });
    const txt = JSON.stringify(d); if (/<\s*script\b|\son[a-z]+\s*=/i.test(txt)) E.push("script or event handler in content");
    return E }

  /* ---------- rate limits + log ---------- */
  const cnt = async (env, uid, kind, since) => ((await env.DB.prepare("SELECT COUNT(*) n FROM book_log WHERE user_id=? AND kind=? AND at>?").bind(String(uid), kind, since).first()) || {}).n || 0;
  async function limited(env, me, adm, kind) { const c = await cfg(env), x = adm ? c.adminX : 1, t = now_();
    if (kind === "page") { if (await cnt(env, me.id, "page", t - c.winMin * 60000) >= c.perWin * x) return `You've read ${c.perWin * x} pages in ${c.winMin} minutes. Take a short break; the reader opens again in a few minutes.`;
      if (await cnt(env, me.id, "page", t - 86400000) >= c.perDay * x) return `You've reached today's reading limit (${c.perDay * x} pages in 24 hours). It resets over the next day.` }
    if (kind === "search" && await cnt(env, me.id, "search", t - c.winMin * 60000) >= c.searchWin * x) return "Too many searches. Wait a few minutes and try again.";
    if (kind === "answer" && await cnt(env, me.id, "answer", t - c.winMin * 60000) >= c.answerWin * x) return "Too many answers in a short time. Wait a few minutes.";
    return null }
  const log = (env, req, me, sid, kind, ch, p, q, nonce) => env.DB.prepare("INSERT INTO book_log (at,user_id,sid,kind,ch,p,q,nonce,ip) VALUES (?,?,?,?,?,?,?,?,?)").bind(now_(), String(me.id), sid || null, kind, ch || null, p == null ? null : p, q || null, nonce || null, ipOf(req)).run();
  const BURST = new Map(); function burst(uid, max) { const t = now_(), L = (BURST.get(uid) || []).filter(x => t - x < 60000); L.push(t); BURST.set(uid, L); if (BURST.size > 5000) BURST.clear(); return L.length > max }

  /* ---------- tokens ---------- */
  async function mint(env, o) { const body = b64u(new TextEncoder().encode(JSON.stringify(o))); return body + "." + b64u(await mac(env, "tok|" + body)) }
  async function open_(env, t) { const [body, sig] = String(t || "").split("."); if (!body || !sig || t.length > 600) return null; const good = b64u(await mac(env, "tok|" + body)); if (good.length !== sig.length) return null; let diff = 0; for (let i = 0; i < good.length; i++) diff |= good.charCodeAt(i) ^ sig.charCodeAt(i); if (diff) return null; try { return JSON.parse(new TextDecoder().decode(ub64u(body))) } catch (e) { return null } }

  /* ---------- API ---------- */
  async function api(req, env, ctx, url) {
    await init(env); const seg = url.pathname.replace(/^\/api\/book\/?/, "").split("/").filter(Boolean); const M = req.method;
    if (M !== "GET" && req.headers.get("X-NCLEX") !== "1") return J({ error: "Bad request" }, 400);
    const me = await current(env, req); const A = await access(env, me);
    const body = async () => { try { return await req.json() } catch (e) { return {} } };
    if (seg[0] === "access" && M === "GET") return J({ ok: A.ok, reason: A.reason || "", admin: !!A.admin, name: me ? me.name : "", email: me ? me.email : "", schools: A.schools || [], label: LABEL }, me ? 200 : 401);
    if (!A.ok) { if (me && seg[0] !== "access") { try { await log(env, req, me, null, "denied", null, null, seg.join("/").slice(0, 60)) } catch (e) { } } return J({ error: A.reason }, A.code) }
    const adm = !!A.admin;

    if (seg[0] === "toc" && M === "GET") { const T = await toc(env); const P = {}; try { ((await env.DB.prepare("SELECT ch, COUNT(*) n, SUM(score) s, SUM(max) m FROM book_ans WHERE user_id=? GROUP BY ch").bind(String(me.id)).all()).results || []).forEach(r => P[r.ch] = { n: r.n, s: r.s, m: r.m }) } catch (e) { }
      return J({ title: T.title, label: T.label || LABEL, version: T.version || "", units: (T.units || []).map(u => ({ n: u.n, title: u.title, chapters: (u.chapters || []).map(c => ({ id: c.id, num: c.num, title: c.title, status: c.status, n: c.n || 0, sections: c.status === "ready" ? c.sections || [] : [], qp: c.qp, nq: c.nq || 0, progress: P[c.id] || null })) })) }) }
    if (seg[0] === "session" && M === "POST") { const sid = hex(4).toUpperCase(); await env.DB.prepare("INSERT INTO book_sess (id,user_id,created,last,ua,ip) VALUES (?,?,?,?,?,?)").bind(sid, String(me.id), now_(), now_(), cl(req.headers.get("User-Agent"), 200), ipOf(req)).run(); const c = await cfg(env);
      return J({ sid, wm: { name: cl(me.name, 80), email: cl(me.email, 120) }, limits: { perWin: c.perWin * (adm ? c.adminX : 1), winMin: c.winMin, perDay: c.perDay * (adm ? c.adminX : 1) }, admin: adm }) }
    if (seg[0] === "tok" && M === "POST") { const b = await body(); const sid = String(b.sid || ""), ch = String(b.ch || ""), p = parseInt(b.p, 10);
      const s = /^[0-9A-F]{8}$/.test(sid) && await env.DB.prepare("SELECT user_id FROM book_sess WHERE id=?").bind(sid).first(); if (!s || s.user_id !== String(me.id)) return J({ error: "Your reading session ended. Reopen the book." }, 403);
      const T = await toc(env); if (readyIds(T).indexOf(ch) < 0) return J({ error: "Not found" }, 404); const o = await chapter(env, ch); if (!o || !(p >= 0 && p < o.pages.length)) return J({ error: "Not found" }, 404);
      if (burst(String(me.id), (await cfg(env)).burst * (adm ? (await cfg(env)).adminX : 1))) return J({ error: "Slow down a little. Pages are opening too fast." }, 429, { "Retry-After": "60" });
      const lim = await limited(env, me, adm, "page"); if (lim) { await log(env, req, me, sid, "blocked", ch, p); return J({ error: lim, limit: true }, 429, { "Retry-After": "300" }) }
      const c = await cfg(env), exp = now_() + c.tokTtl * 1000; return J({ t: await mint(env, { u: String(me.id), s: sid, c: ch, p, e: exp, n: hex(8) }), exp }) }
    if (seg[0] === "page" && M === "GET") { const k = await open_(env, url.searchParams.get("t")); if (!k) return J({ error: "This page link isn't valid. Turn the page again." }, 403);
      if (k.u !== String(me.id)) return J({ error: "This page link belongs to another reader." }, 403); if (k.e < now_()) return J({ error: "This page link expired. Turn the page again." }, 410);
      const lim = await limited(env, me, adm, "page"); if (lim) { await log(env, req, me, k.s, "blocked", k.c, k.p); return J({ error: lim, limit: true }, 429, { "Retry-After": "300" }) }
      const o = await chapter(env, k.c); if (!o || !(k.p >= 0 && k.p < o.pages.length)) return J({ error: "Not found" }, 404);
      try { await log(env, req, me, k.s, "page", k.c, k.p, null, k.n) } catch (e) { return J({ error: "This page link was already used. Turn the page again." }, 409) }
      const c = await cfg(env); const html = await renderPage(env, o, k.p, { uid: String(me.id), sid: k.s, fp: c.fp });
      const keys = []; const pg = o.pages[k.p]; if (pg.k === "c") for (let i = pg.a; i < pg.b; i++) keys.push(pg.s + "." + i);
      const hl = {}; if (keys.length) ((await env.DB.prepare(`SELECT b, color FROM book_hl WHERE user_id=? AND ch=? AND b IN (${keys.map(() => "?").join(",")})`).bind(String(me.id), k.c, ...keys).all()).results || []).forEach(r => hl[r.b] = r.color);
      const mk = await env.DB.prepare("SELECT label FROM book_marks WHERE user_id=? AND ch=? AND p=?").bind(String(me.id), k.c, k.p).first();
      const seed = (await mac(env, "wm|" + k.n))[0]; await env.DB.prepare("UPDATE book_sess SET last=? WHERE id=?").bind(now_(), k.s).run();
      return J({ ch: k.c, p: k.p, n: o.pages.length, kind: pg.k, sec: secTitle(o.d, pg), title: o.d.title, num: o.d.num, html, wm: { t: `${cl(me.name, 60)} · ${cl(me.email, 80)} · ${k.s}`, x: seed % 7, y: (seed >> 3) % 5, at: now_() }, hl, mark: mk ? (mk.label || "") : null }) }
    if (seg[0] === "search" && M === "GET") { const q = cl(url.searchParams.get("q"), 60).toLowerCase().replace(/\s+/g, " "); if (q.length < 3) return J({ error: "Type at least 3 letters." }, 400);
      const lim = await limited(env, me, adm, "search"); if (lim) return J({ error: lim, limit: true }, 429); await log(env, req, me, null, "search", url.searchParams.get("ch") || null, null, q);
      const T = await toc(env); let ids = readyIds(T); const only = url.searchParams.get("ch"); if (only) ids = ids.filter(x => x === only); const hits = []; const W = 60;
      for (const id of ids) { const o = await chapter(env, id); if (!o) continue; if (!o.text) o.text = o.pages.map((x, i) => x.k === "src" ? "" : pageText(o, i)); for (let i = 0; i < o.text.length && hits.length < 20; i++) { const t = o.text[i], lo = t.toLowerCase(); const j = lo.indexOf(q); if (j < 0) continue;
        const a = Math.max(0, j - W), b = Math.min(t.length, j + q.length + W); hits.push({ ch: id, num: o.d.num, title: o.d.title, p: i, sec: secTitle(o.d, o.pages[i]), snip: [(a > 0 ? "…" : "") + t.slice(a, j), t.slice(j, j + q.length), t.slice(j + q.length, b) + (b < t.length ? "…" : "")] }) } if (hits.length >= 20) break }
      return J({ q, hits, more: hits.length >= 20 }) }
    if (seg[0] === "answer" && M === "POST") { const b = await body(); const ch = String(b.ch || ""), id = String(b.q || ""); const o = await chapter(env, ch); if (!o) return J({ error: "Not found" }, 404);
      const p = pageOfQ(o, id); if (p < 0) return J({ error: "Not found" }, 404);
      const seen = await env.DB.prepare("SELECT 1 FROM book_log WHERE user_id=? AND kind='page' AND ch=? AND p=? AND at>?").bind(String(me.id), ch, p, now_() - 3 * 3600000).first(); if (!seen) return J({ error: "Open the question page first." }, 403);
      const lim = await limited(env, me, adm, "answer"); if (lim) return J({ error: lim, limit: true }, 429);
      const q = qOf(o.d, o.pages[p]); const g = await grade(env, String(me.id), q, id, b.resp); await log(env, req, me, null, "answer", ch, p, id);
      await env.DB.prepare("INSERT INTO book_ans (user_id,ch,q,score,max,at) VALUES (?,?,?,?,?,?) ON CONFLICT(user_id,ch,q) DO UPDATE SET score=excluded.score, max=excluded.max, at=excluded.at").bind(String(me.id), ch, id, g.score, g.max, now_()).run();
      return J({ score: g.score, max: g.max, fb: fbHTML(q, g, q.sources) }) }
    if (seg[0] === "progress" && M === "GET") { const R = (await env.DB.prepare("SELECT ch, COUNT(*) n, SUM(score) s, SUM(max) m FROM book_ans WHERE user_id=? GROUP BY ch").bind(String(me.id)).all()).results || []; return J({ chapters: R }) }
    if (seg[0] === "marks") {
      if (M === "GET") return J({ marks: (await env.DB.prepare("SELECT ch, p, label, created FROM book_marks WHERE user_id=? ORDER BY created DESC LIMIT 500").bind(String(me.id)).all()).results || [] });
      const b = M === "DELETE" ? { ch: url.searchParams.get("ch"), p: url.searchParams.get("p") } : await body(); const ch = String(b.ch || ""), p = parseInt(b.p, 10); if (!/^[a-z0-9-]{2,40}$/.test(ch) || !(p >= 0 && p < 5000)) return J({ error: "Bad request" }, 400);
      if (M === "DELETE") { await env.DB.prepare("DELETE FROM book_marks WHERE user_id=? AND ch=? AND p=?").bind(String(me.id), ch, p).run(); return J({ ok: true }) }
      if (M === "POST") { const n = await env.DB.prepare("SELECT COUNT(*) n FROM book_marks WHERE user_id=?").bind(String(me.id)).first(); if (n && n.n >= 500) return J({ error: "You have 500 bookmarks. Remove some first." }, 409);
        await env.DB.prepare("INSERT INTO book_marks (user_id,ch,p,label,created) VALUES (?,?,?,?,?) ON CONFLICT(user_id,ch,p) DO UPDATE SET label=excluded.label").bind(String(me.id), ch, p, cl(b.label, 120), now_()).run(); return J({ ok: true }) } }
    if (seg[0] === "hl") { const ch = M === "GET" ? String(url.searchParams.get("ch") || "") : "";
      if (M === "GET") { if (!/^[a-z0-9-]{2,40}$/.test(ch)) return J({ error: "Bad request" }, 400); const hl = {}; ((await env.DB.prepare("SELECT b, color FROM book_hl WHERE user_id=? AND ch=?").bind(String(me.id), ch).all()).results || []).forEach(r => hl[r.b] = r.color); return J({ hl }) }
      if (M === "POST") { const b = await body(); const c2 = String(b.ch || ""), k = String(b.b || ""); if (!/^[a-z0-9-]{2,40}$/.test(c2) || !/^[a-z0-9]{1,3}\.\d{1,4}$/.test(k)) return J({ error: "Bad request" }, 400);
        if (!b.color) { await env.DB.prepare("DELETE FROM book_hl WHERE user_id=? AND ch=? AND b=?").bind(String(me.id), c2, k).run(); return J({ ok: true }) }
        if (HLC.indexOf(b.color) < 0) return J({ error: "Bad color" }, 400); const n = await env.DB.prepare("SELECT COUNT(*) n FROM book_hl WHERE user_id=?").bind(String(me.id)).first(); if (n && n.n >= 3000) return J({ error: "You have 3,000 highlights. Remove some first." }, 409);
        await env.DB.prepare("INSERT INTO book_hl (user_id,ch,b,color,created) VALUES (?,?,?,?,?) ON CONFLICT(user_id,ch,b) DO UPDATE SET color=excluded.color").bind(String(me.id), c2, k, b.color, now_()).run(); return J({ ok: true }) } }

    /* ---------- admin ---------- */
    if (seg[0] === "admin") { if (!adm) return J({ error: "Admins only." }, 403);
      if (seg[1] === "reads" && !seg[2] && M === "GET") { const days = Math.max(1, Math.min(90, parseInt(url.searchParams.get("days") || "7", 10) || 7)); const since = now_() - days * 86400000;
        const R = (await env.DB.prepare("SELECT l.user_id, u.name, u.email, u.role, SUM(l.kind='page') pages, COUNT(DISTINCT CASE WHEN l.kind='page' THEN l.ch END) chapters, SUM(l.kind='search') searches, SUM(l.kind='answer') answers, SUM(l.kind='blocked') blocked, SUM(l.kind='denied') denied, MAX(l.at) last, COUNT(DISTINCT l.sid) sessions, COUNT(DISTINCT l.ip) ips FROM book_log l LEFT JOIN users u ON u.id=l.user_id WHERE l.at>? GROUP BY l.user_id ORDER BY pages DESC, last DESC LIMIT 500").bind(since).all()).results || [];
        const c = await cfg(env); return J({ days, limits: c, users: R.map(r => Object.assign(r, { flag: r.blocked > 0 || r.pages >= c.perDay * 0.8 * days || r.ips > 5 })) }) }
      if (seg[1] === "reads" && seg[2] && M === "GET") { const uid = decodeURIComponent(seg[2]).slice(0, 80); const u = await env.DB.prepare("SELECT id, name, email, role FROM users WHERE id=?").bind(uid).first();
        const L = (await env.DB.prepare("SELECT at, sid, kind, ch, p, q, ip FROM book_log WHERE user_id=? ORDER BY at DESC LIMIT 300").bind(uid).all()).results || []; return J({ user: u || { id: uid }, events: L }) }
      if (seg[1] === "cfg") { if (M === "GET") return J({ cfg: await cfg(env), defaults: CFG0 }); if (M === "PUT") { const b = await body(); const o = {}; for (const k of Object.keys(CFG0)) { if (b[k] == null) continue; if (typeof CFG0[k] === "boolean") o[k] = !!b[k]; else { const v = Math.round(+b[k]); if (v >= 1 && v <= 100000) o[k] = v } } await env.SITE.put("book:cfg", JSON.stringify(o)); CFG = null; return J({ ok: true, cfg: await cfg(env) }) } }
      if (seg[1] === "status" && M === "GET") { const T = await toc(env); return J({ version: T.version || "", units: (T.units || []).map(u => ({ n: u.n, title: u.title, chapters: (u.chapters || []).map(c => ({ id: c.id, title: c.title, status: c.status, n: c.n || 0, nq: c.nq || 0, at: c.at || null })) })) }) }
      if (seg[1] === "toc" && M === "PUT") { const b = await body(); const t = b.toc; if (!t || !Array.isArray(t.units)) return J({ error: "toc.units required" }, 400); const old = await toc(env); const R = {}; (old.units || []).forEach(u => (u.chapters || []).forEach(c => { if (c.status === "ready") R[c.id] = c }));
        t.units.forEach(u => u.chapters = (u.chapters || []).map(c => R[c.id] ? Object.assign({}, c, R[c.id], { title: c.title, num: c.num }) : Object.assign({}, c, { status: "planned" })));
        t.label = t.label || LABEL; await env.SITE.put("book:toc", JSON.stringify(t)); return J({ ok: true }) }
      if (seg[1] === "chapter" && M === "POST") { const b = await body(); const id = String(b.id || ""); if (!/^[a-z0-9-]{2,40}$/.test(id) || typeof b.gz !== "string" || b.gz.length > 8000000) return J({ error: "id and gz (base64 gzip) required" }, 400);
        let d; try { d = JSON.parse(await gunzip(ub64u(b.gz.replace(/\s+/g, "")).buffer)) } catch (e) { return J({ error: "Could not read the gzip JSON." }, 400) }
        if (d.id !== id) return J({ error: "id does not match the chapter JSON" }, 400); const E = check(d); if (E.length) return J({ error: "Chapter failed checks", errs: E }, 400);
        const gz = await gzip(JSON.stringify(d)); await env.SITE.put("book:ch:" + id, gz); CH.delete(id); const o = await chapter(env, id);
        const T = await toc(env); let hit = null; (T.units || []).forEach(u => (u.chapters || []).forEach(c => { if (c.id === id) hit = c })); if (!hit) { let u = (T.units || []).find(x => x.n === d.unit); if (!u) { u = { n: d.unit, title: d.unitTitle, chapters: [] }; T.units = (T.units || []).concat(u).sort((a, b) => a.n - b.n) } hit = { id }; u.chapters.push(hit); u.chapters.sort((a, b) => a.num - b.num) }
        Object.assign(hit, { num: d.num, title: d.title, status: "ready", n: o.pages.length, nq: (d.questions || []).length + (d.cases || []).reduce((a, c) => a + c.items.length, 0), qp: o.pages.findIndex(x => x.k === "qh"), sections: d.sections.map((s, si) => ({ t: s.title, p: o.pages.findIndex(x => x.k === "c" && x.s === si) })), at: now_() }); T.version = d.version || T.version || ""; T.label = T.label || LABEL;
        await env.SITE.put("book:toc", JSON.stringify(T)); if (typeof audit === "function") { try { await audit(env, req, me.id, "book_upload", id, d.title) } catch (e) { } } return J({ ok: true, id, pages: o.pages.length, bytes: gz.length }) }
      if (seg[1] === "chapter" && seg[2] && M === "DELETE") { const id = seg[2]; await env.SITE.delete("book:ch:" + id); CH.delete(id); const T = await toc(env); (T.units || []).forEach(u => (u.chapters || []).forEach(c => { if (c.id === id) { c.status = "planned"; delete c.sections; c.n = 0 } })); await env.SITE.put("book:toc", JSON.stringify(T)); return J({ ok: true }) }
    }
    return J({ error: "Not found" }, 404);
  }
  return { api, LABEL, _paginate: paginate, _render: renderPage, _text: pageText, _grade: grade, _views: views, _check: check, _fb: fbHTML, _tocEntry: null, CATN, TYPEN };
})();
