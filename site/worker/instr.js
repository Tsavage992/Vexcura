/* ---- v39 INSTR: Instructor My Chart workspace. Live activity digest (progress sync + clinical days + a small event feed),
   item-level feedback, flowsheet-style gradebook with audit log, LTI 1.3 AGS grade passback, LMS CSV exports. ----
   Inserted INSIDE MOD before `\nglobalThis.__BADGE = BADGE;` (see worker/INSTR-DEPLOY.md). Reads SCHL, CLIN, CLINDAY, CASES and LTI tables;
   creates its own instr_* tables and lti_ctx with CREATE TABLE IF NOT EXISTS. Uses LTI.v39 (token, platforms) after lti-v39.patch.js. */
const INSTR = (() => {
  const J = (o, s, h) => new Response(JSON.stringify(o), { status: s || 200, headers: Object.assign({ "Content-Type": "application/json", "Cache-Control": "no-store" }, h || {}) });
  const clip = (s, n) => String(s == null ? "" : s).slice(0, n);
  const now = () => Date.now();
  const rid = p => p + "_" + [...crypto.getRandomValues(new Uint8Array(8))].map(b => b.toString(16).padStart(2, "0")).join("");
  const qs = n => Array(n).fill("?").join(",");
  const pj = (s, d) => { try { const v = typeof s === "string" ? JSON.parse(s) : s; return v == null ? d : v } catch (e) { return d } };
  const num = v => { const n = typeof v === "number" ? v : parseFloat(String(v == null ? "" : v).replace(/[^0-9.\-]/g, "")); return isFinite(n) ? n : null };
  const AGS = { li: "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem", sc: "https://purl.imsglobal.org/spec/lti-ags/scope/score", liT: "application/vnd.ims.lis.v2.lineitem+json", licT: "application/vnd.ims.lis.v2.lineitemcontainer+json", scT: "application/vnd.ims.lis.v1.score+json" };
  const KINDS = ["score", "pct", "sui", "rubric", "avg", "hours", "status"];
  const CALC = ["avg", "hours", "status"];
  const SUI = { S: "Satisfactory", NI: "Needs improvement", U: "Unsatisfactory" };
  const FBK = ["flow", "mar", "note", "order", "lda", "care", "sdoh", "sbar", "drill", "exam", "exi", "quick", "practice", "tele", "ausc", "code", "rounds", "clinday", "lib", "prep", "eval", "case", "grade", "general"];
  /* identifiers that never belong in feedback about practice charts (same idea as CLINDAY's phi check) */
  const phi = s => /\b(MRN|SSN)\b|\b\d{3}-\d{2}-\d{4}\b|\b\d{1,2}\/\d{1,2}\/(19|20)\d{2}\b|\b\d{8,}\b/i.test(String(s || ""));
  let ready = false;
  async function init(env) {
    if (ready) return;
    const S = [
      /* existing tables this module reads (exact schemas from schl.js, clin.js, clinday.js, cases.js, lti.js) so a fresh database works in any order */
      "CREATE TABLE IF NOT EXISTS clin_groups (id TEXT PRIMARY KEY, school_id TEXT NOT NULL, instructor_id TEXT NOT NULL, name TEXT NOT NULL, course TEXT, archived INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS group_members (group_id TEXT NOT NULL, user_id TEXT NOT NULL, joined INTEGER NOT NULL, PRIMARY KEY (group_id, user_id))",
      "CREATE TABLE IF NOT EXISTS school_members (school_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', joined INTEGER NOT NULL, PRIMARY KEY (school_id, user_id))",
      "CREATE TABLE IF NOT EXISTS clinical_days (id TEXT PRIMARY KEY, school_id TEXT NOT NULL, group_id TEXT, date TEXT NOT NULL, start TEXT, end TEXT, site TEXT, unit TEXT, note TEXT, by_id TEXT, by_name TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS clinical_day_students (day_id TEXT NOT NULL, user_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT '', at INTEGER, how TEXT, note TEXT, by_id TEXT, added INTEGER NOT NULL, PRIMARY KEY (day_id, user_id))",
      "CREATE TABLE IF NOT EXISTS case_assign (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, school_id TEXT NOT NULL, src TEXT NOT NULL, case_id TEXT NOT NULL, title TEXT NOT NULL, note TEXT, rubric TEXT, by_id TEXT NOT NULL, created INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1)",
      "CREATE TABLE IF NOT EXISTS case_grades (aid TEXT NOT NULL, student_id TEXT NOT NULL, patient_id TEXT NOT NULL, score REAL, detail TEXT, comment TEXT, by_id TEXT, at INTEGER NOT NULL, released INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (aid, student_id))",
      "CREATE TABLE IF NOT EXISTS prep_posts (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, author_id TEXT NOT NULL, author_name TEXT, title TEXT NOT NULL, summary TEXT NOT NULL, due INTEGER, target TEXT, archived INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, updated INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS prep_subs (post_id TEXT NOT NULL, student_id TEXT NOT NULL, data TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', feedback TEXT, ready INTEGER, rev_by TEXT, rev_at INTEGER, updated INTEGER NOT NULL, PRIMARY KEY (post_id, student_id))",
      "CREATE TABLE IF NOT EXISTS clin_evals (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, student_id TEXT NOT NULL, week INTEGER NOT NULL, ratings TEXT NOT NULL, comments TEXT, goals TEXT, instr_id TEXT NOT NULL, instr_name TEXT, signed INTEGER, ack INTEGER, ack_comment TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS lti_users (platform_id TEXT NOT NULL, sub TEXT NOT NULL, user_id TEXT NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY (platform_id, sub))",
      "CREATE TABLE IF NOT EXISTS lti_links (platform_id TEXT NOT NULL, resource_link_id TEXT NOT NULL, context_id TEXT, assign_id TEXT, group_id TEXT, lineitem TEXT, lineitems TEXT, scope TEXT, updated INTEGER NOT NULL, PRIMARY KEY (platform_id, resource_link_id))",
      /* new */
      "CREATE TABLE IF NOT EXISTS lti_ctx (platform_id TEXT NOT NULL, context_id TEXT NOT NULL, user_id TEXT NOT NULL, title TEXT, lineitems TEXT, scope TEXT, teacher INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL, PRIMARY KEY (platform_id, context_id, user_id))",
      "CREATE TABLE IF NOT EXISTS instr_fb (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, student_id TEXT NOT NULL, author_id TEXT NOT NULL, author_name TEXT, kind TEXT NOT NULL, ref TEXT NOT NULL, pid TEXT, label TEXT, text TEXT NOT NULL, score REAL, max REAL, rubric TEXT, visible INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL, updated INTEGER NOT NULL, read_at INTEGER, deleted INTEGER NOT NULL DEFAULT 0)",
      "CREATE INDEX IF NOT EXISTS instr_fb_g ON instr_fb (group_id, updated)",
      "CREATE INDEX IF NOT EXISTS instr_fb_s ON instr_fb (student_id, updated)",
      "CREATE TABLE IF NOT EXISTS instr_rev (group_id TEXT NOT NULL, ref TEXT NOT NULL, by_id TEXT, at INTEGER NOT NULL, PRIMARY KEY (group_id, ref))",
      "CREATE TABLE IF NOT EXISTS instr_ev (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, k TEXT NOT NULL, ref TEXT, label TEXT, sc REAL, d TEXT, at INTEGER NOT NULL)",
      "CREATE INDEX IF NOT EXISTS instr_ev_u ON instr_ev (user_id, id)",
      "CREATE TABLE IF NOT EXISTS instr_cols (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, label TEXT NOT NULL, kind TEXT NOT NULL, max REAL, weight REAL, src TEXT, lms INTEGER NOT NULL DEFAULT 0, lineitem TEXT, ord INTEGER NOT NULL DEFAULT 0, due TEXT, rubric TEXT, archived INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, updated INTEGER NOT NULL)",
      "CREATE INDEX IF NOT EXISTS instr_cols_g ON instr_cols (group_id)",
      "CREATE TABLE IF NOT EXISTS instr_grades (group_id TEXT NOT NULL, col_id TEXT NOT NULL, student_id TEXT NOT NULL, val TEXT, score REAL, src TEXT, cm TEXT, by_id TEXT, at INTEGER NOT NULL, PRIMARY KEY (group_id, col_id, student_id))",
      "CREATE TABLE IF NOT EXISTS instr_sync (group_id TEXT NOT NULL, col_id TEXT NOT NULL, student_id TEXT NOT NULL, status TEXT NOT NULL, msg TEXT, score REAL, at INTEGER NOT NULL, PRIMARY KEY (group_id, col_id, student_id))",
      "CREATE TABLE IF NOT EXISTS instr_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT NOT NULL, col_id TEXT, student_id TEXT, old TEXT, new TEXT, src TEXT, what TEXT, by_id TEXT, by_name TEXT, at INTEGER NOT NULL)",
      "CREATE INDEX IF NOT EXISTS instr_audit_g ON instr_audit (group_id, id)",
      "CREATE TABLE IF NOT EXISTS instr_lms (group_id TEXT PRIMARY KEY, platform_id TEXT NOT NULL, context_id TEXT NOT NULL, lineitems TEXT, title TEXT, by_id TEXT, updated INTEGER NOT NULL)"];
    for (const q of S) await env.DB.prepare(q).run();
    ready = true;
  }
  async function who(req, env, ctx, url) { try { const r = await __W.fetch(new Request(url.origin + "/api/auth/me", { headers: { cookie: req.headers.get("cookie") || "" } }), env, ctx); return (await r.json()).user || null } catch (e) { return null } }
  const csrf = (req, url) => { if (["GET", "HEAD"].includes(req.method)) return true; const o = req.headers.get("Origin"); return req.headers.get("X-NCLEX") === "1" && (!o || o === url.origin) };
  const isSite = me => !!(me && me.role === "admin" && !me.mustReset);
  /* v40 re-auth: when SECM (worker/sec.js) is deployed, changing grades that were already filed and changing the LMS link need a
     fresh "confirm it's you" (sec_reauth, 10 minutes, same rule as SECM's SENS routes). The app's fetch wrapper prompts and retries. */
  async function reauthOK(env, req) {
    if (!globalThis.__SECM) return true; const m = (req.headers.get("Cookie") || "").match(/(?:^|;\s*)__Host-nsid=([^;]+)/); if (!m || m[1].length > 100) return false;
    const sid = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(m[1])))].map(b => b.toString(16).padStart(2, "0")).join("");
    try { const r = await env.DB.prepare("SELECT until FROM sec_reauth WHERE sid=?").bind(sid).first(); return !!(r && r.until > Date.now()) } catch (e) { return false }
  }
  const REAUTH = () => J({ error: "Please confirm it's you to continue.", code: "reauth" }, 401);

  /* ---------- access: same rule as SCHL.groupFor (group instructor, the school's program admins, site admins); members are students ---------- */
  async function access(env, me, gid) {
    const g = await env.DB.prepare("SELECT * FROM clin_groups WHERE id=?").bind(clip(gid, 40)).first(); if (!g) return { g: null, role: null };
    const uid = String(me.id);
    if (isSite(me) || String(g.instructor_id) === uid) return { g, role: "teach" };
    const m = await env.DB.prepare("SELECT role, status FROM school_members WHERE school_id=? AND user_id=?").bind(g.school_id, uid).first();
    if (m && m.status === "active" && m.role === "admin") return { g, role: "teach" };
    const gm = await env.DB.prepare("SELECT 1 x FROM group_members WHERE group_id=? AND user_id=?").bind(g.id, uid).first();
    if (gm) return { g, role: "student" };
    return { g, role: null };
  }
  const members = async (env, gid) => (await env.DB.prepare("SELECT gm.user_id id, gm.joined, u.name, u.email FROM group_members gm LEFT JOIN users u ON u.id=gm.user_id WHERE gm.group_id=? ORDER BY u.name").bind(gid).all()).results || [];
  async function audit(env, gid, me, o) {
    await env.DB.prepare("INSERT INTO instr_audit (group_id, col_id, student_id, old, new, src, what, by_id, by_name, at) VALUES (?,?,?,?,?,?,?,?,?,?)").bind(gid, o.col || null, o.uid || null, o.old == null ? null : clip(o.old, 200), o.nw == null ? null : clip(o.nw, 200), o.src || null, o.what || "grade", String(me.id), clip(me.name, 80), now()).run();
  }

  /* ---------- live digest: turns a student's synced progress keys into small events (no answer keys, no free text) ---------- */
  const K = { hist: "nclexsim.v1.history", sess: "nclexsim.v1.session", deter: "nclexsim.v1.deter", tele: "nclexsim.v1.tele", ausc: "nclexsim.v1.ausc", lib: "nclexsim.v1.library", days: "nclexsim.v1.days", qotd: "nclexsim.v1.qotd", wl: "nclexsim.v1.worklist", cu: "nclexsim.v1.currdone" };
  const MODEN = { cat: "Practice exam", quick: "Quick round", testday: "Test-day exam", topic: "Topic exam" };
  function digest(row) {
    const g = k => pj(row[k], null); const E = [];
    const H = g("h"); if (Array.isArray(H)) H.slice(0, 12).forEach(r => {
      if (!r || !r.id) return; const it = (r.items || []).filter(x => x && !x.pre); const pct = it.length ? Math.round(it.reduce((a, x) => a + (+x.s || 0), 0) / it.length * 100) : null;
      E.push({ k: r.mode === "quick" ? "quick" : "exam", ref: "exam:" + r.id, t: r.id, label: (MODEN[r.mode] || "Practice exam") + " · " + (r.n || it.length) + " items", sc: pct, d: { mode: r.mode, n: r.n, pred: r.pred != null ? Math.round(r.pred * 100) : null, outcome: r.outcome || null, used: r.used || 0, items: (r.items || []).slice(0, 160).map(x => ({ id: x.id, s: Math.round((+x.s || 0) * 100) / 100, pre: x.pre ? 1 : 0, r: x.resp == null ? null : clip(JSON.stringify(x.resp), 300) })) } }) });
    const S = g("s"); if (S && Array.isArray(S.items) && S.items.length) { const it = S.items.filter(x => !x.pre); E.push({ k: "live", ref: "sess:" + (S.start || S.id || "now"), t: row.updated, label: (MODEN[S.mode] || "Exam") + " in progress · " + S.items.length + " answered", sc: it.length ? Math.round(it.reduce((a, x) => a + (+x.s || 0), 0) / it.length * 100) : null, d: { mode: S.mode, n: S.items.length, last: S.items.slice(-5).map(x => ({ id: x.id, s: Math.round((+x.s || 0) * 100) / 100 })) } }) }
    const D = g("dt"); if (D && Array.isArray(D.hist)) D.hist.slice(-30).forEach(h => { if (h && h.t) E.push({ k: "drill", ref: "drill:" + h.c + ":" + h.t, t: h.t, label: "Deteriorating-patient drill · tier " + (h.tier || 1), sc: h.sc, d: { c: h.c, tier: h.tier, b: h.b || null, r1: h.r1, d: h.d } }) });
    const T = g("te"); if (T && Array.isArray(T.hist)) T.hist.slice(0, 30).forEach(h => { if (h && h.t) E.push({ k: "tele", ref: "tele:" + h.t, t: h.t, label: "Telemetry & EKG · " + (h.rid || "rhythm"), sc: h.sc, d: { rid: h.rid } }) });
    const A = g("au"); if (A && Array.isArray(A.hist)) A.hist.slice(0, 30).forEach(h => { if (h && h.t) E.push({ k: "ausc", ref: "ausc:" + h.t, t: h.t, label: "Assessment & Auscultation · " + (h.m === "p" ? "patient exam" : h.m === "c" ? "sound card" : "practice") + (h.cid ? " " + h.cid : h.f ? " " + h.f : ""), sc: h.sc != null ? h.sc : h.ok != null ? h.ok * 100 : null, d: { m: h.m, cid: h.cid || h.f || null } }) });
    const L = g("lb"); if (L && typeof L === "object") { const dn = L.d || {}, rd = L.r || {}; const ts = v => typeof v === "number" && v > 1e12 ? v : 0;
      Object.keys(dn).slice(-200).forEach(id => E.push({ k: "lib", ref: "lib:" + id, t: ts(dn[id]), label: "Library · finished " + clip(id, 60), sc: null, d: { id, done: 1 } }));
      Object.keys(rd).filter(id => !dn[id]).slice(-200).forEach(id => E.push({ k: "lib", ref: "lib:" + id, t: ts(rd[id]), label: "Library · opened " + clip(id, 60), sc: null, d: { id } })) }
    const Dy = g("dy"); if (Dy && typeof Dy === "object") Object.entries(Dy).slice(-20).forEach(([day, sc]) => E.push({ k: "practice", ref: "daily:" + day, t: Date.parse(day + "T12:00:00") || 0, label: "Daily rounds · " + day, sc: num(sc), d: null }));
    const W = g("wl"); if (Array.isArray(W)) W.filter(w => w && w.done).slice(-20).forEach(w => E.push({ k: "practice", ref: "wl:" + (w.id || w.t), t: +w.done || 0, label: "Worklist order done · " + clip(w.act || w.title || "", 60), sc: null, d: null }));
    return E.sort((a, b) => (b.t || 0) - (a.t || 0)).slice(0, 220);
  }
  async function progFor(env, ids, since) {
    const out = []; for (let i = 0; i < ids.length; i += 60) { const part = ids.slice(i, i + 60);
      const R = (await env.DB.prepare(`SELECT user_id, updated, json_extract(data,'$."${K.hist}"') h, json_extract(data,'$."${K.sess}"') s, json_extract(data,'$."${K.deter}"') dt, json_extract(data,'$."${K.tele}"') te, json_extract(data,'$."${K.ausc}"') au, json_extract(data,'$."${K.lib}"') lb, json_extract(data,'$."${K.days}"') dy, json_extract(data,'$."${K.wl}"') wl FROM progress WHERE user_id IN (${qs(part.length)}) AND updated>?`).bind(...part, since).all().catch(() => ({ results: [] }))).results || [];
      R.forEach(r => out.push({ uid: r.user_id, updated: r.updated, ev: digest(r) })) }
    return out;
  }
  const mins = s => { const m = /^(\d\d):(\d\d)$/.exec(s || ""); return m ? +m[1] * 60 + +m[2] : null };
  async function daysFor(env, g, ids) {
    if (!ids.length) return [];
    const R = (await env.DB.prepare(`SELECT ds.user_id, ds.status, ds.at, ds.how, d.id, d.date, d.start, d.end, d.site, d.unit, d.group_id FROM clinical_day_students ds JOIN clinical_days d ON d.id=ds.day_id WHERE d.school_id=? AND (d.group_id=? OR d.group_id IS NULL OR d.group_id='') AND ds.user_id IN (${qs(ids.length)}) ORDER BY d.date DESC LIMIT 2000`).bind(g.school_id, g.id, ...ids).all().catch(() => ({ results: [] }))).results || [];
    return R.map(r => { const a = mins(r.start), b = mins(r.end); const hrs = (r.status === "present" || r.status === "late") && a != null && b != null && b > a ? Math.round((b - a) / 6) / 10 : 0; return { uid: r.user_id, day: r.id, date: r.date, start: r.start || "", end: r.end || "", site: r.site || "", unit: r.unit || "", status: r.status || "", at: r.at || null, how: r.how || "", hrs } });
  }
  const pubFb = f => ({ id: f.id, uid: f.student_id, kind: f.kind, ref: f.ref, pid: f.pid || "", label: f.label || "", text: f.deleted ? "" : f.text, score: f.score, max: f.max, rubric: pj(f.rubric, null), visible: !!f.visible, author: f.author_name || "Instructor", created: f.created, updated: f.updated, read_at: f.read_at || null, deleted: !!f.deleted });

  /* ---------- gradebook ---------- */
  function cleanCol(b, prev) {
    prev = prev || {}; const kind = KINDS.indexOf(b.kind) >= 0 ? b.kind : (prev.kind || "score");
    const label = clip(b.label != null ? b.label : prev.label, 80).trim() || "Untitled";
    let max = num(b.max != null ? b.max : prev.max); if (kind === "pct") max = 100; if (kind === "sui" || CALC.indexOf(kind) >= 0) max = null; if ((kind === "score" || kind === "rubric") && !(max > 0)) max = 100;
    let weight = num(b.weight != null ? b.weight : prev.weight); if (!(weight >= 0)) weight = 0; weight = Math.min(1000, weight);
    const src = clip(b.src != null ? b.src : prev.src, 80).replace(/[^A-Za-z0-9_:|-]/g, "") || null;
    let rubric = b.rubric !== undefined ? b.rubric : pj(prev.rubric, null); if (kind !== "rubric") rubric = null;
    if (rubric) rubric = (Array.isArray(rubric) ? rubric : []).slice(0, 12).map(c => ({ k: clip(c.k || c.label, 40).replace(/[^A-Za-z0-9_-]/g, "") || "c", label: clip(c.label, 80), max: Math.max(0, Math.min(1000, num(c.max) || 0)) })).filter(c => c.max > 0);
    if (kind === "rubric" && rubric && rubric.length) max = rubric.reduce((a, c) => a + c.max, 0);
    return { label, kind, max, weight, src, lms: (b.lms != null ? !!b.lms : !!prev.lms) && kind !== "hours" && kind !== "status" ? 1 : 0, due: clip(b.due != null ? b.due : prev.due, 10).replace(/[^0-9-]/g, "") || null, ord: Math.round(num(b.ord != null ? b.ord : prev.ord) || 0), rubric };
  }
  /* validates one cell for its column; returns {ok, val, score, msg} */
  function cellVal(col, v) {
    if (v == null || String(v).trim() === "") return { ok: true, val: null, score: null };
    const s = String(v).trim();
    if (CALC.indexOf(col.kind) >= 0) return { ok: false, msg: "Calculated column" };
    if (col.kind === "sui") { const u = s.toUpperCase().replace(/[^A-Z]/g, ""); const k = u === "S" || /^SAT/.test(u) ? "S" : u === "U" || /^UNS/.test(u) ? "U" : u === "NI" || /^N/.test(u) ? "NI" : null; if (!k) return { ok: false, msg: "Use S, NI or U" }; return { ok: true, val: k, score: k === "S" ? 1 : k === "NI" ? 0.5 : 0 } }
    const n = num(s.replace(/%$/, "")); if (n == null) return { ok: false, msg: "Enter a number" };
    const mx = col.kind === "pct" ? 100 : col.max || 100; if (n < 0 || n > mx * 1.5) return { ok: false, msg: "0 to " + mx + (mx * 1.5 > mx ? " (up to " + mx * 1.5 + " with extra credit)" : "") };
    return { ok: true, val: String(Math.round(n * 100) / 100), score: Math.round(n * 100) / 100 };
  }
  const pctOf = (col, g) => { if (!g || g.score == null) return null; if (col.kind === "pct") return g.score; if (col.kind === "sui") return null; return col.max ? g.score / col.max * 100 : null };
  /* auto-fill values from app activity; returned as {colId: {uid: {val, score, why}}} */
  async function autoVals(env, g, cols, ids) {
    const out = {}; if (!ids.length) return out; const need = cols.filter(c => c.src); if (!need.length) return out;
    const prog = {}; if (need.some(c => /^(exam|quick|drill|tele|ausc|code|rounds)/.test(c.src))) (await progFor(env, ids, 0)).forEach(p => { prog[p.uid] = p.ev });
    const evs = {}; if (need.some(c => /^(code|rounds|practice)/.test(c.src))) ((await env.DB.prepare(`SELECT user_id, k, ref, sc, at FROM instr_ev WHERE user_id IN (${qs(ids.length)}) ORDER BY id DESC LIMIT 3000`).bind(...ids).all()).results || []).forEach(e => { (evs[e.user_id] = evs[e.user_id] || []).push(e) });
    let days = null;
    for (const c of need) {
      const o = out[c.id] = {}; const [kind, arg] = c.src.split(":");
      if (["exam", "quick", "drill", "tele", "ausc"].indexOf(kind) >= 0) ids.forEach(u => { const L = (prog[u] || []).filter(e => e.k === kind && e.sc != null && (!arg || arg === "best" || arg === "last" || (kind === "drill" && e.d && e.d.c === arg))); if (!L.length) return; const e = arg === "best" ? L.reduce((m, x) => x.sc > m.sc ? x : m, L[0]) : L[0]; const sc = c.kind === "pct" ? e.sc : c.kind === "sui" ? null : Math.round(e.sc / 100 * (c.max || 100) * 10) / 10; if (c.kind === "sui") { o[u] = { val: e.sc >= 77 ? "S" : e.sc >= 60 ? "NI" : "U", why: e.label + " · " + e.sc + "%" } } else o[u] = { val: String(sc), score: sc, why: e.label + " · " + e.sc + "%" } });
      else if (kind === "code" || kind === "rounds") ids.forEach(u => { const e = (evs[u] || []).find(x => x.k === kind && x.sc != null); if (!e) return; const sc = c.kind === "pct" ? e.sc : Math.round(e.sc / 100 * (c.max || 100) * 10) / 10; o[u] = c.kind === "sui" ? { val: e.sc >= 77 ? "S" : e.sc >= 60 ? "NI" : "U", why: kind + " " + e.sc + "%" } : { val: String(sc), score: sc, why: (kind === "code" ? "Megacode " : "Bedside rounds ") + e.sc + "%" } });
      else if (kind === "case" && arg) ((await env.DB.prepare("SELECT student_id, score FROM case_grades WHERE aid=? AND score IS NOT NULL").bind(arg).all()).results || []).forEach(r => { if (ids.indexOf(String(r.student_id)) < 0) return; const sc = c.kind === "pct" ? Math.round(r.score) : Math.round(r.score / 100 * (c.max || 100) * 10) / 10; o[r.student_id] = c.kind === "sui" ? { val: r.score >= 77 ? "S" : r.score >= 60 ? "NI" : "U", why: "Case grade " + Math.round(r.score) + "%" } : { val: String(sc), score: sc, why: "Case grade " + Math.round(r.score) + "%" } });
      else if (kind === "prep" && arg) ((await env.DB.prepare("SELECT student_id, status, ready FROM prep_subs WHERE post_id=?").bind(arg).all()).results || []).forEach(r => { if (r.status !== "reviewed") return; o[r.student_id] = { val: r.ready ? "S" : "NI", why: r.ready ? "Prep reviewed: ready" : "Prep reviewed: not ready" } });
      else if (kind === "eval" && arg) ((await env.DB.prepare("SELECT student_id, ratings, signed FROM clin_evals WHERE group_id=? AND week=?").bind(g.id, +arg || 0).all()).results || []).forEach(r => { if (!r.signed) return; const R = Object.values(pj(r.ratings, {})); const v = R.indexOf("U") >= 0 ? "U" : R.indexOf("NI") >= 0 ? "NI" : R.length ? "S" : null; if (v) o[r.student_id] = { val: v, why: "Week " + arg + " evaluation (signed)" } });
      else if (kind === "day" && arg) { days = days || await daysFor(env, g, ids); days.filter(d => d.day === arg).forEach(d => { if (!d.status) return; o[d.uid] = { val: d.status === "absent" ? "U" : d.status === "excused" ? null : "S", why: "Clinical day " + d.date + ": " + d.status } }) }
    }
    Object.values(out).forEach(o => Object.keys(o).forEach(u => { if (o[u].val == null) delete o[u] }));
    return out;
  }
  /* calculated columns, computed the same way in the app */
  function calcRow(cols, G, uid, hrs) {
    const by = c => G[c.id + "|" + uid]; const out = {};
    const num_ = cols.filter(c => (c.kind === "score" || c.kind === "pct" || c.kind === "rubric") && c.weight > 0);
    let w = 0, s = 0; num_.forEach(c => { const p = pctOf(c, by(c)); if (p == null) return; w += c.weight; s += p * c.weight });
    const sui = cols.filter(c => c.kind === "sui").map(c => (by(c) || {}).val).filter(Boolean);
    cols.forEach(c => { if (c.kind === "avg") out[c.id] = w ? { val: (Math.round(s / w * 10) / 10).toFixed(1), score: Math.round(s / w * 10) / 10 } : null; if (c.kind === "hours") out[c.id] = { val: String(hrs || 0), score: hrs || 0 }; if (c.kind === "status") out[c.id] = sui.length ? { val: sui.indexOf("U") >= 0 ? "U" : sui.indexOf("NI") >= 0 ? "NI" : "S" } : null });
    return out;
  }
  async function book(env, g, me) {
    const M = await members(env, g.id); const ids = M.map(m => String(m.id));
    const cols = ((await env.DB.prepare("SELECT * FROM instr_cols WHERE group_id=? AND archived=0 ORDER BY ord, created").bind(g.id).all()).results || []).map(c => Object.assign({}, c, { lms: !!c.lms, rubric: pj(c.rubric, null) }));
    const G = {}; ((await env.DB.prepare("SELECT * FROM instr_grades WHERE group_id=?").bind(g.id).all()).results || []).forEach(r => { G[r.col_id + "|" + r.student_id] = r });
    const SY = {}; ((await env.DB.prepare("SELECT * FROM instr_sync WHERE group_id=?").bind(g.id).all()).results || []).forEach(r => { SY[r.col_id + "|" + r.student_id] = { st: r.status, msg: r.msg || "", at: r.at } });
    const days = await daysFor(env, g, ids); const hrs = {}; days.forEach(d => { hrs[d.uid] = Math.round(((hrs[d.uid] || 0) + d.hrs) * 10) / 10 });
    const auto = await autoVals(env, g, cols, ids);
    const calc = {}; ids.forEach(u => { calc[u] = calcRow(cols, G, u, hrs[u]) });
    const lms = await env.DB.prepare("SELECT platform_id, context_id, title, updated FROM instr_lms WHERE group_id=?").bind(g.id).first();
    const linked = lms ? ((await env.DB.prepare("SELECT user_id FROM lti_users WHERE platform_id=?").bind(lms.platform_id).all()).results || []).map(r => String(r.user_id)).filter(u => ids.indexOf(u) >= 0) : [];
    const grades = {}; Object.entries(G).forEach(([k, r]) => { grades[k] = { val: r.val, score: r.score, src: r.src || "manual", cm: r.cm || "", at: r.at } });
    const au = ((await env.DB.prepare("SELECT col_id, student_id, old, new, src, what, by_name, at FROM instr_audit WHERE group_id=? ORDER BY id DESC LIMIT 60").bind(g.id).all()).results || []);
    return { ok: true, group: { id: g.id, name: g.name, course: g.course || "" }, students: M.map(m => ({ id: String(m.id), name: m.name || m.email || "Student", email: m.email || "" })), cols, grades, auto, calc, hours: hrs, sync: SY, lms: lms ? { platform_id: lms.platform_id, context_id: lms.context_id, title: lms.title || lms.context_id, linked } : null, audit: au };
  }
  async function fileCells(env, g, me, cells) {
    const cols = {}; ((await env.DB.prepare("SELECT * FROM instr_cols WHERE group_id=? AND archived=0").bind(g.id).all()).results || []).forEach(c => { cols[c.id] = c });
    const ids = new Set((await members(env, g.id)).map(m => String(m.id)));
    const lms = await env.DB.prepare("SELECT * FROM instr_lms WHERE group_id=?").bind(g.id).first();
    const bad = [], st = [], changed = [];
    for (const c of (Array.isArray(cells) ? cells : []).slice(0, 2000)) {
      const col = cols[clip(c.c, 40)], u = clip(c.u, 40); if (!col || !ids.has(u)) { bad.push({ c: c.c, u, msg: !col ? "Unknown column" : "Not in this group" }); continue }
      const v = cellVal(col, c.v); if (!v.ok) { bad.push({ c: col.id, u, msg: v.msg }); continue }
      const cm = clip(c.cm, 500); if (phi(cm)) { bad.push({ c: col.id, u, msg: "Remove patient identifiers from the comment" }); continue }
      const prev = await env.DB.prepare("SELECT val, cm FROM instr_grades WHERE group_id=? AND col_id=? AND student_id=?").bind(g.id, col.id, u).first();
      const src = c.src === "auto" ? "auto" : "manual";
      if (prev && (prev.val || null) === (v.val || null) && (prev.cm || "") === cm) continue;
      if (v.val == null && !cm) st.push(env.DB.prepare("DELETE FROM instr_grades WHERE group_id=? AND col_id=? AND student_id=?").bind(g.id, col.id, u));
      else st.push(env.DB.prepare("INSERT INTO instr_grades (group_id, col_id, student_id, val, score, src, cm, by_id, at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(group_id, col_id, student_id) DO UPDATE SET val=excluded.val, score=excluded.score, src=excluded.src, cm=excluded.cm, by_id=excluded.by_id, at=excluded.at").bind(g.id, col.id, u, v.val, v.score, src, cm, String(me.id), now()));
      st.push(env.DB.prepare("INSERT INTO instr_audit (group_id, col_id, student_id, old, new, src, what, by_id, by_name, at) VALUES (?,?,?,?,?,?,?,?,?,?)").bind(g.id, col.id, u, prev ? prev.val : null, v.val, src, (prev && (prev.val || null) === (v.val || null)) ? "comment" : "grade", String(me.id), clip(me.name, 80), now()));
      if (lms && col.lms && (prev ? (prev.val || null) !== (v.val || null) : v.val != null)) st.push(env.DB.prepare("INSERT INTO instr_sync (group_id, col_id, student_id, status, msg, score, at) VALUES (?,?,?,'pending','',?,?) ON CONFLICT(group_id, col_id, student_id) DO UPDATE SET status='pending', msg='', score=excluded.score, at=excluded.at").bind(g.id, col.id, u, v.score, now()));
      changed.push({ c: col.id, u, v: v.val });
    }
    for (let i = 0; i < st.length; i += 60) await env.DB.batch(st.slice(i, i + 60));
    return { bad, changed };
  }
  /* ---------- LTI AGS passback ---------- */
  const scoresUrl = li => li.replace(/\?.*$/, "") + "/scores" + (li.indexOf("?") >= 0 ? li.slice(li.indexOf("?")) : "");
  async function ensureLineitem(env, tk, link, col, gName) {
    if (col.lineitem) return col.lineitem;
    const [k, a] = String(col.src || "").split(":");
    if (k === "case" && a) { const l = await env.DB.prepare("SELECT lineitem FROM lti_links WHERE assign_id=? AND platform_id=? AND lineitem IS NOT NULL ORDER BY updated DESC").bind(a, link.platform_id).first(); if (l && l.lineitem) { await env.DB.prepare("UPDATE instr_cols SET lineitem=? WHERE id=?").bind(l.lineitem, col.id).run(); return l.lineitem } }
    if (!link.lineitems) throw new Error("The LMS course didn't share a gradebook address. Open Vexcura once from the course as the instructor.");
    const rid_ = "vx39_" + col.id; const base = link.lineitems;
    const sep = base.indexOf("?") >= 0 ? "&" : "?";
    const r0 = await fetch(base + sep + "resource_id=" + encodeURIComponent(rid_), { headers: { Authorization: "Bearer " + tk, Accept: AGS.licT } }).catch(() => null);
    if (r0 && r0.ok) { const L = await r0.json().catch(() => []); const hit = (Array.isArray(L) ? L : []).find(x => x && x.resourceId === rid_ && x.id); if (hit) { await env.DB.prepare("UPDATE instr_cols SET lineitem=? WHERE id=?").bind(hit.id, col.id).run(); return hit.id } }
    const mx = col.kind === "sui" ? 1 : col.kind === "pct" || col.kind === "avg" ? 100 : col.max || 100;
    const r = await fetch(base, { method: "POST", headers: { Authorization: "Bearer " + tk, "Content-Type": AGS.liT, Accept: AGS.liT }, body: JSON.stringify({ scoreMaximum: mx, label: clip("Vexcura: " + col.label, 120), resourceId: rid_, tag: "vexcura-" + col.kind }) }).catch(() => null);
    if (!r || !r.ok) throw new Error("The LMS didn't create the grade column" + (r ? " (" + r.status + ")" : "") + ".");
    const j = await r.json().catch(() => ({})); if (!j.id) throw new Error("The LMS didn't return the new grade column's address.");
    await env.DB.prepare("UPDATE instr_cols SET lineitem=? WHERE id=?").bind(j.id, col.id).run(); return j.id;
  }
  function scoreBody(col, grade, sub) {
    let given, mx, comment = "Vexcura: " + col.label;
    if (col.kind === "sui") { given = grade.val === "S" ? 1 : grade.val === "NI" ? 0.5 : 0; mx = 1; comment += " · " + (SUI[grade.val] || grade.val) }
    else if (col.kind === "pct") { given = +grade.score; mx = 100 }
    else if (col.kind === "avg") { given = +grade.score; mx = 100 }
    else { given = +grade.score; mx = col.max || 100 }
    if (grade.cm) comment += " · " + clip(grade.cm, 400);
    return { userId: sub, scoreGiven: given, scoreMaximum: mx, comment, timestamp: new Date().toISOString(), activityProgress: "Completed", gradingProgress: "FullyGraded" };
  }
  async function passback(env, g, opt) {
    opt = opt || {}; const link = await env.DB.prepare("SELECT * FROM instr_lms WHERE group_id=?").bind(g.id).first(); if (!link) return { linked: false, sent: 0, failed: 0, skipped: 0 };
    const LT = typeof LTI !== "undefined" ? LTI : globalThis.__LTI; if (!LT || !LT.v39) return { linked: true, sent: 0, failed: 0, skipped: 0, error: "LTI module is missing the v39 hooks (apply lti-v39.patch.js)." };
    const P = (await LT.v39.platforms(env)).find(x => x.id === link.platform_id); if (!P) return { linked: true, sent: 0, failed: 0, skipped: 0, error: "This LMS connection was removed." };
    const cols = ((await env.DB.prepare("SELECT * FROM instr_cols WHERE group_id=? AND archived=0 AND lms=1").bind(g.id).all()).results || []);
    const pend = ((await env.DB.prepare("SELECT * FROM instr_sync WHERE group_id=? AND status IN ('pending','error')").bind(g.id).all()).results || []).filter(r => !opt.only || opt.only.has(r.col_id + "|" + r.student_id));
    if (!pend.length) return { linked: true, sent: 0, failed: 0, skipped: 0 };
    const mark = (r, st, msg) => env.DB.prepare("UPDATE instr_sync SET status=?, msg=?, at=? WHERE group_id=? AND col_id=? AND student_id=?").bind(st, clip(msg, 200), now(), g.id, r.col_id, r.student_id).run();
    let tk; try { tk = await LT.v39.token(env, P, AGS.li + " " + AGS.sc) } catch (e) { for (const r of pend) await mark(r, "error", e.message || "No grade token"); return { linked: true, sent: 0, failed: pend.length, skipped: 0, error: e.message } }
    const subs = {}; ((await env.DB.prepare("SELECT sub, user_id FROM lti_users WHERE platform_id=?").bind(P.id).all()).results || []).forEach(r => { subs[String(r.user_id)] = r.sub });
    const G = {}; ((await env.DB.prepare("SELECT * FROM instr_grades WHERE group_id=?").bind(g.id).all()).results || []).forEach(r => { G[r.col_id + "|" + r.student_id] = r });
    let sent = 0, failed = 0, skipped = 0; const errs = [];
    for (const col of cols) {
      const L = pend.filter(r => r.col_id === col.id); if (!L.length) continue;
      let li; try { li = await ensureLineitem(env, tk, link, col, g.name) } catch (e) { for (const r of L) await mark(r, "error", e.message); failed += L.length; errs.push(e.message); continue }
      for (const r of L) {
        const sub = subs[String(r.student_id)]; if (!sub) { await mark(r, "error", "This student hasn't opened Vexcura from the LMS course yet, so the LMS doesn't know who they are."); skipped++; continue }
        const gr = G[col.id + "|" + r.student_id]; if (!gr || gr.val == null) { await mark(r, "synced", "Cleared in Vexcura (the LMS keeps its last score)"); continue }
        const res = await fetch(scoresUrl(li), { method: "POST", headers: { Authorization: "Bearer " + tk, "Content-Type": AGS.scT }, body: JSON.stringify(scoreBody(col, gr, sub)) }).catch(() => null);
        if (res && res.ok) { sent++; await mark(r, "synced", "") } else { failed++; const m = res ? "The LMS answered " + res.status : "Couldn't reach the LMS"; errs.push(m); await mark(r, "error", m) }
      }
    }
    return { linked: true, sent, failed, skipped, errors: [...new Set(errs)].slice(0, 3) };
  }
  /* average columns flagged for the LMS: queued on every file; values are computed at send time */
  async function queueAvg(env, g) {
    const link = await env.DB.prepare("SELECT 1 x FROM instr_lms WHERE group_id=?").bind(g.id).first(); if (!link) return;
    const A = ((await env.DB.prepare("SELECT id FROM instr_cols WHERE group_id=? AND archived=0 AND lms=1 AND kind='avg'").bind(g.id).all()).results || []); if (!A.length) return;
    const ids = (await members(env, g.id)).map(m => String(m.id)); const st = [];
    A.forEach(c => ids.forEach(u => st.push(env.DB.prepare("INSERT INTO instr_sync (group_id, col_id, student_id, status, msg, score, at) VALUES (?,?,?,'pending','',NULL,?) ON CONFLICT(group_id, col_id, student_id) DO UPDATE SET status='pending', at=excluded.at").bind(g.id, c.id, u, now()))));
    for (let i = 0; i < st.length; i += 60) await env.DB.batch(st.slice(i, i + 60));
  }
  async function passbackAll(env, g, opt) {
    /* calculated averages are materialized into instr_grades (src 'calc') right before sending */
    const b = await book(env, g); const A = b.cols.filter(c => c.kind === "avg" && c.lms); const st = [];
    A.forEach(c => b.students.forEach(s => { const v = (b.calc[s.id] || {})[c.id]; if (v) st.push(env.DB.prepare("INSERT INTO instr_grades (group_id, col_id, student_id, val, score, src, cm, by_id, at) VALUES (?,?,?,?,?,'calc','',NULL,?) ON CONFLICT(group_id, col_id, student_id) DO UPDATE SET val=excluded.val, score=excluded.score, src='calc', at=excluded.at").bind(g.id, c.id, s.id, v.val, v.score, now())) }));
    for (let i = 0; i < st.length; i += 60) await env.DB.batch(st.slice(i, i + 60));
    return passback(env, g, opt);
  }
  /* ---------- CSV exports (formats as each LMS documents its gradebook import; see INSTR-DEPLOY.md for the sources) ---------- */
  const csvQ = v => { const s = v == null ? "" : String(v); return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s };
  const csv = rows => "﻿" + rows.map(r => r.map(csvQ).join(",")).join("\r\n") + "\r\n";
  function split(n) { const p = String(n || "").trim().split(/\s+/); return { first: p.length > 1 ? p.slice(0, -1).join(" ") : p[0] || "", last: p.length > 1 ? p[p.length - 1] : "" } }
  function exportCSV(b, fmt) {
    const cols = b.cols; const S = b.students; const cell = (c, u) => { if (CALC.indexOf(c.kind) >= 0) { const v = (b.calc[u] || {})[c.id]; return v ? v.val : "" } const g = b.grades[c.id + "|" + u]; return g && g.val != null ? g.val : "" };
    const numC = cols.filter(c => c.kind !== "sui" && c.kind !== "status"), txtC = cols.filter(c => c.kind === "sui" || c.kind === "status");
    if (fmt === "canvas") { /* Canvas: Student, ID, SIS User ID, SIS Login ID, Section, then one column per assignment (points). Text grades aren't imported. */
      const rows = [["Student", "ID", "SIS User ID", "SIS Login ID", "Section"].concat(numC.map(c => c.label))];
      S.forEach(s => { const n = split(s.name); rows.push([(n.last ? n.last + ", " : "") + n.first, "", "", s.email, b.group.name].concat(numC.map(c => cell(c, s.id)))) }); return csv(rows) }
    if (fmt === "blackboard") { /* Blackboard: the header row needs a Username column; new columns come in as text columns */
      const rows = [["Last Name", "First Name", "Username"].concat(cols.map(c => c.label))];
      S.forEach(s => { const n = split(s.name); rows.push([n.last, n.first, s.email].concat(cols.map(c => cell(c, s.id)))) }); return csv(rows) }
    if (fmt === "moodle") { /* Moodle: identify users by Email address; map each column to a grade item during import; feedback columns are optional */
      const rows = [["Email address"].concat(cols.map(c => c.label), cols.filter(c => CALC.indexOf(c.kind) < 0).map(c => c.label + " Feedback"))];
      S.forEach(s => rows.push([s.email].concat(cols.map(c => cell(c, s.id)), cols.filter(c => CALC.indexOf(c.kind) < 0).map(c => { const g = b.grades[c.id + "|" + s.id]; return g ? g.cm || "" : "" })))); return csv(rows) }
    if (fmt === "d2l") { /* Brightspace: OrgDefinedId and/or Username, "<item> Points Grade" or "<item> Text Grade", last column End-of-Line Indicator = # ; no names or emails */
      const rows = [["OrgDefinedId", "Username"].concat(numC.filter(c => c.kind !== "avg" && c.kind !== "hours").map(c => c.label + " Points Grade"), txtC.filter(c => c.kind !== "status").map(c => c.label + " Text Grade"), ["End-of-Line Indicator"])];
      S.forEach(s => rows.push(["", s.email].concat(numC.filter(c => c.kind !== "avg" && c.kind !== "hours").map(c => cell(c, s.id)), txtC.filter(c => c.kind !== "status").map(c => cell(c, s.id)), ["#"]))); return csv(rows) }
    const rows = [["Student", "Email"].concat(cols.map(c => c.label + (c.kind === "score" || c.kind === "rubric" ? " (/" + c.max + ")" : c.kind === "pct" || c.kind === "avg" ? " (%)" : c.kind === "hours" ? " (h)" : "")))];
    S.forEach(s => rows.push([s.name, s.email].concat(cols.map(c => cell(c, s.id))))); return csv(rows);
  }

  /* ---------- LTI hook (called from LTI launch after lti-v39.patch.js): remembers which LMS course a user launched from ---------- */
  async function ltiSeen(env, o) {
    await init(env); const cx = o.ctx || {}; if (!cx.id) return;
    await env.DB.prepare("INSERT INTO lti_ctx (platform_id, context_id, user_id, title, lineitems, scope, teacher, updated) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(platform_id, context_id, user_id) DO UPDATE SET title=excluded.title, lineitems=COALESCE(excluded.lineitems, lti_ctx.lineitems), scope=COALESCE(excluded.scope, lti_ctx.scope), teacher=excluded.teacher, updated=excluded.updated").bind(o.pid, clip(cx.id, 255), String(o.uid), clip(cx.title || cx.label || cx.id, 200), clip((o.ags || {}).lineitems, 1000) || null, ((o.ags || {}).scope || []).join(" ") || null, o.teacher ? 1 : 0, now()).run();
    if ((o.ags || {}).lineitems) await env.DB.prepare("UPDATE instr_lms SET lineitems=?, updated=? WHERE platform_id=? AND context_id=?").bind(clip(o.ags.lineitems, 1000), now(), o.pid, clip(cx.id, 255)).run();
  }

  async function api(req, env, ctx, url) {
    const p = url.pathname; if (!csrf(req, url)) return J({ error: "Request blocked." }, 403);
    const me = await who(req, env, ctx, url); if (!me || me.mustReset) return J({ error: "Sign in first." }, 401);
    await init(env); const uid = String(me.id); let b = {};
    if (req.method !== "GET") { try { b = await req.json() } catch (e) { b = {} } }
    const seg = p.split("/").slice(3);
    /* ---- students: my feedback + my filed grades; event feed ---- */
    if (seg[0] === "my" && !seg[1] && req.method === "GET") {
      const fb = ((await env.DB.prepare("SELECT f.*, g.name gname FROM instr_fb f JOIN group_members m ON m.group_id=f.group_id AND m.user_id=f.student_id LEFT JOIN clin_groups g ON g.id=f.group_id WHERE f.student_id=? AND f.visible=1 AND f.deleted=0 ORDER BY f.updated DESC LIMIT 400").bind(uid).all()).results || []).map(f => Object.assign(pubFb(f), { group: f.gname || "" }));
      const gr = ((await env.DB.prepare("SELECT x.col_id, x.val, x.cm, x.at, c.label, c.kind, c.max, g.name gname, g.id gid FROM instr_grades x JOIN instr_cols c ON c.id=x.col_id AND c.archived=0 JOIN group_members m ON m.group_id=x.group_id AND m.user_id=x.student_id JOIN clin_groups g ON g.id=x.group_id WHERE x.student_id=? AND x.val IS NOT NULL ORDER BY x.at DESC LIMIT 300").bind(uid).all()).results || []).map(r => ({ col: r.col_id, label: r.label, kind: r.kind, max: r.max, val: r.val, cm: r.cm || "", at: r.at, group: r.gname, gid: r.gid }));
      return J({ ok: true, fb, grades: gr, n: fb.filter(f => !f.read_at).length });
    }
    if (seg[0] === "my" && seg[1] === "read" && req.method === "POST") { const ids = (Array.isArray(b.ids) ? b.ids : []).slice(0, 200).map(x => clip(x, 40)); if (ids.length) await env.DB.batch(ids.map(i => env.DB.prepare("UPDATE instr_fb SET read_at=? WHERE id=? AND student_id=? AND read_at IS NULL").bind(now(), i, uid))); return J({ ok: true }) }
    if (seg[0] === "ev" && req.method === "POST") {
      const inG = await env.DB.prepare("SELECT 1 x FROM group_members WHERE user_id=? LIMIT 1").bind(uid).first(); if (!inG) return J({ ok: true, stored: 0 });
      const L = (Array.isArray(b.ev) ? b.ev : []).slice(0, 25).filter(e => e && /^[a-z]{2,12}$/.test(String(e.k || ""))); const st = [];
      for (const e of L) { const d = e.d == null ? null : clip(JSON.stringify(e.d), 4000); const lab = clip(e.label, 160); if (phi(lab)) continue; st.push(env.DB.prepare("INSERT INTO instr_ev (user_id, k, ref, label, sc, d, at) VALUES (?,?,?,?,?,?,?)").bind(uid, e.k, clip(e.ref, 120), lab, num(e.sc), d, now())) }
      if (st.length) await env.DB.batch(st); return J({ ok: true, stored: st.length });
    }
    /* ---- instructor: groups I can teach ---- */
    if (seg[0] === "groups" && req.method === "GET") {
      let G;
      if (isSite(me)) G = (await env.DB.prepare("SELECT g.*, s.name school FROM clin_groups g LEFT JOIN schools s ON s.id=g.school_id ORDER BY g.archived, g.created DESC LIMIT 300").all()).results || [];
      else G = (await env.DB.prepare("SELECT g.*, s.name school FROM clin_groups g LEFT JOIN schools s ON s.id=g.school_id WHERE g.instructor_id=?1 OR g.school_id IN (SELECT school_id FROM school_members WHERE user_id=?1 AND status='active' AND role='admin') ORDER BY g.archived, g.created DESC LIMIT 300").bind(uid).all()).results || [];
      const N = {}; if (G.length) ((await env.DB.prepare(`SELECT group_id, COUNT(*) n FROM group_members WHERE group_id IN (${qs(G.length)}) GROUP BY group_id`).bind(...G.map(g => g.id)).all()).results || []).forEach(r => { N[r.group_id] = r.n });
      const LK = {}; if (G.length) ((await env.DB.prepare(`SELECT group_id, title FROM instr_lms WHERE group_id IN (${qs(G.length)})`).bind(...G.map(g => g.id)).all()).results || []).forEach(r => { LK[r.group_id] = r.title || "LMS" });
      return J({ ok: true, groups: G.map(g => ({ id: g.id, name: g.name, course: g.course || "", school_id: g.school_id, school: g.school || "", archived: !!g.archived, mine: String(g.instructor_id) === uid, n: N[g.id] || 0, lms: LK[g.id] || null })) });
    }
    if (seg[0] !== "g" || !/^g_[a-f0-9]{16}$/.test(seg[1] || "")) return J({ error: "Not found" }, 404);
    const A = await access(env, me, seg[1]); if (!A.g) return J({ error: "Group not found." }, 404);
    if (A.role !== "teach") return J({ error: "Only this group's instructor and program admins can see this." }, 403);
    const g = A.g, gid = g.id, what = seg[2] || "", M = req.method;
    /* live digest */
    if (what === "live" && M === "GET") {
      const ps = Math.max(0, +url.searchParams.get("p") || 0), fs_ = Math.max(0, +url.searchParams.get("f") || 0), es = Math.max(0, +url.searchParams.get("e") || 0), full = url.searchParams.get("days") === "1" || !ps;
      const mem = await members(env, gid); const ids = mem.map(m => String(m.id));
      const prog = ids.length ? await progFor(env, ids, ps) : [];
      const ev = ids.length ? ((await env.DB.prepare(`SELECT id, user_id uid, k, ref, label, sc, d, at FROM instr_ev WHERE user_id IN (${qs(ids.length)}) AND id>? ORDER BY id DESC LIMIT 300`).bind(...ids, es).all()).results || []).map(e => Object.assign(e, { d: pj(e.d, null) })) : [];
      const fb = ((await env.DB.prepare("SELECT * FROM instr_fb WHERE group_id=? AND updated>? ORDER BY updated LIMIT 500").bind(gid, fs_).all()).results || []).map(pubFb);
      const rev = fs_ ? [] : ((await env.DB.prepare("SELECT ref, at FROM instr_rev WHERE group_id=?").bind(gid).all()).results || []);
      const days = full ? await daysFor(env, g, ids) : null;
      const pcur = prog.reduce((m, x) => Math.max(m, x.updated || 0), ps), fcur = fb.reduce((m, x) => Math.max(m, x.updated || 0), fs_), ecur = ev.reduce((m, x) => Math.max(m, x.id || 0), es);
      return J({ ok: true, now: now(), members: mem.map(m => ({ id: String(m.id), name: m.name || m.email || "Student", email: m.email || "", joined: m.joined })), prog, ev, fb, rev, days, cur: { p: pcur, f: fcur, e: ecur } });
    }
    if (what === "days" && M === "GET") return J({ ok: true, days: await daysFor(env, g, (await members(env, gid)).map(m => String(m.id))) });
    /* feedback */
    if (what === "fb" && !seg[3] && M === "POST") {
      const su = clip(b.uid, 40); if (!(await env.DB.prepare("SELECT 1 x FROM group_members WHERE group_id=? AND user_id=?").bind(gid, su).first())) return J({ error: "That student isn't in this group." }, 404);
      const text = clip(b.text, 4000).trim(); const sc = num(b.score), mx = num(b.max);
      if (!text && sc == null) return J({ error: "Write a comment or give a score." }, 400);
      if (phi(text) || phi(b.label)) return J({ error: "Remove patient identifiers (MRN, birth dates, long ID numbers) first." }, 400);
      const kind = FBK.indexOf(b.kind) >= 0 ? b.kind : "general"; const ref = clip(b.ref, 160) || "gen";
      if (sc != null && (sc < 0 || (mx != null && sc > mx * 1.5))) return J({ error: "The score is out of range." }, 400);
      const rub = Array.isArray(b.rubric) ? JSON.stringify(b.rubric.slice(0, 12).map(r => ({ k: clip(r.k, 40), label: clip(r.label, 80), v: num(r.v), max: num(r.max) }))) : null;
      const id = rid("fb"), t = now();
      await env.DB.prepare("INSERT INTO instr_fb (id, group_id, student_id, author_id, author_name, kind, ref, pid, label, text, score, max, rubric, visible, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(id, gid, su, uid, clip(me.name, 80), kind, ref, clip(b.pid, 48), clip(b.label, 200), text || "", sc, mx, rub, b.visible === false ? 0 : 1, t, t).run();
      await env.DB.prepare("INSERT INTO instr_rev (group_id, ref, by_id, at) VALUES (?,?,?,?) ON CONFLICT(group_id, ref) DO UPDATE SET by_id=excluded.by_id, at=excluded.at").bind(gid, su + "|" + ref, uid, t).run();
      return J({ ok: true, item: pubFb(await env.DB.prepare("SELECT * FROM instr_fb WHERE id=?").bind(id).first()) });
    }
    if (what === "fb" && seg[3]) {
      const f = await env.DB.prepare("SELECT * FROM instr_fb WHERE id=? AND group_id=?").bind(clip(seg[3], 40), gid).first(); if (!f) return J({ error: "Feedback not found." }, 404);
      if (M === "DELETE") { await env.DB.prepare("UPDATE instr_fb SET deleted=1, updated=? WHERE id=?").bind(now(), f.id).run(); return J({ ok: true }) }
      if (M === "PUT") { const text = b.text != null ? clip(b.text, 4000).trim() : f.text; if (phi(text)) return J({ error: "Remove patient identifiers first." }, 400); const sc = b.score !== undefined ? num(b.score) : f.score;
        await env.DB.prepare("UPDATE instr_fb SET text=?, score=?, visible=?, updated=? WHERE id=?").bind(text, sc, b.visible === undefined ? f.visible : (b.visible ? 1 : 0), now(), f.id).run();
        return J({ ok: true, item: pubFb(await env.DB.prepare("SELECT * FROM instr_fb WHERE id=?").bind(f.id).first()) }) }
    }
    if (what === "reviewed" && M === "POST") {
      const refs = (Array.isArray(b.refs) ? b.refs : []).slice(0, 300).map(r => clip(r, 200)).filter(Boolean); const t = now();
      if (refs.length) await env.DB.batch(refs.map(r => b.on === false ? env.DB.prepare("DELETE FROM instr_rev WHERE group_id=? AND ref=?").bind(gid, r) : env.DB.prepare("INSERT INTO instr_rev (group_id, ref, by_id, at) VALUES (?,?,?,?) ON CONFLICT(group_id, ref) DO UPDATE SET at=excluded.at").bind(gid, r, uid, t)));
      return J({ ok: true, n: refs.length });
    }
    /* gradebook */
    if (what === "gb" && !seg[3] && M === "GET") return J(await book(env, g, me));
    if (what === "gb" && seg[3] === "cols" && M === "POST") {
      const L = (Array.isArray(b.cols) ? b.cols : [b]).slice(0, 40); const made = []; const cnt = ((await env.DB.prepare("SELECT COUNT(*) n FROM instr_cols WHERE group_id=? AND archived=0").bind(gid).first()) || {}).n || 0;
      if (cnt + L.length > 120) return J({ error: "A gradebook can have up to 120 columns." }, 400);
      for (const x of L) { const c = cleanCol(x); const id = rid("gc"); await env.DB.prepare("INSERT INTO instr_cols (id, group_id, label, kind, max, weight, src, lms, ord, due, rubric, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(id, gid, c.label, c.kind, c.max, c.weight, c.src, c.lms, c.ord || cnt + made.length + 1, c.due, c.rubric ? JSON.stringify(c.rubric) : null, now(), now()).run(); made.push(id); await audit(env, gid, me, { col: id, what: "column", nw: c.label + " (" + c.kind + ")" }) }
      return J(Object.assign(await book(env, g, me), { made }));
    }
    if (what === "gb" && seg[3] === "cols" && seg[4]) {
      const prev = await env.DB.prepare("SELECT * FROM instr_cols WHERE id=? AND group_id=?").bind(clip(seg[4], 40), gid).first(); if (!prev) return J({ error: "Column not found." }, 404);
      if (M === "DELETE") { await env.DB.prepare("UPDATE instr_cols SET archived=1, updated=? WHERE id=?").bind(now(), prev.id).run(); await audit(env, gid, me, { col: prev.id, what: "column removed", old: prev.label }); return J(await book(env, g, me)) }
      if (M === "PUT") { const c = cleanCol(b, prev); if (c.kind !== prev.kind && (await env.DB.prepare("SELECT 1 x FROM instr_grades WHERE col_id=? LIMIT 1").bind(prev.id).first())) return J({ error: "This column has grades. Make a new column to change its type." }, 409);
        await env.DB.prepare("UPDATE instr_cols SET label=?, kind=?, max=?, weight=?, src=?, lms=?, ord=?, due=?, rubric=?, lineitem=CASE WHEN ?=1 THEN lineitem ELSE NULL END, updated=? WHERE id=?").bind(c.label, c.kind, c.max, c.weight, c.src, c.lms, c.ord, c.due, c.rubric ? JSON.stringify(c.rubric) : null, (prev.max === c.max && prev.label === c.label) ? 1 : 0, now(), prev.id).run();
        await audit(env, gid, me, { col: prev.id, what: "column edited", old: prev.label + " /" + (prev.max || "") + " w" + (prev.weight || 0), nw: c.label + " /" + (c.max || "") + " w" + c.weight }); return J(await book(env, g, me)) }
    }
    if (what === "gb" && seg[3] === "file" && M === "POST") {
      { const L = (Array.isArray(b.cells) ? b.cells : []).slice(0, 2000); let over = false;
        for (let i = 0; i < L.length && !over; i += 80) { const part = L.slice(i, i + 80).filter(c => c && c.c && c.u); if (!part.length) continue;
          const R = (await env.DB.prepare(`SELECT col_id, student_id, val FROM instr_grades WHERE group_id=? AND val IS NOT NULL AND (${part.map(() => "(col_id=? AND student_id=?)").join(" OR ")})`).bind(gid, ...part.flatMap(c => [clip(c.c, 40), clip(c.u, 40)])).all()).results || [];
          over = R.some(r => { const c = part.find(x => clip(x.c, 40) === r.col_id && clip(x.u, 40) === String(r.student_id)); if (!c) return false; const nv = String(c.v == null ? "" : c.v).trim().replace(/%$/, ""); const ov = String(r.val); return !(nv.toUpperCase() === ov.toUpperCase() || (nv !== "" && isFinite(+nv) && isFinite(+ov) && +nv === +ov)) }) }
        if (over && !(await reauthOK(env, req))) return REAUTH() }
      const r = await fileCells(env, g, me, b.cells); await queueAvg(env, g);
      const pb = await passbackAll(env, g); return J(Object.assign(await book(env, g, me), { filed: r.changed.length, bad: r.bad, passback: pb }));
    }
    if (what === "gb" && seg[3] === "sync" && M === "POST") { await queueAvg(env, g); const pb = await passbackAll(env, g); return J(Object.assign(await book(env, g, me), { passback: pb })) }
    if (what === "gb" && seg[3] === "export" && M === "GET") {
      const fmt = ["canvas", "blackboard", "moodle", "d2l", "generic"].indexOf(url.searchParams.get("fmt")) >= 0 ? url.searchParams.get("fmt") : "generic";
      const bk = await book(env, g, me); await audit(env, gid, me, { what: "export " + fmt });
      const name = ("Vexcura-" + g.name + "-" + fmt).replace(/[^A-Za-z0-9-]+/g, "-") + ".csv";
      return new Response(exportCSV(bk, fmt), { headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": 'attachment; filename="' + name + '"', "Cache-Control": "no-store" } });
    }
    if (what === "gb" && seg[3] === "audit" && M === "GET") { const su = clip(url.searchParams.get("uid"), 40); const R = ((await env.DB.prepare("SELECT col_id, student_id, old, new, src, what, by_name, at FROM instr_audit WHERE group_id=? " + (su ? "AND student_id=? " : "") + "ORDER BY id DESC LIMIT 300").bind(...(su ? [gid, su] : [gid])).all()).results || []); return J({ ok: true, audit: R }) }
    /* LMS link for this group */
    if (what === "lms") {
      if (M === "GET") { const cur = await env.DB.prepare("SELECT platform_id, context_id, title, updated FROM instr_lms WHERE group_id=?").bind(gid).first();
        const opts = ((await env.DB.prepare("SELECT platform_id, context_id, title, lineitems IS NOT NULL ags, updated FROM lti_ctx WHERE user_id=? AND teacher=1 ORDER BY updated DESC LIMIT 40").bind(uid).all()).results || []);
        const LT = typeof LTI !== "undefined" ? LTI : globalThis.__LTI; let P = []; try { P = LT && LT.v39 ? await LT.v39.platforms(env) : [] } catch (e) { }
        return J({ ok: true, current: cur || null, options: opts.map(o => ({ platform_id: o.platform_id, context_id: o.context_id, title: o.title || o.context_id, ags: !!o.ags, lms: (P.find(x => x.id === o.platform_id) || {}).name || "LMS" })) }) }
      if (M === "DELETE" && !(await reauthOK(env, req))) return REAUTH();
      if (M === "PUT") { const o = await env.DB.prepare("SELECT * FROM lti_ctx WHERE platform_id=? AND context_id=? AND user_id=? AND teacher=1").bind(clip(b.platform_id, 40), clip(b.context_id, 255), uid).first();
        if (!o) return J({ error: "Open Vexcura from that LMS course as its instructor first, then link it here." }, 403);
        if (!(await reauthOK(env, req))) return REAUTH();
        await env.DB.prepare("INSERT INTO instr_lms (group_id, platform_id, context_id, lineitems, title, by_id, updated) VALUES (?,?,?,?,?,?,?) ON CONFLICT(group_id) DO UPDATE SET platform_id=excluded.platform_id, context_id=excluded.context_id, lineitems=excluded.lineitems, title=excluded.title, by_id=excluded.by_id, updated=excluded.updated").bind(gid, o.platform_id, o.context_id, o.lineitems, o.title, uid, now()).run();
        await env.DB.prepare("UPDATE instr_cols SET lineitem=NULL WHERE group_id=?").bind(gid).run(); await audit(env, gid, me, { what: "lms link", nw: o.title || o.context_id });
        /* everything already filed for LMS columns is queued for the newly linked course */
        const G = (await env.DB.prepare("SELECT x.col_id, x.student_id, x.score FROM instr_grades x JOIN instr_cols c ON c.id=x.col_id WHERE x.group_id=? AND c.lms=1 AND c.archived=0 AND x.val IS NOT NULL").bind(gid).all()).results || [];
        const st = G.map(x => env.DB.prepare("INSERT INTO instr_sync (group_id, col_id, student_id, status, msg, score, at) VALUES (?,?,?,'pending','',?,?) ON CONFLICT(group_id, col_id, student_id) DO UPDATE SET status='pending', msg='', at=excluded.at").bind(gid, x.col_id, x.student_id, x.score, now()));
        for (let i = 0; i < st.length; i += 60) await env.DB.batch(st.slice(i, i + 60));
        return J({ ok: true, queued: st.length }) }
      if (M === "DELETE") { await env.DB.prepare("DELETE FROM instr_lms WHERE group_id=?").bind(gid).run(); await env.DB.prepare("DELETE FROM instr_sync WHERE group_id=?").bind(gid).run(); await audit(env, gid, me, { what: "lms unlink" }); return J({ ok: true }) }
    }
    return J({ error: "Not found" }, 404);
  }
  return { api, ltiSeen, _t: { digest, cellVal, cleanCol, calcRow, exportCSV, scoreBody, scoresUrl } };
})();
