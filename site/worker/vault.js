/* ---- v41 Compliance vault (VAULT): /api/vault/*  ----
   A school's clinical and program compliance records: clinical site records (affiliation agreement, COI, contacts, onboarding,
   orientation, renewal terms), student and faculty requirement tracking with per-site checklists and a clearance grid, preceptor,
   board, accreditation, institutional and policy documents. See vault/RESEARCH.md for what each item is based on.

   Security model (server-enforced; the app only hides entry points):
   - Roles per school: admin (school admin / dean) full; coord (clinical coordinator: sites, students, preceptors, clearance);
     instructor (clearance status only, only for students in their own clinical groups); student (own items only);
     site (Vexcura site admin, users.role='admin', not a member): metadata only, never file contents, unless the school grants
     support access with an expiry. Restricted types (Title IX, accommodations, exposure, faculty health) are school-admin only.
   - Files: AES-256-GCM. Each file has its own random data key, wrapped by the school's key; the school key is wrapped by a key
     derived (HKDF-SHA-256) from the worker secret VAULT_MASTER (VAULT_MASTER_PREV is accepted for rotation). Ciphertext only in R2
     (binding VAULT). Never in KV or D1. Secure deletion destroys the wrapped data key and deletes the object.
   - Downloads: POST .../link returns a 60-second, single-use, user-bound HMAC URL; GET /api/vault/file/<token> re-checks the
     session, the role and the nonce, decrypts, stamps a watermark on PDFs, and answers as an attachment with nosniff and a sandbox CSP.
   - Uploads: PDF, JPEG, PNG, HEIC only; at most 15 MB; magic bytes must match the declared type and the extension; PDFs with
     JavaScript, launch actions, embedded files, RichMedia or XFA are refused.
   - Data minimization: immunization/TB proof and background/drug-screen documents are not stored unless the school admin turns
     storage on for that class (with a warning); the default is status, dates, verifier and attestation only.
   - Audit: vault_audit is append-only (UPDATE/DELETE triggers abort) and hash-chained per school. Every view, download and change
     is logged. GET .../audit/verify recomputes the chain.
   Uses from the host worker: current(env, req), audit(env, req, actor, action, target, detail), now(). D1 (env.DB), R2 (env.VAULT,
   optional), secrets VAULT_MASTER (+ optional VAULT_MASTER_PREV). See worker/VAULT-DEPLOY.md. Not legal advice. */
const VAULT = (() => {
  const VER = "vault/1";
  const J = (o, s, h) => new Response(JSON.stringify(o), { status: s || 200, headers: Object.assign({ "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }, h || {}) });
  const cl = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").slice(0, n).trim();
  const hexId = n => [...crypto.getRandomValues(new Uint8Array(n))].map(b => b.toString(16).padStart(2, "0")).join("");
  const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s || "") && !isNaN(Date.parse(s + "T00:00:00Z"));
  const dOr = s => isDate(s) ? s : "";
  const int = (v, lo, hi, d) => { const n = parseInt(v, 10); return isFinite(n) ? Math.max(lo, Math.min(hi, n)) : d };
  const pj = (s, d) => { try { const v = s ? JSON.parse(s) : null; return v == null ? d : v } catch (e) { return d } };
  const qs = n => Array(n).fill("?").join(",");
  const te = new TextEncoder(), td = new TextDecoder();
  const b64 = u => { let s = ""; const a = u instanceof Uint8Array ? u : new Uint8Array(u); for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000)); return btoa(s) };
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const b64u = u => b64(u).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const unb64u = s => unb64(String(s).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(s).length + 3) % 4));
  const hex = u => [...new Uint8Array(u)].map(b => b.toString(16).padStart(2, "0")).join("");
  const sha = async s => hex(await crypto.subtle.digest("SHA-256", typeof s === "string" ? te.encode(s) : s));
  const isSite = me => !!(me && me.role === "admin" && !me.mustReset && !me.must_reset);
  const DAY = 864e5;
  const todayUTC = () => new Date(now()).toISOString().slice(0, 10);
  const addDays = (d, n) => new Date(Date.parse(d + "T00:00:00Z") + n * DAY).toISOString().slice(0, 10);
  const addMonths = (d, n) => { const t = new Date(d + "T00:00:00Z"); const day = t.getUTCDate(); t.setUTCDate(1); t.setUTCMonth(t.getUTCMonth() + n); const last = new Date(Date.UTC(t.getUTCFullYear(), t.getUTCMonth() + 1, 0)).getUTCDate(); t.setUTCDate(Math.min(day, last)); return t.toISOString().slice(0, 10) };
  const daysBetween = (a, b) => Math.round((Date.parse(b + "T00:00:00Z") - Date.parse(a + "T00:00:00Z")) / DAY);
  const MAXB = 15 * 1024 * 1024, LINK_TTL = 60000, LINK_BURST = 60;
  const STORE_MSG = "File storage turns on when your administrator enables secure storage.";
  const AUDIT_RETENTION = "Kept at least 6 years (rows can't be changed or deleted).";
  const PHI_NOTICE = "Don't upload protected health information (PHI). Student health documents kept by a school are generally FERPA education records, not HIPAA PHI (HHS/ED Joint Guidance, 2019), but patient information from a clinical site is the facility's PHI and must never be uploaded here. Recording status, dates and who verified is the safer choice for immunizations, background checks and drug screens.";
  /* v40 security module (worker/sec.js) hooks, used when present: __SEC.hipaaMode(env, sid) and __SEC.phiScan(text) and __SEC.requestBAA(env, req, me, info) */
  const SECM = () => (typeof globalThis !== "undefined" && globalThis.__SEC) || null;
  async function hipaaOn(env, sid) { const S = SECM(); try { if (S && typeof S.hipaaMode === "function") return !!(await S.hipaaMode(env, sid)) } catch (e) { } return false }
  const PHI_RE = /\b(MRN|medical record (no|number)|DOB|date of birth|SSN)\b|\b\d{3}-\d{2}-\d{4}\b/i;
  function phiHit(t) { const S = SECM(); try { if (S && typeof S.phiScan === "function") { const r = S.phiScan(String(t || "")); if (r && (r === true || r.hit || (Array.isArray(r) && r.length))) return true } } catch (e) { } return PHI_RE.test(String(t || "")) }

  /* ---------- catalog (see vault/RESEARCH.md; tags: law | board | accred | guidance | practice | facility) ---------- */
  const CATS = { site: "Clinical sites", student: "Students", faculty: "Faculty", preceptor: "Preceptors", board: "Board and state", accred: "Accreditation", inst: "Institutional", policy: "Policies" };
  const T = (label, o) => Object.assign({ label }, o || {});
  const TYPES = {
    site: { agreement: T("Clinical affiliation agreement", { core: 1, basis: "board", cite: "GA 410-8-.10(7),(10); GA 410-9-.10(2); TN 1000-01-.11(1)(b)1.(iii); ACEN 4.9(a); CCNE Std II; CNEA V-E" }), coi: T("Certificate of insurance", { core: 1, basis: "facility" }), amend: T("Amendment or addendum"), onboard: T("Onboarding packet", { basis: "facility" }), orient: T("Orientation materials", { basis: "facility" }), approval: T("Board approval of clinical affiliate", { basis: "board", cite: "GA 410-9-.10(2)(a) (PN)" }), contacts: T("Contact sheet"), other: T("Other site document") },
    student: { handbook_ack: T("Handbook acknowledgment", { basis: "practice" }), ferpa_release: T("FERPA release to clinical sites", { basis: "law", cite: "34 CFR Part 99" }), confid: T("Confidentiality agreement", { basis: "facility" }), eval: T("Clinical evaluation", { basis: "accred" }), incident: T("Incident or near-miss report", { basis: "board", cite: "AL 610-X-3-.02(9)(d)" }), exposure: T("Exposure report", { restricted: 1, health: 1 }), accom: T("Accommodation record (ADA/504)", { restricted: 1, cite: "34 CFR 104.44" }), titleix: T("Title IX record", { restricted: 1, cite: "34 CFR Part 106" }), other: T("Other student document") },
    faculty: { license_ver: T("License verification (Nursys)", { basis: "board" }), cv: T("CV or resume"), transcript: T("Transcript or degree"), fqr: T("Faculty qualification record", { basis: "board", cite: "GA 410-9-.07(2) (PN, within 1 month of hire)" }), orient_prog: T("Program orientation"), orient_site: T("Clinical site orientation", { basis: "facility" }), competency: T("Clinical competency or recent practice", { basis: "board" }), eval: T("Annual evaluation"), job: T("Job description or contract"), health: T("Faculty health record (kept separate)", { restricted: 1, health: 1, cite: "29 CFR 1630.14(c)(1)" }), other: T("Other faculty document") },
    preceptor: { agreement: T("Preceptor agreement", { basis: "practice" }), license: T("License verification", { basis: "board", cite: "TN 1000-01-.11(6)(b) (Nursys e-Notify)" }), cv: T("CV or qualifications", { basis: "accred", cite: "CCNE II-G; CNEA III-B" }), orient: T("Preceptor orientation", { basis: "accred" }), eval: T("Preceptor evaluation", { basis: "accred" }), other: T("Other preceptor document") },
    board: { approval: T("Board approval letter", { core: 1, basis: "board" }), annual: T("Annual report (as submitted)", { core: 1, basis: "board" }), visit: T("Site visit report and response", { basis: "board" }), change: T("Substantive change approval", { basis: "board" }), plan: T("NCLEX or improvement action plan", { basis: "board" }), corr: T("Board correspondence"), other: T("Other board document") },
    accred: { decision: T("Accreditation decision letter", { core: 1, basis: "accred", na: 1 }), selfstudy: T("Self-study"), visit: T("Site visit report"), report: T("Interim or annual report", { basis: "accred" }), change: T("Substantive change notice"), corr: T("Accreditor correspondence", { cite: "AL 610-X-3-.03(7)(b)1 (copies to the Board)" }), other: T("Other accreditation document") },
    inst: { auth: T("State authorization (GNPEC, THEC, ACCS/ACHE or system approval)", { core: 1, basis: "law" }), accred: T("Institutional accreditation letter", { core: 1, basis: "law" }), sara: T("SARA approval or renewal", { core: 1, na: 1, basis: "practice" }), licdisc: T("Professional licensure disclosure (668.43)", { core: 1, na: 1, basis: "law", cite: "34 CFR 668.43; 668.14(b)(32)" }), ppa: T("Program Participation Agreement (Title IV)", { na: 1 }), other: T("Other institutional document") },
    policy: { handbook: T("Student handbook", { core: 1, basis: "board", cite: "AL 610-X-3-.02(9); GA 410-8-.07" }), attendance: T("Attendance and clinical absence policy", { core: 1, basis: "practice" }), evaltool: T("Clinical evaluation tools", { core: 1, basis: "accred", cite: "CCNE III-H; ACEN 4.10" }), incident: T("Incident and exposure procedure", { core: 1, basis: "board" }), titleix: T("Title IX policy and training materials (keep 7 years)", { core: 1, basis: "law", cite: "34 CFR 106.45(b)(10)" }), ada: T("Disability accommodation policy", { core: 1, basis: "law" }), ferpa: T("FERPA annual notice and directory-information policy", { core: 1, basis: "law", cite: "34 CFR 99.7, 99.37" }), dfsca: T("Drug and alcohol prevention program and biennial review", { core: 1, na: 1, basis: "law", cite: "34 CFR Part 86" }), clery: T("Annual Security Report (Clery)", { na: 1, basis: "law", cite: "34 CFR 668.46" }), retention: T("Records retention schedule", { basis: "practice" }), other: T("Other policy") }
  };
  const RESTRICTED = (cat, type) => !!((TYPES[cat] || {})[type] || {}).restricted;
  const HEALTHDOC = (cat, type) => !!((TYPES[cat] || {})[type] || {}).health;
  /* requirement templates. freq: {m: months} or {d: days} or {} (once). sens: health | screen | "" */
  const REQS = {
    mmr: { label: "MMR immunity (2 doses or titer)", sens: "health", basis: "guidance", cite: "CDC HCP (Immunize.org P2017, 2025-10-13); TN college rule" },
    varicella: { label: "Varicella immunity", sens: "health", basis: "guidance", cite: "CDC HCP; TN college rule" },
    hepb: { label: "Hepatitis B series and anti-HBs (or declination)", sens: "health", basis: "guidance", cite: "CDC HCP; TN rule for health-science students" },
    tdap: { label: "Tdap within 10 years", sens: "health", freq: { m: 120 }, basis: "guidance", cite: "CDC HCP" },
    flu: { label: "Influenza, current season", sens: "health", freq: { m: 12 }, basis: "facility", cite: "CDC recommends annual for all HCP incl. students" },
    tb: { label: "TB screening (baseline IGRA/TST + symptom screen)", sens: "health", basis: "guidance", cite: "CDC/NTCA 2019 (no routine annual test); annual only if the site requires" },
    covid: { label: "COVID-19 (only if this site still requires it)", sens: "health", basis: "facility", cite: "No CDC HCP-specific recommendation; CMS mandate withdrawn 2023" },
    bg: { label: "Criminal background check (outcome only)", sens: "screen", freq: { d: 365 }, basis: "facility", cite: "TN 1000-01-.11(4)(d) (registries + Nursys); FCRA procedures via vendor" },
    drug: { label: "Drug screen (outcome only)", sens: "screen", freq: { m: 12 }, basis: "facility" },
    bls: { label: "BLS/CPR (AHA BLS Provider or equivalent)", freq: { m: 24 }, basis: "practice" },
    hipaa: { label: "HIPAA training", freq: { m: 12 }, basis: "law", cite: "45 CFR 164.530(b) (via the facility)" },
    bbp: { label: "Bloodborne pathogens training", freq: { m: 12 }, basis: "practice", cite: "29 CFR 1910.1030 covers employees (faculty); facilities require it for students" },
    orient: { label: "Site orientation", basis: "facility" },
    fit: { label: "N95 fit test", freq: { m: 12 }, basis: "facility", cite: "29 CFR 1910.134(f)(2) for employees" },
    insur: { label: "Personal health insurance", basis: "facility" },
    confid: { label: "Signed confidentiality agreement", basis: "facility" },
    ferpa: { label: "FERPA release to clinical sites", basis: "law", cite: "34 CFR Part 99" },
    license: { label: "RN license verified (Nursys)", applies: "faculty", basis: "board" }
  };
  const BASIS = { law: "Law", board: "Board rule", accred: "Accreditor", guidance: "CDC guidance", practice: "Common practice", facility: "Facility" };

  let ready = false;
  async function init(env) {
    if (ready) return;
    const S = [
      "CREATE TABLE IF NOT EXISTS clinical_days (id TEXT PRIMARY KEY, school_id TEXT NOT NULL, group_id TEXT, date TEXT NOT NULL, start TEXT, end TEXT, site TEXT, unit TEXT, note TEXT, by_id TEXT, by_name TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS clinical_day_students (day_id TEXT NOT NULL, user_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT '', at INTEGER, how TEXT, note TEXT, by_id TEXT, added INTEGER NOT NULL, PRIMARY KEY (day_id, user_id))",
      "CREATE TABLE IF NOT EXISTS vault_settings (school_id TEXT PRIMARY KEY, store_health INTEGER NOT NULL DEFAULT 0, store_screens INTEGER NOT NULL DEFAULT 0, ack TEXT, support_until INTEGER, support_by TEXT, na TEXT, by_id TEXT, updated INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS vault_staff (school_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'coord', by_id TEXT, at INTEGER NOT NULL, PRIMARY KEY (school_id, user_id))",
      "CREATE TABLE IF NOT EXISTS vault_keys (school_id TEXT PRIMARY KEY, wrapped TEXT NOT NULL, kver INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL, rewrapped INTEGER)",
      "CREATE TABLE IF NOT EXISTS vault_sites (id TEXT PRIMARY KEY, school_id TEXT NOT NULL, name TEXT NOT NULL, kind TEXT, address TEXT, contacts TEXT, units TEXT, renewal TEXT, notes TEXT, status TEXT NOT NULL DEFAULT 'active', sample INTEGER NOT NULL DEFAULT 0, by_id TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL, eie INTEGER NOT NULL DEFAULT 0, eie_reason TEXT, eie_by TEXT, eie_by_name TEXT, eie_at INTEGER)",
      "CREATE INDEX IF NOT EXISTS vault_sites_s ON vault_sites (school_id)",
      "CREATE TABLE IF NOT EXISTS vault_people (id TEXT PRIMARY KEY, school_id TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'preceptor', name TEXT NOT NULL, email TEXT, title TEXT, site_id TEXT, license_type TEXT, license_state TEXT, license_exp TEXT, verified_on TEXT, note TEXT, status TEXT NOT NULL DEFAULT 'active', sample INTEGER NOT NULL DEFAULT 0, by_id TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL, eie INTEGER NOT NULL DEFAULT 0, eie_reason TEXT, eie_by TEXT, eie_by_name TEXT, eie_at INTEGER)",
      "CREATE TABLE IF NOT EXISTS vault_docs (id TEXT PRIMARY KEY, school_id TEXT NOT NULL, cat TEXT NOT NULL, type TEXT NOT NULL, title TEXT NOT NULL, site_id TEXT, person_id TEXT, person_name TEXT, effective TEXT, expires TEXT, auto_renew INTEGER NOT NULL DEFAULT 0, renew_term TEXT, notice_days INTEGER, owner_id TEXT, owner_name TEXT, status TEXT NOT NULL DEFAULT 'active', signed_on TEXT, signers TEXT, tags TEXT, note TEXT, keep_until TEXT, hold INTEGER NOT NULL DEFAULT 0, hold_reason TEXT, rev INTEGER NOT NULL DEFAULT 1, files INTEGER NOT NULL DEFAULT 0, deleted INTEGER NOT NULL DEFAULT 0, sample INTEGER NOT NULL DEFAULT 0, by_id TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL, eie INTEGER NOT NULL DEFAULT 0, eie_reason TEXT, eie_by TEXT, eie_by_name TEXT, eie_at INTEGER)",
      "CREATE INDEX IF NOT EXISTS vault_docs_s ON vault_docs (school_id, cat)",
      "CREATE TABLE IF NOT EXISTS vault_docrev (doc_id TEXT NOT NULL, rev INTEGER NOT NULL, at INTEGER NOT NULL, by_id TEXT, by_name TEXT, snap TEXT NOT NULL, PRIMARY KEY (doc_id, rev))",
      "CREATE TABLE IF NOT EXISTS vault_blobs (id TEXT PRIMARY KEY, school_id TEXT NOT NULL, owner TEXT NOT NULL, owner_id TEXT NOT NULL, ver INTEGER NOT NULL, r2key TEXT, name TEXT, ctype TEXT, size INTEGER, sha256 TEXT, iv TEXT, wkey TEXT, by_id TEXT, by_name TEXT, at INTEGER NOT NULL, note TEXT, deleted INTEGER NOT NULL DEFAULT 0, phi INTEGER NOT NULL DEFAULT 0, eie INTEGER NOT NULL DEFAULT 0, eie_reason TEXT, eie_by TEXT, eie_by_name TEXT, eie_at INTEGER)",
      "CREATE INDEX IF NOT EXISTS vault_blobs_o ON vault_blobs (owner, owner_id)",
      "CREATE TABLE IF NOT EXISTS vault_reqs (id TEXT PRIMARY KEY, school_id TEXT NOT NULL, site_id TEXT NOT NULL DEFAULT '', code TEXT NOT NULL, label TEXT NOT NULL, applies TEXT NOT NULL DEFAULT 'student', fm INTEGER, fd INTEGER, sens TEXT, basis TEXT, note TEXT, sort INTEGER NOT NULL DEFAULT 0, sample INTEGER NOT NULL DEFAULT 0, by_id TEXT, updated INTEGER NOT NULL, doc INTEGER NOT NULL DEFAULT 0, eie INTEGER NOT NULL DEFAULT 0, eie_reason TEXT, eie_by TEXT, eie_by_name TEXT, eie_at INTEGER)",
      "CREATE INDEX IF NOT EXISTS vault_reqs_s ON vault_reqs (school_id, site_id)",
      "CREATE TABLE IF NOT EXISTS vault_items (id TEXT PRIMARY KEY, school_id TEXT NOT NULL, user_id TEXT NOT NULL, code TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'submitted', done_on TEXT, expires TEXT, method TEXT, outcome TEXT, attest INTEGER NOT NULL DEFAULT 0, attest_at INTEGER, waived INTEGER NOT NULL DEFAULT 0, verifier_id TEXT, verifier_name TEXT, verified_at INTEGER, reason TEXT, files INTEGER NOT NULL DEFAULT 0, by_id TEXT, by_name TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL, supersedes TEXT, eie INTEGER NOT NULL DEFAULT 0, eie_reason TEXT, eie_by TEXT, eie_by_name TEXT, eie_at INTEGER)",
      "CREATE INDEX IF NOT EXISTS vault_items_u ON vault_items (school_id, user_id)",
      "CREATE TABLE IF NOT EXISTS vault_reviews (id TEXT PRIMARY KEY, school_id TEXT NOT NULL, item_id TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT, by_id TEXT, by_name TEXT, at INTEGER NOT NULL, eie INTEGER NOT NULL DEFAULT 0, eie_reason TEXT, eie_by TEXT, eie_by_name TEXT, eie_at INTEGER)",
      "CREATE INDEX IF NOT EXISTS vault_reviews_i ON vault_reviews (item_id)",
      "CREATE TABLE IF NOT EXISTS vault_acks (school_id TEXT NOT NULL, key TEXT NOT NULL, state TEXT NOT NULL, note TEXT, by_id TEXT, by_name TEXT, at INTEGER NOT NULL, PRIMARY KEY (school_id, key))",
      "CREATE TABLE IF NOT EXISTS vault_daysite (day_id TEXT PRIMARY KEY, school_id TEXT NOT NULL, site_id TEXT NOT NULL, by_id TEXT, at INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS vault_nonce (n TEXT PRIMARY KEY, exp INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS vault_audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, school_id TEXT NOT NULL, at INTEGER NOT NULL, actor_id TEXT, actor_name TEXT, actor_role TEXT, action TEXT NOT NULL, kind TEXT, target TEXT, detail TEXT, ip TEXT, sens INTEGER NOT NULL DEFAULT 0, prev TEXT, hash TEXT NOT NULL)",
      "CREATE TABLE IF NOT EXISTS vault_baa (school_id TEXT PRIMARY KEY, status TEXT NOT NULL, contact TEXT, note TEXT, via TEXT, by_id TEXT, by_name TEXT, requested INTEGER NOT NULL, updated INTEGER NOT NULL)",
      "CREATE INDEX IF NOT EXISTS vault_audit_s ON vault_audit (school_id, seq)",
      "CREATE TRIGGER IF NOT EXISTS vault_audit_noupd BEFORE UPDATE ON vault_audit BEGIN SELECT RAISE(ABORT, 'vault audit is append-only'); END",
      "CREATE TRIGGER IF NOT EXISTS vault_audit_nodel BEFORE DELETE ON vault_audit BEGIN SELECT RAISE(ABORT, 'vault audit is append-only'); END"];
    await env.DB.batch(S.map(s => env.DB.prepare(s)));
    const ADD = { vault_sites: [], vault_people: [], vault_docs: [], vault_blobs: ["phi INTEGER NOT NULL DEFAULT 0"], vault_reqs: ["doc INTEGER NOT NULL DEFAULT 0"], vault_items: ["supersedes TEXT"], vault_reviews: [] };
    for (const [t, ex] of Object.entries(ADD)) { try { const have = new Set((((await env.DB.prepare("PRAGMA table_info(" + t + ")").all()).results) || []).map(c => c.name)); for (const col of ex.concat(["eie INTEGER NOT NULL DEFAULT 0", "eie_reason TEXT", "eie_by TEXT", "eie_by_name TEXT", "eie_at INTEGER"])) if (!have.has(col.split(" ")[0])) await env.DB.prepare("ALTER TABLE " + t + " ADD COLUMN " + col).run() } catch (e) { } }
    ready = true;
  }
  /* "Entered in error" (Epic-style): nothing is deleted; a record marked in error stays viewable, greyed out, and is left out of
     counts, dashboards and clearance. Un-marking needs a reason too. Both are audited. */
  const EIE_T = { doc: "vault_docs", version: "vault_blobs", site: "vault_sites", req: "vault_reqs", item: "vault_items", review: "vault_reviews", person: "vault_people" };
  const eieOf = r => r && r.eie ? { reason: r.eie_reason || "", by: r.eie_by_name || "", at: r.eie_at || null } : null;
  const NODEL = () => J({ error: "Records can't be deleted. Mark it in error instead; it stays in the record, greyed out.", code: "nodelete" }, 405);

  /* ---------- crypto ---------- */
  const KC = new Map();
  async function masterKeys(env, which) {
    const sec = which === "prev" ? env.VAULT_MASTER_PREV : env.VAULT_MASTER; if (!sec || String(sec).length < 32) return null;
    const ck = which + ":" + (await sha(String(sec))).slice(0, 16); if (KC.has(ck)) return KC.get(ck);
    const base = await crypto.subtle.importKey("raw", te.encode(String(sec)), "HKDF", false, ["deriveKey"]);
    const d = (info, alg, use) => crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: te.encode("vexcura-vault/v1"), info: te.encode(info) }, base, alg, false, use);
    const k = { kek: await d("kek", { name: "AES-GCM", length: 256 }, ["encrypt", "decrypt"]), mac: await d("url", { name: "HMAC", hash: "SHA-256", length: 256 }, ["sign", "verify"]) };
    KC.set(ck, k); return k;
  }
  const gcm = async (key, data, aad, iv) => { iv = iv || crypto.getRandomValues(new Uint8Array(12)); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(aad), tagLength: 128 }, key, data)); return { iv, ct } };
  const ungcm = async (key, iv, ct, aad) => new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: te.encode(aad), tagLength: 128 }, key, ct));
  const pack = (iv, ct) => { const o = new Uint8Array(iv.length + ct.length); o.set(iv); o.set(ct, iv.length); return b64(o) };
  const unpack = s => { const u = unb64(s); return { iv: u.slice(0, 12), ct: u.slice(12) } };
  async function schoolKey(env, sid, create) {
    const mk = await masterKeys(env); if (!mk) return null;
    const row = await env.DB.prepare("SELECT wrapped, kver FROM vault_keys WHERE school_id=?").bind(sid).first();
    const imp = raw => crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    if (row) {
      const p = unpack(row.wrapped);
      try { return await imp(await ungcm(mk.kek, p.iv, p.ct, "vault-school:" + sid)) } catch (e) {
        const pk = await masterKeys(env, "prev"); if (!pk) throw new Error("vault key unwrap failed");
        const raw = await ungcm(pk.kek, p.iv, p.ct, "vault-school:" + sid); const w = await gcm(mk.kek, raw, "vault-school:" + sid);
        await env.DB.prepare("UPDATE vault_keys SET wrapped=?, kver=kver+1, rewrapped=? WHERE school_id=?").bind(pack(w.iv, w.ct), now(), sid).run();
        return await imp(raw);
      }
    }
    if (!create) return null;
    const raw = crypto.getRandomValues(new Uint8Array(32)); const w = await gcm(mk.kek, raw, "vault-school:" + sid);
    await env.DB.prepare("INSERT INTO vault_keys (school_id, wrapped, kver, created) VALUES (?,?,1,?) ON CONFLICT(school_id) DO NOTHING").bind(sid, pack(w.iv, w.ct), now()).run();
    return schoolKey(env, sid, false);
  }
  async function encryptFile(env, sid, blobId, bytes) {
    if (await secReady(env)) return { iv: null, wkey: "sec", ct: await SECC().sealTenant(env, sid, bytes, { aad: "vault:" + blobId }) };
    const sk = await schoolKey(env, sid, true); const dek = crypto.getRandomValues(new Uint8Array(32));
    const dk = await crypto.subtle.importKey("raw", dek, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const f = await gcm(dk, bytes, sid + "|" + blobId); const w = await gcm(sk, dek, "dek:" + blobId); dek.fill(0);
    return { iv: b64(f.iv), ct: f.ct, wkey: pack(w.iv, w.ct) };
  }
  async function decryptFile(env, sid, blob, ct) {
    if (blob.wkey === "sec") { const C = SECC(); if (!C) throw new Error("security module unavailable"); return new Uint8Array(await C.openTenant(env, sid, new Uint8Array(ct), { aad: "vault:" + blob.id })) }
    const sk = await schoolKey(env, sid, false); if (!sk || !blob.wkey) throw new Error("key unavailable");
    const w = unpack(blob.wkey); const dek = await ungcm(sk, w.iv, w.ct, "dek:" + blob.id);
    const dk = await crypto.subtle.importKey("raw", dek, { name: "AES-GCM", length: 256 }, false, ["decrypt"]); dek.fill(0);
    return ungcm(dk, unb64(blob.iv), new Uint8Array(ct), sid + "|" + blob.id);
  }
  /* v40 security module (worker/sec.js, security/CRYPTO-API.md): when SECM is deployed and SEC_KEY is set, files are sealed with its
     per-school envelope encryption (sealTenant/openTenant, AES-256-GCM) and links are signed with its HMAC. VAULT_MASTER is only the
     fallback for a worker without SECM. Each blob records which one sealed it (wkey "sec" = SECM). */
  const SECC = () => { const S = (typeof globalThis !== "undefined" && (globalThis.__SECM || globalThis.__SEC)) || null; return S && S.crypto && typeof S.crypto.sealTenant === "function" ? S.crypto : null };
  async function secReady(env) { const C = SECC(); if (!C) return false; try { const r = await C.ready(env); return !!(r && r.ok && !r.fallback) } catch (e) { return false } }
  async function storage(env) { const r2 = !!(env.VAULT && typeof env.VAULT.put === "function"); const sec = await secReady(env); const mk = !!(await masterKeys(env)); return { r2, master: sec || mk, sec, on: r2 && (sec || mk) } }

  /* ---------- signed links ---------- */
  async function linkSig(env, p) { if (await secReady(env)) { const h = await SECC().blind(env, p, "vault-link"); return b64u(Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)))) } const mk = await masterKeys(env); if (!mk) return null; return b64u(await crypto.subtle.sign("HMAC", mk.mac, te.encode(p))) }
  const sameStr = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0 };
  async function mkLink(env, o) { const p = b64u(te.encode(JSON.stringify(Object.assign({ n: hexId(12), e: now() + LINK_TTL }, o)))); const s = await linkSig(env, p); return { token: p + "." + s, exp: now() + LINK_TTL } }
  async function readLink(env, tok) {
    const m = /^([A-Za-z0-9_-]{20,600})\.([A-Za-z0-9_-]{43})$/.exec(String(tok || "")); if (!m) return { err: "bad" };
    const want = await linkSig(env, m[1]); if (!want) return { err: "off" }; if (!sameStr(want, m[2])) return { err: "bad" };
    const o = pj(td.decode(unb64u(m[1])), null); if (!o || typeof o.e !== "number") return { err: "bad" };
    if (o.e < now()) return { err: "expired" };
    if (await env.DB.prepare("SELECT 1 x FROM vault_nonce WHERE n=?").bind(String(o.n)).first()) return { err: "used" };
    return { o };
  }

  /* ---------- audit (append-only, hash-chained per school) ---------- */
  const ipOfReq = req => cl(req && req.headers && (req.headers.get("CF-Connecting-IP") || ""), 64);
  async function vlog(env, req, C, action, kind, target, detail, sens) {
    const at = now(); const d = detail == null ? "" : cl(typeof detail === "string" ? detail : JSON.stringify(detail), 600);
    const prevRow = await env.DB.prepare("SELECT hash FROM vault_audit WHERE school_id=? ORDER BY seq DESC LIMIT 1").bind(C.sid).first();
    const prev = prevRow ? prevRow.hash : "genesis:" + C.sid;
    const row = [C.sid, at, C.uid || "", cl(C.name, 80), C.role || "", action, kind || "", cl(target, 80), d, ipOfReq(req), sens ? 1 : 0];
    const hash = await sha(prev + "␞" + row.join("␟"));
    await env.DB.prepare("INSERT INTO vault_audit (school_id, at, actor_id, actor_name, actor_role, action, kind, target, detail, ip, sens, prev, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(...row, prev, hash).run();
  }
  async function verifyChain(env, sid) {
    const R = (await env.DB.prepare("SELECT * FROM vault_audit WHERE school_id=? ORDER BY seq").bind(sid).all()).results || [];
    const seen = new Set(["genesis:" + sid]); let bad = 0, fork = 0, last = "genesis:" + sid; const badSeq = [];
    for (const r of R) {
      const h = await sha(r.prev + "␞" + [r.school_id, r.at, r.actor_id || "", r.actor_name || "", r.actor_role || "", r.action, r.kind || "", r.target || "", r.detail || "", r.ip || "", r.sens ? 1 : 0].join("␟"));
      if (h !== r.hash) { bad++; badSeq.push(r.seq) } if (!seen.has(r.prev)) { bad++; badSeq.push(r.seq) } else if (r.prev !== last) fork++;
      seen.add(r.hash); last = r.hash;
    }
    return { ok: bad === 0, rows: R.length, bad, forks: fork, bad_seq: badSeq.slice(0, 20), head: last };
  }

  /* ---------- roles ---------- */
  async function settingsOf(env, sid) { const r = await env.DB.prepare("SELECT * FROM vault_settings WHERE school_id=?").bind(sid).first(); return r || { school_id: sid, store_health: 0, store_screens: 0, support_until: null, na: "[]" } }
  async function ctxFor(env, me, sid) {
    const uid = String(me.id); const C = { sid, uid, name: me.name || "", me };
    const m = await env.DB.prepare("SELECT m.role, m.status, s.status sst, s.name sname FROM school_members m JOIN schools s ON s.id=m.school_id WHERE m.school_id=? AND m.user_id=?").bind(sid, uid).first().catch(() => null);
    if (m && m.status === "active") {
      C.school = m.sname;
      if (m.role === "admin") C.role = "admin";
      else if (m.role === "instructor") {
        let co = await env.DB.prepare("SELECT 1 x FROM vault_staff WHERE school_id=? AND user_id=?").bind(sid, uid).first();
        if (!co) co = await env.DB.prepare("SELECT 1 x FROM regs_staff WHERE school_id=? AND user_id=?").bind(sid, uid).first().catch(() => null);
        C.role = co ? "coord" : "instructor";
      } else if (m.role === "student") C.role = "student";
    }
    if (!C.role && isSite(me)) { const s = await env.DB.prepare("SELECT name FROM schools WHERE id=?").bind(sid).first(); if (s) { C.role = "site"; C.school = s.name } }
    if (!C.role) return null;
    const st = await settingsOf(env, sid); C.settings = st; C.support = C.role === "site" && st.support_until && st.support_until > now();
    return C;
  }
  /* what a role may do with a library category */
  function canCat(C, cat, type, op) {
    const r = C.role; if (!CATS[cat]) return false;
    if (type && RESTRICTED(cat, type)) return r === "admin" || (r === "site" && op === "meta");
    if (r === "admin") return true;
    if (r === "site") return op === "meta" || (op === "file" && C.support);
    if (r === "coord") { if (["site", "student", "preceptor"].includes(cat)) return true; if (cat === "policy") return op === "meta" || op === "file"; return false }
    return false;
  }
  const canWrite = C => C.role === "admin" || C.role === "coord";
  async function myGroupStudents(env, C) {
    const r = (await env.DB.prepare("SELECT DISTINCT gm.user_id FROM clin_groups g JOIN group_members gm ON gm.group_id=g.id WHERE g.school_id=? AND g.instructor_id=? AND g.archived=0").bind(C.sid, C.uid).all().catch(() => ({ results: [] }))).results || [];
    return new Set(r.map(x => x.user_id));
  }

  /* ---------- requirement status ---------- */
  function reqExpiry(req, item) { if (item.expires) return item.expires; if (!item.done_on) return ""; if (req.fm) return addMonths(item.done_on, req.fm); if (req.fd) return addDays(item.done_on, req.fd); return "" }
  function cellFor(req, items, at) {
    const L = items.filter(i => i.code === req.code).sort((a, b) => (b.done_on || "").localeCompare(a.done_on || "") || b.updated - a.updated);
    const ap = L.filter(i => i.status === "approved");
    for (const i of ap) { const ex = reqExpiry(req, i); if (!ex || ex >= at) { const left = ex ? daysBetween(at, ex) : null; return { st: left != null && left <= 30 ? "expiring" : "met", exp: ex, done: i.done_on || "", item: i.id, waived: !!i.waived, left } } }
    const pend = L.find(i => i.status === "submitted"); if (pend) return { st: "pending", item: pend.id, done: pend.done_on || "" };
    if (ap.length) return { st: "expired", exp: reqExpiry(req, ap[0]), item: ap[0].id };
    const rej = L.find(i => i.status === "rejected"); if (rej) return { st: "missing", rejected: true, reason: rej.reason || "", item: rej.id };
    return { st: "missing" };
  }
  const OKST = s => s === "met" || s === "expiring";
  /* requirement for a code, as it applies to this person (students vs faculty can share a code, e.g. BLS) */
  async function reqLookup(env, sid, reqs) {
    const roles = {}; ((await env.DB.prepare("SELECT user_id, role FROM school_members WHERE school_id=?").bind(sid).all()).results || []).forEach(m => { roles[m.user_id] = m.role });
    return (code, uid) => { const who = roles[uid] === "instructor" || roles[uid] === "admin" ? "faculty" : "student"; const L = reqs.filter(r => r.code === code); return L.find(r => r.site_id === "" && r.applies === who) || L.find(r => r.applies === who) || L.find(r => r.applies === "both") || null };
  }
  async function reqsOf(env, sid, siteId, who) {
    const R = (await env.DB.prepare("SELECT * FROM vault_reqs WHERE school_id=? ORDER BY sort, label").bind(sid).all()).results || [];
    return R.filter(r => !r.eie && (siteId === null || r.site_id === "" || (siteId && r.site_id === siteId)) && (!who || r.applies === who || r.applies === "both"));
  }
  async function itemsOf(env, sid, uids) {
    if (!uids.length) return [];
    const out = []; for (let i = 0; i < uids.length; i += 80) { const ch = uids.slice(i, i + 80); out.push(...(((await env.DB.prepare(`SELECT * FROM vault_items WHERE school_id=? AND eie=0 AND user_id IN (${qs(ch.length)})`).bind(sid, ...ch).all()).results) || [])) }
    return out;
  }
  async function roster(env, sid, role) {
    return ((await env.DB.prepare("SELECT u.id, u.name FROM school_members m JOIN users u ON u.id=m.user_id WHERE m.school_id=? AND m.role=? AND m.status='active' ORDER BY u.name").bind(sid, role).all()).results || []).map(x => ({ id: x.id, name: x.name || (role === "student" ? "Student" : "Instructor") }));
  }
  async function grid(env, C, siteId, who, at) {
    const reqs = await reqsOf(env, C.sid, siteId, who === "faculty" ? "faculty" : "student");
    let people = await roster(env, C.sid, who === "faculty" ? "instructor" : "student");
    if (C.role === "instructor") { if (who === "faculty") people = []; else { const mine = await myGroupStudents(env, C); people = people.filter(p => mine.has(p.id)) } }
    const items = await itemsOf(env, C.sid, people.map(p => p.id));
    const rows = people.map(p => { const its = items.filter(i => i.user_id === p.id); const cells = {}; let ok = true, exp = false; reqs.forEach(r => { const c = cellFor(r, its, at); if (C.role === "instructor") { delete c.item; delete c.reason } cells[r.id] = c; if (!OKST(c.st)) ok = false; if (c.st === "expiring") exp = true }); return { id: p.id, name: p.name, cells, cleared: ok && reqs.length > 0 ? true : reqs.length ? false : null, expiring: exp } });
    return { at, site_id: siteId || "", who, reqs: reqs.map(r => ({ id: r.id, code: r.code, label: r.label, site_id: r.site_id, fm: r.fm, fd: r.fd, basis: r.basis || "", sens: r.sens || "" })), rows };
  }
  const normName = s => String(s || "").toLowerCase().replace(/\(fictional\)/g, "").replace(/[^a-z0-9]+/g, " ").trim();
  async function siteForDay(env, sid, day, sites) {
    const o = await env.DB.prepare("SELECT site_id FROM vault_daysite WHERE day_id=?").bind(day.id).first(); if (o) return sites.find(s => s.id === o.site_id) || null;
    const t = normName(day.site); if (!t) return null;
    /* exact name, or the day's text contains the whole site name ("Riverbend Memorial Hospital 4 West"); never a partial name, which could be a different facility */
    return sites.find(s => normName(s.name) === t) || sites.find(s => { const n = normName(s.name); return n.length > 3 && (" " + t + " ").includes(" " + n + " ") }) || null;
  }
  /* exported for CLINDAY / REGS: clearance of everyone on a clinical day */
  async function gate(env, sid, dayId) {
    await init(env);
    const day = await env.DB.prepare("SELECT * FROM clinical_days WHERE id=? AND school_id=?").bind(dayId, sid).first(); if (!day) return null;
    const sites = (await env.DB.prepare("SELECT id, name FROM vault_sites WHERE school_id=? AND status='active' AND eie=0").bind(sid).all()).results || [];
    const site = await siteForDay(env, sid, day, sites);
    const ros = ((await env.DB.prepare("SELECT c.user_id id, u.name FROM clinical_day_students c LEFT JOIN users u ON u.id=c.user_id WHERE c.day_id=?").bind(dayId).all()).results) || [];
    const reqs = await reqsOf(env, sid, site ? site.id : "", "student"); const items = await itemsOf(env, sid, ros.map(r => r.id));
    const students = ros.map(r => { const its = items.filter(i => i.user_id === r.id); const miss = reqs.filter(q => !OKST(cellFor(q, its, day.date).st)).map(q => q.label); return { id: r.id, name: r.name || "Student", cleared: reqs.length ? !miss.length : null, missing: miss } });
    return { day_id: dayId, date: day.date, site: site ? { id: site.id, name: site.name } : null, site_text: day.site || "", reqs: reqs.length, students };
  }

  /* ---------- dashboard ---------- */
  async function overview(env, C) {
    const t = todayUTC(); const sid = C.sid;
    const docs = ((await env.DB.prepare("SELECT id, cat, type, title, site_id, person_name, effective, expires, auto_renew, notice_days, status, hold, keep_until, files FROM vault_docs WHERE school_id=? AND deleted=0 AND eie=0").bind(sid).all()).results || []).filter(d => canCat(C, d.cat, d.type, "meta"));
    const sites = (await env.DB.prepare("SELECT id, name, kind, status FROM vault_sites WHERE school_id=? AND eie=0 ORDER BY name").bind(sid).all()).results || [];
    const active = d => !["superseded", "archived"].includes(d.status);
    const exp = [], notice = [];
    docs.filter(active).forEach(d => {
      if (d.expires) { const n = daysBetween(t, d.expires); exp.push({ id: d.id, cat: d.cat, type: d.type, title: d.title, site_id: d.site_id || "", person: d.person_name || "", expires: d.expires, days: n, auto_renew: !!d.auto_renew }) }
      if (d.expires && d.notice_days) { const dl = addDays(d.expires, -d.notice_days); const n = daysBetween(t, dl); if (n <= 90 && daysBetween(t, d.expires) >= 0) notice.push({ id: d.id, title: d.title, site_id: d.site_id || "", deadline: dl, days: n, expires: d.expires, notice_days: d.notice_days, auto_renew: !!d.auto_renew }) }
    });
    const missing = [];
    if (canCat(C, "site", "agreement", "meta")) sites.filter(s => s.status === "active").forEach(s => {
      ["agreement", "coi"].forEach(ty => { const L = docs.filter(d => d.cat === "site" && d.site_id === s.id && d.type === ty && active(d)); const cur = L.find(d => (!d.expires || d.expires >= t) && (ty !== "agreement" || ["active", "signed"].includes(d.status))); if (!cur) missing.push({ kind: "site", site_id: s.id, site: s.name, type: ty, label: TYPES.site[ty].label, why: L.length ? (L.some(d => d.status === "pending_sig") ? "Waiting for signatures" : "Expired or not current") : "Not on file" }) });
    });
    const na = new Set(pj(C.settings.na, []));
    for (const cat of ["board", "accred", "inst", "policy"]) { if (!canCat(C, cat, null, "meta")) continue; for (const [ty, def] of Object.entries(TYPES[cat])) { if (!def.core || na.has(cat + "." + ty)) continue; if (!docs.some(d => d.cat === cat && d.type === ty && active(d) && (!d.expires || d.expires >= t))) missing.push({ kind: "program", cat, type: ty, label: def.label, na_ok: !!def.na, basis: def.basis || "", cite: def.cite || "" }) } }
    /* people requirement items (expiring / pending) */
    let pending = 0, itemsExp = [];
    if (["admin", "coord", "site"].includes(C.role)) {
      pending = ((await env.DB.prepare("SELECT COUNT(*) n FROM vault_items WHERE school_id=? AND status='submitted' AND eie=0").bind(sid).first()) || {}).n || 0;
      const reqs = await reqsOf(env, sid, null, null); const RQF = await reqLookup(env, sid, reqs);
      const its = (await env.DB.prepare("SELECT i.*, u.name uname FROM vault_items i LEFT JOIN users u ON u.id=i.user_id WHERE i.school_id=? AND i.status='approved' AND i.eie=0").bind(sid).all()).results || [];
      const latest = {}; its.forEach(i => { const k = i.user_id + "|" + i.code; if (!latest[k] || (i.done_on || "") > (latest[k].done_on || "")) latest[k] = i });
      Object.values(latest).forEach(i => { const r = RQF(i.code, i.user_id); if (!r) return; const ex = reqExpiry(r, i); if (!ex) return; const n = daysBetween(t, ex); if (n <= 90) itemsExp.push({ user: i.uname || "Person", user_id: i.user_id, code: i.code, label: r.label, expires: ex, days: n }) });
      itemsExp.sort((a, b) => a.days - b.days);
    }
    const purge = docs.filter(d => d.keep_until && d.keep_until < t && !d.hold).map(d => ({ id: d.id, title: d.title, keep_until: d.keep_until }));
    const b = { expired: exp.filter(x => x.days < 0), d30: exp.filter(x => x.days >= 0 && x.days <= 30), d60: exp.filter(x => x.days > 30 && x.days <= 60), d90: exp.filter(x => x.days > 60 && x.days <= 90) };
    Object.values(b).forEach(L => L.sort((x, y) => x.days - y.days)); notice.sort((x, y) => x.days - y.days);
    const alerts = [];
    b.expired.forEach(x => alerts.push({ level: "bad", line: `${x.title} expired ${-x.days} day${x.days === -1 ? "" : "s"} ago`, doc: x.id }));
    notice.filter(n => n.days <= 30).forEach(n => alerts.push({ level: n.days < 0 ? "bad" : "warn", line: n.days < 0 ? `${n.title}: the ${n.notice_days}-day notice deadline passed on ${n.deadline}${n.auto_renew ? "; it renews automatically on " + n.expires : ""}` : `${n.title}: give notice by ${n.deadline} (${n.days} day${n.days === 1 ? "" : "s"}) if you want to change or end it`, doc: n.id }));
    b.d30.forEach(x => alerts.push({ level: "warn", line: `${x.title} expires in ${x.days} day${x.days === 1 ? "" : "s"} (${x.expires})`, doc: x.id }));
    missing.filter(m => m.kind === "site").forEach(m => alerts.push({ level: "bad", line: `${m.site}: ${m.label.toLowerCase()} missing (${m.why.toLowerCase()})`, site: m.site_id }));
    if (pending) alerts.push({ level: "info", line: `${pending} requirement${pending === 1 ? "" : "s"} waiting for review`, go: "review" });
    return { today: t, counts: { expired: b.expired.length, d30: b.d30.length, d60: b.d60.length, d90: b.d90.length, missing: missing.length, notice: notice.length, pending, items: itemsExp.filter(x => x.days <= 30).length, purge: purge.length }, buckets: b, notice, missing, items: itemsExp.slice(0, 200), purge, alerts: alerts.slice(0, 60), sites: sites.map(s => ({ id: s.id, name: s.name, kind: s.kind || "", status: s.status })) };
  }


  /* ---------- Needs attention: one queue, every reason a record needs someone to look at it ---------- */
  async function attention(env, C) {
    const sid = C.sid, t = todayUTC(), L = [];
    const add = (key, reason, sev, label, target, extra) => L.push(Object.assign({ key, reason, sev, label, target }, extra || {}));
    const o = await overview(env, C);
    o.buckets.expired.forEach(x => add(`doc_expired:${x.id}:${x.expires}`, "expired", "bad", `${x.title}: expired ${x.expires}`, { kind: "doc", id: x.id }));
    const allDocs = ((await env.DB.prepare("SELECT * FROM vault_docs WHERE school_id=? AND deleted=0").bind(sid).all()).results || []).filter(d => canCat(C, d.cat, d.type, "meta"));
    const liveDocs = allDocs.filter(d => !d.eie && !["superseded", "archived"].includes(d.status));
    liveDocs.forEach(d => { if (!d.expires) return; const n = daysBetween(t, d.expires); const win = Math.max(30, d.notice_days || 0); if (n >= 0 && n <= win) add(`doc_expiring:${d.id}:${d.expires}`, "expiring", "warn", `${d.title}: expires ${d.expires} (${n} day${n === 1 ? "" : "s"})`, { kind: "doc", id: d.id }) });
    o.notice.filter(n => n.days < 0).forEach(n => add(`notice_passed:${n.id}:${n.deadline}`, "notice_passed", "bad", `${n.title}: the ${n.notice_days}-day notice deadline passed ${n.deadline}${n.auto_renew ? "; it renews automatically " + n.expires : ""}`, { kind: "doc", id: n.id }));
    o.missing.forEach(m => m.kind === "site" ? add(`missing:site:${m.site_id}:${m.type}`, m.type === "coi" ? "no_coi" : "missing", "bad", `${m.site}: ${m.label.toLowerCase()} ${m.type === "coi" ? "not current" : "missing"} (${m.why.toLowerCase()})`, { kind: "site", id: m.site_id }, { add: { cat: "site", type: m.type, site_id: m.site_id } }) : add(`missing:prog:${m.cat}.${m.type}`, "missing", "warn", `${m.label}: not on file`, { kind: "cat", id: m.cat }, { add: { cat: m.cat, type: m.type } }));
    /* executed copies */
    const blobs = (await env.DB.prepare("SELECT id, owner, owner_id, ver, eie, phi, name FROM vault_blobs WHERE school_id=? AND deleted=0").bind(sid).all()).results || [];
    const liveFiles = id => blobs.filter(b => b.owner_id === id && !b.eie).length;
    liveDocs.filter(d => d.type === "agreement" && ["signed", "active"].includes(d.status) && !liveFiles(d.id)).forEach(d => add(`unexecuted:${d.id}`, "no_executed_copy", "warn", `${d.title}: no executed copy on file`, { kind: "doc", id: d.id }));
    /* entered in error, needing a replacement */
    allDocs.filter(d => d.eie).forEach(d => { const rep = liveDocs.some(x => x.cat === d.cat && x.type === d.type && (x.site_id || "") === (d.site_id || "") && (x.person_id || "") === (d.person_id || "") && x.created > (d.created || 0)); if (!rep) add(`eie_doc:${d.id}`, "eie_replace", "warn", `${d.title}: entered in error; add the corrected record`, { kind: "doc", id: d.id }, { add: { cat: d.cat, type: d.type, site_id: d.site_id || "" } }) });
    blobs.filter(b => b.eie && b.owner === "doc").forEach(b => { const d = allDocs.find(x => x.id === b.owner_id); if (!d || d.eie) return; if (!blobs.some(x => x.owner_id === b.owner_id && !x.eie && x.ver > b.ver)) add(`eie_ver:${b.id}`, "eie_replace", "warn", `${d.title}: file v${b.ver} entered in error; upload the correct copy`, { kind: "doc", id: d.id }) });
    blobs.filter(b => b.phi && !b.eie).forEach(b => { const d = b.owner === "doc" ? allDocs.find(x => x.id === b.owner_id) : null; if (b.owner === "doc" && !d) return; add(`phi:${b.id}`, "phi", "bad", `Possible protected health information in ${b.name} (v${b.ver}). Check it; mark it in error if it contains patient information.`, b.owner === "doc" ? { kind: "doc", id: b.owner_id } : { kind: "item", id: b.owner_id }) });
    liveDocs.filter(d => d.keep_until && d.keep_until < t && !d.hold).forEach(d => add(`retention:${d.id}:${d.keep_until}`, "retention", "info", `${d.title}: keep-until date ${d.keep_until} passed. Review retention (nothing is deleted automatically).`, { kind: "doc", id: d.id }));
    /* people requirements */
    if (["admin", "coord", "site"].includes(C.role)) {
      const its = (await env.DB.prepare("SELECT i.*, u.name uname FROM vault_items i LEFT JOIN users u ON u.id=i.user_id WHERE i.school_id=?").bind(sid).all()).results || [];
      const reqs = await reqsOf(env, sid, null, null); const docReq = new Set(reqs.filter(r => r.doc).map(r => r.code)); const RQF = await reqLookup(env, sid, reqs); const lab = i => (RQF(i.code, i.user_id) || {}).label || i.code;
      its.filter(i => !i.eie && i.status === "submitted").forEach(i => { const lb = lab(i); const resub = its.some(x => x.user_id === i.user_id && x.code === i.code && x.status === "rejected" && x.created < i.created); add(`item_pending:${i.id}`, resub ? "resubmitted" : "awaiting_verification", "info", `${i.uname || "Person"}: ${lb} ${resub ? "resubmitted after a rejection" : "waiting for verification"}`, { kind: "item", id: i.id, user_id: i.user_id }) });
      its.filter(i => !i.eie && ["submitted", "approved"].includes(i.status) && docReq.has(i.code) && !liveFiles(i.id)).forEach(i => add(`item_nodoc:${i.id}`, "attest_no_doc", "warn", `${i.uname || "Person"}: ${lab(i)} attested without the required document`, { kind: "item", id: i.id, user_id: i.user_id }));
      its.filter(i => i.eie).forEach(i => { if (!RQF(i.code, i.user_id)) return; if (!its.some(x => x.user_id === i.user_id && x.code === i.code && !x.eie && x.created > i.created)) add(`eie_item:${i.id}`, "eie_replace", "warn", `${i.uname || "Person"}: ${lab(i)} entered in error; needs a corrected entry`, { kind: "item", id: i.id, user_id: i.user_id }) });
      o.items.forEach(x => add(`item_exp:${x.user_id}:${x.code}:${x.expires}`, x.days < 0 ? "expired" : "expiring", x.days < 0 ? "bad" : "warn", `${x.user}: ${x.label} ${x.days < 0 ? "expired " + x.expires : "expires " + x.expires}`, { kind: "person", id: x.user_id, user_id: x.user_id }));
    }
    const acks = {}; ((await env.DB.prepare("SELECT * FROM vault_acks WHERE school_id=?").bind(sid).all()).results || []).forEach(a => { acks[a.key] = { state: a.state, note: a.note || "", by: a.by_name || "", at: a.at } });
    const seen = new Set(); const out = L.filter(x => !seen.has(x.key) && seen.add(x.key)).map(x => Object.assign(x, { ack: acks[x.key] || null }));
    const sevO = { bad: 0, warn: 1, info: 2 }; out.sort((a, b) => sevO[a.sev] - sevO[b.sev]);
    return { items: out, open: out.filter(x => !x.ack || x.ack.state !== "resolved").length };
  }
  /* ---------- file validation ---------- */
  const EXT = { "application/pdf": ["pdf"], "image/jpeg": ["jpg", "jpeg"], "image/png": ["png"], "image/heic": ["heic", "heif"], "image/heif": ["heic", "heif"] };
  function sniff(u) {
    if (u.length >= 5 && u[0] === 0x25 && u[1] === 0x50 && u[2] === 0x44 && u[3] === 0x46 && u[4] === 0x2d) return "application/pdf";
    if (u.length >= 8 && u[0] === 0x89 && u[1] === 0x50 && u[2] === 0x4e && u[3] === 0x47 && u[4] === 0x0d && u[5] === 0x0a && u[6] === 0x1a && u[7] === 0x0a) return "image/png";
    if (u.length >= 3 && u[0] === 0xff && u[1] === 0xd8 && u[2] === 0xff) return "image/jpeg";
    if (u.length >= 12 && td.decode(u.slice(4, 8)) === "ftyp") { const br = td.decode(u.slice(8, 12)); if (["heic", "heix", "hevc", "hevx", "heim", "heis", "mif1", "msf1"].includes(br)) return "image/heic" }
    return "";
  }
  const latin = u => { let s = ""; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return s };
  async function inflate(u) { try { const ds = new DecompressionStream("deflate"); const w = ds.writable.getWriter(); w.write(u).catch(() => { }); w.close().catch(() => { }); return new Uint8Array(await new Response(ds.readable).arrayBuffer()) } catch (e) { return null } }
  /* PDF objects: uncompressed ones and those inside object streams. Last definition in the file wins (incremental updates). */
  async function pdfObjects(u, s) {
    const map = new Map(); const re = /(\d+)\s+(\d+)\s+obj\b/g; let m; const streams = [];
    while ((m = re.exec(s))) {
      const st = m.index + m[0].length; const end = s.indexOf("endobj", st); if (end < 0) break; const body = s.slice(st, end);
      const si = body.indexOf("stream"); const dict = si >= 0 ? body.slice(0, si) : body;
      map.set(+m[1], { num: +m[1], gen: +m[2], pos: m.index, body: dict.trim(), inStm: false });
      if (si >= 0 && /\/Type\s*\/ObjStm\b/.test(dict)) { let a = st + si + 6; if (s[a] === "\r") a++; if (s[a] === "\n") a++; const b = s.lastIndexOf("endstream", end); streams.push({ pos: m.index, dict, bytes: u.subarray(a, Math.max(a, b)) }) }
      re.lastIndex = end + 6;
    }
    const inner = [];
    for (const S of streams) {
      if (!/\/FlateDecode/.test(S.dict) || /\/DecodeParms/.test(S.dict)) continue;
      let raw = await inflate(S.bytes); if (!raw) { let k = S.bytes.length; while (k > 0 && (S.bytes[k - 1] === 0x0a || S.bytes[k - 1] === 0x0d)) k--; raw = await inflate(S.bytes.subarray(0, k)) } if (!raw) continue;
      const txt = latin(raw); inner.push(txt);
      const N = +((/\/N\s+(\d+)/.exec(S.dict) || [])[1] || 0), F = +((/\/First\s+(\d+)/.exec(S.dict) || [])[1] || 0); if (!N || !F) continue;
      const hdr = txt.slice(0, F).trim().split(/\s+/).map(Number); const offs = [];
      for (let i = 0; i < N; i++) offs.push([hdr[2 * i], hdr[2 * i + 1]]);
      offs.forEach(([num, off], i) => { const a = F + off, b = i + 1 < offs.length ? F + offs[i + 1][1] : txt.length; const prev = map.get(num); if (!prev || prev.pos < S.pos) map.set(num, { num, gen: 0, pos: S.pos, body: txt.slice(a, b).trim(), inStm: true }) });
    }
    return { map, inner };
  }
  const pdfName = s => s.replace(/#([0-9A-Fa-f]{2})/g, (x, h) => String.fromCharCode(parseInt(h, 16)));
  async function pdfActive(u) {
    const s = latin(u); const { inner } = await pdfObjects(u, s); const all = pdfName(s + "\n" + inner.join("\n"));
    const hit = /\/(JavaScript|JS|Launch|EmbeddedFiles?|RichMedia|XFA|SubmitForm|ImportData)\b/.exec(all);
    return hit ? hit[1] : "";
  }
  /* possible PHI inside a PDF: inflate content streams and look for MRN / DOB / SSN patterns in the text (a review flag, never proof) */
  async function pdfPhi(u) {
    const s = latin(u); const parts = [s.slice(0, 2e6)]; const re = /stream\r?\n/g; let m, n = 0;
    while ((m = re.exec(s)) && n < 60) { const a = m.index + m[0].length; const e = s.indexOf("endstream", a); if (e < 0) break; const dict = s.slice(Math.max(0, m.index - 300), m.index); if (/\/FlateDecode/.test(dict) && !/\/DecodeParms/.test(dict) && e - a < 4e6) { const raw = await inflate(u.subarray(a, e)); if (raw) { parts.push(latin(raw).replace(/\)\s*-?\d+(\.\d+)?\s*\(/g, "")); n++ } } re.lastIndex = e }
    const txt = parts.join("\n"); const S = SECM();
    try { if (S && typeof S.phiScan === "function") { const r = S.phiScan(txt.slice(0, 2e5)); if (r && (r === true || r.hit || (Array.isArray(r) && r.length))) return true } } catch (e) { }
    return /\b(MRN|Medical Record (No|Number)|DOB|Date of Birth)\b\s*[:#]?\s*\(?\s*[\w\/-]{3,}|\b\d{3}-\d{2}-\d{4}\b/i.test(txt);
  }
  /* watermark: an incremental update adding a locked, printable FreeText annotation (own appearance stream + font) to each page */
  const pdfStr = t => "(" + String(t).replace(/[^\x20-\x7e]/g, "?").replace(/([\\()])/g, "\\$1") + ")";
  async function stampPdf(u, text) {
    const s = latin(u);
    const sx = s.lastIndexOf("startxref"); if (sx < 0) return null; const prev = +((/startxref\s+(\d+)/.exec(s.slice(sx)) || [])[1]); if (!isFinite(prev)) return null;
    let trailer = ""; const ti = s.lastIndexOf("trailer"); if (ti > prev - 1 && ti >= 0) trailer = s.slice(ti, sx); else { const xm = /^\s*(\d+)\s+(\d+)\s+obj([\s\S]*?)stream/.exec(s.slice(prev, prev + 4000)); if (!xm) return null; trailer = xm[3] }
    if (/\/Encrypt\b/.test(trailer)) return null;
    const size = +((/\/Size\s+(\d+)/.exec(trailer) || [])[1] || 0); const root = /\/Root\s+(\d+\s+\d+\s+R)/.exec(trailer); if (!size || !root) return null;
    const info = /\/Info\s+(\d+\s+\d+\s+R)/.exec(trailer); const id = /\/ID\s*(\[[^\]]*\])/.exec(trailer);
    const { map } = await pdfObjects(u, s);
    const pages = [...map.values()].filter(o => /\/Type\s*\/Page(?![s\w])/.test(o.body) && /^<</.test(o.body)).sort((a, b) => a.num - b.num); if (!pages.length || pages.length > 2000) return null;
    let next = Math.max(size, ...[...map.keys()].map(k => k + 1)); const objs = []; const apFor = new Map();
    for (const p of pages) {
      const mb = /\/MediaBox\s*\[\s*([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s*\]/.exec(p.body); const [x0, y0, x1] = mb ? [+mb[1], +mb[2], +mb[3]] : [0, 0, 612];
      const w = Math.max(100, Math.round((x1 - x0) - 36)); let ap = apFor.get(w);
      if (!ap) { ap = next++; apFor.set(w, ap); const cs = `q 0.42 0.42 0.42 rg BT /Helv 7 Tf 2 3.2 Td ${pdfStr(text)} Tj ET Q`; objs.push([ap, 0, `<< /Type /XObject /Subtype /Form /BBox [0 0 ${w} 11] /Resources << /Font << /Helv << /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >> >> >> /Length ${cs.length} >>\nstream\n${cs}\nendstream`]) }
      const an = next++; objs.push([an, 0, `<< /Type /Annot /Subtype /FreeText /Rect [${x0 + 18} ${y0 + 6} ${x0 + 18 + w} ${y0 + 17}] /Contents ${pdfStr(text)} /F 708 /DA (/Helv 7 Tf 0.42 0.42 0.42 rg) /Border [0 0 0] /AP << /N ${ap} 0 R >> /NM (vx-wm-${an}) >>`]);
      let body = p.body; const am = /\/Annots\s*(\[[^\]]*\]|(\d+)\s+(\d+)\s+R)/.exec(body);
      if (!am) body = body.replace(/>>\s*$/, ` /Annots [${an} 0 R] >>`);
      else if (am[1][0] === "[") body = body.replace(am[0], "/Annots " + am[1].slice(0, -1) + ` ${an} 0 R]`);
      else { const ao = map.get(+am[2]); if (!ao || !/^\[[\s\S]*\]$/.test(ao.body)) return null; body = body.replace(am[0], "/Annots " + ao.body.slice(0, -1) + ` ${an} 0 R]`) }
      objs.push([p.num, p.gen, body]);
    }
    let out = s.endsWith("\n") ? "" : "\n"; let off = u.length + out.length; const ents = [];
    for (const [n, g, b] of objs) { const o = `${n} ${g} obj\n${b}\nendobj\n`; ents.push([n, g, off]); off += o.length; out += o }
    ents.sort((a, b) => a[0] - b[0]); let x = "xref\n"; let i = 0;
    while (i < ents.length) { let j = i; while (j + 1 < ents.length && ents[j + 1][0] === ents[j][0] + 1) j++; x += `${ents[i][0]} ${j - i + 1}\n`; for (let k = i; k <= j; k++) x += String(ents[k][2]).padStart(10, "0") + " " + String(ents[k][1]).padStart(5, "0") + " n\r\n"; i = j + 1 }
    x += `trailer\n<< /Size ${next} /Root ${root[1]}${info ? " /Info " + info[1] : ""}${id ? " /ID " + id[1] : ""} /Prev ${prev} >>\nstartxref\n${off}\n%%EOF\n`;
    out += x; const add = new Uint8Array(out.length); for (let k = 0; k < out.length; k++) add[k] = out.charCodeAt(k) & 0xff;
    const r = new Uint8Array(u.length + add.length); r.set(u); r.set(add, u.length); return r;
  }
  function safeName(n, ctype) { let b = cl(n, 140).replace(/[\\/:*?"<>|\u0000-\u001f]+/g, "_").replace(/^\.+/, "").replace(/\s+/g, " "); const ext = (/\.([A-Za-z0-9]{2,5})$/.exec(b) || [])[1]; if (!ext) b += "." + EXT[ctype][0]; return b || "file." + EXT[ctype][0] }

  async function putBlob(env, C, owner, ownerId, req, sens) {
    const S = await storage(env); if (!S.on) return J({ error: STORE_MSG, code: "nostorage" }, 503);
    if (sens === "health" && !C.settings.store_health) return J({ error: "Your program records the dates and who verified them for health items. Storing the documents is turned off. A school admin can turn it on in Vault settings.", code: "minimized" }, 403);
    if (sens === "screen" && !C.settings.store_screens) return J({ error: "Background check and drug screen reports aren't stored. Record the outcome only. A school admin can change this in Vault settings after counsel approves.", code: "minimized" }, 403);
    const recent = ((await env.DB.prepare("SELECT COUNT(*) n FROM vault_audit WHERE school_id=? AND actor_id=? AND action='upload' AND at>?").bind(C.sid, C.uid, now() - 600000).first()) || {}).n || 0; if (recent >= 40) return J({ error: "Too many uploads. Wait a few minutes." }, 429);
    const len = +(req.headers.get("Content-Length") || 0); if (len > MAXB) return J({ error: "Files can be up to 15 MB." }, 413);
    const decl = cl(req.headers.get("Content-Type"), 60).toLowerCase().split(";")[0]; const name = (() => { try { return decodeURIComponent(req.headers.get("X-Vault-Name") || "") } catch (e) { return "" } })();
    if (!EXT[decl]) return J({ error: "Upload a PDF, JPG, PNG or HEIC file." }, 415);
    const u = new Uint8Array(await req.arrayBuffer()); if (!u.length) return J({ error: "The file is empty." }, 400); if (u.length > MAXB) return J({ error: "Files can be up to 15 MB." }, 413);
    const real = sniff(u); const ext = ((/\.([A-Za-z0-9]{2,5})$/.exec(name) || [])[1] || "").toLowerCase();
    const same = a => a === decl || (a === "image/heic" && decl === "image/heif");
    if (!real || !same(real) || (ext && !EXT[decl].includes(ext))) return J({ error: "That file's contents don't match its type. Upload a real PDF, JPG, PNG or HEIC file.", code: "mismatch" }, 415);
    if (real === "application/pdf") { const a = await pdfActive(u); if (a) return J({ error: `This PDF contains active content (${a}). Print it to a new PDF and upload that copy.`, code: "active" }, 415) }
    const id = "vb_" + hexId(12); const verRow = await env.DB.prepare("SELECT COALESCE(MAX(ver),0) v FROM vault_blobs WHERE owner=? AND owner_id=?").bind(owner, ownerId).first(); const ver = ((verRow && verRow.v) || 0) + 1;
    let phiFlag = 0; if (real === "application/pdf") { try { phiFlag = (await pdfPhi(u)) ? 1 : 0 } catch (e) { } }
    const digest = await sha(u); const enc = await encryptFile(env, C.sid, id, u); const key = "v1/" + C.sid + "/" + hexId(16);
    await env.VAULT.put(key, enc.ct, { httpMetadata: { contentType: "application/octet-stream" }, customMetadata: { v: "1" } });
    const fn = safeName(name, decl);
    await env.DB.prepare("INSERT INTO vault_blobs (id, school_id, owner, owner_id, ver, r2key, name, ctype, size, sha256, iv, wkey, by_id, by_name, at, note, phi) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(id, C.sid, owner, ownerId, ver, key, fn, real === "image/heic" ? decl : real, u.length, digest, enc.iv, enc.wkey, C.uid, cl(C.name, 80), now(), cl(req.headers.get("X-Vault-Note"), 200), phiFlag).run();
    await env.DB.prepare(owner === "doc" ? "UPDATE vault_docs SET files=files+1, updated=? WHERE id=?" : "UPDATE vault_items SET files=files+1, updated=? WHERE id=?").bind(now(), ownerId).run();
    await vlog(env, req, C, "upload", owner, ownerId, { blob: id, ver, size: u.length, type: real }, owner === "item" || !!sens);
    return J({ ok: true, id, ver, name: fn, size: u.length, ctype: real, phi: !!phiFlag }, 201);
  }
  /* (v41b) nothing is deleted or crypto-shredded through the app; see VAULT-DEPLOY.md "Destruction for a legal reason" */
  const blobView = b => ({ id: b.id, ver: b.ver, name: b.name, ctype: b.ctype, size: b.size, sha256: b.sha256 ? b.sha256.slice(0, 16) : "", by: b.by_name || "", at: b.at, note: b.note || "", deleted: !!b.deleted, phi: !!b.phi, eie: eieOf(b) });

  /* ---------- docs ---------- */
  const DOCF = ["cat", "type", "title", "site_id", "person_id", "person_name", "effective", "expires", "auto_renew", "renew_term", "notice_days", "owner_id", "owner_name", "status", "signed_on", "signers", "tags", "note", "keep_until"];
  const DSTAT = ["draft", "pending_sig", "active", "signed", "expired", "superseded", "archived"];
  function cleanDoc(b, base) {
    const o = Object.assign({}, base || {});
    if (b.cat !== undefined) o.cat = cl(b.cat, 12); if (b.type !== undefined) o.type = cl(b.type, 20); if (b.title !== undefined) o.title = cl(b.title, 160);
    for (const k of ["site_id", "person_id"]) if (b[k] !== undefined) o[k] = cl(b[k], 40);
    for (const k of ["person_name", "owner_name", "renew_term"]) if (b[k] !== undefined) o[k] = cl(b[k], 120);
    if (b.owner_id !== undefined) o.owner_id = cl(b.owner_id, 40);
    for (const k of ["effective", "expires", "signed_on", "keep_until"]) if (b[k] !== undefined) o[k] = dOr(b[k]);
    if (b.auto_renew !== undefined) o.auto_renew = b.auto_renew ? 1 : 0; if (b.notice_days !== undefined) o.notice_days = b.notice_days === "" || b.notice_days == null ? null : int(b.notice_days, 0, 1095, null);
    if (b.status !== undefined) o.status = DSTAT.includes(b.status) ? b.status : "active";
    if (b.signers !== undefined) o.signers = JSON.stringify((Array.isArray(b.signers) ? b.signers : []).slice(0, 8).map(x => ({ name: cl(x && x.name, 100), title: cl(x && x.title, 100), party: cl(x && x.party, 60) })).filter(x => x.name));
    if (b.tags !== undefined) o.tags = JSON.stringify([...new Set((Array.isArray(b.tags) ? b.tags : String(b.tags || "").split(",")).map(x => cl(x, 30).toLowerCase()).filter(Boolean))].slice(0, 12));
    if (b.note !== undefined) o.note = cl(b.note, 2000);
    return o;
  }
  const docView = (d, withNote) => ({ id: d.id, cat: d.cat, type: d.type, type_label: ((TYPES[d.cat] || {})[d.type] || {}).label || d.type, title: d.title, site_id: d.site_id || "", person_id: d.person_id || "", person_name: d.person_name || "", effective: d.effective || "", expires: d.expires || "", auto_renew: !!d.auto_renew, renew_term: d.renew_term || "", notice_days: d.notice_days, owner_name: d.owner_name || "", status: d.status, signed_on: d.signed_on || "", signers: pj(d.signers, []), tags: pj(d.tags, []), note: withNote ? d.note || "" : undefined, keep_until: d.keep_until || "", hold: !!d.hold, hold_reason: d.hold ? d.hold_reason || "" : "", rev: d.rev, files: d.files, sample: !!d.sample, restricted: RESTRICTED(d.cat, d.type), eie: eieOf(d), created: d.created, updated: d.updated });

  async function snapDoc(env, C, d) { await env.DB.prepare("INSERT OR REPLACE INTO vault_docrev (doc_id, rev, at, by_id, by_name, snap) VALUES (?,?,?,?,?,?)").bind(d.id, d.rev, now(), C.uid, cl(C.name, 80), JSON.stringify(docView(d, true))).run() }

  /* ---------- items (requirements) ---------- */
  function cleanItem(b) { return { done_on: dOr(b.done_on), expires: dOr(b.expires), method: cl(b.method, 120), outcome: ["meets", "does_not_meet", "pending", ""].includes(b.outcome) ? b.outcome || "" : "" } }
  const itemView = (i, full) => Object.assign({ id: i.id, user_id: i.user_id, code: i.code, status: i.status, done_on: i.done_on || "", expires: i.expires || "", outcome: i.outcome || "", waived: !!i.waived, attest: !!i.attest, verifier: i.verifier_name || "", verified_at: i.verified_at || null, reason: i.reason || "", files: i.files, by: i.by_name || "", created: i.created, updated: i.updated, supersedes: i.supersedes || "", eie: eieOf(i) }, full ? { method: i.method || "" } : {});

  async function seedSample(env, C) {
    const t = todayUTC(); const ts = now(); const sid = C.sid; const st = [];
    const site = (name, kind, addr, contacts, units, renewal) => { const id = "vs_" + hexId(8); st.push(env.DB.prepare("INSERT INTO vault_sites (id, school_id, name, kind, address, contacts, units, renewal, status, sample, by_id, created, updated) VALUES (?,?,?,?,?,?,?,?, 'active', 1, ?,?,?)").bind(id, sid, name, kind, addr, JSON.stringify(contacts), units, renewal, C.uid, ts, ts)); return id };
    const s1 = site("Riverbend Memorial Hospital (fictional)", "hospital", "100 River Rd, Ringgold, GA (fictional)", [{ role: "Clinical education liaison", name: "Pat Liaison (fictional)", email: "liaison@riverbend.example", phone: "555-0100" }, { role: "Nurse manager, 4 West", name: "Sam Manager (fictional)", email: "4west@riverbend.example", phone: "555-0101" }], "4 West Med-Surg; 3 North Telemetry; Labor & Delivery", "Renews each July 1 unless either party gives 90 days' written notice");
    const s2 = site("Oak Hollow Rehabilitation Center (fictional)", "ltc", "22 Oak Hollow Ln, Fort Oglethorpe, GA (fictional)", [{ role: "Director of nursing", name: "Lee Director (fictional)", email: "don@oakhollow.example", phone: "555-0200" }], "Rehab unit; Long-term care", "Fixed 2-year term; renegotiate before expiration");
    const s3 = site("Catoosa Valley Health Department (fictional)", "community", "5 Main St, Ringgold, GA (fictional)", [{ role: "Nursing supervisor", name: "Jo Supervisor (fictional)", email: "nursing@cvhd.example", phone: "555-0300" }], "Immunization clinic; school health", "New agreement in signature");
    const doc = (cat, type, title, o) => { const id = "vd_" + hexId(8); const d = Object.assign({ site_id: "", person_name: "", effective: "", expires: "", auto_renew: 0, renew_term: "", notice_days: null, status: "active", signed_on: "", signers: "[]", tags: '["sample"]', note: "" }, o || {}); st.push(env.DB.prepare("INSERT INTO vault_docs (id, school_id, cat, type, title, site_id, person_name, effective, expires, auto_renew, renew_term, notice_days, owner_id, owner_name, status, signed_on, signers, tags, note, sample, by_id, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)").bind(id, sid, cat, type, title, d.site_id, d.person_name, d.effective, d.expires, d.auto_renew, d.renew_term, d.notice_days, C.uid, cl(C.name, 80), d.status, d.signed_on, d.signers, d.tags, d.note, C.uid, ts, ts)); return id };
    const sg = JSON.stringify([{ name: "Dr. Morgan Lee (fictional)", title: "Dean of Nursing", party: "School" }, { name: "Chris Officer (fictional)", title: "Chief Nursing Officer", party: "Facility" }]);
    doc("site", "agreement", "Riverbend Memorial clinical affiliation agreement", { site_id: s1, effective: addMonths(t, -22), expires: addDays(t, 45), auto_renew: 1, renew_term: "1 year", notice_days: 90, status: "signed", signed_on: addMonths(t, -22), signers: sg, note: "Student professional liability $1M/$3M. Facility may remove a student for cause. 90 days' written notice to terminate." });
    doc("site", "coi", "Certificate of insurance: student professional liability", { site_id: s1, effective: addMonths(t, -11), expires: addDays(t, 20) });
    doc("site", "orient", "Riverbend student orientation module", { site_id: s1, effective: addMonths(t, -3) });
    doc("site", "agreement", "Oak Hollow clinical affiliation agreement", { site_id: s2, effective: addMonths(t, -21), expires: addDays(t, 75), renew_term: "2 years (fixed)", status: "signed", signed_on: addMonths(t, -21) });
    doc("site", "coi", "Certificate of insurance (prior policy year)", { site_id: s2, effective: addMonths(t, -12), expires: addDays(t, -10) });
    doc("site", "agreement", "Catoosa Valley Health Department agreement (draft)", { site_id: s3, status: "pending_sig", note: "Sent for signature." });
    doc("site", "coi", "Certificate of insurance: student professional liability", { site_id: s3, effective: addMonths(t, -2), expires: addMonths(t, 10) });
    doc("board", "approval", "Board of Nursing approval letter: Full approval", { effective: addMonths(t, -30), expires: addMonths(t, 90), status: "active" });
    doc("board", "annual", "Annual report submitted (prior year)", { effective: addMonths(t, -4) });
    doc("accred", "decision", "Accreditation decision letter", { effective: addMonths(t, -40), expires: addMonths(t, 56) });
    doc("inst", "auth", "State authorization certificate", { effective: addMonths(t, -10), expires: addDays(t, 58), renew_term: "Renewal due 60 days before expiration", notice_days: 60 });
    doc("inst", "accred", "Institutional accreditation letter", { effective: addMonths(t, -50), expires: addMonths(t, 70) });
    doc("policy", "handbook", "Student handbook 2026-2027", { effective: addMonths(t, -3), expires: addMonths(t, 9) });
    doc("policy", "attendance", "Clinical attendance and absence policy", { effective: addMonths(t, -3) });
    doc("policy", "evaltool", "Clinical evaluation tool (all clinical courses)", { effective: addMonths(t, -3) });
    const rq = (site_id, code, o) => { const R = REQS[code]; const f = Object.assign({}, R.freq || {}, o || {}); st.push(env.DB.prepare("INSERT INTO vault_reqs (id, school_id, site_id, code, label, applies, fm, fd, sens, basis, note, sort, sample, by_id, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)").bind("vq_" + hexId(8), sid, site_id, code, (o && o.label) || R.label, (o && o.applies) || R.applies || "student", f.m || null, f.d || null, R.sens || "", R.basis || "", (o && o.note) || R.cite || "", st.length, C.uid, ts)) };
    ["mmr", "varicella", "hepb", "tdap", "tb", "bls", "hipaa", "bbp", "ferpa"].forEach(c => rq("", c));
    rq("", "license", { applies: "faculty" }); rq("", "bls", { applies: "faculty", label: "BLS/CPR (faculty)" });
    ["flu", "drug", "bg", "orient", "confid"].forEach(c => rq(s1, c, c === "bg" ? { note: "Riverbend: within 90 days before the first placement, then yearly (facility rule)." } : null));
    ["flu", "orient", "fit"].forEach(c => rq(s2, c)); rq(s3, "orient");
    await env.DB.batch(st); return { sites: 3 };
  }

  /* ---------- API ---------- */
  async function api(req, env, ctx, url) {
    await init(env); const seg = url.pathname.replace(/^\/api\/vault\/?/, "").split("/").filter(Boolean).map(x => { try { return decodeURIComponent(x) } catch (e) { return "" } }); const M = req.method;
    if (M !== "GET") { const o = req.headers.get("Origin"); if (req.headers.get("X-NCLEX") !== "1" || (o && o !== url.origin)) return J({ error: "Request blocked." }, 403) }
    const me = await current(env, req); if (!me) return J({ error: "Sign in first." }, 401); if (me.mustReset || me.must_reset) return J({ error: "Set a new password first." }, 401);
    const uid = String(me.id);
    const body = async () => { if (M === "GET" || M === "DELETE") return {}; try { return (await req.json()) || {} } catch (e) { return {} } };

    /* signed file download */
    if (seg[0] === "file" && seg[1] && M === "GET") {
      const L = await readLink(env, seg[1]); if (L.err) return new Response(L.err === "expired" ? "This link expired. Go back and select Download again." : L.err === "used" ? "This link was already used. Go back and select Download again." : "Link not valid.", { status: L.err === "off" ? 503 : 403, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
      const o = L.o; if (o.u !== uid) return new Response("This link belongs to another user.", { status: 403, headers: { "Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff" } });
      /* consume the nonce only once the right user presents it (single use) */
      try { await env.DB.prepare("INSERT INTO vault_nonce (n, exp) VALUES (?,?)").bind(String(o.n), o.e + DAY).run() } catch (e) { return new Response("This link was already used. Go back and select Download again.", { status: 403, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } }) }
      if (Math.random() < 0.05) env.DB.prepare("DELETE FROM vault_nonce WHERE exp<?").bind(now()).run().catch(() => { });
      const blob = await env.DB.prepare("SELECT * FROM vault_blobs WHERE id=? AND school_id=? AND deleted=0").bind(o.b, o.s).first(); if (!blob) return J({ error: "That file was removed." }, 404);
      const C = await ctxFor(env, me, o.s); if (!C) return J({ error: "Not allowed." }, 403);
      if (!(await canBlob(env, C, blob))) { await vlog(env, req, C || { sid: o.s, uid }, "download_denied", blob.owner, blob.owner_id, { blob: blob.id }, 1); return J({ error: "You can't open this file." }, 403) }
      const S = await storage(env); if (!S.on) return J({ error: STORE_MSG, code: "nostorage" }, 503);
      const obj = await env.VAULT.get(blob.r2key); if (!obj) return J({ error: "The stored file is missing." }, 404);
      let bytes; try { bytes = await decryptFile(env, o.s, blob, await obj.arrayBuffer()) } catch (e) { await vlog(env, req, C, "decrypt_failed", blob.owner, blob.owner_id, { blob: blob.id }); return J({ error: "The file couldn't be decrypted." }, 500) }
      if (await sha(bytes) !== blob.sha256) return J({ error: "Integrity check failed." }, 500);
      let wm = "none";
      if (blob.ctype === "application/pdf" && o.p !== "raw") { const stamp = `Vexcura vault - ${cl(me.name, 60) || "user"} - ${new Date(now()).toISOString().slice(0, 16).replace("T", " ")} UTC - ref ${blob.id.slice(3, 11)} - confidential`; try { const st = await stampPdf(bytes, stamp); if (st) { bytes = st; wm = "stamped" } } catch (e) { } }
      await vlog(env, req, C, o.m === "view" ? "view_file" : "download", blob.owner, blob.owner_id, { blob: blob.id, ver: blob.ver, wm }, 1);
      try { const S = globalThis.__SECM || globalThis.__SEC; if (S && typeof S.event === "function") S.event(env, ctx, "vault_read", 1, { req, uid: me.id, who: me.email, detail: { sid: o.s, blob: blob.id, mode: o.m } }) } catch (e) { }
      const fn = blob.name.replace(/[^\x20-\x7e]/g, "_").replace(/"/g, "'");
      return new Response(bytes, { status: 200, headers: { "Content-Type": blob.ctype, "Content-Disposition": `attachment; filename="${fn}"; filename*=UTF-8''${encodeURIComponent(blob.name)}`, "Content-Length": String(bytes.length), "Cache-Control": "no-store, private", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox", "Cross-Origin-Resource-Policy": "same-origin", "Referrer-Policy": "no-referrer", "X-Vault-Watermark": wm } });
    }

    if (seg[0] === "me" && M === "GET") {
      const mem = (await env.DB.prepare("SELECT s.id, s.name, s.short, m.role FROM school_members m JOIN schools s ON s.id=m.school_id WHERE m.user_id=? AND m.status='active' AND s.status IN ('pilot','active') ORDER BY s.name").bind(uid).all()).results || [];
      const out = []; for (const m of mem) { const C = await ctxFor(env, me, m.id); if (C) out.push({ id: m.id, name: m.name, short: m.short || "", role: C.role }) }
      if (isSite(me)) { const all = (await env.DB.prepare("SELECT id, name, short FROM schools ORDER BY name LIMIT 200").all()).results || []; for (const s of all) if (!out.some(x => x.id === s.id)) { const st = await settingsOf(env, s.id); out.push({ id: s.id, name: s.name, short: s.short || "", role: "site", support: !!(st.support_until && st.support_until > now()) }) } }
      return J({ schools: out, storage: await storage(env), site: isSite(me), version: VER });
    }
    if (seg[0] === "catalog" && M === "GET") return J({ cats: CATS, types: TYPES, reqs: REQS, basis: BASIS, version: VER });

    /* personal: My requirements (students and instructors) */
    if (seg[0] === "mine") {
      const sid = cl(url.searchParams.get("sid") || "", 40) || ((await env.DB.prepare("SELECT school_id FROM school_members WHERE user_id=? AND status='active' AND role IN ('student','instructor') ORDER BY joined LIMIT 1").bind(uid).first()) || {}).school_id;
      if (!sid) return J({ error: "Join your program first.", code: "noschool" }, 404);
      const C = await ctxFor(env, me, sid); if (!C || C.role === "site") return J({ error: "Join your program first.", code: "noschool" }, 404);
      const who = C.role === "student" ? "student" : "faculty";
      if (!seg[1] && M === "GET") {
        const t = todayUTC();
        const days = who === "student" ? ((await env.DB.prepare("SELECT d.id, d.date, d.site FROM clinical_day_students c JOIN clinical_days d ON d.id=c.day_id WHERE c.user_id=? AND d.school_id=? AND d.date>=? ORDER BY d.date LIMIT 30").bind(uid, sid, t).all()).results || []) : [];
        const sites = (await env.DB.prepare("SELECT id, name, kind FROM vault_sites WHERE school_id=? AND status='active' AND eie=0 ORDER BY name").bind(sid).all()).results || [];
        const mySites = []; for (const d of days) { const s = await siteForDay(env, sid, d, sites); if (s && !mySites.some(x => x.id === s.id)) mySites.push({ id: s.id, name: s.name, next: d.date }) }
        const all = await reqsOf(env, sid, null, who); const items = await itemsOf(env, sid, [uid]); const allMine = (await env.DB.prepare("SELECT * FROM vault_items WHERE school_id=? AND user_id=?").bind(sid, uid).all()).results || [];
        const reqs = all.filter(r => r.site_id === "" || mySites.some(s => s.id === r.site_id) || url.searchParams.get("all") === "1");
        const seen = new Set(); const list = [];
        for (const r of reqs) { const k = r.code + "|" + (r.fm || "") + "|" + (r.fd || ""); const site = sites.find(s => s.id === r.site_id); const c = cellFor(r, items, t); const it = items.filter(i => i.code === r.code).sort((a, b) => b.created - a.created)[0];
          if (seen.has(k) && r.site_id) { const prev = list.find(x => x.k === k); if (prev && site) prev.sites.push(site.name); continue } seen.add(k);
          list.push({ k, req_id: r.id, code: r.code, label: r.label, sites: site ? [site.name] : [], fm: r.fm, fd: r.fd, sens: r.sens || "", basis: r.basis || "", note: r.note || "", cell: c, item: it ? itemView(it, true) : null, upload: (await storage(env)).on && (!r.sens || (r.sens === "health" ? !!C.settings.store_health : !!C.settings.store_screens)), doc_required: !!r.doc, history: allMine.filter(i => i.code === r.code).sort((a, b) => b.created - a.created).slice(0, 10).map(i => itemView(i, true)) }) }
        const st = await storage(env);
        await vlog(env, req, C, "view", "mine", uid, null, 1);
        return J({ school: { id: sid, name: C.school || "" }, hipaa: await hipaaOn(env, sid), phi_notice: PHI_NOTICE, role: C.role, who, today: t, sites: mySites, all_sites: sites.map(s => ({ id: s.id, name: s.name })), list, storage: st, store: { health: !!C.settings.store_health, screens: !!C.settings.store_screens } });
      }
      if (seg[1] === "items" && !seg[2] && M === "POST") {
        const b = await body(); const code = cl(b.code, 20); const rq = (await reqsOf(env, sid, null, who)).find(r => r.code === code); if (!rq) return J({ error: "That requirement isn't on your list." }, 400);
        if (phiHit(b.method)) return J({ error: "That text looks like it contains protected health information (an MRN, date of birth or SSN). Remove it; the vault is not for patient information.", code: "phi" }, 400); const o = cleanItem(b); if (!o.done_on) return J({ error: "Enter the date it was done." }, 400); if (o.done_on > addDays(todayUTC(), 1)) return J({ error: "That date is in the future." }, 400); if (!b.attest) return J({ error: "Check the box to confirm this is accurate." }, 400);
        if (rq.sens === "screen") o.outcome = o.outcome === "meets" || o.outcome === "does_not_meet" ? o.outcome : "pending";
        const id = "vi_" + hexId(10); const t = now(); const prev = await env.DB.prepare("SELECT id FROM vault_items WHERE school_id=? AND user_id=? AND code=? AND eie=0 ORDER BY created DESC LIMIT 1").bind(sid, uid, code).first();
        await env.DB.prepare("INSERT INTO vault_items (id, school_id, user_id, code, status, done_on, expires, method, outcome, attest, attest_at, by_id, by_name, created, updated, supersedes) VALUES (?,?,?,?, 'submitted', ?,?,?,?,1,?,?,?,?,?,?)").bind(id, sid, uid, code, o.done_on, o.expires, o.method, o.outcome, t, uid, cl(me.name, 80), t, t, prev ? prev.id : null).run();
        await vlog(env, req, C, "submit", "item", id, { code }, 1); return J({ ok: true, id }, 201);
      }
      if (seg[1] === "items" && seg[2]) {
        const it = await env.DB.prepare("SELECT * FROM vault_items WHERE id=? AND school_id=? AND user_id=?").bind(seg[2], sid, uid).first(); if (!it) return J({ error: "Not found" }, 404);
        if (seg[3] === "file" && M === "POST") { if (it.eie) return J({ error: "This entry is marked entered in error." }, 409); if (it.status === "approved") return J({ error: "This item is already approved. Add a new entry instead." }, 409); const rq = (await reqsOf(env, sid, null, who)).find(r => r.code === it.code); return putBlob(env, C, "item", it.id, req, rq ? rq.sens : "") }
        if (seg[3] === "files" && M === "GET") { const B = (await env.DB.prepare("SELECT * FROM vault_blobs WHERE owner='item' AND owner_id=? ORDER BY ver DESC").bind(it.id).all()).results || []; return J({ files: B.map(blobView) }) }
        if (!seg[3] && M === "DELETE") return NODEL();
      }
      if (seg[1] === "items" && seg[2] && seg[3] === "eie" && M === "POST") {
        const it = await env.DB.prepare("SELECT * FROM vault_items WHERE id=? AND school_id=? AND user_id=?").bind(seg[2], sid, uid).first(); if (!it) return J({ error: "Not found" }, 404);
        const b = await body(); const reason = cl(b.reason, 300); if (reason.length < 3) return J({ error: "Give a reason." }, 400);
        if (b.on === false) { if (!it.eie || it.eie_by !== uid) return J({ error: "Only the person who marked it can undo that here." }, 403); await env.DB.prepare("UPDATE vault_items SET eie=0, eie_reason=NULL, eie_by=NULL, eie_by_name=NULL, eie_at=NULL, updated=? WHERE id=?").bind(now(), it.id).run(); await vlog(env, req, C, "unmark_in_error", "item", it.id, { reason }, 1); return J({ ok: true }) }
        if (it.status !== "submitted") return J({ error: "Ask your program to correct an item that was already reviewed." }, 409);
        await env.DB.prepare("UPDATE vault_items SET eie=1, eie_reason=?, eie_by=?, eie_by_name=?, eie_at=?, updated=? WHERE id=?").bind(reason, uid, cl(me.name, 80), now(), now(), it.id).run(); await vlog(env, req, C, "mark_in_error", "item", it.id, { reason }, 1); return J({ ok: true });
      }
      if (seg[1] === "link" && M === "POST") { const b = await body(); const blob = await env.DB.prepare("SELECT b.* FROM vault_blobs b JOIN vault_items i ON i.id=b.owner_id WHERE b.id=? AND b.owner='item' AND i.user_id=? AND b.deleted=0").bind(cl(b.blob, 40), uid).first(); if (!blob) return J({ error: "Not found" }, 404); return linkFor(env, req, C, blob, b.mode) }
      return J({ error: "Not found" }, 404);
    }

    /* school scope */
    if (seg[0] === "s" && seg[1]) {
      const sid = cl(seg[1], 40); const C = await ctxFor(env, me, sid); if (!C) return J({ error: "The compliance vault is for your program's admins and clinical staff." }, 403);
      const what = seg[2] || ""; const t = now();
      if (C.role === "student") return J({ error: "Students use My requirements.", code: "student" }, 403);
      const lib = ["admin", "coord", "site"].includes(C.role);
      const ro = C.role === "site" || C.role === "instructor";

      if (what === "overview" && M === "GET") { if (!lib) return J({ error: "Not allowed." }, 403); const o = await overview(env, C); await vlog(env, req, C, "view", "overview", sid, null); const baa = await env.DB.prepare("SELECT status, requested, via FROM vault_baa WHERE school_id=?").bind(sid).first(); try { o.counts.attention = (await attention(env, C)).open } catch (e) { o.counts.attention = 0 } return J(Object.assign(o, { role: C.role, school: C.school || "", hipaa: await hipaaOn(env, sid), phi_notice: PHI_NOTICE, baa: baa ? { status: baa.status, requested: baa.requested, via: baa.via } : null, audit_retention: AUDIT_RETENTION, storage: await storage(env), settings: { store_health: !!C.settings.store_health, store_screens: !!C.settings.store_screens, support_until: C.settings.support_until || null, na: pj(C.settings.na, []) }, cats: CATS })) }

      if (what === "settings" && M === "PUT") {
        if (C.role !== "admin") return J({ error: "School admin only." }, 403); const b = await body(); const cur = C.settings;
        const sh = b.store_health === undefined ? cur.store_health : (b.store_health ? 1 : 0), ss = b.store_screens === undefined ? cur.store_screens : (b.store_screens ? 1 : 0);
        if ((sh && !cur.store_health || ss && !cur.store_screens) && b.ack !== "minimize-ack/1") return J({ error: "Read and accept the warning first.", code: "ack" }, 400);
        const na = b.na === undefined ? cur.na || "[]" : JSON.stringify((Array.isArray(b.na) ? b.na : []).map(x => cl(x, 30)).filter(x => /^[a-z]+\.[a-z_]+$/.test(x)).slice(0, 60));
        await env.DB.prepare("INSERT INTO vault_settings (school_id, store_health, store_screens, ack, support_until, support_by, na, by_id, updated) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(school_id) DO UPDATE SET store_health=excluded.store_health, store_screens=excluded.store_screens, ack=COALESCE(excluded.ack, vault_settings.ack), na=excluded.na, by_id=excluded.by_id, updated=excluded.updated").bind(sid, sh, ss, b.ack === "minimize-ack/1" ? "minimize-ack/1 " + new Date(t).toISOString() : null, cur.support_until || null, cur.support_by || null, na, uid, t).run();
        await vlog(env, req, C, "settings", "school", sid, { store_health: sh, store_screens: ss }); try { await audit(env, req, uid, "vault_settings", sid, "health=" + sh + " screens=" + ss) } catch (e) { }
        return J({ ok: true });
      }
      if (what === "support") {
        if (C.role !== "admin") return J({ error: "School admin only." }, 403);
        if (M === "POST") { const b = await body(); const days = int(b.days, 1, 14, 3); const until = t + days * DAY; await env.DB.prepare("INSERT INTO vault_settings (school_id, support_until, support_by, updated) VALUES (?,?,?,?) ON CONFLICT(school_id) DO UPDATE SET support_until=excluded.support_until, support_by=excluded.support_by, updated=excluded.updated").bind(sid, until, uid, t).run(); await vlog(env, req, C, "support_grant", "school", sid, { days }); try { await audit(env, req, uid, "vault_support_grant", sid, days + "d") } catch (e) { } return J({ ok: true, support_until: until }) }
        if (M === "DELETE") { await env.DB.prepare("UPDATE vault_settings SET support_until=NULL, updated=? WHERE school_id=?").bind(t, sid).run(); await vlog(env, req, C, "support_revoke", "school", sid, null); return J({ ok: true }) }
      }
      /* Business Associate Agreement request: the v40 security module's flow when present, else a CRM task for Vexcura */
      if (what === "baa") {
        if (C.role !== "admin" && !(C.role === "site" && M === "GET")) return J({ error: "School admin only." }, 403);
        const cur = await env.DB.prepare("SELECT * FROM vault_baa WHERE school_id=?").bind(sid).first();
        if (M === "GET") return J({ baa: cur ? { status: cur.status, requested: cur.requested, via: cur.via, by: cur.by_name || "" } : null, hipaa: await hipaaOn(env, sid), note: "Vexcura can't sign a BAA or hold PHI until its hosting is covered by one. Your request is recorded and Vexcura will contact you." });
        if (M === "POST") {
          const b = await body(); const contact = cl(b.contact, 200), note = cl(b.note, 1000); if (phiHit(note)) return J({ error: "That text looks like it contains protected health information (an MRN, date of birth or SSN). Remove it; the vault is not for patient information.", code: "phi" }, 400);
          let via = "crm"; const S = SECM();
          if (S && typeof S.requestBAA === "function") { try { const r = await S.requestBAA(env, req, me, { school_id: sid, school: C.school || "", contact, note, source: "vault" }); if (r !== false) via = "sec" } catch (e) { via = "crm" } }
          if (via === "crm") {
            await env.DB.batch([env.DB.prepare("CREATE TABLE IF NOT EXISTS crm_programs (key TEXT PRIMARY KEY, name TEXT NOT NULL, stage TEXT, contact TEXT NOT NULL DEFAULT '{}', next_date TEXT, next_step TEXT, value INTEGER, source TEXT, school_id TEXT, onb_id TEXT, lost_reason TEXT, by_name TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL)"), env.DB.prepare("CREATE TABLE IF NOT EXISTS crm_tasks (id TEXT PRIMARY KEY, key TEXT NOT NULL, title TEXT NOT NULL, due TEXT, done INTEGER NOT NULL DEFAULT 0, by_name TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL)")]);
            let p = await env.DB.prepare("SELECT key FROM crm_programs WHERE school_id=? LIMIT 1").bind(sid).first(); let key = p && p.key;
            if (!key) { key = "vault-" + sid; await env.DB.prepare("INSERT INTO crm_programs (key, name, stage, contact, source, school_id, by_name, created, updated) VALUES (?,?, 'customer', ?, 'vault-baa', ?, ?, ?, ?) ON CONFLICT(key) DO NOTHING").bind(key, C.school || sid, JSON.stringify({ name: cl(me.name, 80), email: cl(me.email, 160), note: contact }), sid, cl(me.name, 80), t, t).run() }
            await env.DB.prepare("INSERT INTO crm_tasks (id, key, title, due, done, by_name, created, updated) VALUES (?,?,?,?,0,?,?,?)").bind("ct_" + hexId(8), key, cl("BAA requested by " + (me.name || "school admin") + " (" + (C.school || sid) + ")" + (contact ? " - contact: " + contact : ""), 200), addDays(todayUTC(), 5), cl(me.name, 80), t, t).run();
          }
          await env.DB.prepare("INSERT INTO vault_baa (school_id, status, contact, note, via, by_id, by_name, requested, updated) VALUES (?, 'requested', ?,?,?,?,?,?,?) ON CONFLICT(school_id) DO UPDATE SET status='requested', contact=excluded.contact, note=excluded.note, via=excluded.via, by_id=excluded.by_id, by_name=excluded.by_name, updated=excluded.updated").bind(sid, contact, note, via, uid, cl(me.name, 80), cur ? cur.requested : t, t).run();
          await vlog(env, req, C, "baa_request", "school", sid, { via }); try { await audit(env, req, uid, "vault_baa_request", sid, via) } catch (e) { }
          return J({ ok: true, via, status: "requested" });
        }
      }
      if (what === "staff" && M === "PUT") {
        if (C.role !== "admin") return J({ error: "School admin only." }, 403); const b = await body(); const u = cl(b.user_id, 40);
        const m = await env.DB.prepare("SELECT role FROM school_members WHERE school_id=? AND user_id=? AND status='active'").bind(sid, u).first(); if (!m || m.role !== "instructor") return J({ error: "Pick an instructor in this program." }, 400);
        if (b.coord) await env.DB.prepare("INSERT INTO vault_staff (school_id, user_id, role, by_id, at) VALUES (?,?, 'coord', ?,?) ON CONFLICT(school_id, user_id) DO NOTHING").bind(sid, u, uid, t).run(); else await env.DB.prepare("DELETE FROM vault_staff WHERE school_id=? AND user_id=?").bind(sid, u).run();
        await vlog(env, req, C, b.coord ? "coord_add" : "coord_remove", "user", u, null); return J({ ok: true });
      }
      if (what === "staff" && M === "GET") { if (!lib) return J({ error: "Not allowed." }, 403); const R = (await env.DB.prepare("SELECT u.id, u.name, m.role, (SELECT 1 FROM vault_staff v WHERE v.school_id=m.school_id AND v.user_id=m.user_id) coord FROM school_members m JOIN users u ON u.id=m.user_id WHERE m.school_id=? AND m.status='active' AND m.role IN ('admin','instructor') ORDER BY u.name").bind(sid).all()).results || []; return J({ staff: R.map(x => ({ id: x.id, name: x.name, role: x.role, coord: !!x.coord })) }) }

      /* sites */
      if (what === "sites") {
        if (!seg[3] && M === "GET") { if (!lib && C.role !== "instructor") return J({ error: "Not allowed." }, 403); const R = (await env.DB.prepare("SELECT * FROM vault_sites WHERE school_id=? ORDER BY status, name").bind(sid).all()).results || []; return J({ sites: R.map(s => ({ id: s.id, name: s.name, kind: s.kind || "", status: s.status, units: lib ? s.units || "" : undefined, eie: eieOf(s) })) }) }
        if (!seg[3] && M === "POST") { if (!canWrite(C)) return J({ error: "Not allowed." }, 403); const b = await body(); if (phiHit([b.notes, b.units].join(" "))) return J({ error: "That text looks like it contains protected health information (an MRN, date of birth or SSN). Remove it; the vault is not for patient information.", code: "phi" }, 400); const name = cl(b.name, 140); if (!name) return J({ error: "Enter the site name." }, 400); const id = "vs_" + hexId(8); await env.DB.prepare("INSERT INTO vault_sites (id, school_id, name, kind, address, contacts, units, renewal, notes, status, by_id, created, updated) VALUES (?,?,?,?,?,?,?,?,?, 'active', ?,?,?)").bind(id, sid, name, cl(b.kind, 20), cl(b.address, 240), JSON.stringify(cleanContacts(b.contacts)), cl(b.units, 400), cl(b.renewal, 400), cl(b.notes, 2000), uid, t, t).run(); await vlog(env, req, C, "create", "site", id, { name }); return J({ ok: true, id }, 201) }
        if (seg[3]) {
          const s = await env.DB.prepare("SELECT * FROM vault_sites WHERE id=? AND school_id=?").bind(seg[3], sid).first(); if (!s) return J({ error: "Not found" }, 404);
          if (M === "GET") {
            if (!lib) return J({ error: "Not allowed." }, 403);
            const docs = ((await env.DB.prepare("SELECT * FROM vault_docs WHERE school_id=? AND site_id=? AND deleted=0 ORDER BY type, expires DESC").bind(sid, s.id).all()).results || []).filter(d => canCat(C, d.cat, d.type, "meta")).map(d => docView(d));
            const reqs = (await env.DB.prepare("SELECT * FROM vault_reqs WHERE school_id=? AND site_id=? ORDER BY sort, label").bind(sid, s.id).all()).results || [];
            const base = (await env.DB.prepare("SELECT * FROM vault_reqs WHERE school_id=? AND site_id='' ORDER BY sort, label").bind(sid).all()).results || [];
            await vlog(env, req, C, "view", "site", s.id, null);
            return J({ site: { id: s.id, name: s.name, kind: s.kind || "", address: s.address || "", contacts: pj(s.contacts, []), units: s.units || "", renewal: s.renewal || "", notes: s.notes || "", status: s.status, sample: !!s.sample, eie: eieOf(s) }, docs, reqs: reqs.map(reqView), base: base.map(reqView) });
          }
          if (M === "PUT") { if (!canWrite(C)) return J({ error: "Not allowed." }, 403); const b = await body(); if (phiHit([b.notes, b.units].join(" "))) return J({ error: "That text looks like it contains protected health information (an MRN, date of birth or SSN). Remove it; the vault is not for patient information.", code: "phi" }, 400); await env.DB.prepare("UPDATE vault_sites SET name=?, kind=?, address=?, contacts=?, units=?, renewal=?, notes=?, status=?, updated=? WHERE id=?").bind(cl(b.name, 140) || s.name, b.kind === undefined ? s.kind : cl(b.kind, 20), b.address === undefined ? s.address : cl(b.address, 240), b.contacts === undefined ? s.contacts : JSON.stringify(cleanContacts(b.contacts)), b.units === undefined ? s.units : cl(b.units, 400), b.renewal === undefined ? s.renewal : cl(b.renewal, 400), b.notes === undefined ? s.notes : cl(b.notes, 2000), b.status === "inactive" ? "inactive" : "active", t, s.id).run(); await vlog(env, req, C, "update", "site", s.id, null); return J({ ok: true }) }
        }
      }

      /* requirement checklists */
      if (what === "reqs") {
        if (M === "GET") { const site = cl(url.searchParams.get("site") || "", 40); const R = (await env.DB.prepare("SELECT * FROM vault_reqs WHERE school_id=? ORDER BY site_id, sort, label").bind(sid).all()).results || []; return J({ reqs: R.filter(r => !site || r.site_id === site || r.site_id === "").map(reqView), templates: REQS, basis: BASIS }) }
        if (!canWrite(C)) return J({ error: "Not allowed." }, 403);
        if (M === "POST") { const b = await body(); const site = cl(b.site_id, 40); if (site && !(await env.DB.prepare("SELECT id FROM vault_sites WHERE id=? AND school_id=?").bind(site, sid).first())) return J({ error: "Unknown site." }, 400);
          const code = cl(b.code, 20).toLowerCase().replace(/[^a-z0-9_]/g, ""); if (!code) return J({ error: "Pick a requirement." }, 400); const T0 = REQS[code] || {};
          const label = cl(b.label, 120) || T0.label; if (!label) return J({ error: "Enter a name for this requirement." }, 400);
          const fm = b.fm === undefined ? (T0.freq || {}).m || null : int(b.fm, 1, 240, null), fd = b.fd === undefined ? (T0.freq || {}).d || null : int(b.fd, 1, 3650, null);
          const applies = ["student", "faculty", "both"].includes(b.applies) ? b.applies : T0.applies || "student"; const sens = ["health", "screen", ""].includes(b.sens) ? b.sens : T0.sens || "";
          const id = "vq_" + hexId(8); await env.DB.prepare("INSERT INTO vault_reqs (id, school_id, site_id, code, label, applies, fm, fd, sens, basis, note, sort, by_id, updated, doc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(id, sid, site, code, label, applies, fm, fd, sens, cl(b.basis, 12) || T0.basis || "facility", cl(b.note, 400) || T0.cite || "", int(b.sort, 0, 999, 100), uid, t, b.doc ? 1 : 0).run();
          await vlog(env, req, C, "create", "req", id, { code, site }); return J({ ok: true, id }, 201) }
        if (seg[3] && M === "PUT") { const b = await body(); const r = await env.DB.prepare("SELECT * FROM vault_reqs WHERE id=? AND school_id=?").bind(seg[3], sid).first(); if (!r) return J({ error: "Not found" }, 404); await env.DB.prepare("UPDATE vault_reqs SET label=?, fm=?, fd=?, applies=?, note=?, doc=?, updated=? WHERE id=?").bind(cl(b.label, 120) || r.label, b.fm === undefined ? r.fm : int(b.fm, 1, 240, null), b.fd === undefined ? r.fd : int(b.fd, 1, 3650, null), ["student", "faculty", "both"].includes(b.applies) ? b.applies : r.applies, b.note === undefined ? r.note : cl(b.note, 400), b.doc === undefined ? r.doc : (b.doc ? 1 : 0), t, r.id).run(); await vlog(env, req, C, "update", "req", r.id, null); return J({ ok: true }) }
        if (seg[3] && M === "DELETE") return NODEL();
      }

      /* clearance grid (instructors: status only, their students only) */
      if (what === "grid" && M === "GET") {
        const site = cl(url.searchParams.get("site") || "", 40); const who = url.searchParams.get("who") === "faculty" ? "faculty" : "students"; const at = dOr(url.searchParams.get("at")) || todayUTC();
        if (who === "faculty" && C.role === "instructor") return J({ error: "Not allowed." }, 403);
        const g = await grid(env, C, site, who, at); await vlog(env, req, C, "view", "grid", site || "program", { who, n: g.rows.length }, 1); return J(g);
      }
      if (what === "days" && M === "GET") {
        const from = dOr(url.searchParams.get("from")) || todayUTC(); const to = addDays(from, int(url.searchParams.get("n"), 1, 120, 30));
        let D = (await env.DB.prepare("SELECT d.id, d.date, d.start, d.end, d.site, d.unit, d.group_id, g.name gname, g.instructor_id FROM clinical_days d LEFT JOIN clin_groups g ON g.id=d.group_id WHERE d.school_id=? AND d.date>=? AND d.date<=? ORDER BY d.date, d.start LIMIT 200").bind(sid, from, to).all().catch(() => ({ results: [] }))).results || [];
        if (C.role === "instructor") D = D.filter(d => d.instructor_id === uid);
        const out = []; for (const d of D) { const g = await gate(env, sid, d.id); if (!g) continue; out.push({ id: d.id, date: d.date, start: d.start || "", end: d.end || "", site_text: d.site || "", unit: d.unit || "", group: d.gname || "", site: g.site, reqs: g.reqs, n: g.students.length, cleared: g.students.filter(s => s.cleared).length, not: g.students.filter(s => s.cleared === false).map(s => ({ id: s.id, name: s.name, missing: s.missing })) }) }
        await vlog(env, req, C, "view", "days", sid, { n: out.length }, 1); return J({ from, to, days: out });
      }
      if (what === "day" && seg[3]) {
        const day = await env.DB.prepare("SELECT d.*, g.instructor_id FROM clinical_days d LEFT JOIN clin_groups g ON g.id=d.group_id WHERE d.id=? AND d.school_id=?").bind(seg[3], sid).first(); if (!day) return J({ error: "Not found" }, 404);
        if (C.role === "instructor" && day.instructor_id !== uid && day.by_id !== uid) return J({ error: "Not allowed." }, 403);
        if (M === "PUT") { if (!canWrite(C)) return J({ error: "Not allowed." }, 403); const b = await body(); const site = cl(b.site_id, 40); if (site) { if (!(await env.DB.prepare("SELECT id FROM vault_sites WHERE id=? AND school_id=?").bind(site, sid).first())) return J({ error: "Unknown site." }, 400); await env.DB.prepare("INSERT INTO vault_daysite (day_id, school_id, site_id, by_id, at) VALUES (?,?,?,?,?) ON CONFLICT(day_id) DO UPDATE SET site_id=excluded.site_id, by_id=excluded.by_id, at=excluded.at").bind(day.id, sid, site, uid, t).run() } else await env.DB.prepare("DELETE FROM vault_daysite WHERE day_id=?").bind(day.id).run(); await vlog(env, req, C, "link_day", "day", day.id, { site }); return J({ ok: true }) }
        if (M === "GET") { const g = await gate(env, sid, day.id); if (C.role === "instructor") { const mine = await myGroupStudents(env, C); g.students = g.students.filter(s => mine.has(s.id) || day.by_id === uid) } await vlog(env, req, C, "view", "day", day.id, null, 1); return J(g) }
      }
      /* clearance for a set of people at a site (used by the instructor hub's clinical day view) */
      if (what === "clear" && M === "POST") {
        const b = await body(); const ids = [...new Set((Array.isArray(b.ids) ? b.ids : []).map(x => cl(x, 40)).filter(Boolean))].slice(0, 200); const at = dOr(b.date) || todayUTC();
        const sites = (await env.DB.prepare("SELECT id, name FROM vault_sites WHERE school_id=? AND status='active' AND eie=0").bind(sid).all()).results || [];
        const site = b.day_id ? await siteForDay(env, sid, { id: cl(b.day_id, 40), site: cl(b.site_text, 200) }, sites) : await siteForDay(env, sid, { id: "", site: cl(b.site_text, 200) }, sites);
        let allow = ids; if (C.role === "instructor") { const mine = await myGroupStudents(env, C); allow = ids.filter(i => mine.has(i)) }
        const reqs = await reqsOf(env, sid, site ? site.id : "", "student"); const items = await itemsOf(env, sid, allow);
        const out = allow.map(id => { const its = items.filter(i => i.user_id === id); const miss = reqs.filter(q => !OKST(cellFor(q, its, at).st)).map(q => q.label); return { id, cleared: reqs.length ? !miss.length : null, missing: miss } });
        await vlog(env, req, C, "view", "clear", site ? site.id : "", { n: out.length }, 1); return J({ site: site ? { id: site.id, name: site.name } : null, at, reqs: reqs.length, people: out });
      }

      /* requirement items: queue, per-person, review, record on behalf */
      if (what === "queue" && M === "GET") { if (!["admin", "coord", "site"].includes(C.role)) return J({ error: "Not allowed." }, 403); const R = (await env.DB.prepare("SELECT i.*, u.name uname FROM vault_items i LEFT JOIN users u ON u.id=i.user_id WHERE i.school_id=? AND i.status='submitted' AND i.eie=0 ORDER BY i.created LIMIT 300").bind(sid).all()).results || []; await vlog(env, req, C, "view", "queue", sid, { n: R.length }, 1); return J({ items: R.map(i => Object.assign(itemView(i, true), { name: i.uname || "Person" })) }) }
      if (what === "person" && seg[3] && M === "GET") {
        if (!["admin", "coord", "site"].includes(C.role)) return J({ error: "Not allowed." }, 403);
        const m = await env.DB.prepare("SELECT m.role, u.name FROM school_members m JOIN users u ON u.id=m.user_id WHERE m.school_id=? AND m.user_id=?").bind(sid, seg[3]).first(); if (!m) return J({ error: "Not found" }, 404);
        if (C.role === "coord" && m.role !== "student" && m.role !== "instructor") return J({ error: "Not allowed." }, 403);
        const its = (await env.DB.prepare("SELECT * FROM vault_items WHERE school_id=? AND user_id=? ORDER BY updated DESC").bind(sid, seg[3]).all()).results || [];
        const files = its.length ? ((await env.DB.prepare(`SELECT * FROM vault_blobs WHERE owner='item' AND owner_id IN (${qs(its.length)}) ORDER BY ver DESC`).bind(...its.map(i => i.id)).all()).results || []) : [];
        const revs = its.length ? ((await env.DB.prepare(`SELECT * FROM vault_reviews WHERE item_id IN (${qs(its.length)}) ORDER BY at DESC`).bind(...its.map(i => i.id)).all()).results || []) : [];
        await vlog(env, req, C, "view", "person", seg[3], null, 1);
        return J({ person: { id: seg[3], name: m.name, role: m.role }, can: { eie: canWrite(C), access: C.role === "admin" }, items: its.map(i => Object.assign(itemView(i, true), { files: files.filter(f => f.owner_id === i.id).map(blobView), reviews: revs.filter(v => v.item_id === i.id).map(v => ({ id: v.id, decision: v.decision, reason: v.reason || "", by: v.by_name || "", at: v.at, eie: eieOf(v) })) })) });
      }
      if (what === "items" && seg[3] && seg[4] === "link" && M === "POST") { const b = await body(); const blob = await env.DB.prepare("SELECT * FROM vault_blobs WHERE id=? AND owner='item' AND owner_id=? AND school_id=? AND deleted=0").bind(cl(b.blob, 40), seg[3], sid).first(); if (!blob) return J({ error: "Not found" }, 404); return linkFor(env, req, C, blob, b.mode) }
      if (what === "items") {
        if (!canWrite(C)) return J({ error: "Not allowed." }, 403);
        if (!seg[3] && M === "POST") { /* staff records an item from source records (status/dates/verifier only) */
          const b = await body(); const u = cl(b.user_id, 40); const m = await env.DB.prepare("SELECT role FROM school_members WHERE school_id=? AND user_id=? AND status='active'").bind(sid, u).first(); if (!m) return J({ error: "Pick a person in this program." }, 400);
          const code = cl(b.code, 20); if (!(await env.DB.prepare("SELECT id FROM vault_reqs WHERE school_id=? AND code=? LIMIT 1").bind(sid, code).first())) return J({ error: "Add that requirement to a checklist first." }, 400);
          const o = cleanItem(b); if (!o.done_on && !b.waived) return J({ error: "Enter the date it was done." }, 400);
          const id = "vi_" + hexId(10); const prev = await env.DB.prepare("SELECT id FROM vault_items WHERE school_id=? AND user_id=? AND code=? AND eie=0 ORDER BY created DESC LIMIT 1").bind(sid, u, code).first();
          await env.DB.prepare("INSERT INTO vault_items (id, school_id, user_id, code, status, done_on, expires, method, outcome, attest, attest_at, waived, verifier_id, verifier_name, verified_at, by_id, by_name, created, updated, supersedes) VALUES (?,?,?,?, 'approved', ?,?,?,?,1,?,?,?,?,?,?,?,?,?,?)").bind(id, sid, u, code, o.done_on, o.expires, o.method, o.outcome, t, b.waived ? 1 : 0, uid, cl(me.name, 80), t, uid, cl(me.name, 80), t, t, prev ? prev.id : null).run();
          await env.DB.prepare("INSERT INTO vault_reviews (id, school_id, item_id, decision, reason, by_id, by_name, at) VALUES (?,?,?, 'approved', 'Recorded from source records', ?,?,?)").bind("vr_" + hexId(8), sid, id, uid, cl(me.name, 80), t).run();
          await vlog(env, req, C, "record", "item", id, { code, user: u, waived: !!b.waived }, 1); return J({ ok: true, id }, 201);
        }
        if (seg[3]) {
          const it = await env.DB.prepare("SELECT * FROM vault_items WHERE id=? AND school_id=?").bind(seg[3], sid).first(); if (!it) return J({ error: "Not found" }, 404);
          if (seg[4] === "review" && M === "POST") { const b = await body(); if (it.status !== "submitted" || it.eie) return J({ error: it.eie ? "This item is marked entered in error." : "This item was already reviewed." }, 409); if (it.user_id === uid) return J({ error: "Someone else must verify your own items." }, 403);
            if (b.ok) { const o = cleanItem(Object.assign({ done_on: it.done_on, expires: it.expires, method: it.method, outcome: it.outcome }, b)); await env.DB.prepare("UPDATE vault_items SET status='approved', done_on=?, expires=?, outcome=?, waived=?, verifier_id=?, verifier_name=?, verified_at=?, reason=NULL, updated=? WHERE id=?").bind(o.done_on, o.expires, o.outcome, b.waived ? 1 : 0, uid, cl(me.name, 80), t, t, it.id).run(); await env.DB.prepare("INSERT INTO vault_reviews (id, school_id, item_id, decision, reason, by_id, by_name, at) VALUES (?,?,?, 'approved', ?,?,?,?)").bind("vr_" + hexId(8), sid, it.id, cl(b.note, 300) || null, uid, cl(me.name, 80), t).run(); await vlog(env, req, C, "approve", "item", it.id, { code: it.code }, 1); return J({ ok: true }) }
            const reason = cl(b.reason, 300); if (!reason) return J({ error: "Say why, so the person can fix it." }, 400);
            await env.DB.prepare("UPDATE vault_items SET status='rejected', reason=?, verifier_id=?, verifier_name=?, verified_at=?, updated=? WHERE id=?").bind(reason, uid, cl(me.name, 80), t, t, it.id).run(); await env.DB.prepare("INSERT INTO vault_reviews (id, school_id, item_id, decision, reason, by_id, by_name, at) VALUES (?,?,?, 'rejected', ?,?,?,?)").bind("vr_" + hexId(8), sid, it.id, reason, uid, cl(me.name, 80), t).run(); await vlog(env, req, C, "reject", "item", it.id, { code: it.code }, 1); return J({ ok: true }) }
          if (seg[4] === "file" && M === "POST") { if (it.eie) return J({ error: "This entry is marked entered in error." }, 409); const rq = (await env.DB.prepare("SELECT sens FROM vault_reqs WHERE school_id=? AND code=? LIMIT 1").bind(sid, it.code).first()) || {}; return putBlob(env, C, "item", it.id, req, rq.sens || "") }
          if (!seg[4] && M === "DELETE") return NODEL();
        }
      }

      /* people (preceptors and other non-account people) */
      if (what === "people") {
        if (!lib) return J({ error: "Not allowed." }, 403);
        if (!seg[3] && M === "GET") { const R = (await env.DB.prepare("SELECT * FROM vault_people WHERE school_id=? ORDER BY status, name").bind(sid).all()).results || []; const fac = C.role === "coord" ? [] : await roster(env, sid, "instructor"); const stu = await roster(env, sid, "student"); return J({ people: R.map(p => ({ id: p.id, kind: p.kind, name: p.name, email: p.email || "", title: p.title || "", site_id: p.site_id || "", license_type: p.license_type || "", license_state: p.license_state || "", license_exp: p.license_exp || "", verified_on: p.verified_on || "", status: p.status, eie: eieOf(p) })), faculty: fac, students: stu }) }
        if (!canWrite(C)) return J({ error: "Not allowed." }, 403); const b = await body();
        const vals = [["preceptor", "other"].includes(b.kind) ? b.kind : "preceptor", cl(b.name, 120), cl(b.email, 160), cl(b.title, 120), cl(b.site_id, 40), cl(b.license_type, 10), cl(b.license_state, 2).toUpperCase(), dOr(b.license_exp), dOr(b.verified_on), cl(b.note, 1000)];
        if (/\b\d{6,}\b/.test(cl(b.note, 1000))) return J({ error: "Don't store license numbers here. Record the verification date instead." }, 400);
        if (!seg[3] && M === "POST") { if (!vals[1]) return J({ error: "Enter a name." }, 400); const id = "vp_" + hexId(8); await env.DB.prepare("INSERT INTO vault_people (kind, name, email, title, site_id, license_type, license_state, license_exp, verified_on, note, id, school_id, by_id, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(...vals, id, sid, uid, t, t).run(); await vlog(env, req, C, "create", "person", id, null); return J({ ok: true, id }, 201) }
        if (seg[3] && M === "PUT") { await env.DB.prepare("UPDATE vault_people SET kind=?, name=?, email=?, title=?, site_id=?, license_type=?, license_state=?, license_exp=?, verified_on=?, note=?, status=?, updated=? WHERE id=? AND school_id=?").bind(...vals.slice(0, 10).map((v, i) => i === 1 && !v ? "Preceptor" : v), b.status === "inactive" ? "inactive" : "active", t, seg[3], sid).run(); await vlog(env, req, C, "update", "person", seg[3], null); return J({ ok: true }) }
      }

      /* documents */
      if (what === "docs") {
        if (!lib) return J({ error: "Not allowed." }, 403);
        if (!seg[3] && M === "GET") {
          const cat = cl(url.searchParams.get("cat") || "", 12), site = cl(url.searchParams.get("site") || "", 40), person = cl(url.searchParams.get("person") || "", 40), q = cl(url.searchParams.get("q") || "", 80).toLowerCase();
          let R = (await env.DB.prepare("SELECT * FROM vault_docs WHERE school_id=? AND deleted=0 ORDER BY COALESCE(NULLIF(effective,''), '0000') DESC, created DESC LIMIT 2000").bind(sid).all()).results || [];
          R = R.filter(d => canCat(C, d.cat, d.type, "meta") && (!cat || d.cat === cat) && (!site || d.site_id === site) && (!person || d.person_id === person) && (!q || (d.title + " " + (d.person_name || "") + " " + (d.tags || "") + " " + (((TYPES[d.cat] || {})[d.type] || {}).label || "")).toLowerCase().includes(q)));
          await vlog(env, req, C, "list", "docs", cat || "all", { n: R.length }); return J({ docs: R.map(d => docView(d)) });
        }
        if (!seg[3] && M === "POST") {
          const b = await body(); if (phiHit([b.title, b.note, b.person_name].join(" "))) return J({ error: "That text looks like it contains protected health information (an MRN, date of birth or SSN). Remove it; the vault is not for patient information.", code: "phi" }, 400); const o = cleanDoc(b, {}); if (!CATS[o.cat] || !(TYPES[o.cat] || {})[o.type]) return J({ error: "Pick a category and document type." }, 400);
          if (!canCat(C, o.cat, o.type, "write") || ro) return J({ error: "You can't add this kind of document." }, 403);
          if (!o.title) o.title = TYPES[o.cat][o.type].label; if (o.site_id && !(await env.DB.prepare("SELECT id FROM vault_sites WHERE id=? AND school_id=?").bind(o.site_id, sid).first())) return J({ error: "Unknown site." }, 400);
          const id = "vd_" + hexId(10); const d = Object.assign({ id, school_id: sid, rev: 1, files: 0, hold: 0, deleted: 0, sample: 0, by_id: uid, created: t, updated: t, owner_id: uid, owner_name: cl(me.name, 80), status: "active", auto_renew: 0 }, o);
          await env.DB.prepare(`INSERT INTO vault_docs (id, school_id, ${DOCF.join(", ")}, rev, by_id, created, updated) VALUES (?,?,${qs(DOCF.length)},1,?,?,?)`).bind(id, sid, ...DOCF.map(k => d[k] === undefined ? null : d[k]), uid, t, t).run();
          await snapDoc(env, C, d); await vlog(env, req, C, "create", "doc", id, { cat: o.cat, type: o.type }); return J({ ok: true, id }, 201);
        }
        if (seg[3]) {
          const d = await env.DB.prepare("SELECT * FROM vault_docs WHERE id=? AND school_id=? AND deleted=0").bind(seg[3], sid).first(); if (!d) return J({ error: "Not found" }, 404);
          if (!canCat(C, d.cat, d.type, "meta")) return J({ error: "Not allowed." }, 403);
          const w = !ro && canCat(C, d.cat, d.type, "write");
          const EIEB = () => J({ error: "This record is marked entered in error. It stays viewable; add a corrected record, or un-mark it first.", code: "eie" }, 409);
          if (d.eie && M !== "GET" && !["link", "hold"].includes(seg[4])) return EIEB();
          if (!seg[4] && M === "GET") {
            const B = (await env.DB.prepare("SELECT * FROM vault_blobs WHERE owner='doc' AND owner_id=? ORDER BY ver DESC").bind(d.id).all()).results || [];
            const revs = (await env.DB.prepare("SELECT rev, at, by_name FROM vault_docrev WHERE doc_id=? ORDER BY rev DESC LIMIT 50").bind(d.id).all()).results || [];
            const log = C.role === "admin" ? ((await env.DB.prepare("SELECT at, actor_name, actor_role, action, detail FROM vault_audit WHERE school_id=? AND target=? ORDER BY seq DESC LIMIT 200").bind(sid, d.id).all()).results || []) : [];
            await vlog(env, req, C, "view", "doc", d.id, null, RESTRICTED(d.cat, d.type) || HEALTHDOC(d.cat, d.type) || d.cat === "student");
            return J({ doc: docView(d, true), files: B.map(blobView), revs, log, can: { write: w, file: canCat(C, d.cat, d.type, "file"), eie: w, hold: C.role === "admin", access: C.role === "admin" }, storage: await storage(env), hipaa: await hipaaOn(env, sid), phi_notice: PHI_NOTICE, minimized: HEALTHDOC(d.cat, d.type) && !C.settings.store_health });
          }
          if (!seg[4] && M === "PUT") {
            if (!w) return J({ error: "Not allowed." }, 403); const b = await body(); delete b.cat; if (phiHit([b.title, b.note, b.person_name].join(" "))) return J({ error: "That text looks like it contains protected health information (an MRN, date of birth or SSN). Remove it; the vault is not for patient information.", code: "phi" }, 400); const o = cleanDoc(b, d); if (o.type !== d.type && !(TYPES[d.cat] || {})[o.type]) return J({ error: "Unknown document type." }, 400);
            o.rev = d.rev + 1; o.updated = t; await env.DB.prepare(`UPDATE vault_docs SET ${DOCF.filter(k => k !== "cat").map(k => k + "=?").join(", ")}, rev=?, updated=? WHERE id=?`).bind(...DOCF.filter(k => k !== "cat").map(k => o[k] === undefined ? null : o[k]), o.rev, t, d.id).run();
            const ch = DOCF.filter(k => String(o[k] == null ? "" : o[k]) !== String(d[k] == null ? "" : d[k]) && k !== "note"); await snapDoc(env, C, o); await vlog(env, req, C, "update", "doc", d.id, { rev: o.rev, fields: ch }); return J({ ok: true, rev: o.rev });
          }
          if (seg[4] === "rev" && seg[5] && M === "GET") { const r = await env.DB.prepare("SELECT rev, at, by_name, snap FROM vault_docrev WHERE doc_id=? AND rev=?").bind(d.id, int(seg[5], 1, 1e6, 0)).first(); if (!r) return J({ error: "Not found" }, 404); await vlog(env, req, C, "view_version", "doc", d.id, { rev: r.rev }, RESTRICTED(d.cat, d.type) || d.cat === "student"); return J({ rev: r.rev, at: r.at, by: r.by_name || "", doc: pj(r.snap, {}) }) }
          if (seg[4] === "sign" && M === "POST") { if (!w) return J({ error: "Not allowed." }, 403); const b = await body(); const o = cleanDoc({ signed_on: b.signed_on, signers: b.signers, status: "signed" }, d); if (!o.signed_on) return J({ error: "Enter the date it was signed." }, 400); if (!pj(o.signers, []).length) return J({ error: "Add at least one signer." }, 400); o.rev = d.rev + 1; await env.DB.prepare("UPDATE vault_docs SET signed_on=?, signers=?, status='signed', rev=?, updated=? WHERE id=?").bind(o.signed_on, o.signers, o.rev, t, d.id).run(); await snapDoc(env, C, Object.assign({}, d, o)); await vlog(env, req, C, "mark_signed", "doc", d.id, { on: o.signed_on, n: pj(o.signers, []).length }); return J({ ok: true }) }
          if (seg[4] === "hold" && M === "POST") { if (C.role !== "admin") return J({ error: "School admin only." }, 403); const b = await body(); await env.DB.prepare("UPDATE vault_docs SET hold=?, hold_reason=?, updated=? WHERE id=?").bind(b.on ? 1 : 0, b.on ? cl(b.reason, 200) || "Legal hold" : null, t, d.id).run(); await vlog(env, req, C, b.on ? "hold_on" : "hold_off", "doc", d.id, null); return J({ ok: true }) }
          if (seg[4] === "file" && M === "POST") { if (!w) return J({ error: "Not allowed." }, 403); return putBlob(env, C, "doc", d.id, req, HEALTHDOC(d.cat, d.type) ? "health" : "") }
          if (seg[4] === "link" && M === "POST") { if (!canCat(C, d.cat, d.type, "file")) { await vlog(env, req, C, "link_denied", "doc", d.id, null); return J({ error: C.role === "site" ? "Vexcura staff can't open school documents unless the school grants support access." : "Not allowed." }, 403) } const b = await body(); const blob = await env.DB.prepare("SELECT * FROM vault_blobs WHERE id=? AND owner='doc' AND owner_id=? AND deleted=0").bind(cl(b.blob, 40), d.id).first(); if (!blob) return J({ error: "Not found" }, 404); return linkFor(env, req, C, blob, b.mode) }
          if (!seg[4] && M === "DELETE") return NODEL();
        }
      }
      /* Needs attention queue + acknowledge / resolve (with a note) */
      if (what === "attention" && M === "GET") { if (!lib) return J({ error: "Not allowed." }, 403); const A = await attention(env, C); await vlog(env, req, C, "view", "attention", sid, { n: A.items.length }, 1); return J(A) }
      if (what === "attention" && seg[3] === "ack" && M === "POST") {
        if (!canWrite(C)) return J({ error: "Not allowed." }, 403); const b = await body(); const key = cl(b.key, 200); const st = ["ack", "resolved", "open"].includes(b.state) ? b.state : "ack"; const note = cl(b.note, 500);
        if (!key) return J({ error: "Missing item." }, 400); if (st !== "open" && note.length < 2) return J({ error: "Add a note." }, 400);
        if (st === "open") await env.DB.prepare("DELETE FROM vault_acks WHERE school_id=? AND key=?").bind(sid, key).run();
        else await env.DB.prepare("INSERT INTO vault_acks (school_id, key, state, note, by_id, by_name, at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(school_id, key) DO UPDATE SET state=excluded.state, note=excluded.note, by_id=excluded.by_id, by_name=excluded.by_name, at=excluded.at").bind(sid, key, st, note, uid, cl(me.name, 80), t).run();
        await vlog(env, req, C, st === "resolved" ? "attention_resolve" : st === "open" ? "attention_reopen" : "attention_ack", "attention", key.slice(0, 80), { note }); return J({ ok: true });
      }
      /* Mark in error / un-mark (every record kind); reason required both ways */
      if (what === "eie" && M === "POST") {
        const b = await body(); const kind = cl(b.kind, 12); const tb = EIE_T[kind]; const id = cl(b.id, 40); const reason = cl(b.reason, 300); const on = b.on !== false;
        if (!tb) return J({ error: "Unknown record type." }, 400); if (reason.length < 3) return J({ error: "Give a reason." }, 400);
        const row = await env.DB.prepare("SELECT * FROM " + tb + " WHERE id=? AND school_id=?").bind(id, sid).first(); if (!row) return J({ error: "Not found" }, 404);
        let ok = canWrite(C), sens = 0;
        if (kind === "doc") { ok = ok && canCat(C, row.cat, row.type, "write"); sens = RESTRICTED(row.cat, row.type) || row.cat === "student" }
        if (kind === "version") { if (row.owner === "doc") { const d = await env.DB.prepare("SELECT cat, type FROM vault_docs WHERE id=?").bind(row.owner_id).first(); ok = ok && !!d && canCat(C, d.cat, d.type, "write") } else sens = 1 }
        if (kind === "item" || kind === "review") sens = 1;
        if (!ok) return J({ error: "Not allowed." }, 403);
        if (on === !!row.eie) return J({ error: on ? "Already marked entered in error." : "This record isn't marked in error." }, 409);
        if (on) await env.DB.prepare("UPDATE " + tb + " SET eie=1, eie_reason=?, eie_by=?, eie_by_name=?, eie_at=? WHERE id=?").bind(reason, uid, cl(me.name, 80), t, id).run();
        else await env.DB.prepare("UPDATE " + tb + " SET eie=0, eie_reason=NULL, eie_by=NULL, eie_by_name=NULL, eie_at=NULL WHERE id=?").bind(id).run();
        if (kind === "review") { /* a verification decision entered in error sends the item back for review; un-marking restores it */
          const it = await env.DB.prepare("SELECT * FROM vault_items WHERE id=?").bind(row.item_id).first();
          if (it && on) { const other = await env.DB.prepare("SELECT * FROM vault_reviews WHERE item_id=? AND eie=0 AND id<>? ORDER BY at DESC LIMIT 1").bind(it.id, id).first(); if (other) await env.DB.prepare("UPDATE vault_items SET status=?, reason=?, verifier_id=?, verifier_name=?, verified_at=?, updated=? WHERE id=?").bind(other.decision, other.decision === "rejected" ? other.reason : null, other.by_id, other.by_name, other.at, t, it.id).run(); else await env.DB.prepare("UPDATE vault_items SET status='submitted', reason=NULL, verifier_id=NULL, verifier_name=NULL, verified_at=NULL, updated=? WHERE id=?").bind(t, it.id).run() }
          if (it && !on) await env.DB.prepare("UPDATE vault_items SET status=?, reason=?, verifier_id=?, verifier_name=?, verified_at=?, updated=? WHERE id=?").bind(row.decision, row.decision === "rejected" ? row.reason : null, row.by_id, row.by_name, row.at, t, it.id).run();
        }
        await vlog(env, req, C, on ? "mark_in_error" : "unmark_in_error", kind, kind === "version" ? row.owner_id : kind === "review" ? row.item_id : id, { kind, id, reason }, sens);
        return J({ ok: true });
      }
      /* per-record access history (school admins), like an Epic audit trail */
      if (what === "access" && M === "GET") {
        if (C.role !== "admin") return J({ error: "School admin only." }, 403);
        let ids = (url.searchParams.get("ids") || "").split(",").map(x => cl(x, 80)).filter(Boolean).slice(0, 50); const person = cl(url.searchParams.get("person") || "", 40);
        if (person) { const its = (await env.DB.prepare("SELECT id FROM vault_items WHERE school_id=? AND user_id=?").bind(sid, person).all()).results || []; ids = ids.concat([person], its.map(i => i.id)) }
        if (!ids.length) return J({ rows: [] });
        const rows = []; for (let i = 0; i < ids.length; i += 60) { const ch = ids.slice(i, i + 60); rows.push(...(((await env.DB.prepare(`SELECT seq, at, actor_name, actor_role, action, kind, target, detail, ip, sens FROM vault_audit WHERE school_id=? AND target IN (${qs(ch.length)}) ORDER BY seq DESC LIMIT 500`).bind(sid, ...ch).all()).results) || [])) }
        rows.sort((a, b) => b.seq - a.seq); await vlog(env, req, C, "view", "access_history", (person || ids[0]).slice(0, 80), { n: rows.length }, 1);
        return J({ rows: rows.slice(0, 500) });
      }
      /* print / export events from the app (the server already logs views and downloads) */
      if (what === "log" && M === "POST") { const b = await body(); const act = ["print", "export"].includes(b.action) ? b.action : null; if (!act) return J({ error: "Unknown action." }, 400); await vlog(env, req, C, act, cl(b.kind, 20), cl(b.id, 80), { what: cl(b.what, 80) }, 1); return J({ ok: true }) }
      if (what === "audit" && M === "GET") {
        if (!["admin", "site"].includes(C.role)) return J({ error: "School admin only." }, 403);
        if (seg[3] === "verify") { const v = await verifyChain(env, sid); await vlog(env, req, C, "audit_verify", "school", sid, { ok: v.ok, rows: v.rows }); return J(v) }
        const before = int(url.searchParams.get("before"), 0, 1e15, 1e15); const lim = int(url.searchParams.get("limit"), 1, 500, 100);
        const sf = url.searchParams.get("sens") === "1" ? " AND sens=1" : ""; const R = (await env.DB.prepare("SELECT seq, at, actor_name, actor_role, action, kind, target, detail, ip, sens FROM vault_audit WHERE school_id=? AND seq<?" + sf + " ORDER BY seq DESC LIMIT ?").bind(sid, before, lim).all()).results || [];
        await vlog(env, req, C, "view", "audit", sid, null); return J({ rows: R, retention: AUDIT_RETENTION });
      }
      if (what === "sample") {
        if (C.role !== "admin") return J({ error: "School admin only." }, 403);
        if (M === "POST") { const n = ((await env.DB.prepare("SELECT COUNT(*) n FROM vault_sites WHERE school_id=?").bind(sid).first()) || {}).n || 0; if (n) return J({ error: "Sample data can only be loaded into an empty vault." }, 409); await seedSample(env, C); await vlog(env, req, C, "sample_load", "school", sid, null); return J({ ok: true }) }
        if (M === "DELETE") { /* retire sample data: mark every sample record entered in error (nothing is deleted) */ const by = cl(me.name, 80); await env.DB.batch(["vault_docs", "vault_sites", "vault_reqs"].map(tb => env.DB.prepare("UPDATE " + tb + " SET eie=1, eie_reason='Sample data (fictional) retired', eie_by=?, eie_by_name=?, eie_at=? WHERE school_id=? AND sample=1 AND eie=0").bind(uid, by, t, sid))); await vlog(env, req, C, "sample_retire", "school", sid, null); return J({ ok: true }) }
      }
      return J({ error: "Not found" }, 404);
    }
    return J({ error: "Not found" }, 404);
  }
  const reqView = r => ({ id: r.id, site_id: r.site_id, code: r.code, label: r.label, applies: r.applies, fm: r.fm, fd: r.fd, sens: r.sens || "", basis: r.basis || "", note: r.note || "", doc: !!r.doc, eie: eieOf(r) });
  const cleanContacts = L => (Array.isArray(L) ? L : []).slice(0, 12).map(c => ({ role: cl(c && c.role, 80), name: cl(c && c.name, 100), email: cl(c && c.email, 160), phone: cl(c && c.phone, 40) })).filter(c => c.name || c.email || c.phone);
  async function canBlob(env, C, blob) {
    if (blob.owner === "doc") { const d = await env.DB.prepare("SELECT cat, type FROM vault_docs WHERE id=? AND school_id=? AND deleted=0").bind(blob.owner_id, C.sid).first(); return !!d && canCat(C, d.cat, d.type, "file") }
    if (blob.owner === "item") { const it = await env.DB.prepare("SELECT user_id FROM vault_items WHERE id=? AND school_id=?").bind(blob.owner_id, C.sid).first(); if (!it) return false; if (it.user_id === C.uid) return true; if (C.role === "admin" || C.role === "coord") return true; return C.role === "site" && !!C.support }
    return false;
  }
  async function linkFor(env, req, C, blob, mode) {
    const S = await storage(env); if (!S.on) return J({ error: STORE_MSG, code: "nostorage" }, 503);
    if (!(await canBlob(env, C, blob))) { await vlog(env, req, C, "link_denied", blob.owner, blob.owner_id, { blob: blob.id }); return J({ error: "Not allowed." }, 403) }
    const n = ((await env.DB.prepare("SELECT COUNT(*) n FROM vault_audit WHERE school_id=? AND actor_id=? AND action='link' AND at>?").bind(C.sid, C.uid, now() - 600000).first()) || {}).n || 0;
    if (n >= LINK_BURST) { await vlog(env, req, C, "link_throttled", blob.owner, blob.owner_id, null); return J({ error: "Too many downloads in a short time. Wait a few minutes." }, 429) }
    const L = await mkLink(env, { b: blob.id, s: C.sid, u: C.uid, m: mode === "view" ? "view" : "dl" });
    await vlog(env, req, C, "link", blob.owner, blob.owner_id, { blob: blob.id, mode: mode === "view" ? "view" : "dl" }, 1);
    return J({ url: "/api/vault/file/" + L.token, exp: L.exp, ttl: LINK_TTL / 1000 });
  }
  /* for the manual, two-confirmation legal-destruction script only (VAULT-DEPLOY.md section 5); never called by the app */
  const legalLog = (env, sid, target, detail, who) => vlog(env, null, { sid, uid: "site", name: who || "Vexcura site admin", role: "site" }, "legal_destruction", "legal", target, detail, 1);
  return { api, gate, VER, legalLog, _t: { stampPdf, pdfActive, sniff, cellFor, reqExpiry, addMonths, verifyChain, readLink, mkLink, schoolKey, encryptFile, decryptFile, canCat, TYPES, REQS } };
})();
