/* ---- v24 ATS: applicant tracking + public careers portal for independent (1099) clinical education sales reps.
   Inserted INSIDE MOD (uses current, audit, now, sha256; tooMany when present), immediately BEFORE `globalThis.__BADGE = BADGE;`,
   then `globalThis.__ATS = ATS;`.
   Public:  GET /careers · GET /careers/<slug> (JobPosting JSON-LD) · GET /careers/status[?t=] · POST /api/ats/apply ·
            POST /api/ats/status (token actions) · POST /api/ats/status/find (email + code) · sitemap.xml injection via route().
   Admin:   /api/ats/admin/* (site admin only, writes need X-NCLEX:1).
   Never shows the owner's home address, personal email or RN license number. Applicant license numbers are stored as a
   peppered SHA-256 (KV ats:pepper) plus the last 4 characters; only the last 4 ever leave the server.
   No outside posting, no account creation, no vendor calls: job-board "kits" are text for the owner to paste himself. ---- */
const ATS = (() => {
  const J = (o, s, h) => new Response(JSON.stringify(o), { status: s || 200, headers: Object.assign({ "Content-Type": "application/json", "Cache-Control": "no-store" }, h || {}) });
  const ORIGIN = "https://nclexsim.com";
  const ENT = { name: "Vexcura LLC", brand: "Vexcura", street: "27 General Cleburne St.", city: "Ringgold", region: "GA", zip: "30736", phone: "762-677-2802", tel: "+17626772802" };
  const T = () => (typeof now === "function" ? now() : Date.now());
  const STAGES = [["applied", "Applied"], ["screen", "Screen"], ["license", "License verified"], ["interview", "Interview & demo"], ["references", "References"], ["background", "Background (consent)"], ["offer", "Offer"], ["agreement", "Agreement signed"], ["onboarded", "Onboarded"], ["not_selected", "Not selected"], ["withdrawn", "Withdrawn"]];
  const SK = STAGES.map(s => s[0]), SN = Object.fromEntries(STAGES), CLOSED = ["onboarded", "not_selected", "withdrawn"], IDX = k => SK.indexOf(k);
  const RUBRIC = [["clinical", "Clinical credibility"], ["ehr", "EHR breadth"], ["teach", "Teaching / communication"], ["drive", "Sales drive"], ["fit", "Territory fit"]];
  const EHRS = ["Epic", "Cerner/Oracle Health", "MEDITECH", "athenahealth", "eClinicalWorks", "Other"];
  const HEARD = ["Indeed", "LinkedIn", "Google", "Glassdoor", "Handshake", "Nursing association", "Facebook", "Craigslist", "A friend or colleague", "Vexcura website", "Other"];
  const ST = { AL: "Alabama", AK: "Alaska", AZ: "Arizona", AR: "Arkansas", CA: "California", CO: "Colorado", CT: "Connecticut", DE: "Delaware", DC: "District of Columbia", FL: "Florida", GA: "Georgia", HI: "Hawaii", ID: "Idaho", IL: "Illinois", IN: "Indiana", IA: "Iowa", KS: "Kansas", KY: "Kentucky", LA: "Louisiana", ME: "Maine", MD: "Maryland", MA: "Massachusetts", MI: "Michigan", MN: "Minnesota", MS: "Mississippi", MO: "Missouri", MT: "Montana", NE: "Nebraska", NV: "Nevada", NH: "New Hampshire", NJ: "New Jersey", NM: "New Mexico", NY: "New York", NC: "North Carolina", ND: "North Dakota", OH: "Ohio", OK: "Oklahoma", OR: "Oregon", PA: "Pennsylvania", RI: "Rhode Island", SC: "South Carolina", SD: "South Dakota", TN: "Tennessee", TX: "Texas", UT: "Utah", VT: "Vermont", VA: "Virginia", WA: "Washington", WV: "West Virginia", WI: "Wisconsin", WY: "Wyoming" };
  /* current list prices, mirrored from seo/programs.js PLANS (and worker/onb.js DEF_PLANS). Change them there and here together. */
  const PLANS = [{ k: "per_student", name: "Per student", price: 99, unit: "seat", who: "Any size; priced per student seat" }, { k: "site100", name: "Site 100", price: 7500, who: "Up to 100 students" }, { k: "site250", name: "Site 250", price: 15000, who: "101 to 250 students" }, { k: "site500", name: "Site 500", price: 25000, who: "251 to 500 students" }];
  const RATE = { y1: 0.20, renew: 0.10 };
  const FCRA_V = "fcra-1.0";
  const MAXF = 5 * 1024 * 1024;

  /* ---------- helpers ---------- */
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const cl = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
  const ml = (s, n) => String(s == null ? "" : s).replace(/\r\n?/g, "\n").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").replace(/\n{3,}/g, "\n\n").trim().slice(0, n);
  const hex = n => [...crypto.getRandomValues(new Uint8Array(n))].map(b => b.toString(16).padStart(2, "0")).join("");
  const rid = p => p + "_" + hex(8);
  const P = (s, d) => { try { const v = JSON.parse(s); return v == null ? d : v } catch (e) { return d } };
  const EM = /^[^\s@<>()",;:]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;
  const ymd = s => /^\d{4}-\d{2}-\d{2}$/.test(s || "") && !isNaN(Date.parse(s + "T00:00:00Z")) ? s : "";
  const day = t => new Date(t).toISOString().slice(0, 10);
  const dayH = t => { try { return new Date(typeof t === "number" ? t : Date.parse(t + "T12:00:00Z")).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric", timeZone: "UTC" }) } catch (e) { return String(t) } };
  const money = n => "$" + Number(n).toLocaleString("en-US", { minimumFractionDigits: Number(n) % 1 ? 2 : 0, maximumFractionDigits: 2 });
  const r2 = n => Math.round(n * 100) / 100;
  const sha = async s => { if (typeof sha256 === "function") return sha256(s); const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)); return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("") };
  const ipOf_ = req => req.headers.get("CF-Connecting-IP") || "";
  const slugify = s => String(s || "").toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/&/g, " and ").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 70).replace(/-+$/, "");
  const csvCell = v => { let s = String(v == null ? "" : v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s };
  async function limited(env, key, win, max) { /* the site's attempts table + tooMany helper when present */
    try { if (typeof tooMany === "function" && await tooMany(env, key, win, max)) return true; await env.DB.prepare("INSERT INTO attempts (k,at) VALUES (?,?)").bind(key, T()).run() } catch (e) { }
    return false }
  async function pepper(env) { let p = await env.SITE.get("ats:pepper"); if (!p) { p = hex(32); await env.SITE.put("ats:pepper", p) } return p }
  const normLic = s => String(s || "").toUpperCase().replace(/[^A-Z0-9]/g, "");

  /* ---------- schema (lazy) ---------- */
  let ready = false;
  async function init(env) {
    if (ready) return;
    await env.DB.batch([
      env.DB.prepare("CREATE TABLE IF NOT EXISTS ats_territories (id TEXT PRIMARY KEY, name TEXT NOT NULL, states TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'open', rep_app TEXT, rep_name TEXT, note TEXT, sort INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, updated INTEGER NOT NULL)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS ats_posts (id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, title TEXT NOT NULL, territory TEXT, status TEXT NOT NULL DEFAULT 'draft', summary TEXT, body TEXT, reqs TEXT, comp TEXT, remote INTEGER NOT NULL DEFAULT 1, posted INTEGER, valid_through TEXT, by_name TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS ats_applicants (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT, home_state TEXT, lic_type TEXT, lic_state TEXT, lic_states TEXT NOT NULL DEFAULT '[]', lic_hash TEXT, lic_last4 TEXT, years INTEGER, ehrs TEXT NOT NULL DEFAULT '[]', ehr_other TEXT, edu TEXT, sales TEXT, linkedin TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS ats_app_email ON ats_applicants(email)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS ats_apps (id TEXT PRIMARY KEY, person TEXT NOT NULL, post TEXT, terr_pref TEXT, heard TEXT, src TEXT, stage TEXT NOT NULL DEFAULT 'applied', stage_at INTEGER NOT NULL, reason TEXT, scores TEXT NOT NULL DEFAULT '{}', consents TEXT NOT NULL DEFAULT '{}', resume_name TEXT, resume_type TEXT, resume_size INTEGER, tok_hash TEXT, code_hash TEXT, seen INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, updated INTEGER NOT NULL)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS ats_apps_stage ON ats_apps(stage, stage_at)"),
      env.DB.prepare("CREATE UNIQUE INDEX IF NOT EXISTS ats_apps_tok ON ats_apps(tok_hash)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS ats_screen (id TEXT PRIMARY KEY, app TEXT NOT NULL, kind TEXT NOT NULL, status TEXT, data TEXT NOT NULL DEFAULT '{}', by_name TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS ats_screen_app ON ats_screen(app, kind)"),
      env.DB.prepare("CREATE TABLE IF NOT EXISTS ats_activity (id TEXT PRIMARY KEY, app TEXT, post TEXT, kind TEXT NOT NULL, text TEXT NOT NULL, by_name TEXT, at INTEGER NOT NULL)"),
      env.DB.prepare("CREATE INDEX IF NOT EXISTS ats_act_app ON ats_activity(app, at)")]);
    const n = await env.DB.prepare("SELECT COUNT(*) n FROM ats_territories").first();
    if (!n || !n.n) { const t = T(); await env.DB.batch([["t_ga", "Georgia", ["GA"], 1], ["t_tn", "Tennessee", ["TN"], 2], ["t_al", "Alabama", ["AL"], 3]].map(([id, nm, s, o]) => env.DB.prepare("INSERT OR IGNORE INTO ats_territories (id,name,states,status,sort,created,updated) VALUES (?,?,?,'open',?,?,?)").bind(id, nm, JSON.stringify(s), o, t, t))) }
    ready = true;
  }
  const act = (env, app, post, kind, text, by) => env.DB.prepare("INSERT INTO ats_activity (id,app,post,kind,text,by_name,at) VALUES (?,?,?,?,?,?,?)").bind(rid("av"), app || null, post || null, kind, cl(text, 600), by || "", T()).run();

  /* ---------- commission model (single source for the API, the posting copy and the PDF) ---------- */
  function planRev(k, seats) { const p = PLANS.find(x => x.k === k); if (!p) return null; return p.unit ? p.price * Math.max(1, Math.min(5000, Math.round(+seats || 0))) : p.price }
  function calc(o) {
    o = o || {}; const years = Math.max(1, Math.min(10, Math.round(+o.years || 3)));
    const one = (k, seats) => { const rev = planRev(k, seats); if (rev == null) return null; const rows = []; for (let y = 1; y <= years; y++) { const r = y === 1 ? RATE.y1 : RATE.renew; rows.push({ year: y, kind: y === 1 ? "first year" : "renewal", revenue: rev, rate: r, rep: r2(rev * r), net: r2(rev - rev * r) }) }
      const sum = f => r2(rows.reduce((a, x) => a + x[f], 0)); return { plan: k, name: PLANS.find(x => x.k === k).name, seats: PLANS.find(x => x.k === k).unit ? Math.max(1, Math.round(+seats || 0)) : null, revenue: rev, rows, total: { revenue: sum("revenue"), rep: sum("rep"), net: sum("net") } } };
    const plans = PLANS.map(p => one(p.k, p.unit ? (+o.seats || 60) : 0));
    const mix = Array.isArray(o.mix) && o.mix.length ? o.mix : [{ plan: "site100", n: 1 }, { plan: "site250", n: 2 }, { plan: "site500", n: 1 }, { plan: "per_student", n: 1, seats: 60 }];
    const accts = []; mix.slice(0, 50).forEach(m => { for (let i = 0; i < Math.max(0, Math.min(50, Math.round(+m.n || 0))); i++) { const a = one(m.plan, m.seats); if (a) accts.push(a) } });
    const byYear = []; for (let y = 1; y <= years; y++) { const L = accts.map(a => a.rows[y - 1]); byYear.push({ year: y, revenue: r2(L.reduce((s, x) => s + x.revenue, 0)), rep: r2(L.reduce((s, x) => s + x.rep, 0)), net: r2(L.reduce((s, x) => s + x.net, 0)) }) }
    const single = o.plan ? one(o.plan, o.seats) : null;
    return { rates: RATE, years, plans, single, example: { accounts: accts.length, mix, byYear, total: { revenue: r2(byYear.reduce((s, x) => s + x.revenue, 0)), rep: r2(byYear.reduce((s, x) => s + x.rep, 0)), net: r2(byYear.reduce((s, x) => s + x.net, 0)) } },
      timing: "Commission is earned only on money Vexcura has actually collected: it becomes payable on the next monthly statement after the school's check clears the bank. A school that hasn't paid, or a check that bounces, earns nothing yet. If Vexcura refunds a payment, the commission paid on it is deducted from the next statement (clawback). Figures are before Vexcura's own costs and taxes." };
  }
  function compText() {
    const c = calc({ years: 2, seats: 1 }); const g = k => c.plans.find(p => p.plan === k);
    return `Commission only, paid as a 1099 independent contractor. There is no base pay, hourly pay, draw or guaranteed minimum.
- ${Math.round(RATE.y1 * 100)}% of first-year license revenue for each school you bring in
- ${Math.round(RATE.renew * 100)}% of each renewal year while the school stays active and your agreement is in effect
- Paid on a monthly statement after the school's check clears
- If a school's payment is refunded, the commission on it is reversed

Good-faith estimate at current list prices: a Site 100 license (${money(g("site100").revenue)} a year) pays you ${money(g("site100").rows[0].rep)} in year one and ${money(g("site100").rows[1].rep)} each renewal year; Site 250 (${money(g("site250").revenue)}) pays ${money(g("site250").rows[0].rep)} and ${money(g("site250").rows[1].rep)}; Site 500 (${money(g("site500").revenue)}) pays ${money(g("site500").rows[0].rep)} and ${money(g("site500").rows[1].rep)}; per-student licenses (${money(PLANS[0].price)} a seat) pay ${money(r2(PLANS[0].price * RATE.y1))} a seat in year one and ${money(r2(PLANS[0].price * RATE.renew))} a seat at renewal. What you earn depends entirely on the schools you sign.`;
  }
  const TEMPLATE = () => ({
    title: "Clinical Education Sales Representative (RN/LPN) — 1099, Commission",
    slug: "clinical-education-sales-representative",
    summary: "Experienced RNs and LPNs: introduce the nursing programs in your state to Vexcura, the NCLEX-RN readiness platform and academic EHR built by a registered nurse. Independent contractor, commission only, work from home.",
    body: `About Vexcura
Vexcura (nclexsim.com) gives nursing programs NCLEX-RN practice, an academic Epic-style EHR, clinical paperwork and simulation drills in one platform. Students and faculty use it free; the school licenses it. Vexcura was founded by a registered nurse with more than a decade at the bedside.

The role
You represent Vexcura to nursing programs (ADN, BSN and LPN/PN) in your exclusive territory: find the faculty and directors who decide, run demos, and help programs move from a free pilot to a license. You're an independent contractor: you decide how, when and where you work, and you use your own phone, computer and internet.

What you'll do
- Build your own list of nursing programs and decision-makers in your territory
- Run live video demos of the practice EHR and NCLEX tools from a Vexcura demo account
- Answer clinical and EHR questions with the credibility of a working nurse
- Pass interested schools to Vexcura for pricing approval and contracting; only Vexcura LLC signs school contracts
- Keep short notes on your accounts and share new opportunities

Where you work
This role is 100% remote: you work from your own home office. You must live in the territory you apply for. Campus visits are optional and at your own expense unless Vexcura approves an expense in advance.`,
    reqs: `- Active, unencumbered RN or LPN license (we check it on Nursys QuickConfirm or your state board's website)
- At least 3 years of bedside nursing experience
- Hands-on charting in more than one EHR (for example Epic, Cerner/Oracle Health, MEDITECH)
- Teaching, precepting, clinical instructor or staff-education experience preferred
- Comfortable on video calls and presenting to faculty
- Sales or business-development experience is a plus, not required
- Lives in the posted territory
- Your own computer, phone and reliable internet`,
    comp: compText()
  });
  const EEO = `Vexcura LLC is an equal opportunity company. We consider all qualified applicants without regard to race, color, religion, sex (including pregnancy, sexual orientation and gender identity), national origin, age, disability, genetic information, veteran status, or any other status protected by law. If you need an accommodation to apply, call ${ENT.phone}.`;
  const PRIVACY = `What we collect: the information in this form and your resume. Why: only to consider you for this role and, if you're selected, to set up your independent contractor agreement. Your license number is used only to match the public license lookup; we store it scrambled (hashed) and show staff only the last 4 characters. We don't ask for your Social Security number or date of birth; if you become a finalist, the background screening company asks for those directly, and only after you sign a separate authorization. We don't sell your information. We keep applications for up to 2 years and delete them sooner if you ask (call ${ENT.phone}). See the full Privacy Policy at ${ORIGIN}/#privacy.`;
  const ACK = { privacy: "I have read the applicant privacy notice above.", contractor: "I understand this is an independent contractor (1099) role, not employment: I would control my own methods and hours, provide my own equipment, pay my own taxes and expenses, and receive no employee benefits.", commission: "I understand the role is commission only: no base pay, hourly pay or draw, and commission is paid only after the school's payment clears." };
  const FCRA_DISCLOSURE = `Vexcura LLC may obtain a consumer report about you from a consumer reporting agency to evaluate you for engagement as an independent sales representative. The report may include information about your criminal history, verification of your education and work history, and the status of your professional licenses.

The consumer reporting agency is: [name, address, telephone number and website of the consumer reporting agency, to be filled in when Vexcura selects one].

You have the right to request from the consumer reporting agency a copy of any report about you and to dispute information in it that is inaccurate or incomplete.`;
  const FCRA_AUTH = "I have read the Background Check Disclosure. I authorize Vexcura LLC to obtain a consumer report about me from the consumer reporting agency named in the disclosure, to evaluate me for engagement as an independent sales representative.";

  /* ---------- rows ---------- */
  const pubTerr = x => ({ id: x.id, name: x.name, states: P(x.states, []), status: x.status, rep: x.rep_app ? { app: x.rep_app, name: x.rep_name || "" } : null, note: x.note || "", sort: x.sort, updated: x.updated });
  const pubPost = x => ({ id: x.id, slug: x.slug, title: x.title, territory: x.territory || "", status: x.status, summary: x.summary || "", body: x.body || "", reqs: x.reqs || "", comp: x.comp || "", remote: !!x.remote, posted: x.posted || null, valid_through: x.valid_through || "", by: x.by_name || "", created: x.created, updated: x.updated });
  function expired(p) { return p.valid_through && p.valid_through < day(T()) }
  const isLive = p => p && p.status === "open" && !expired(p);
  async function terrs(env) { return ((await env.DB.prepare("SELECT * FROM ats_territories ORDER BY sort, name").all()).results || []).map(pubTerr) }
  async function postStates(env, p) { const L = await terrs(env); if (p.territory) { const t = L.find(x => x.id === p.territory); return t ? t.states : [] } return [...new Set(L.filter(t => t.status !== "closed").flatMap(t => t.states))] }
  const avg = s => { const v = RUBRIC.map(r => +s[r[0]]).filter(n => n >= 1 && n <= 5); return v.length ? Math.round(v.reduce((a, b) => a + b, 0) / v.length * 10) / 10 : null };

  /* ---------- text -> HTML (posting copy is plain text: blank-line paragraphs, "- " bullets, short lines as headings) ---------- */
  function blocks(txt) {
    const out = []; String(txt || "").split(/\n{2,}/).forEach(chunk => { const L = chunk.split("\n").map(s => s.trim()).filter(Boolean); let i = 0;
      if (L.length > 1 && !/^[-*•]\s/.test(L[0]) && L[0].length <= 60 && !/[.:;]$/.test(L[0])) { out.push({ h: L[0] }); i = 1 }
      let ul = null; for (; i < L.length; i++) { const m = L[i].match(/^[-*•]\s+(.*)$/); if (m) { if (!ul) { ul = []; out.push({ ul }) } ul.push(m[1]) } else { ul = null; out.push({ p: L[i] }) } } });
    return out }
  const toHTML = (txt, hTag) => blocks(txt).map(b => b.h ? `<${hTag || "h3"}>${esc(b.h)}</${hTag || "h3"}>` : b.ul ? `<ul>${b.ul.map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : `<p>${esc(b.p)}</p>`).join("");
  const toLD = txt => blocks(txt).map(b => b.h ? `<p><strong>${esc(b.h)}</strong></p>` : b.ul ? `<ul>${b.ul.map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : `<p>${esc(b.p)}</p>`).join("");
  const toPlain = txt => blocks(txt).map(b => b.h ? b.h.toUpperCase() : b.ul ? b.ul.map(x => "• " + x).join("\n") : b.p).join("\n\n");

  /* ---------- JobPosting JSON-LD (Google Job Search) ---------- */
  async function jobLD(env, p, base) {
    const states = await postStates(env, p); const url = (base || ORIGIN) + "/careers/" + p.slug;
    const desc = `<p>${esc(p.summary)}</p>` + toLD(p.body) + `<p><strong>Requirements</strong></p>` + toLD(p.reqs) + `<p><strong>Compensation</strong></p>` + toLD(p.comp) + `<p>${esc(EEO)}</p>`;
    const o = { "@context": "https://schema.org/", "@type": "JobPosting", title: p.title.replace(/\s+[—–-]\s+1099.*$/, "").trim() || p.title, description: desc, identifier: { "@type": "PropertyValue", name: ENT.name, value: p.id },
      datePosted: day(p.posted || p.created), employmentType: "CONTRACTOR",
      hiringOrganization: { "@type": "Organization", name: ENT.name, sameAs: ORIGIN, logo: ORIGIN + "/apple-touch-icon.png" },
      directApply: true, url,
      /* No baseSalary: Google requires it to be the actual base pay, and this role has none (commission only). The commission terms
         are stated in incentiveCompensation and in the description. */
      incentiveCompensation: `Commission only: ${Math.round(RATE.y1 * 100)}% of first-year license revenue and ${Math.round(RATE.renew * 100)}% of each renewal while the account is active, paid after the school's payment clears. No base pay.`,
      experienceRequirements: { "@type": "OccupationalExperienceRequirements", monthsOfExperience: 36 },
      industry: "Health care education software", occupationalCategory: "41-4011.00 Sales Representatives, Wholesale and Manufacturing, Technical and Scientific Products" };
    if (p.valid_through) o.validThrough = p.valid_through + "T23:59:59-05:00";
    if (p.remote) { o.jobLocationType = "TELECOMMUTE"; o.applicantLocationRequirements = [{ "@type": "Country", name: "US" }].concat(states.map(s => ({ "@type": "State", name: ST[s] || s }))) }
    else o.jobLocation = (states.length ? states : ["GA"]).map(s => ({ "@type": "Place", address: { "@type": "PostalAddress", addressRegion: s, addressCountry: "US" } }));
    return o;
  }

  /* ---------- public page template: header, footer and CSS copied from a live static page (same approach as daily.js) ---------- */
  const TPL_PATHS = ["/about", "/for-nursing-schools", "/clinical-instructor-tools"];
  let TPL = null, TPLT = 0;
  async function template(env) {
    if (TPL && T() - TPLT < 600000) return TPL;
    let h = null; for (const s of TPL_PATHS) { try { h = await env.SITE.get("p:" + s) } catch (e) { } if (h) break }
    const pick = (re, d) => { const m = h && h.match(re); return m ? m[1] : d };
    TPL = { css: pick(/<link rel="stylesheet" href="(\/s-[a-z0-9]+\.css)">/, ""), nav: pick(/<body>([\s\S]*?)<main>/, `<header class="top"><div class="w"><a class="brand" href="/">Vexcura</a></div></header>`),
      foot: pick(/<\/main>([\s\S]*?)<\/body>/, `<footer class="foot"><div class="w"><p class="legal">© ${new Date(T()).getUTCFullYear()} Vexcura · ${ENT.street}, ${ENT.city}, ${ENT.region} ${ENT.zip} · ${ENT.phone}</p></div></footer>`), ok: !!h };
    if (!TPL.css) TPL.fallbackCss = `<style>:root{--bg:#e9f0f3;--surface:#f7fafb;--sunk:#dde7ec;--ink:#14232b;--muted:#4c6470;--line:#bccdd5;--navy:#103a4f;--navy-ink:#eef4f7;--accent:#1d5670;--accent-ink:#fff;--good:#2f6146;--bad:#9d2a22}body{margin:0;font:17px/1.6 system-ui,sans-serif;color:var(--ink);background:var(--bg)}.w{max-width:1080px;margin:0 auto;padding:0 16px}.top,.foot{background:var(--navy);color:var(--navy-ink);padding:12px 0}.top a,.foot a{color:var(--navy-ink)}.btn{display:inline-flex;background:var(--accent);color:#fff;padding:11px 18px;border:0;border-radius:3px;font-weight:700;text-decoration:none;cursor:pointer}.btn.alt{background:transparent;color:var(--ink);box-shadow:inset 0 0 0 1.5px var(--ink)}.pform{background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:20px}.pform label{display:flex;flex-direction:column;gap:4px;font-weight:600}.pform input,.pform select,.pform textarea{font:inherit;padding:9px 10px;border:1px solid var(--line);border-radius:4px}.pill{display:inline-block;font-size:13px;font-weight:700;background:var(--sunk);padding:2px 9px;border-radius:12px;margin:0 6px 6px 0}.crumb{padding-top:14px;font-size:14px}</style>`;
    TPLT = T(); return TPL;
  }
  const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
  const HTMLH = (o) => Object.assign({ "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=120", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "strict-origin-when-cross-origin", "X-Frame-Options": "DENY", "Content-Security-Policy": CSP }, o || {});
  const ld = o => `<script type="application/ld+json">${JSON.stringify(o).replace(/</g, "\\u003c")}</script>`;
  function head(Tp, o) { /* mirrors seo/gen.js page() <head>, like DAILY.head(); keep in sync */
    const url = ORIGIN + o.path, og = ORIGIN + "/og/default.png";
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>${esc(o.title)}</title><meta name="description" content="${esc(o.desc)}"><link rel="canonical" href="${url}">
<meta name="robots" content="${o.noindex ? "noindex,nofollow" : "index,follow,max-image-preview:large,max-snippet:-1"}"><meta name="theme-color" content="#103a4f">
<meta property="og:type" content="website"><meta property="og:locale" content="en_US"><meta property="og:site_name" content="Vexcura"><meta property="og:title" content="${esc(o.title)}"><meta property="og:description" content="${esc(o.desc)}"><meta property="og:url" content="${url}"><meta property="og:image" content="${og}"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630"><meta property="og:image:alt" content="${esc(o.title)}">
<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="${esc(o.title)}"><meta name="twitter:description" content="${esc(o.desc)}"><meta name="twitter:image" content="${og}">
<link rel="icon" href="/favicon.ico"><link rel="apple-touch-icon" href="/apple-touch-icon.png"><link rel="manifest" href="/manifest.webmanifest"><meta name="application-name" content="Vexcura">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=IM+Fell+English&family=Source+Sans+3:wght@400;600;700&display=swap" onload="this.onload=null;this.rel='stylesheet'"><noscript><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IM+Fell+English&family=Source+Sans+3:wght@400;600;700&display=swap"></noscript>
${Tp.css ? `<link rel="stylesheet" href="${Tp.css}">` : Tp.fallbackCss}${(o.ld || []).map(ld).join("")}${CCSS}</head><body>${Tp.nav}<main>`;
  }
  const CCSS = `<style>.vxc .pills{margin:0 0 14px}.vxc .pill{background:rgba(255,255,255,.12);color:inherit}.vxc-body h2{margin-top:30px}.vxc-body h3{font-size:19px;margin:22px 0 6px}.vxc-card{display:block;background:var(--surface);border:1px solid var(--line);border-top:4px solid var(--accent);padding:16px 18px;margin:0 0 14px;text-decoration:none;color:var(--ink);border-radius:4px}.vxc-card b{font-size:20px;display:block;color:var(--accent)}.vxc-card small{color:var(--muted)}.vxc-steps{counter-reset:s;list-style:none;padding:0}.vxc-steps li{counter-increment:s;position:relative;padding:4px 0 10px 40px}.vxc-steps li::before{content:counter(s);position:absolute;left:0;top:2px;width:28px;height:28px;border-radius:50%;background:var(--accent);color:var(--accent-ink);display:grid;place-items:center;font-weight:700;font-size:15px}
.vxc-est{border-collapse:collapse;width:100%;font-size:15.5px;margin:8px 0 6px}.vxc-est th,.vxc-est td{border:1px solid var(--line);padding:7px 9px;text-align:left}.vxc-est th{background:var(--sunk)}.vxc-tw{overflow-x:auto}
.vxc-form label:not(.ck){display:block}.vxc-form label:not(.ck)>input,.vxc-form label:not(.ck)>select,.vxc-form label:not(.ck)>textarea{display:block;width:100%;margin-top:5px;box-sizing:border-box}.vxc-form label:not(.ck)>small{display:block;margin-top:3px;font-weight:400}.vxc-form .grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,250px),1fr));gap:12px 16px;margin:10px 0}.vxc-form label small{font-weight:400;color:var(--muted)}.vxc-form fieldset{border:0;padding:0;margin:14px 0 4px;display:flex;flex-wrap:wrap;gap:6px 16px}.vxc-form legend{font-weight:700;margin-bottom:6px;padding:0}.vxc-form label.ck{flex-direction:row;align-items:flex-start;gap:8px;font-weight:400}.vxc-form label.ck input{margin-top:5px;flex:none;width:18px;height:18px}.vxc-form .req{color:var(--bad)}.vxc-form .hp{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}.vxc-form input[type=file]{max-width:100%}.vxc-note{font-size:14.5px;color:var(--muted)}.vxc-ok{background:var(--surface);border:2px solid var(--good);border-radius:6px;padding:18px 20px;margin:20px 0}.vxc-ok code{font-size:17px;font-weight:700;word-break:break-all}.vxc-link{word-break:break-all}.vxc-err{color:var(--bad);font-weight:600}
.vxc-track{list-style:none;padding:0;margin:14px 0;display:grid;gap:6px}.vxc-track li{padding:8px 12px;border:1px solid var(--line);border-radius:4px;background:var(--surface)}.vxc-track li.done{border-left:5px solid var(--good)}.vxc-track li.now{border-left:5px solid var(--accent);font-weight:700}.vxc-track li.todo{color:var(--muted)}.vxc-doc{background:#fff;color:#14232b;border:1px solid var(--line);padding:20px 22px;border-radius:4px;max-width:760px}.vxc-doc h2{margin-top:0}
details.vxc-pn{background:var(--surface);border:1px solid var(--line);border-radius:4px;padding:10px 14px;margin:10px 0}details.vxc-pn summary{cursor:pointer;font-weight:700}</style>`;
  const crumb = cr => `<nav class="crumb w" aria-label="Breadcrumb">${cr.map((c, i) => i < cr.length - 1 ? `<a href="${c[1]}">${esc(c[0])}</a> › ` : `<span>${esc(c[0])}</span>`).join("")}</nav>`;
  const crumbLD = cr => ({ "@context": "https://schema.org", "@type": "BreadcrumbList", itemListElement: cr.map((c, i) => ({ "@type": "ListItem", position: i + 1, name: c[0], item: ORIGIN + c[1] })) });
  const STEPS = ["Apply here (about 10 minutes)", "Short phone or video screen", "We confirm your license on Nursys QuickConfirm or your state board", "Video interview plus a 15-minute mock demo of Vexcura", "Two professional references", "Finalists only: a background check, after you read a separate disclosure and sign a written authorization", "Offer, territory letter and independent sales representative agreement"];

  async function openPosts(env) { const L = ((await env.DB.prepare("SELECT * FROM ats_posts WHERE status='open' ORDER BY posted DESC, created DESC").all()).results || []).map(pubPost); return L.filter(p => !expired(p)) }
  async function listPage(env) {
    const Tp = await template(env), L = await openPosts(env), Tr = await terrs(env); const cr = [["Home", "/"], ["Careers", "/careers"]];
    const tn = p => { const t = Tr.find(x => x.id === p.territory); return t ? t.name : Tr.filter(x => x.status !== "closed").map(x => x.name).join(", ") };
    return head(Tp, { path: "/careers", title: "Careers at Vexcura | Clinical education sales for RNs and LPNs", desc: "Work with Vexcura: independent clinical education sales roles for experienced RNs and LPNs who know nursing education and EHRs.", ld: [crumbLD(cr)] }) +
      `${crumb(cr)}<section class="hero w vxc"><h1>Careers at Vexcura</h1><p class="lead">Vexcura brings NCLEX-RN readiness and an academic EHR to nursing programs. We work with experienced nurses who can show faculty what their students will use.</p></section>
<div class="w vxc-body"><h2>Open positions</h2>${L.length ? L.map(p => `<a class="vxc-card" href="/careers/${p.slug}"><b>${esc(p.title)}</b><span>${esc(p.summary)}</span><br><small>${p.remote ? "Remote" : "In territory"} · ${esc(tn(p))} · 1099 independent contractor · Commission only</small></a>`).join("") : `<p>There are no open positions right now. Check back soon.</p>`}
<h2>How hiring works</h2><ol class="vxc-steps">${STEPS.map(s => `<li>${esc(s)}</li>`).join("")}</ol>
<h2>Already applied?</h2><p><a href="/careers/status">Check your application status</a> with the link or code you received when you applied.</p>
<p class="vxc-note">${esc(EEO)}</p></div></main>${Tp.foot}</body></html>`;
  }
  function estTable() { const c = calc({ years: 2, seats: 1 }); return `<div class="vxc-tw"><table class="vxc-est"><thead><tr><th>School license (list price a year)</th><th>You earn in year one (${Math.round(RATE.y1 * 100)}%)</th><th>Each renewal year (${Math.round(RATE.renew * 100)}%)</th></tr></thead><tbody>${c.plans.map(p => `<tr><td>${esc(p.name)} (${money(p.revenue)}${p.seats ? " per seat" : ""})</td><td>${money(p.rows[0].rep)}${p.seats ? " per seat" : ""}</td><td>${money(p.rows[1].rep)}${p.seats ? " per seat" : ""}</td></tr>`).join("")}</tbody></table></div><p class="vxc-note">Illustration only, at current list prices. Actual commission is figured on what the school actually pays (after any discount Vexcura approves) and is paid only after its check clears. There is no guaranteed minimum.</p>` }
  function applyForm(p, Tr, sts) {
    const opts = (o, sel) => o.map(([v, l]) => `<option value="${esc(v)}"${v === sel ? " selected" : ""}>${esc(l)}</option>`).join("");
    const terrOpts = [["", "No preference"]].concat(Tr.filter(t => t.status !== "closed").map(t => [t.id, t.name + (t.rep ? " (assigned)" : "")]));
    const stateOpts = [["", "Choose a state"]].concat(Object.entries(ST).sort((a, b) => a[1].localeCompare(b[1])));
    const show = [...new Set(sts.concat(Tr.filter(t => t.status !== "closed").flatMap(t => t.states)))].sort();
    return `<form class="pform vxc-form" id="apply" data-slug="${esc(p.slug)}" novalidate>
<h2>Apply</h2><p class="vxc-note">Fields marked <span class="req" aria-hidden="true">*</span><span class="sr-only" style="position:absolute;left:-9999px">with an asterisk</span> are required. It takes about 10 minutes.</p>
<div class="grid2"><label>Full name <span class="req" aria-hidden="true">*</span><input name="name" autocomplete="name" required maxlength="120"></label>
<label>Email <span class="req" aria-hidden="true">*</span><input name="email" type="email" autocomplete="email" required maxlength="254"></label>
<label>Mobile phone <span class="req" aria-hidden="true">*</span><input name="phone" type="tel" autocomplete="tel" required maxlength="30"></label>
<label>State you live in <span class="req" aria-hidden="true">*</span><select name="home_state" required>${opts(stateOpts, "")}</select></label></div>
<fieldset><legend>License type <span class="req" aria-hidden="true">*</span></legend><label class="ck"><input type="radio" name="lic_type" value="RN" required> RN</label><label class="ck"><input type="radio" name="lic_type" value="LPN"> LPN / LVN</label></fieldset>
<div class="grid2"><label>License state (the license you want us to look up) <span class="req" aria-hidden="true">*</span><select name="lic_state" required>${opts(stateOpts, "")}</select></label>
<label>Your license number <span class="req" aria-hidden="true">*</span><input name="lic_no" required maxlength="30" autocomplete="off" spellcheck="false" aria-describedby="lic-help"><small id="lic-help">Your own license, so we can confirm it on Nursys QuickConfirm. We store it scrambled and staff see only the last 4.</small></label></div>
<fieldset><legend>Other states where you hold an active license <small>(optional)</small></legend>${show.map(s => `<label class="ck"><input type="checkbox" name="lic_states" value="${s}"> ${esc(ST[s] || s)}</label>`).join("")}<label class="ck"><input type="checkbox" name="lic_states" value="NLC"> Multistate (compact) license</label></fieldset>
<div class="grid2"><label>Years of bedside experience <span class="req" aria-hidden="true">*</span><input name="years" type="number" min="0" max="60" inputmode="numeric" required></label>
<label>Preferred territory<select name="terr">${opts(terrOpts, p.territory || "")}</select></label></div>
<fieldset><legend>EHRs you've charted in <span class="req" aria-hidden="true">*</span></legend>${EHRS.map(e => `<label class="ck"><input type="checkbox" name="ehrs" value="${esc(e)}"> ${esc(e)}</label>`).join("")}</fieldset>
<label class="full">If other, which EHRs?<input name="ehr_other" maxlength="200"></label>
<label class="full">Education and teaching background <small>(degrees, precepting, clinical instructor, staff educator…)</small><textarea name="edu" rows="3" maxlength="2000"></textarea></label>
<label class="full">Sales or business-development experience <small>(none is fine)</small><textarea name="sales" rows="3" maxlength="2000"></textarea></label>
<div class="grid2"><label>LinkedIn profile <small>(optional)</small><input name="linkedin" type="url" inputmode="url" placeholder="https://www.linkedin.com/in/…" maxlength="300"></label>
<label>How did you hear about this job? <span class="req" aria-hidden="true">*</span><select name="heard" required>${opts([["", "Choose one"]].concat(HEARD.map(h => [h, h])), "")}</select></label></div>
<label class="full">Resume <span class="req" aria-hidden="true">*</span> <small>PDF or Word (.docx), up to 5 MB</small><input name="resume" type="file" accept=".pdf,.docx,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document" required></label>
<details class="vxc-pn"><summary>Applicant privacy notice</summary><p>${esc(PRIVACY)}</p></details>
<fieldset><legend>Before you apply <span class="req" aria-hidden="true">*</span></legend>
<label class="ck"><input type="checkbox" name="ack_privacy" required> ${esc(ACK.privacy)}</label>
<label class="ck"><input type="checkbox" name="ack_contractor" required> ${esc(ACK.contractor)}</label>
<label class="ck"><input type="checkbox" name="ack_commission" required> ${esc(ACK.commission)}</label></fieldset>
<div class="hp" aria-hidden="true"><label>Leave this empty<input name="company_site" tabindex="-1" autocomplete="off"></label></div>
<input type="hidden" name="ts" value="${T()}"><p class="vxc-note">${esc(EEO)}</p>
<p id="apply-msg" class="pmsg" role="status" aria-live="polite"></p><button class="btn" type="submit">Submit application</button></form>
<script>(function(){var f=document.getElementById("apply");if(!f)return;var m=document.getElementById("apply-msg");var src=(new URLSearchParams(location.search).get("src")||"").slice(0,30);
var map={indeed:"Indeed",linkedin:"LinkedIn",google:"Google",glassdoor:"Glassdoor",handshake:"Handshake",facebook:"Facebook",craigslist:"Craigslist",gna:"Nursing association",tna:"Nursing association",asna:"Nursing association"};if(map[src]){f.heard.value=map[src]}
function say(t,bad){m.textContent=t;m.className="pmsg "+(bad?"no vxc-err":"ok")}
f.resume.addEventListener("change",function(){say("")});
f.addEventListener("submit",function(ev){ev.preventDefault();var fd=new FormData(f);var file=f.resume.files[0];
 var need=[["name","your full name"],["email","your email"],["phone","your phone"],["home_state","the state you live in"],["lic_state","your license state"],["lic_no","your license number"],["years","your years of bedside experience"],["heard","how you heard about the job"]];
 for(var i=0;i<need.length;i++){if(!String(fd.get(need[i][0])||"").trim()){say("Enter "+need[i][1]+".",1);f[need[i][0]].focus();return}}
 if(!fd.get("lic_type")){say("Choose RN or LPN.",1);return}if(!fd.getAll("ehrs").length){say("Choose at least one EHR you've charted in.",1);return}
 if(!file){say("Attach your resume (PDF or Word).",1);f.resume.focus();return}if(file.size>5242880){say("Your resume is larger than 5 MB. Save a smaller PDF and try again.",1);return}
 if(!f.ack_privacy.checked||!f.ack_contractor.checked||!f.ack_commission.checked){say("Check all three boxes under \\"Before you apply\\".",1);return}
 var b=f.querySelector("button[type=submit]");b.disabled=true;say("Sending your application…");var rd=new FileReader();rd.onerror=function(){b.disabled=false;say("We couldn't read that file. Try a different copy.",1)};
 rd.onload=function(){var o={slug:f.dataset.slug,src:src,resume:{name:file.name,data:rd.result}};["name","email","phone","home_state","lic_type","lic_state","lic_no","years","terr","ehr_other","edu","sales","linkedin","heard","company_site","ts"].forEach(function(k){o[k]=fd.get(k)||""});o.lic_states=fd.getAll("lic_states");o.ehrs=fd.getAll("ehrs");o.acks={privacy:f.ack_privacy.checked,contractor:f.ack_contractor.checked,commission:f.ack_commission.checked};
  fetch("/api/ats/apply",{method:"POST",headers:{"Content-Type":"application/json","X-NCLEX":"1"},body:JSON.stringify(o)}).then(function(r){return r.json().then(function(j){return{r:r,j:j}})}).then(function(x){if(!x.r.ok){b.disabled=false;say((x.j&&x.j.error)||"Something went wrong. Try again.",1);return}
   var d=document.createElement("div");d.className="vxc-ok";d.setAttribute("role","status");d.innerHTML='<h2>Thank you. Your application is in.</h2><p>Save this private link. It is the only way to check your status and to finish later steps (references and, for finalists, the background check authorization). We can\\'t email it to you yet, so copy it now.</p><p><a class="vxc-link" id="st-link"></a></p><p>Your backup code: <code id="st-code"></code><br><span class="vxc-note">With your email address, this code opens your status page at nclexsim.com/careers/status if you lose the link.</span></p><p><button class="btn" type="button" id="st-copy">Copy link and code</button></p>';
   f.replaceWith(d);var a=d.querySelector("#st-link");a.href=x.j.status_url;a.textContent=x.j.status_url;d.querySelector("#st-code").textContent=x.j.code;d.querySelector("#st-copy").onclick=function(){var t=x.j.status_url+"\\nCode: "+x.j.code;(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){this.textContent="Copied"}.bind(this),function(){})};d.querySelector("h2").setAttribute("tabindex","-1");d.querySelector("h2").focus()}).catch(function(){b.disabled=false;say("We couldn't reach the server. Check your connection and try again.",1)})};rd.readAsDataURL(file)})})();</script>`;
  }
  async function postPage(env, p, base) {
    const Tp = await template(env), Tr = await terrs(env), sts = await postStates(env, p); const path = "/careers/" + p.slug; const cr = [["Home", "/"], ["Careers", "/careers"], [p.title.replace(/\s+[—–-]\s+1099.*$/, ""), path]];
    const where = p.remote ? `Remote · must live in ${sts.map(s => ST[s] || s).join(", ") || "the territory"}` : `In territory · ${sts.map(s => ST[s] || s).join(", ")}`;
    return head(Tp, { path, title: (p.title.replace(/\s+[—–-]\s+1099.*$/, "") + " | Careers at Vexcura").slice(0, 90), desc: cl(p.summary, 160), ld: [crumbLD(cr), await jobLD(env, p, base)] }) +
      `${crumb(cr)}<section class="hero w vxc"><h1>${esc(p.title)}</h1><p class="lead">${esc(p.summary)}</p><p class="pills"><span class="pill">1099 independent contractor</span><span class="pill">Commission only</span><span class="pill">${esc(where)}</span>${p.valid_through ? `<span class="pill">Apply by ${esc(dayH(p.valid_through))}</span>` : ""}</p><div class="cta"><a class="btn" href="#apply">Apply now</a><a class="btn alt" href="/careers">All openings</a></div></section>
<div class="w vxc-body">${toHTML(p.body, "h2")}<h2>Requirements</h2>${toHTML(p.reqs)}<h2>Compensation</h2>${toHTML(p.comp)}${estTable()}
<h2>How hiring works</h2><ol class="vxc-steps">${STEPS.map(s => `<li>${esc(s)}</li>`).join("")}</ol><p class="vxc-note">Posted ${esc(dayH(day(p.posted || p.created)))} by ${esc(ENT.name)}, ${esc(ENT.city)}, ${esc(ENT.region)}. Questions: ${esc(ENT.phone)}.</p>
${applyForm(p, Tr, sts)}</div></main>${Tp.foot}</body></html>`;
  }
  async function closedPage(env, p) { const Tp = await template(env); return head(Tp, { path: "/careers/" + p.slug, title: "Position closed | Careers at Vexcura", desc: "This position is no longer accepting applications.", noindex: true }) + `${crumb([["Home", "/"], ["Careers", "/careers"], ["Closed", "/careers/" + p.slug]])}<section class="hero w vxc"><h1>${esc(p.title)}</h1><p class="lead">This position is no longer accepting applications.</p><div class="cta"><a class="btn" href="/careers">See open positions</a></div></section></main>${Tp.foot}</body></html>` }

  /* ---------- applicant status (magic link) ---------- */
  const PUBSTEPS = [["Received", ["applied"]], ["Under review", ["screen", "license"]], ["Interview and demo", ["interview"]], ["References", ["references"]], ["Background check", ["background"]], ["Offer", ["offer"]], ["Welcome aboard", ["agreement", "onboarded"]]];
  async function appByTok(env, t) { if (!/^[a-f0-9]{48}$/.test(t || "")) return null; return env.DB.prepare("SELECT a.*, p.name pname, p.email pemail FROM ats_apps a JOIN ats_applicants p ON p.id=a.person WHERE a.tok_hash=?").bind(await sha("ats|" + t)).first() }
  async function statusData(env, a) {
    const post = a.post ? await env.DB.prepare("SELECT title, slug FROM ats_posts WHERE id=?").bind(a.post).first() : null;
    const S = (await env.DB.prepare("SELECT kind, status, data FROM ats_screen WHERE app=? AND kind IN ('fcra','reference') ORDER BY created").bind(a.id).all()).results || [];
    const f = S.find(x => x.kind === "fcra"); const refs = S.filter(x => x.kind === "reference").map(x => { const d = P(x.data, {}); return { name: d.name, org: d.org || "", relation: d.relation || "" } });
    const ix = PUBSTEPS.findIndex(s => s[1].indexOf(a.stage) >= 0);
    return { name: a.pname, title: post ? post.title : "Application", stage: a.stage, closed: a.stage === "not_selected" || a.stage === "withdrawn", label: a.stage === "not_selected" ? "Not selected" : a.stage === "withdrawn" ? "Withdrawn" : (PUBSTEPS[ix] || PUBSTEPS[0])[0], steps: PUBSTEPS.map((s, i) => ({ t: s[0], st: ix < 0 ? "todo" : i < ix ? "done" : i === ix ? "now" : "todo" })),
      fcra: f ? { status: f.status, signed: f.status === "signed" ? P(f.data, {}).at : null } : null, refsWanted: (IDX(a.stage) >= IDX("interview") && IDX(a.stage) <= IDX("background")) && refs.length < 2, refs, applied: a.created };
  }
  async function statusPage(env, url) {
    const Tp = await template(env); const t = url.searchParams.get("t") || ""; const doc = url.searchParams.get("doc") || "";
    const H = h => head(Tp, { path: "/careers/status", title: "Application status | Careers at Vexcura", desc: "Check your application status.", noindex: true }) + h + `</main>${Tp.foot}</body></html>`;
    const NH = { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex" };
    const a = t ? await appByTok(env, t) : null;
    if (!a) return new Response(H(`${crumb([["Home", "/"], ["Careers", "/careers"], ["Application status", "/careers/status"]])}<section class="hero w vxc"><h1>Application status</h1><p class="lead">${t ? "That link has expired or was replaced. " : ""}Enter the email you applied with and your backup code.</p></section>
<div class="w"><form class="pform vxc-form" id="find"><div class="grid2"><label>Email<input name="email" type="email" autocomplete="email" required></label><label>Backup code<input name="code" autocomplete="off" required placeholder="XXXX-XXXX" maxlength="12"></label></div><p class="pmsg" id="find-msg" role="status" aria-live="polite"></p><button class="btn">Open my status</button></form></div>
<script>(function(){var f=document.getElementById("find"),m=document.getElementById("find-msg");f.addEventListener("submit",function(e){e.preventDefault();m.textContent="Checking…";fetch("/api/ats/status/find",{method:"POST",headers:{"Content-Type":"application/json","X-NCLEX":"1"},body:JSON.stringify({email:f.email.value,code:f.code.value})}).then(function(r){return r.json().then(function(j){return{r:r,j:j}})}).then(function(x){if(!x.r.ok){m.textContent=x.j.error||"Not found.";m.className="pmsg no";return}location.href=x.j.status_url}).catch(function(){m.textContent="Try again.";m.className="pmsg no"})})})();</script>`), { status: t ? 404 : 200, headers: HTMLH(NH) });
    const d = await statusData(env, a);
    /* stand-alone FCRA disclosure + authorization: nothing else on the page (FCRA 604(b)(2)(A)) */
    if (doc === "fcra" && d.fcra && d.fcra.status === "requested") return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Background Check Disclosure</title>${Tp.css ? `<link rel="stylesheet" href="${Tp.css}">` : Tp.fallbackCss}${CCSS}</head><body><main>` +
      `<div class="w" style="padding:28px 16px"><div class="vxc-doc" id="fcra-disclosure"><h2>Background Check Disclosure</h2>${toHTML(FCRA_DISCLOSURE)}</div>
<form class="vxc-doc pform vxc-form" id="fa" style="margin-top:18px"><h2>Authorization</h2><p>${esc(FCRA_AUTH)}</p><label>Full legal name (your typed name is your signature)<input name="sig" autocomplete="name" required maxlength="120"></label><label class="ck" style="margin-top:10px"><input type="checkbox" name="agree" required> I authorize the background check described above.</label><p class="pmsg" id="fa-msg" role="status" aria-live="polite"></p><p><button class="btn" type="submit">Sign authorization</button> <button class="btn alt" type="button" id="fa-no">I don't authorize</button></p></form>
<script>(function(){var f=document.getElementById("fa"),m=document.getElementById("fa-msg"),t=${JSON.stringify(t)};function go(o){fetch("/api/ats/status",{method:"POST",headers:{"Content-Type":"application/json","X-NCLEX":"1"},body:JSON.stringify(Object.assign({t:t},o))}).then(function(r){return r.json().then(function(j){return{r:r,j:j}})}).then(function(x){if(!x.r.ok){m.textContent=x.j.error||"Try again.";m.className="pmsg no";return}location.href="/careers/status?t="+t})}
f.addEventListener("submit",function(e){e.preventDefault();if(!f.sig.value.trim()||!f.agree.checked){m.textContent="Type your full legal name and check the box.";m.className="pmsg no";return}go({action:"fcra",sig:f.sig.value,agree:true,tz:(Intl.DateTimeFormat().resolvedOptions().timeZone||"")})});document.getElementById("fa-no").onclick=function(){if(confirm("Decline the background check? Vexcura can't continue your application without it."))go({action:"fcra",decline:true})}})();</script></div></main></body></html>`, { headers: HTMLH(NH) });
    const refForm = d.refsWanted ? `<h2>Your references</h2><p>Add two professional references (a charge nurse, manager, instructor or colleague). We'll contact them ourselves. ${d.refs.length ? `Received so far: ${d.refs.map(r => esc(r.name)).join(", ")}.` : ""}</p>
<form class="pform vxc-form" id="rf">${[0, 1].slice(0, 2 - d.refs.length).map(i => `<fieldset style="display:block"><legend>Reference ${d.refs.length + i + 1}</legend><div class="grid2"><label>Name<input name="n${i}" maxlength="120"></label><label>Title and workplace<input name="o${i}" maxlength="160"></label><label>How you worked together<input name="r${i}" maxlength="160"></label><label>Phone<input name="p${i}" type="tel" maxlength="30"></label><label>Email<input name="e${i}" type="email" maxlength="254"></label></div></fieldset>`).join("")}<p class="pmsg" id="rf-msg" role="status" aria-live="polite"></p><button class="btn">Send references</button></form>` : "";
    const fc = d.fcra && d.fcra.status === "requested" ? `<div class="vxc-ok" style="border-color:var(--accent)"><h2>Action needed: background check authorization</h2><p>You're a finalist. Before Vexcura can run a background check, please read the disclosure and sign the authorization. It's on its own page.</p><p><a class="btn" href="/careers/status?t=${t}&amp;doc=fcra">Read the disclosure and sign</a></p><p class="vxc-note">Your rights: <a href="https://www.consumerfinance.gov/learnmore/" rel="noopener">A Summary of Your Rights Under the Fair Credit Reporting Act</a> (Consumer Financial Protection Bureau).</p></div>` : d.fcra && d.fcra.status === "signed" ? `<p class="vxc-note">Background check authorization signed ${esc(dayH(d.fcra.signed))}. Thank you.</p>` : d.fcra && d.fcra.status === "declined" ? `<p class="vxc-note">You declined the background check authorization.</p>` : "";
    return new Response(H(`${crumb([["Home", "/"], ["Careers", "/careers"], ["Application status", "/careers/status"]])}<section class="hero w vxc"><h1>Hi ${esc(String(d.name).split(" ")[0])}</h1><p class="lead">${esc(d.title)} · applied ${esc(dayH(d.applied))}</p><p class="pills"><span class="pill">Status: ${esc(d.label)}</span></p></section>
<div class="w">${fc}${d.closed ? `<p>${d.stage === "withdrawn" ? "You withdrew this application." : "Thank you for applying. We've decided not to move forward with your application for this role. We'll keep it on file for 2 years unless you ask us to delete it."}</p>` : `<ol class="vxc-track">${d.steps.map(s => `<li class="${s.st}">${s.st === "done" ? "✓ " : ""}${esc(s.t)}</li>`).join("")}</ol>`}${d.closed ? "" : refForm}
${d.closed ? "" : `<details class="vxc-pn"><summary>Withdraw my application</summary><p>If you're no longer interested, you can withdraw. This can't be undone.</p><button class="btn alt" type="button" id="wd">Withdraw</button></details>`}
<p class="vxc-note">Keep this link private. Questions: ${esc(ENT.phone)}.</p></div>
<script>(function(){var t=${JSON.stringify(t)};function go(o,m){return fetch("/api/ats/status",{method:"POST",headers:{"Content-Type":"application/json","X-NCLEX":"1"},body:JSON.stringify(Object.assign({t:t},o))}).then(function(r){return r.json().then(function(j){return{r:r,j:j}})}).then(function(x){if(!x.r.ok){if(m){m.textContent=x.j.error||"Try again.";m.className="pmsg no"}return}location.reload()})}
var w=document.getElementById("wd");if(w)w.onclick=function(){if(confirm("Withdraw your application?"))go({action:"withdraw",confirm:true})};
var f=document.getElementById("rf");if(f)f.addEventListener("submit",function(e){e.preventDefault();var L=[];for(var i=0;i<2;i++){if(!f["n"+i])continue;var o={name:f["n"+i].value,org:f["o"+i].value,relation:f["r"+i].value,phone:f["p"+i].value,email:f["e"+i].value};if(o.name.trim())L.push(o)}go({action:"refs",refs:L},document.getElementById("rf-msg"))})})();</script>`), { headers: HTMLH(NH) });
  }

  /* ---------- job-board posting kits (text for the owner to paste; nothing is posted automatically) ---------- */
  const BOARDS = [
    { k: "google", name: "Google for Jobs", cost: "Free · automatic", free: "yes", url: "https://search.google.com/test/rich-results", url2: "https://search.google.com/search-console", note: "Nothing to post. Your careers page carries JobPosting structured data, so Google can list it in job search on its own. After you open a posting, paste its link into the Rich Results Test to confirm it's eligible, then use URL Inspection → Request indexing in Search Console. When you close a posting the page returns 410 and drops out of the sitemap, which tells Google to remove it.", src: [["Google Search Central: JobPosting structured data", "https://developers.google.com/search/docs/appearance/structured-data/job-posting"]] },
    { k: "indeed", name: "Indeed", cost: "Free with limits · may require sponsorship", free: "maybe", url: "https://employers.indeed.com/", note: "Indeed lets direct employers post up to three free jobs per calendar month (each live up to 30 days). Indeed says it may require sponsorship for some jobs, and it names commission-only roles as one example, so this posting may not be eligible for a free listing. If Indeed asks you to sponsor, you can stop there; Google for Jobs and your careers page still work free.", src: [["Indeed: free (organic) vs sponsored jobs", "https://www.indeed.com/lead/the-difference-between-organic-listings-sponsored-jobs"]] },
    { k: "glassdoor", name: "Glassdoor (through Indeed)", cost: "No separate post", free: "via", url: "https://employers.indeed.com/", note: "Glassdoor no longer takes job posts directly; jobs posted on Indeed appear on Glassdoor. Posting on Indeed covers both. Keep your free Glassdoor employer profile for reviews only.", src: [["100Hires: Glassdoor vs Indeed (2026)", "https://100hires.com/glassdoor-vs-indeed.html"]] },
    { k: "linkedin", name: "LinkedIn (free job post)", cost: "Free · one job at a time", free: "yes", url: "https://www.linkedin.com/talent/post-a-job", note: "LinkedIn allows one free job post open at a time. Free posts can be paused around day 14, close at day 30 and stop showing after an applicant cap; LinkedIn may withhold the free option for some roles or new accounts. Don't click Promote unless you mean to pay.", src: [["LinkedIn: job posting pricing", "https://business.linkedin.com/talent-solutions/jobs-101/pricing"], ["100Hires: posting on LinkedIn in 2026", "https://100hires.com/how-to-post-a-job-on-linkedin.html"]] },
    { k: "facebook", name: "Facebook (Page job post + groups)", cost: "Free", free: "yes", url: "https://www.facebook.com/", note: "Meta brought job listings back to Facebook in the US in October 2025 (Pages and the Marketplace jobs tab). You can also share the short text below in nurse groups you belong to. Read each group's rules first; many ban recruiting posts. Never post in a group as if you were a member looking for work.", src: [["TechBriefly: Meta relaunches free job listings on Facebook (Oct 2025)", "https://techbriefly.com/2025/10/14/meta-relaunches-free-job-listings-on-facebook-in-us/"]] },
    { k: "handshake", name: "Handshake", cost: "Free Basic plan · low fit", free: "yes", url: "https://joinhandshake.com/employers/", note: "Handshake's Basic employer plan is free and includes job posting, but its audience is college students and recent graduates. This role needs nurses with 3+ years at the bedside, so expect few qualified applicants. Optional.", src: [["Handshake: How much does Handshake cost?", "https://support.joinhandshake.com/hc/en-us/articles/115014792267-How-Much-Does-Handshake-Cost-"]] },
    { k: "gna", name: "Georgia Nurses Association job board", cost: "Paid (about $300 / 30 days)", free: "no", url: "https://georgianurses.nursingnetwork.com/nursing-jobs/for-employers", note: "GNA's job board runs on Nursing Network. We found no free employer option; Nursing Network's employer page lists $299.99 for a single 30-day post. Confirm the price on GNA's own employer page before paying. Members can still share the posting in GNA communities for free if the rules allow.", src: [["GNA on Nursing Network", "https://georgianurses.nursingnetwork.com/"], ["Nursing Network employer pricing (another association's board)", "https://nemsd.nursingnetwork.com/nursing-jobs/for-employers"]] },
    { k: "tna", name: "Tennessee Nurses Association", cost: "No free board found", free: "no", url: "https://jobs.ana.org/", note: "We found no free job board for the Tennessee Nurses Association. The ANA Career Center (which state associations point members to) doesn't publish employer prices. Call TNA and ask whether they share member-employer openings in a newsletter for free.", src: [["ANA Career Center", "https://jobs.ana.org/"]] },
    { k: "asna", name: "Alabama State Nurses Association / Alabama Board of Nursing", cost: "No free board found · ABN link list (ask)", free: "maybe", url: "https://www.abn.alabama.gov/abn-nursing-excellence/workforce-data/workforce-job-boards/", note: "ASNA sells newsletter and email advertising through Multiview (price on request); we found no free job board. The Alabama Board of Nursing keeps a free 'Workforce Job Boards' page that links to employers' own career pages. It doesn't say how employers get added, so call ABN (1-800-656-5318) and ask whether they'll list nclexsim.com/careers.", src: [["ASNA media kit (Multiview)", "https://mediakitpublic.multiview.com/ASNA"], ["Alabama Board of Nursing: Workforce Job Boards", "https://www.abn.alabama.gov/abn-nursing-excellence/workforce-data/workforce-job-boards/"]] },
    { k: "ziprecruiter", name: "ZipRecruiter", cost: "Not free (trial, then paid)", free: "no", url: "https://www.ziprecruiter.com/post-a-job", note: "ZipRecruiter has no permanent free posting. It offers a short free trial that needs a credit card and becomes a paid plan unless you cancel. Recommendation: skip it.", src: [["100Hires: posting on ZipRecruiter (2026)", "https://100hires.com/how-to-post-a-job-on-ziprecruiter.html"]] },
    { k: "nursecom", name: "Nurse.com", cost: "Paid (price on request)", free: "no", url: "https://www.nurse.com/solutions/recruiting", note: "Nurse.com takes employer job posts but doesn't publish a free option or prices. Skip unless you decide to pay.", src: [["Nurse.com recruiting solutions", "https://www.nurse.com/solutions/recruiting"]] },
    { k: "allnurses", name: "allnurses", cost: "Paid ($250–$500 a month)", free: "no", url: "https://allnurses.com/jobs-recruitment", note: "allnurses' job boards are paid (Basic Jobs Package $250–$500 a month). No free option found.", src: [["allnurses: jobs and recruitment", "https://allnurses.com/jobs-recruitment"]] },
    { k: "craigslist", name: "Craigslist", cost: "Paid ($10–$75 per post, by city)", free: "no", url: "https://www.craigslist.org/", note: "Craigslist charges for job posts in US areas: $10 to $75 depending on the city. The exact price appears before you publish. Post in one city at a time (Atlanta, Chattanooga, Nashville, Birmingham…) under jobs › healthcare or sales.", src: [["Craigslist: posting fees", "https://www.craigslist.org/about/help/posting_fees"]] }];
  async function kits(env, p, base) {
    const sts = await postStates(env, p); const where = sts.map(s => ST[s] || s).join(", "); const link = k => (base || ORIGIN) + "/careers/" + p.slug + "?src=" + k;
    const title = p.title, desc = [p.summary, toPlain(p.body)].join("\n\n"), reqs = toPlain(p.reqs), comp = toPlain(p.comp);
    return BOARDS.map(b => { const L = link(b.k); const fields = b.k === "google" ? [["Posting link (paste into the Rich Results Test)", (base || ORIGIN) + "/careers/" + p.slug]] :
      b.k === "facebook" ? [["Share text", `Nurses in ${where}: Vexcura is looking for experienced RNs and LPNs (3+ years at the bedside, more than one EHR) to introduce nursing schools to our NCLEX-RN and academic EHR platform. Independent contractor, commission only (20% of first-year license revenue, 10% of renewals), work from home. Details and apply: ${L}`], ["Apply link", L]] :
      [["Job title", title], ["Location", p.remote ? `Remote (must live in ${where})` : where], ["Employment type", "Contract / independent contractor (1099)"], ["Description", desc + "\n\nApply: " + L], ["Requirements", reqs], ["Compensation", comp], ["Apply link", L]];
      return { k: b.k, name: b.name, cost: b.cost, free: b.free, post_url: b.url, url2: b.url2 || "", note: b.note, sources: b.src.map(s => ({ title: s[0], url: s[1] })), fields: fields.map(f => ({ label: f[0], text: f[1] })), all: fields.map(f => f[0] + ":\n" + f[1]).join("\n\n") } });
  }

  /* ---------- the applicant-side API ---------- */
  function sniff(bin, name) { const ext = (String(name).toLowerCase().match(/\.([a-z0-9]+)$/) || [])[1] || ""; const h = String.fromCharCode(...bin.slice(0, 5));
    if (h === "%PDF-") return "pdf";
    if (bin[0] === 0x50 && bin[1] === 0x4b && bin[2] === 3 && bin[3] === 4 && ext === "docx") { const s = new TextDecoder("latin1").decode(bin.length > 400000 ? bin.slice(0, 200000) : bin) + new TextDecoder("latin1").decode(bin.length > 400000 ? bin.slice(-200000) : new Uint8Array(0)); if (s.indexOf("word/") >= 0 || s.indexOf("[Content_Types].xml") >= 0) return "docx" }
    return null }
  const FT = { pdf: "application/pdf", docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" };
  async function apply(req, env, url) {
    const ip = ipOf_(req); let b = {}; try { b = await req.json() } catch (e) { return J({ error: "Your resume is too large. The limit is 5 MB." }, 413) }
    if (b.company_site) return J({ error: "Something went wrong. Call " + ENT.phone + " to apply by phone." }, 400);
    const ts = +b.ts || 0; if (!ts || T() - ts < 3000) return J({ error: "Please take a moment to review your application, then submit again." }, 400);
    if (await limited(env, "ats:" + ip, 3600e3, 6)) return J({ error: "Too many applications from this network. Try again in an hour." }, 429);
    const p = (b.slug && /^[a-z0-9-]{3,80}$/.test(b.slug)) ? await env.DB.prepare("SELECT * FROM ats_posts WHERE slug=?").bind(b.slug).first() : null;
    if (!p || !isLive(pubPost(p))) return J({ error: "This position is no longer accepting applications." }, 410);
    const o = { name: cl(b.name, 120), email: cl(b.email, 254).toLowerCase(), phone: cl(b.phone, 30), home_state: ST[b.home_state] ? b.home_state : "", lic_type: ["RN", "LPN"].indexOf(b.lic_type) >= 0 ? b.lic_type : "", lic_state: ST[b.lic_state] ? b.lic_state : "", lic_no: normLic(b.lic_no).slice(0, 30),
      lic_states: [...new Set((Array.isArray(b.lic_states) ? b.lic_states : []).filter(s => ST[s] || s === "NLC"))].slice(0, 60), years: Math.round(+b.years), ehrs: [...new Set((Array.isArray(b.ehrs) ? b.ehrs : []).filter(e => EHRS.indexOf(e) >= 0))], ehr_other: cl(b.ehr_other, 200), edu: ml(b.edu, 2000), sales: ml(b.sales, 2000), linkedin: cl(b.linkedin, 300), heard: HEARD.indexOf(b.heard) >= 0 ? b.heard : "", src: cl(b.src, 30).replace(/[^a-z0-9_-]/gi, ""), terr: cl(b.terr, 40) };
    const bad = (f, m) => J({ error: m, field: f }, 400);
    if (o.name.split(" ").filter(Boolean).length < 2) return bad("name", "Enter your full name, first and last.");
    if (!EM.test(o.email)) return bad("email", "Enter a valid email address.");
    if (o.phone.replace(/\D/g, "").length < 10) return bad("phone", "Enter a phone number with area code.");
    if (!o.home_state) return bad("home_state", "Choose the state you live in.");
    if (!o.lic_type) return bad("lic_type", "Choose RN or LPN.");
    if (!o.lic_state) return bad("lic_state", "Choose the state of the license we should look up.");
    if (o.lic_no.length < 4) return bad("lic_no", "Enter your license number (at least 4 letters or digits).");
    if (!(o.years >= 0 && o.years <= 60)) return bad("years", "Enter your years of bedside experience as a number.");
    if (!o.ehrs.length) return bad("ehrs", "Choose at least one EHR you've charted in.");
    if (o.linkedin && !/^https:\/\/([a-z]{2,3}\.)?linkedin\.com\/[^\s<>"]{2,250}$/i.test(o.linkedin)) return bad("linkedin", "Enter your LinkedIn link starting with https://www.linkedin.com/ (or leave it blank).");
    if (!o.heard) return bad("heard", "Tell us how you heard about the job.");
    const A = b.acks || {}; if (A.privacy !== true || A.contractor !== true || A.commission !== true) return bad("acks", "Check all three boxes under \"Before you apply\".");
    const r = b.resume || {}; const m = /^data:[^;,]*;base64,([A-Za-z0-9+/]+=*)$/.exec(String(r.data || "")); if (!m) return bad("resume", "Attach your resume (PDF or Word).");
    if (m[1].length > Math.ceil(MAXF / 3) * 4 + 4) return J({ error: "Your resume is larger than 5 MB. Save a smaller PDF and try again.", field: "resume" }, 413);
    let bin; try { bin = Uint8Array.from(atob(m[1]), c => c.charCodeAt(0)) } catch (e) { return bad("resume", "Attach your resume again.") }
    if (bin.length > MAXF) return J({ error: "Your resume is larger than 5 MB. Save a smaller PDF and try again.", field: "resume" }, 413);
    const fname = cl(r.name, 120).replace(/[^A-Za-z0-9._ ()-]/g, "") || "resume"; const k = sniff(bin, fname); if (!k) return J({ error: "Upload your resume as a PDF or Word (.docx) file.", field: "resume" }, 415);
    const terr = o.terr ? await env.DB.prepare("SELECT id FROM ats_territories WHERE id=?").bind(o.terr).first() : null;
    const dupe = await env.DB.prepare("SELECT a.id FROM ats_apps a JOIN ats_applicants p ON p.id=a.person WHERE p.email=? AND a.post=? AND a.stage NOT IN ('withdrawn','not_selected')").bind(o.email, p.id).first();
    if (dupe) return J({ error: "You've already applied for this position. Use the status link you saved, or the backup code at nclexsim.com/careers/status." }, 409);
    const t = T(), pep = await pepper(env); const lh = await sha("lic|" + pep + "|" + o.lic_no);
    let person = await env.DB.prepare("SELECT id FROM ats_applicants WHERE email=? ORDER BY updated DESC LIMIT 1").bind(o.email).first(); const pid = person ? person.id : rid("ap");
    const tok = hex(24), code = [...crypto.getRandomValues(new Uint8Array(8))].map(x => "ABCDEFGHJKMNPQRSTUVWXYZ23456789"[x % 31]).join("").replace(/^(.{4})/, "$1-");
    const aid = rid("aa");
    const st = [env.DB.prepare("INSERT INTO ats_applicants (id,name,email,phone,home_state,lic_type,lic_state,lic_states,lic_hash,lic_last4,years,ehrs,ehr_other,edu,sales,linkedin,created,updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, phone=excluded.phone, home_state=excluded.home_state, lic_type=excluded.lic_type, lic_state=excluded.lic_state, lic_states=excluded.lic_states, lic_hash=excluded.lic_hash, lic_last4=excluded.lic_last4, years=excluded.years, ehrs=excluded.ehrs, ehr_other=excluded.ehr_other, edu=excluded.edu, sales=excluded.sales, linkedin=excluded.linkedin, updated=excluded.updated")
        .bind(pid, o.name, o.email, o.phone, o.home_state, o.lic_type, o.lic_state, JSON.stringify(o.lic_states), lh, o.lic_no.slice(-4), o.years, JSON.stringify(o.ehrs), o.ehr_other, o.edu, o.sales, o.linkedin, t, t),
      env.DB.prepare("INSERT INTO ats_apps (id,person,post,terr_pref,heard,src,stage,stage_at,consents,resume_name,resume_type,resume_size,tok_hash,code_hash,seen,created,updated) VALUES (?,?,?,?,?,?,'applied',?,?,?,?,?,?,?,0,?,?)")
        .bind(aid, pid, p.id, terr ? terr.id : "", o.heard, o.src, t, JSON.stringify({ privacy: t, contractor: t, commission: t, text: ACK, ip: ip ? (await sha("ip|" + pep + "|" + ip)).slice(0, 16) : "" }), fname, FT[k], bin.length, await sha("ats|" + tok), await sha("code|" + aid + "|" + code.replace(/-/g, "")), t, t)];
    await env.SITE.put("ats:f:" + aid, bin);
    await env.DB.batch(st);
    await act(env, aid, p.id, "applied", `Applied via ${o.src || o.heard || "careers page"}`, o.name);
    return J({ ok: true, id: aid, status_url: url.origin + "/careers/status?t=" + tok, code }, 201);
  }
  async function statusApi(req, env, url, seg) {
    let b = {}; try { b = await req.json() } catch (e) { }
    if (seg[1] === "find") {
      if (await limited(env, "atsf:" + ipOf_(req), 3600e3, 10)) return J({ error: "Too many tries. Wait an hour, or call " + ENT.phone + "." }, 429);
      const email = cl(b.email, 254).toLowerCase(), code = cl(b.code, 12).toUpperCase().replace(/[^A-Z0-9]/g, "");
      const L = EM.test(email) && code.length === 8 ? (await env.DB.prepare("SELECT a.id FROM ats_apps a JOIN ats_applicants p ON p.id=a.person WHERE p.email=? ORDER BY a.created DESC LIMIT 20").bind(email).all()).results || [] : [];
      for (const x of L) { const h = await sha("code|" + x.id + "|" + code); const y = await env.DB.prepare("SELECT id FROM ats_apps WHERE id=? AND code_hash=?").bind(x.id, h).first(); if (y) { const tok = hex(24); await env.DB.prepare("UPDATE ats_apps SET tok_hash=? WHERE id=?").bind(await sha("ats|" + tok), x.id).run(); await act(env, x.id, null, "link", "Applicant reopened status with backup code (old link replaced)", ""); return J({ ok: true, status_url: url.origin + "/careers/status?t=" + tok }) } }
      return J({ error: "We couldn't find an application with that email and code." }, 404);
    }
    const a = await appByTok(env, String(b.t || "")); if (!a) return J({ error: "This link has expired. Open your status with your email and backup code." }, 404);
    if (b.action === "get") return J(await statusData(env, a));
    if (b.action === "withdraw" && b.confirm === true) { if (CLOSED.indexOf(a.stage) >= 0) return J({ error: "This application is already closed." }, 409); await env.DB.prepare("UPDATE ats_apps SET stage='withdrawn', stage_at=?, reason=?, updated=? WHERE id=?").bind(T(), "Withdrawn by applicant", T(), a.id).run(); await act(env, a.id, a.post, "stage", "Applicant withdrew", a.pname); return J({ ok: true }) }
    if (b.action === "refs") {
      const have = (await env.DB.prepare("SELECT COUNT(*) n FROM ats_screen WHERE app=? AND kind='reference'").bind(a.id).first()).n;
      const L = (Array.isArray(b.refs) ? b.refs : []).slice(0, Math.max(0, 4 - have)).map(r => ({ name: cl(r.name, 120), org: cl(r.org, 160), relation: cl(r.relation, 160), phone: cl(r.phone, 30), email: cl(r.email, 254).toLowerCase() })).filter(r => r.name);
      if (!L.length) return J({ error: "Add at least one reference's name." }, 400);
      for (const r of L) { if (!r.phone && !EM.test(r.email)) return J({ error: `Add a phone number or email for ${r.name}.` }, 400); if (r.email && !EM.test(r.email)) r.email = "" }
      const t = T(); await env.DB.batch(L.map(r => env.DB.prepare("INSERT INTO ats_screen (id,app,kind,status,data,by_name,created,updated) VALUES (?,?,'reference','to_contact',?,?,?,?)").bind(rid("sc"), a.id, JSON.stringify(Object.assign(r, { from: "applicant" })), a.pname, t, t)));
      await act(env, a.id, a.post, "reference", `Applicant added ${L.length} reference${L.length === 1 ? "" : "s"}`, a.pname); return J({ ok: true });
    }
    if (b.action === "fcra") {
      const f = await env.DB.prepare("SELECT * FROM ats_screen WHERE app=? AND kind='fcra' ORDER BY created DESC LIMIT 1").bind(a.id).first();
      if (!f || f.status !== "requested") return J({ error: "There's no authorization waiting for you." }, 409);
      const t = T(); const prev = P(f.data, {});
      if (b.decline === true) { await env.DB.prepare("UPDATE ats_screen SET status='declined', data=?, updated=? WHERE id=?").bind(JSON.stringify(Object.assign(prev, { declined_at: t })), t, f.id).run(); await act(env, a.id, a.post, "fcra", "Applicant declined the background check authorization", a.pname); return J({ ok: true }) }
      const sig = cl(b.sig, 120); if (b.agree !== true || sig.split(" ").filter(Boolean).length < 2) return J({ error: "Type your full legal name and check the box." }, 400);
      const pep = await pepper(env); const rec = Object.assign(prev, { at: t, sig, version: FCRA_V, text_sha: await sha(FCRA_DISCLOSURE + "\n---\n" + FCRA_AUTH), ip: (await sha("ip|" + pep + "|" + ipOf_(req))).slice(0, 16), ua: cl(req.headers.get("User-Agent"), 200), tz: cl(b.tz, 60) });
      await env.DB.prepare("UPDATE ats_screen SET status='signed', data=?, updated=? WHERE id=?").bind(JSON.stringify(rec), t, f.id).run();
      await act(env, a.id, a.post, "fcra", "Background check authorization signed (" + FCRA_V + ")", a.pname); return J({ ok: true });
    }
    return J({ error: "Not found" }, 404);
  }

  /* ---------- admin ---------- */
  async function detail(env, id) {
    const a = await env.DB.prepare("SELECT * FROM ats_apps WHERE id=?").bind(id).first(); if (!a) return null;
    const p = await env.DB.prepare("SELECT * FROM ats_applicants WHERE id=?").bind(a.person).first();
    const post = a.post ? await env.DB.prepare("SELECT id, title, slug, territory FROM ats_posts WHERE id=?").bind(a.post).first() : null;
    const S = ((await env.DB.prepare("SELECT * FROM ats_screen WHERE app=? ORDER BY created").bind(id).all()).results || []).map(x => ({ id: x.id, kind: x.kind, status: x.status || "", data: P(x.data, {}), by: x.by_name || "", created: x.created, updated: x.updated }));
    const A = ((await env.DB.prepare("SELECT * FROM ats_activity WHERE app=? ORDER BY at DESC LIMIT 300").bind(id).all()).results || []).map(x => ({ id: x.id, kind: x.kind, text: x.text, by: x.by_name || "", at: x.at }));
    const other = ((await env.DB.prepare("SELECT a.id, a.stage, a.created, ps.title FROM ats_apps a LEFT JOIN ats_posts ps ON ps.id=a.post WHERE a.person=? AND a.id<>?").bind(a.person, id).all()).results || []);
    return { app: appRow(a, p, post), applicant: p ? { id: p.id, name: p.name, email: p.email, phone: p.phone || "", home_state: p.home_state || "", lic: { type: p.lic_type, state: p.lic_state, states: P(p.lic_states, []), last4: p.lic_last4 ? "••••" + p.lic_last4 : "" }, years: p.years, ehrs: P(p.ehrs, []), ehr_other: p.ehr_other || "", edu: p.edu || "", sales: p.sales || "", linkedin: p.linkedin || "" } : null,
      consents: (() => { const c = P(a.consents, {}); return { privacy: c.privacy || null, contractor: c.contractor || null, commission: c.commission || null, text: c.text || ACK } })(), screen: S, activity: A, other };
  }
  function appRow(a, p, post) { const s = P(a.scores, {}); return { id: a.id, person: a.person, name: p ? p.name : "", email: p ? p.email : "", lic_type: p ? p.lic_type : "", lic_state: p ? p.lic_state : "", home_state: p ? p.home_state : "", years: p ? p.years : null, ehrs: p ? P(p.ehrs, []) : [], post: post ? { id: post.id, title: post.title, slug: post.slug } : null, terr_pref: a.terr_pref || "", heard: a.heard || "", src: a.src || "", stage: a.stage, stage_at: a.stage_at, days: Math.floor((T() - a.stage_at) / 864e5), reason: a.reason || "", scores: s, avg: avg(s), resume: a.resume_name ? { name: a.resume_name, type: a.resume_type, size: a.resume_size } : null, seen: !!a.seen, created: a.created, updated: a.updated } }
  async function list(env, q) {
    const L = (await env.DB.prepare("SELECT a.*, p.name pn, p.email pe, p.lic_type plt, p.lic_state pls, p.home_state phs, p.years py, p.ehrs pehr, ps.id psid, ps.title pst, ps.slug pss FROM ats_apps a JOIN ats_applicants p ON p.id=a.person LEFT JOIN ats_posts ps ON ps.id=a.post ORDER BY a.created DESC LIMIT 2000").all()).results || [];
    return L.map(a => appRow(a, { name: a.pn, email: a.pe, lic_type: a.plt, lic_state: a.pls, home_state: a.phs, years: a.py, ehrs: a.pehr }, a.psid ? { id: a.psid, title: a.pst, slug: a.pss } : null)).filter(x => (!q.stage || x.stage === q.stage) && (!q.post || (x.post && x.post.id === q.post)) && (!q.q || (x.name + " " + x.email).toLowerCase().indexOf(q.q.toLowerCase()) >= 0));
  }
  async function summary(env) {
    const L = await list(env, {}); const t = T(); const items = [];
    const nw = L.filter(a => !a.seen && CLOSED.indexOf(a.stage) < 0);
    const stale = L.filter(a => CLOSED.indexOf(a.stage) < 0 && t - a.stage_at > 5 * 864e5);
    const F = (await env.DB.prepare("SELECT s.app, s.updated, s.data FROM ats_screen s WHERE s.kind='fcra' AND s.status='signed'").all()).results || [];
    const B = new Set(((await env.DB.prepare("SELECT app FROM ats_screen WHERE kind='background' AND status NOT IN ('','not_started')").all()).results || []).map(x => x.app));
    const consents = F.filter(f => !B.has(f.app)).map(f => ({ app: f.app, at: f.updated, a: L.find(x => x.id === f.app) })).filter(x => x.a);
    nw.forEach(a => items.push({ pri: 2, kind: "new", app: a.id, title: `New application: ${a.name}`, sub: `${a.post ? a.post.title.replace(/\s+[—–-]\s+1099.*$/, "") : "Application"} · ${a.lic_type || ""} ${a.lic_state || ""} · ${a.years != null ? a.years + " yrs" : ""}`, btn: "Review" }));
    consents.forEach(c => items.push({ pri: 1, kind: "consent", app: c.app, title: `Background authorization signed: ${c.a.name}`, sub: "Order the check with your screening company, then record it on the Background tab", btn: "Open" }));
    stale.filter(a => a.seen).forEach(a => items.push({ pri: a.days > 10 ? 1 : 2, kind: "stale", app: a.id, title: `${a.name} has been in ${SN[a.stage]} for ${a.days} days`, sub: "Move them forward, or close the application", btn: "Open" }));
    const n = items.length; return { text: n ? `${n} hiring item${n === 1 ? "" : "s"} need${n === 1 ? "s" : ""} you` : "Nothing waiting in hiring", needs: n, counts: { new: nw.length, stale: stale.length, consents: consents.length, active: L.filter(a => CLOSED.indexOf(a.stage) < 0).length }, items: items.sort((x, y) => x.pri - y.pri) };
  }
  function cleanPost(b, prev) { prev = prev || {}; const o = {};
    o.title = cl(b.title != null ? b.title : prev.title, 160); o.summary = cl(b.summary != null ? b.summary : prev.summary, 400);
    o.body = ml(b.body != null ? b.body : prev.body, 12000); o.reqs = ml(b.reqs != null ? b.reqs : prev.reqs, 6000); o.comp = ml(b.comp != null ? b.comp : prev.comp, 6000);
    o.remote = b.remote != null ? (b.remote ? 1 : 0) : (prev.remote == null ? 1 : prev.remote ? 1 : 0); o.territory = b.territory != null ? cl(b.territory, 40) : (prev.territory || "");
    o.valid_through = b.valid_through != null ? ymd(b.valid_through) : (prev.valid_through || ""); o.status = ["draft", "open", "closed"].indexOf(b.status) >= 0 ? b.status : (prev.status || "draft");
    o.slug = slugify(b.slug != null && b.slug !== "" ? b.slug : prev.slug || o.title); return o }
  const SCREEN = { license: ["active_unencumbered", "active_encumbered", "inactive", "expired", "not_found"], reference: ["to_contact", "requested", "received", "declined"], interview: ["scheduled", "done", "no_show", "cancelled"], demo: ["scheduled", "done", "no_show", "cancelled"], offer: ["draft", "sent", "accepted", "declined"], agreement: ["sent", "signed"], onboard: ["open", "done"] };
  const BG = ["not_started", "ordered", "in_progress", "clear", "review", "pre_adverse_sent", "final_adverse_sent", "cancelled"];
  function cleanScreen(kind, b, prev) { prev = prev || {}; const d = Object.assign({}, prev), s = b || {};
    const txt = (k, n) => { if (s[k] != null) d[k] = cl(s[k], n || 200) }; const dt = k => { if (s[k] != null) d[k] = ymd(s[k]) }; const num = (k, lo, hi) => { if (s[k] != null) { const v = Math.round(+s[k]); d[k] = v >= lo && v <= hi ? v : null } };
    if (kind === "license") { if (s.state != null) d.state = ST[s.state] ? s.state : ""; if (s.type != null) d.type = ["RN", "LPN"].indexOf(s.type) >= 0 ? s.type : ""; if (s.source != null) d.source = ["Nursys QuickConfirm", "State board website"].indexOf(s.source) >= 0 ? s.source : "Nursys QuickConfirm"; dt("looked_up"); dt("expires"); txt("note", 600); if (s.discipline != null) d.discipline = !!s.discipline; if (s.compact != null) d.compact = !!s.compact }
    if (kind === "reference") { txt("name", 120); txt("org", 160); txt("relation", 160); txt("phone", 30); txt("email", 254); dt("contacted"); num("rating", 1, 5); txt("notes", 2000); if (s.rehire != null) d.rehire = ["yes", "no", "unsure", ""].indexOf(s.rehire) >= 0 ? s.rehire : "" }
    if (kind === "interview" || kind === "demo") { dt("date"); txt("time", 20); txt("with", 120); txt("link", 300); num("rating", 1, 5); txt("notes", 3000) }
    if (kind === "offer") { if (s.territory != null) d.territory = cl(s.territory, 40); dt("sent"); dt("respond_by"); txt("terms", 600); txt("notes", 2000) }
    if (kind === "agreement") { txt("version", 40); dt("sent"); dt("signed"); txt("notes", 1000) }
    if (kind === "onboard") { ["w9", "agreement", "territory_letter", "demo_account", "training", "brand_guide"].forEach(k => { if (s[k] != null) d[k] = !!s[k] }); txt("notes", 1000) }
    if (kind === "background") { txt("vendor", 120); txt("order_ref", 120); dt("ordered"); dt("completed"); dt("pre_adverse"); dt("final_adverse"); txt("notes", 2000) }
    return d }

  async function admin(req, env, url, seg, me) {
    const M = req.method; const nm = cl(me.name, 120); let b = {}; if (M !== "GET" && M !== "DELETE") { try { b = await req.json() } catch (e) { } }
    const r = seg[1] || "";
    if (r === "meta" && M === "GET") return J({ stages: STAGES, rubric: RUBRIC, ehrs: EHRS, states: ST, plans: PLANS, rates: RATE, boards: BOARDS.map(x => ({ k: x.k, name: x.name, cost: x.cost, free: x.free })), screen: SCREEN, bg: BG, template: TEMPLATE(), ack: ACK, fcra: { version: FCRA_V, disclosure: FCRA_DISCLOSURE, auth: FCRA_AUTH } });
    if (r === "summary" && M === "GET") return J(await summary(env));
    if (r === "commission" && M === "GET") { let mix = null; const mx = url.searchParams.get("mix"); if (mx) mix = mx.split(",").map(s => { const [plan, n, seats] = s.split(":"); return { plan, n: +n || 0, seats: +seats || 0 } }).filter(m => PLANS.some(p => p.k === m.plan));
      return J(calc({ plan: url.searchParams.get("plan") || "", seats: url.searchParams.get("seats"), years: url.searchParams.get("years"), mix })) }
    /* territories */
    if (r === "territories") {
      const id = seg[2];
      if (!id && M === "GET") return J({ territories: await terrs(env) });
      const clean = async (b, prevId) => { const states = [...new Set((Array.isArray(b.states) ? b.states : []).filter(s => ST[s]))]; const L = await terrs(env); const clash = states.filter(s => L.some(t => t.id !== prevId && t.status !== "closed" && t.states.indexOf(s) >= 0)); return { states, clash } };
      if (!id && M === "POST") { const name = cl(b.name, 80); if (!name) return J({ error: "Name the territory." }, 400); const c = await clean(b); if (!c.states.length) return J({ error: "Choose at least one state." }, 400); if (c.clash.length) return J({ error: `${c.clash.map(s => ST[s]).join(", ")} already belong${c.clash.length === 1 ? "s" : ""} to another territory. Territories are exclusive.` }, 409);
        const tid = rid("t"), t = T(); const mx = await env.DB.prepare("SELECT MAX(sort) m FROM ats_territories").first(); await env.DB.prepare("INSERT INTO ats_territories (id,name,states,status,note,sort,created,updated) VALUES (?,?,?,?,?,?,?,?)").bind(tid, name, JSON.stringify(c.states), ["open", "house", "closed"].indexOf(b.status) >= 0 ? b.status : "open", cl(b.note, 400), (mx && mx.m || 0) + 1, t, t).run(); await act(env, null, null, "territory", `Territory added: ${name}`, nm); return J({ ok: true, id: tid }, 201) }
      const x = id && await env.DB.prepare("SELECT * FROM ats_territories WHERE id=?").bind(id).first(); if (!x) return J({ error: "Not found" }, 404);
      if (!seg[3] && M === "PUT") { const name = b.name != null ? cl(b.name, 80) || x.name : x.name; let states = P(x.states, []); if (b.states != null) { const c = await clean(b, id); if (!c.states.length) return J({ error: "Choose at least one state." }, 400); if (c.clash.length) return J({ error: `${c.clash.map(s => ST[s]).join(", ")} already belong${c.clash.length === 1 ? "s" : ""} to another territory. Territories are exclusive.` }, 409); states = c.states }
        const status = ["open", "house", "closed"].indexOf(b.status) >= 0 ? b.status : x.status; await env.DB.prepare("UPDATE ats_territories SET name=?, states=?, status=?, note=?, updated=? WHERE id=?").bind(name, JSON.stringify(states), status, b.note != null ? cl(b.note, 400) : x.note, T(), id).run(); return J({ ok: true }) }
      if (seg[3] === "assign" && M === "PUT") {
        if (!b.app) { await env.DB.prepare("UPDATE ats_territories SET rep_app=NULL, rep_name=NULL, status=CASE WHEN status='assigned' THEN 'open' ELSE status END, updated=? WHERE id=?").bind(T(), id).run(); if (x.rep_app) await act(env, x.rep_app, null, "territory", `Removed from territory ${x.name}`, nm); return J({ ok: true }) }
        const a = await env.DB.prepare("SELECT a.id, a.stage, p.name FROM ats_apps a JOIN ats_applicants p ON p.id=a.person WHERE a.id=?").bind(cl(b.app, 40)).first(); if (!a) return J({ error: "Candidate not found." }, 404);
        if (["offer", "agreement", "onboarded"].indexOf(a.stage) < 0) return J({ error: "Assign a territory once the candidate reaches Offer, Agreement signed or Onboarded." }, 409);
        if (x.rep_app && x.rep_app !== a.id && !b.replace) return J({ error: `${x.name} is already assigned to ${x.rep_name}. Territories are exclusive; remove that rep first.`, code: "taken" }, 409);
        await env.DB.prepare("UPDATE ats_territories SET rep_app=?, rep_name=?, status='assigned', updated=? WHERE id=?").bind(a.id, a.name, T(), id).run(); await act(env, a.id, null, "territory", `Assigned exclusive territory: ${x.name} (${P(x.states, []).join(", ")})`, nm); await audit(env, req, me.id, "ats_territory", id, a.name); return J({ ok: true }) }
      if (!seg[3] && M === "DELETE") { const used = await env.DB.prepare("SELECT COUNT(*) n FROM ats_posts WHERE territory=? AND status<>'closed'").bind(id).first(); if (used && used.n) return J({ error: "Close or move the postings for this territory first." }, 409); if (x.rep_app) return J({ error: "Remove the assigned rep first." }, 409); await env.DB.prepare("DELETE FROM ats_territories WHERE id=?").bind(id).run(); return J({ ok: true }) }
      return J({ error: "Not found" }, 404);
    }
    /* postings */
    if (r === "posts") {
      const id = seg[2];
      if (!id && M === "GET") { const L = ((await env.DB.prepare("SELECT * FROM ats_posts ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'draft' THEN 1 ELSE 2 END, updated DESC").all()).results || []).map(pubPost); const C = (await env.DB.prepare("SELECT post, COUNT(*) n FROM ats_apps GROUP BY post").all()).results || []; L.forEach(p => { p.apps = (C.find(c => c.post === p.id) || {}).n || 0; p.expired = expired(p) }); return J({ posts: L }) }
      if (!id && M === "POST") { const o = cleanPost(Object.assign(TEMPLATE(), b)); if (!o.title) return J({ error: "Give the posting a title." }, 400); if (!o.slug) return J({ error: "Give the posting a web address." }, 400);
        if (o.territory && !(await env.DB.prepare("SELECT id FROM ats_territories WHERE id=?").bind(o.territory).first())) return J({ error: "Choose a territory." }, 400);
        let slug = o.slug; for (let i = 2; await env.DB.prepare("SELECT 1 FROM ats_posts WHERE slug=?").bind(slug).first(); i++) slug = o.slug.slice(0, 66) + "-" + i;
        const pid = rid("jp"), t = T(); if (o.status === "open" && !o.valid_through) o.valid_through = day(t + 60 * 864e5);
        await env.DB.prepare("INSERT INTO ats_posts (id,slug,title,territory,status,summary,body,reqs,comp,remote,posted,valid_through,by_name,created,updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(pid, slug, o.title, o.territory, o.status, o.summary, o.body, o.reqs, o.comp, o.remote, o.status === "open" ? t : null, o.valid_through, nm, t, t).run();
        await act(env, null, pid, "post", `Posting created (${o.status}): ${o.title}`, nm); await audit(env, req, me.id, "ats_post", pid, o.title); return J({ ok: true, id: pid, slug }, 201) }
      const x = id && await env.DB.prepare("SELECT * FROM ats_posts WHERE id=?").bind(id).first(); if (!x) return J({ error: "Not found" }, 404);
      if (!seg[3] && M === "GET") return J({ post: pubPost(x), ld: await jobLD(env, pubPost(x), url.origin) });
      if (seg[3] === "kits" && M === "GET") return J({ post: pubPost(x), live: isLive(pubPost(x)), kits: await kits(env, pubPost(x), url.origin) });
      if (!seg[3] && M === "PUT") { const o = cleanPost(b, x); if (!o.title) return J({ error: "Give the posting a title." }, 400);
        if (o.slug !== x.slug && await env.DB.prepare("SELECT 1 FROM ats_posts WHERE slug=? AND id<>?").bind(o.slug, id).first()) return J({ error: "Another posting already uses that web address." }, 409);
        if (o.slug !== x.slug && x.posted) o.slug = x.slug; /* keep public links stable once posted */
        if (o.territory && !(await env.DB.prepare("SELECT id FROM ats_territories WHERE id=?").bind(o.territory).first())) return J({ error: "Choose a territory." }, 400);
        const t = T(); const posted = x.posted || (o.status === "open" ? t : null); if (o.status === "open" && (!o.valid_through || o.valid_through < day(t))) o.valid_through = day(t + 60 * 864e5);
        await env.DB.prepare("UPDATE ats_posts SET slug=?, title=?, territory=?, status=?, summary=?, body=?, reqs=?, comp=?, remote=?, posted=?, valid_through=?, by_name=?, updated=? WHERE id=?").bind(o.slug, o.title, o.territory, o.status, o.summary, o.body, o.reqs, o.comp, o.remote, posted, o.valid_through, nm, t, id).run();
        if (o.status !== x.status) { await act(env, null, id, "post", `Posting ${o.status === "open" ? "opened" : o.status === "closed" ? "closed" : "moved to draft"}: ${o.title}`, nm); await audit(env, req, me.id, "ats_post_" + o.status, id, o.title) }
        return J({ ok: true, post: pubPost(await env.DB.prepare("SELECT * FROM ats_posts WHERE id=?").bind(id).first()) }) }
      if (!seg[3] && M === "DELETE") { const n = await env.DB.prepare("SELECT COUNT(*) n FROM ats_apps WHERE post=?").bind(id).first(); if (n && n.n) return J({ error: "This posting has applications. Close it instead, or delete the applicants first." }, 409); await env.DB.prepare("DELETE FROM ats_posts WHERE id=?").bind(id).run(); await audit(env, req, me.id, "ats_post_delete", id, x.title); return J({ ok: true }) }
      return J({ error: "Not found" }, 404);
    }
    /* export */
    if (r === "export" && M === "GET") {
      const L = await list(env, { post: url.searchParams.get("post") || "", stage: url.searchParams.get("stage") || "" }); const Pp = {}; for (const a of L) if (!Pp[a.person]) Pp[a.person] = await env.DB.prepare("SELECT phone, lic_states, lic_last4, ehr_other, linkedin FROM ats_applicants WHERE id=?").bind(a.person).first();
      const H = ["Application ID", "Name", "Email", "Phone", "Posting", "Preferred territory", "Stage", "Days in stage", "Applied", "License type", "License state", "Other license states", "License (last 4)", "Years bedside", "EHRs", "Score (avg of 5)", "Heard about us", "LinkedIn"];
      const rows = L.map(a => { const q = Pp[a.person] || {}; return [a.id, a.name, a.email, q.phone || "", a.post ? a.post.title : "", a.terr_pref, SN[a.stage], a.days, day(a.created), a.lic_type, a.lic_state, P(q.lic_states, []).join(" "), q.lic_last4 ? "••••" + q.lic_last4 : "", a.years, a.ehrs.concat(q.ehr_other ? [q.ehr_other] : []).join("; "), a.avg == null ? "" : a.avg, a.heard, q.linkedin || ""] });
      await audit(env, req, me.id, "ats_export", "", L.length + " rows");
      return new Response("\ufeff" + [H].concat(rows).map(r => r.map(csvCell).join(",")).join("\r\n"), { headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="vexcura-applicants-${day(T())}.csv"`, "Cache-Control": "no-store" } });
    }
    /* applicants: delete a person and everything about them (retention) */
    if (r === "applicants" && seg[2] && M === "DELETE") {
      const p = await env.DB.prepare("SELECT id, name FROM ats_applicants WHERE id=?").bind(seg[2]).first(); if (!p) return J({ error: "Not found" }, 404);
      const A = ((await env.DB.prepare("SELECT id FROM ats_apps WHERE person=?").bind(p.id).all()).results || []).map(x => x.id);
      for (const id of A) await env.SITE.delete("ats:f:" + id);
      await env.DB.batch([...A.flatMap(id => [env.DB.prepare("DELETE FROM ats_screen WHERE app=?").bind(id), env.DB.prepare("DELETE FROM ats_activity WHERE app=?").bind(id), env.DB.prepare("UPDATE ats_territories SET rep_app=NULL, rep_name=NULL, status=CASE WHEN status='assigned' THEN 'open' ELSE status END WHERE rep_app=?").bind(id)]), env.DB.prepare("DELETE FROM ats_apps WHERE person=?").bind(p.id), env.DB.prepare("DELETE FROM ats_applicants WHERE id=?").bind(p.id)]);
      await act(env, null, null, "delete", `Applicant record deleted (${A.length} application${A.length === 1 ? "" : "s"}, files removed)`, nm); await audit(env, req, me.id, "ats_applicant_delete", p.id, A.length + " apps");
      return J({ ok: true, deleted: A.length });
    }
    /* applications */
    if (r === "apps") {
      const id = seg[2];
      if (!id && M === "GET") { const L = await list(env, { stage: url.searchParams.get("stage") || "", post: url.searchParams.get("post") || "", q: cl(url.searchParams.get("q"), 80) }); return J({ apps: L, stages: STAGES }) }
      const a = id && await env.DB.prepare("SELECT a.*, p.name pname FROM ats_apps a JOIN ats_applicants p ON p.id=a.person WHERE a.id=?").bind(id).first(); if (!a) return J({ error: "Not found" }, 404);
      const sub = seg[3] || "";
      if (!sub && M === "GET") { if (!a.seen) { await env.DB.prepare("UPDATE ats_apps SET seen=1 WHERE id=?").bind(id).run(); await act(env, id, a.post, "seen", "Application opened", nm) } return J(await detail(env, id)) }
      if (!sub && M === "PUT") {
        const t = T(); let stage = a.stage, reason = a.reason || "";
        if (b.stage != null && b.stage !== a.stage) {
          if (SK.indexOf(b.stage) < 0) return J({ error: "Unknown stage." }, 400); stage = b.stage;
          const S = (await env.DB.prepare("SELECT kind, status FROM ats_screen WHERE app=?").bind(id).all()).results || [];
          const has = (k, st) => S.some(x => x.kind === k && (!st || st.indexOf(x.status) >= 0));
          const at = IDX(stage);
          if (CLOSED.indexOf(stage) < 0 || stage === "onboarded") {
            if (at >= IDX("license") && !has("license", ["active_unencumbered"])) return J({ error: "Record a license lookup showing an active, unencumbered license first (Screening tab).", code: "license" }, 409);
            if (at >= IDX("offer") && !has("fcra", ["signed"])) return J({ error: "The candidate hasn't signed the background check authorization yet (Background tab).", code: "fcra" }, 409);
            if (at >= IDX("offer") && S.filter(x => x.kind === "reference" && x.status === "received").length < 2) return J({ error: "Record two received references first (References tab).", code: "refs" }, 409);
          }
          if (stage === "not_selected" || stage === "withdrawn") reason = cl(b.reason, 300) || (stage === "withdrawn" ? "Withdrawn" : "Not selected");
        }
        const terr = b.terr_pref != null ? cl(b.terr_pref, 40) : a.terr_pref;
        await env.DB.prepare("UPDATE ats_apps SET stage=?, stage_at=?, reason=?, terr_pref=?, updated=? WHERE id=?").bind(stage, stage !== a.stage ? t : a.stage_at, reason, terr, t, id).run();
        if (stage !== a.stage) { await act(env, id, a.post, "stage", `Moved from ${SN[a.stage]} to ${SN[stage]}${reason && (stage === "not_selected" || stage === "withdrawn") ? ` (${reason})` : ""}`, nm); await audit(env, req, me.id, "ats_stage", id, SN[stage]) }
        return J({ ok: true, app: (await detail(env, id)).app });
      }
      if (!sub && M === "DELETE") { /* delete just this application (and its resume); the person row goes too when it was their only one */
        await env.SITE.delete("ats:f:" + id); await env.DB.batch([env.DB.prepare("DELETE FROM ats_screen WHERE app=?").bind(id), env.DB.prepare("DELETE FROM ats_activity WHERE app=?").bind(id), env.DB.prepare("UPDATE ats_territories SET rep_app=NULL, rep_name=NULL, status=CASE WHEN status='assigned' THEN 'open' ELSE status END WHERE rep_app=?").bind(id), env.DB.prepare("DELETE FROM ats_apps WHERE id=?").bind(id)]);
        const left = await env.DB.prepare("SELECT COUNT(*) n FROM ats_apps WHERE person=?").bind(a.person).first(); if (!left || !left.n) await env.DB.prepare("DELETE FROM ats_applicants WHERE id=?").bind(a.person).run();
        await audit(env, req, me.id, "ats_app_delete", id, ""); return J({ ok: true }) }
      if (sub === "notes" && M === "POST") { const text = ml(b.text, 4000); if (!text) return J({ error: "Write a note first." }, 400); await env.DB.prepare("INSERT INTO ats_activity (id,app,post,kind,text,by_name,at) VALUES (?,?,?,?,?,?,?)").bind(rid("av"), id, a.post, "note", text, nm, T()).run(); return J({ ok: true }, 201) }
      if (sub === "scores" && M === "PUT") { const s = {}; for (const [k] of RUBRIC) { const v = Math.round(+b[k]); s[k] = v >= 1 && v <= 5 ? v : null } s.note = cl(b.note, 1000); s.by = nm; s.at = T();
        await env.DB.prepare("UPDATE ats_apps SET scores=?, updated=? WHERE id=?").bind(JSON.stringify(s), T(), id).run(); await act(env, id, a.post, "score", `Scorecard saved: ${RUBRIC.map(([k, l]) => `${l} ${s[k] || "—"}`).join(", ")} (avg ${avg(s) == null ? "—" : avg(s)})`, nm); return J({ ok: true, avg: avg(s), scores: s }) }
      if (sub === "resume" && M === "GET") { if (!a.resume_name) return J({ error: "No resume" }, 404); const v = await env.SITE.get("ats:f:" + id, "arrayBuffer"); if (!v) return J({ error: "Not found" }, 404); await audit(env, req, me.id, "ats_resume", id, "");
        return new Response(v, { headers: { "Content-Type": a.resume_type, "Content-Disposition": `${a.resume_type === "application/pdf" ? "inline" : "attachment"}; filename="${String(a.resume_name).replace(/[^A-Za-z0-9._ ()-]/g, "")}"`, "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox; default-src 'none'; img-src 'self'; style-src 'unsafe-inline'" } }) }
      if (sub === "license-match" && M === "POST") { const n = normLic(b.number); if (n.length < 4) return J({ error: "Enter the license number shown on Nursys or the board's site." }, 400); const p = await env.DB.prepare("SELECT lic_hash, lic_last4 FROM ats_applicants WHERE id=?").bind(a.person).first(); const ok = !!p && p.lic_hash === await sha("lic|" + await pepper(env) + "|" + n);
        await act(env, id, a.post, "license", `License number check: ${ok ? "matches what the applicant entered" : "does NOT match what the applicant entered"}`, nm); return J({ ok: true, match: ok, last4: p && p.lic_last4 ? "••••" + p.lic_last4 : "" }) }
      if (sub === "link" && M === "POST") { const tok = hex(24), code = [...crypto.getRandomValues(new Uint8Array(8))].map(x => "ABCDEFGHJKMNPQRSTUVWXYZ23456789"[x % 31]).join("").replace(/^(.{4})/, "$1-");
        await env.DB.prepare("UPDATE ats_apps SET tok_hash=?, code_hash=? WHERE id=?").bind(await sha("ats|" + tok), await sha("code|" + id + "|" + code.replace(/-/g, "")), id).run(); await act(env, id, a.post, "link", "New status link and backup code created (old ones stop working)", nm); return J({ ok: true, status_url: url.origin + "/careers/status?t=" + tok, code }) }
      if (sub === "fcra" && M === "POST") { /* request the stand-alone FCRA disclosure + authorization from the applicant */
        if (IDX(a.stage) < IDX("references") || CLOSED.indexOf(a.stage) >= 0) return J({ error: "Background checks are for finalists only. Move the candidate to References or Background first." }, 409);
        const f = await env.DB.prepare("SELECT id, status FROM ats_screen WHERE app=? AND kind='fcra' ORDER BY created DESC LIMIT 1").bind(id).first(); if (f && (f.status === "requested" || f.status === "signed")) return J({ error: f.status === "signed" ? "Already signed." : "Already requested. The candidate signs it from their status link." }, 409);
        const t = T(); await env.DB.prepare("INSERT INTO ats_screen (id,app,kind,status,data,by_name,created,updated) VALUES (?,?,'fcra','requested',?,?,?,?)").bind(rid("sc"), id, JSON.stringify({ requested_at: t, version: FCRA_V }), nm, t, t).run();
        if (a.stage !== "background") await env.DB.prepare("UPDATE ats_apps SET stage='background', stage_at=?, updated=? WHERE id=?").bind(t, t, id).run();
        await act(env, id, a.post, "fcra", "Background check authorization requested (stand-alone disclosure shown on the candidate's status page)", nm); return J({ ok: true }) }
      if (sub === "background" && M === "PUT") { /* vendor-agnostic: record what the screening company reports; no vendor API yet */
        const st = BG.indexOf(b.status) >= 0 ? b.status : null; if (!st) return J({ error: "Choose a status." }, 400);
        const f = await env.DB.prepare("SELECT status FROM ats_screen WHERE app=? AND kind='fcra' ORDER BY created DESC LIMIT 1").bind(id).first();
        if (st !== "not_started" && st !== "cancelled" && (!f || f.status !== "signed")) return J({ error: "You can't order a background check until the candidate signs the authorization.", code: "fcra" }, 409);
        const x = await env.DB.prepare("SELECT * FROM ats_screen WHERE app=? AND kind='background' LIMIT 1").bind(id).first(); const t = T(); const d = cleanScreen("background", b, x ? P(x.data, {}) : {});
        if (x) await env.DB.prepare("UPDATE ats_screen SET status=?, data=?, by_name=?, updated=? WHERE id=?").bind(st, JSON.stringify(d), nm, t, x.id).run(); else await env.DB.prepare("INSERT INTO ats_screen (id,app,kind,status,data,by_name,created,updated) VALUES (?,?,'background',?,?,?,?,?)").bind(rid("sc"), id, st, JSON.stringify(d), nm, t, t).run();
        await act(env, id, a.post, "background", `Background check: ${st.replace(/_/g, " ")}${d.vendor ? " · " + d.vendor : ""}`, nm); return J({ ok: true }) }
      if (sub === "screen" && M === "POST") { const kind = b.kind; if (!SCREEN[kind]) return J({ error: "Unknown screening item." }, 400); const status = SCREEN[kind].indexOf(b.status) >= 0 ? b.status : SCREEN[kind][0]; const d = cleanScreen(kind, b.data || {});
        if (kind === "license") { if (!d.state || !d.looked_up) return J({ error: "Enter the license state and the date you looked it up." }, 400); if (d.looked_up > day(T() + 864e5)) return J({ error: "The lookup date can't be in the future." }, 400) }
        if (kind === "reference" && !d.name) return J({ error: "Enter the reference's name." }, 400);
        const t = T(), sid = rid("sc"); await env.DB.prepare("INSERT INTO ats_screen (id,app,kind,status,data,by_name,created,updated) VALUES (?,?,?,?,?,?,?,?)").bind(sid, id, kind, status, JSON.stringify(d), nm, t, t).run();
        await act(env, id, a.post, kind, kind === "license" ? `License lookup (${d.source || "Nursys QuickConfirm"}, ${d.looked_up}): ${d.state} ${d.type || ""} — ${status.replace(/_/g, " ")}${d.discipline ? " · discipline on record" : ""}` : `${kind[0].toUpperCase() + kind.slice(1)} added: ${status.replace(/_/g, " ")}${d.name ? " · " + d.name : ""}${d.date ? " · " + d.date : ""}`, nm);
        return J({ ok: true, id: sid }, 201) }
      return J({ error: "Not found" }, 404);
    }
    if (r === "screen" && seg[2]) {
      const x = await env.DB.prepare("SELECT * FROM ats_screen WHERE id=?").bind(seg[2]).first(); if (!x || x.kind === "fcra") return J({ error: "Not found" }, 404);
      if (M === "PUT") { const status = SCREEN[x.kind] && SCREEN[x.kind].indexOf(b.status) >= 0 ? b.status : x.status; const d = cleanScreen(x.kind, b.data || {}, P(x.data, {})); await env.DB.prepare("UPDATE ats_screen SET status=?, data=?, by_name=?, updated=? WHERE id=?").bind(status, JSON.stringify(d), nm, T(), x.id).run();
        if (status !== x.status) await act(env, x.app, null, x.kind, `${x.kind[0].toUpperCase() + x.kind.slice(1)}${d.name ? " (" + d.name + ")" : ""}: ${String(x.status).replace(/_/g, " ")} → ${status.replace(/_/g, " ")}`, nm); return J({ ok: true }) }
      if (M === "DELETE") { await env.DB.prepare("DELETE FROM ats_screen WHERE id=?").bind(x.id).run(); await act(env, x.app, null, x.kind, `${x.kind[0].toUpperCase() + x.kind.slice(1)} record removed`, nm); return J({ ok: true }) }
    }
    return J({ error: "Not found" }, 404);
  }

  async function api(req, env, ctx, url) {
    await init(env); const seg = url.pathname.replace(/^\/api\/ats\/?/, "").split("/").filter(Boolean); const M = req.method;
    if (M !== "GET" && req.headers.get("X-NCLEX") !== "1") return J({ error: "Bad request" }, 400);
    try {
      if (seg[0] === "apply" && M === "POST") return await apply(req, env, url);
      if (seg[0] === "status" && M === "POST") return await statusApi(req, env, url, seg);
      if (seg[0] === "admin") {
        const me = await current(env, req); if (!me) return J({ error: "Sign in first." }, 401);
        if (me.role !== "admin" || me.mustReset || me.must_reset) return J({ error: "Administrators only." }, 403);
        return await admin(req, env, url, seg, me);
      }
    } catch (e) { return J({ error: "Something went wrong on our side. Try again.", detail: String(e && e.message || e).slice(0, 200) }, 500) }
    return J({ error: "Not found" }, 404);
  }

  /* ---------- sitemap: open postings + /careers. Composes with DAILY's injection when both are installed. ---------- */
  async function sitemap(env, xml) { if (!xml) return xml; await init(env); const L = await openPosts(env); if (xml.indexOf(ORIGIN + "/careers</loc>") >= 0) return xml;
    const add = [`<url><loc>${ORIGIN}/careers</loc><lastmod>${day(L.length ? Math.max(...L.map(p => p.updated)) : T())}</lastmod><priority>0.5</priority></url>`].concat(L.map(p => `<url><loc>${ORIGIN}/careers/${p.slug}</loc><lastmod>${day(p.updated)}</lastmod><priority>0.6</priority></url>`)).join("\n");
    return xml.replace("</urlset>", add + "\n</urlset>") }
  const owns = u => /^\/(careers(\/[a-z0-9-]{1,80})?\/?|sitemap\.xml)$/.test(u.pathname);
  async function route(req, env, ctx, url) {
    if (req.method !== "GET" && req.method !== "HEAD") return null; const p = url.pathname.replace(/\/$/, "") || "/";
    try {
      await init(env);
      if (p === "/sitemap.xml") { let raw = await env.SITE.get("p:/sitemap.xml"); if (!raw) return null; const D = globalThis.__DAILY; if (D && D.sitemap) { try { raw = await D.sitemap(env, raw) } catch (e) { } }
        return new Response(await sitemap(env, raw), { headers: { "Content-Type": "application/xml; charset=utf-8", "Cache-Control": "public, max-age=300" } }) }
      if (p === "/careers") return new Response(await listPage(env), { headers: HTMLH() });
      if (p === "/careers/status") return await statusPage(env, url);
      const m = p.match(/^\/careers\/([a-z0-9-]+)$/); if (!m) return null;
      const x = await env.DB.prepare("SELECT * FROM ats_posts WHERE slug=?").bind(m[1]).first();
      if (!x || x.status === "draft") { const Tp = await template(env); return new Response(head(Tp, { path: "/careers", title: "Position not found | Careers at Vexcura", desc: "This position isn't available.", noindex: true }) + `${crumb([["Home", "/"], ["Careers", "/careers"]])}<section class="hero w vxc"><h1>Position not found</h1><p class="lead">This position isn't available.</p><div class="cta"><a class="btn" href="/careers">See open positions</a></div></section></main>${Tp.foot}</body></html>`, { status: 404, headers: HTMLH({ "X-Robots-Tag": "noindex", "Cache-Control": "no-store" }) }) }
      const post = pubPost(x);
      if (!isLive(post)) return new Response(await closedPage(env, post), { status: 410, headers: HTMLH({ "X-Robots-Tag": "noindex" }) });
      return new Response(await postPage(env, post, url.origin), { headers: HTMLH() });
    } catch (e) { return null }
  }
  return { api, route, owns, sitemap, calc, TEMPLATE, PLANS, RATE, EEO, FCRA_DISCLOSURE, FCRA_AUTH, ACK, PRIVACY, BOARDS, toPlain, _jobLD: jobLD };
})();
