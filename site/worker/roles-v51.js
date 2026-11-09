/* ROLES (v51) — corporate sub-admins with permission tiers + the RN content-reviewer role.
   Authoritative, server-side permission model. Insert inside MOD (uses current, audit, now; env.DB, env.SITE),
   immediately BEFORE the `globalThis.__BADGE = BADGE;` export line, then add `globalThis.__ROLES = ROLES;`.
   Router hooks (see deploy/ROLES-DEPLOY.md):
     1) a guard that runs for every /api/ request and constrains restricted tiers across ALL existing endpoints;
     2) /api/roles/* -> ROLES.api.
   Nothing here edits other endpoints: a reviewer/viewer is a normal role='admin' account (so they can reach the
   admin console) whom the guard holds to exactly the surfaces their tier allows. Enforcement is here, never in the app. */
const ROLES = (function () {
  const J = (o, s) => new Response(JSON.stringify(o), { status: s || 200, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  const clip = (s, n) => String(s == null ? "" : s).slice(0, n || 200);
  const readBody = async req => { try { return await req.json() } catch (e) { return {} } };

  /* ---- tier model (rank orders the ladder: Owner > Admin > Content Reviewer > Read-only) ---- */
  const TIERS = {
    owner:    { rank: 100, label: "Owner",            desc: "Full control, including the team and who holds which role." },
    admin:    { rank: 80,  label: "Administrator",     desc: "Everything in the admin console except managing other administrators." },
    reviewer: { rank: 40,  label: "Content Reviewer",  desc: "Reviews and approves clinical content; signs off as a registered nurse. No access to accounts, settings or security." },
    viewer:   { rank: 20,  label: "Read-only",         desc: "Can see the admin console but cannot change anything." }
  };
  const TIER_ORDER = ["owner", "admin", "reviewer", "viewer"];

  /* ---- capabilities: the single source of truth the app mirrors via /api/roles/me ---- */
  const CAPS = {
    "view.admin":      "Open the admin control center",
    "users.manage":    "Add, edit, disable, reset and delete accounts",
    "content.hide":    "Hide/unhide bank questions and set the question of the day",
    "content.review":  "Review and approve clinical content and sign off as a registered nurse",
    "assign.send":     "Assign orders and send messages to students",
    "site.settings":   "Change site controls, maintenance and access",
    "security.manage": "Security settings, sessions, lockdown, HIPAA, IP/country blocks",
    "exports":         "Export the audit log and program data",
    "team.manage":     "Add administrators and set anyone's permission tier"
  };
  const TIER_CAPS = {
    owner:    Object.keys(CAPS),
    admin:    ["view.admin", "users.manage", "content.hide", "content.review", "assign.send", "site.settings", "security.manage", "exports"],
    reviewer: ["view.admin", "content.review"],
    viewer:   ["view.admin"]
  };
  const canTier = (tier, cap) => !!(TIER_CAPS[tier] && TIER_CAPS[tier].indexOf(cap) >= 0);

  /* ---- store: KV roles:tiers {uid:{tier,by,byName,at}}, roles:owners [uid,...] ---- */
  async function store(env) { let t = {}, o = []; try { t = (await env.SITE.get("roles:tiers", "json")) || {} } catch (e) { } try { o = (await env.SITE.get("roles:owners", "json")) || [] } catch (e) { } return { tiers: t, owners: o }; }
  async function owners(env) {
    const s = await store(env); if (Array.isArray(s.owners) && s.owners.length) return s.owners;
    /* seed: the oldest active administrator is the owner (Tyler) */
    const r = await env.DB.prepare("SELECT id FROM users WHERE role='admin' AND status='active' ORDER BY created ASC LIMIT 1").first();
    const seed = r ? [String(r.id)] : []; if (seed.length) { try { await env.SITE.put("roles:owners", JSON.stringify(seed)) } catch (e) { } }
    return seed;
  }
  /* a user's effective tier. role='admin' accounts are team members; everyone else is null (not on the team). */
  async function tierOf(env, u) {
    if (!u || u.role !== "admin") return null;
    const own = await owners(env); if (own.indexOf(String(u.id)) >= 0) return "owner";
    const s = await store(env); const t = s.tiers[String(u.id)] && s.tiers[String(u.id)].tier;
    return TIERS[t] ? t : "admin";
  }
  async function can(env, u, cap) { const t = await tierOf(env, u); return !!t && canTier(t, cap); }

  /* ================= router guard ================= */
  /* Privileged API surface that the tier model governs. Anything outside this passes untouched, so a reviewer or
     viewer still uses the platform (exams, drills, coach, progress) as any signed-in nurse would. */
  const PRIV = /^\/api\/(admin(\/|$)|sec\/|crm\/|guar\/admin|onb\/admin|school\/[^/]+\/(members|license|roster|invite|remove)|ops\/export|lti\/admin|push\/note|daily\/admin|qbank\/admin|roles\/)/;
  /* Within the privileged surface, what a Content Reviewer may reach (their job: review content). */
  const REVIEWER_OK = [
    { re: /^\/api\/daily\/admin\/(summary|items|bulk|reviewer|pdf-needed|export)(\/|\?|$)/, m: null },
    { re: /^\/api\/daily\/admin\/items\/[^/]+$/, m: ["POST"] },
    { re: /^\/api\/daily\/admin\/pdf\/[^/]+$/, m: ["POST"] },
    { re: /^\/api\/qbank\/admin\//, m: null },
    { re: /^\/api\/roles\//, m: null }
  ];
  const VIEWER_OK = [{ re: /^\/api\/roles\//, m: null }];
  const okList = (list, path, method) => list.some(x => x.re.test(path) && (!x.m || x.m.indexOf(method) >= 0));

  /* Returns a Response to short-circuit (deny), or null to continue. Safe default: deny within PRIV for a
     restricted tier unless explicitly allowed. Owner/admin and non-team users pass (existing gates still apply). */
  async function guard(req, env, url) {
    const path = url.pathname;
    if (!PRIV.test(path)) return null;                 // ordinary API — not ours to police
    let me; try { me = await current(env, req) } catch (e) { return null }
    if (!me || me.role !== "admin" || me.must_reset) return null; // let the endpoint's own auth answer
    const tier = await tierOf(env, me);
    if (tier === "owner" || tier === "admin") return null;        // unrestricted
    const method = req.method.toUpperCase();
    if (tier === "reviewer") {
      if (okList(REVIEWER_OK, path, method)) return null;
      return deny(env, req, me, tier, path, method, "content review");
    }
    if (tier === "viewer") {
      if (method === "GET" || okList(VIEWER_OK, path, method)) return null; // read-only
      return deny(env, req, me, tier, path, method, "read-only");
    }
    return null;
  }
  async function deny(env, req, me, tier, path, method, role) {
    try { await audit(env, req, me.id, "role_denied", String(me.id), method + " " + path + " (" + tier + ")") } catch (e) { }
    return J({ error: "Your role (" + (TIERS[tier] ? TIERS[tier].label : tier) + ") can't do that. Ask an administrator if you need access.", code: "tier", tier, need: role }, 403);
  }

  /* ================= /api/roles/* ================= */
  async function api(req, env, ctx, url) {
    const me = await current(env, req);
    if (!me) return J({ error: "Please sign in." }, 401);
    const seg = url.pathname.replace(/^\/api\/roles\/?/, "").split("/").filter(Boolean);
    const method = req.method.toUpperCase();
    const myTier = await tierOf(env, me);
    if (method !== "GET" && req.headers.get("X-NCLEX") !== "1") return J({ error: "Bad request" }, 400);
    if (method !== "GET") { const o = req.headers.get("Origin"); if (o && o !== url.origin) return J({ error: "Request blocked." }, 403); }

    /* who am I + what can I do (the app gates its UI from this; the guard enforces for real) */
    if (seg[0] === "me" && method === "GET") {
      return J({ tier: myTier, owner: myTier === "owner", reviewer: myTier === "reviewer",
        label: myTier && TIERS[myTier] ? TIERS[myTier].label : null,
        caps: myTier ? TIER_CAPS[myTier] : [], tiers: TIERS, capLabels: CAPS });
    }

    /* reviewer roster — "Reviewed by registered nurses". Professional display names only. */
    if (seg[0] === "reviewers" && method === "GET") return J(await roster(env));

    /* team: owners/admins see the roster of team members and their tiers */
    if (seg[0] === "team") {
      if (!myTier || myTier === "reviewer" || myTier === "viewer") return J({ error: "Administrators only." }, 403);
      if (method === "GET") return J(await team(env, me));
      /* set a member's tier */
      if (seg[1] === "tier" && method === "POST") {
        const b = await readBody(req); const uid = clip(b.uid, 40), tier = clip(b.tier, 20);
        if (!TIERS[tier]) return J({ error: "Unknown role tier." }, 400);
        if (!await can(env, me, "team.manage")) {
          /* an administrator (not owner) may only set reviewer/viewer, and only on non-admin targets */
          if (tier === "owner" || tier === "admin") return J({ error: "Only an owner can grant administrator or owner access.", code: "owner" }, 403);
        }
        const tu = await env.DB.prepare("SELECT id, email, name, role, status FROM users WHERE id=?").bind(uid).first();
        if (!tu) return J({ error: "That account no longer exists." }, 404);
        if (tu.role !== "admin") return J({ error: "Add this person to the team first (create them as a staff account), then set their role tier.", code: "notteam" }, 409);
        const curr = await tierOf(env, tu);
        if (String(uid) === String(me.id) && curr === "owner" && tier !== "owner") { const own = await owners(env); if (own.length <= 1) return J({ error: "You're the only owner. Make someone else an owner first.", code: "lastowner" }, 409); }
        /* only an owner can change an owner, or demote an owner */
        if ((curr === "owner" || tier === "owner") && myTier !== "owner") return J({ error: "Only an owner can change owner access.", code: "owner" }, 403);
        await setTier(env, req, me, tu, tier);
        return J({ ok: true, uid, tier });
      }
      return J({ error: "Not found" }, 404);
    }
    return J({ error: "Not found" }, 404);
  }

  async function setTier(env, req, me, tu, tier) {
    const s = await store(env); let own = s.owners.slice(); const uid = String(tu.id);
    if (tier === "owner") { if (own.indexOf(uid) < 0) own.push(uid); delete s.tiers[uid]; }
    else { own = own.filter(x => x !== uid); if (tier === "admin") delete s.tiers[uid]; else s.tiers[uid] = { tier, by: String(me.id), byName: clip(me.name, 80), at: now() }; }
    try { await env.SITE.put("roles:owners", JSON.stringify(own)) } catch (e) { }
    try { await env.SITE.put("roles:tiers", JSON.stringify(s.tiers)) } catch (e) { }
    /* a tier change is a security-relevant event: drop their sessions so the new role takes effect at once */
    try { await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(uid).run() } catch (e) { }
    try { await audit(env, req, me.id, "role_tier", uid, tier) } catch (e) { }
  }

  /* list every team member (role='admin') with their tier + whether they've confirmed an RN reviewer identity */
  async function team(env, me) {
    const r = (await env.DB.prepare("SELECT id, name, email, status, created, last_login FROM users WHERE role='admin' ORDER BY created ASC LIMIT 200").all()).results || [];
    const s = await store(env); const own = await owners(env);
    const out = [];
    for (const u of r) {
      const tier = own.indexOf(String(u.id)) >= 0 ? "owner" : (s.tiers[String(u.id)] && TIERS[s.tiers[String(u.id)].tier] ? s.tiers[String(u.id)].tier : "admin");
      let rv = null; try { rv = await env.SITE.get("daily:rv:" + u.id) } catch (e) { }
      const set = s.tiers[String(u.id)] || null;
      out.push({ id: u.id, name: u.name, email: u.email, status: u.status, created: u.created, lastLogin: u.last_login || null, tier, reviewer: rv || null, isYou: String(u.id) === String(me.id), setBy: set ? set.byName : null, setAt: set ? set.at : null });
    }
    const myTier = await tierOf(env, me);
    return { members: out, tiers: TIERS, order: TIER_ORDER, capLabels: CAPS, tierCaps: TIER_CAPS, canManageTeam: canTier(myTier, "team.manage"), you: String(me.id) };
  }

  /* the reviewer roster + how many clinical items each has signed off (ties to the "reviewed by a registered nurse" labels) */
  async function roster(env) {
    const s = await store(env); const own = await owners(env);
    const ids = new Set([...own.map(String), ...Object.keys(s.tiers)]);
    const members = [];
    for (const id of ids) {
      let rv = null; try { rv = await env.SITE.get("daily:rv:" + id) } catch (e) { }
      if (!rv) continue; // only people who have confirmed an RN reviewer identity appear
      const cnt = await env.DB.prepare("SELECT COUNT(*) n, MAX(decided) last FROM gen_items WHERE by_id=? AND reviewed=1 AND status='approved'").bind(String(id)).first().catch(() => null);
      const tier = own.indexOf(String(id)) >= 0 ? "owner" : (s.tiers[String(id)] && s.tiers[String(id)].tier || "admin");
      members.push({ display: rv, reviewed: cnt ? cnt.n : 0, lastAt: cnt ? cnt.last : null, tier });
    }
    members.sort((a, b) => (b.reviewed - a.reviewed) || String(a.display).localeCompare(String(b.display)));
    return { reviewers: members, count: members.length, note: members.length ? "Clinical content on Vexcura is reviewed by registered nurses." : "" };
  }

  return { api, guard, tierOf, can, canTier, TIERS, TIER_CAPS, CAPS, TIER_ORDER };
})();
