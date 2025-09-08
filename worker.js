// worker.js - Cloudflare Worker (modules syntax) with PKCE-first token exchange,
// fallback to client_secret, and a verbose debug endpoint.

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // CORS preflight
    if (req.method === "OPTIONS") return cors(new Response("", { status: 204 }));

    try {
      // Root info
      if (url.pathname === "/" && req.method === "GET") {
        return cors(json({
          ok: true,
          message: "Vavlo Worker online",
          endpoints: ["/health", "/debug-token", "/debug-token-verbose", "/upload (POST)", "/save-project (POST)"],
          root: env.ROOT,
          ttlDays: env.TTL_DAYS
        }));
      }

      // Diagnostics
      if (url.pathname === "/health" && req.method === "GET") {
        return cors(json({ ok: true, root: env.ROOT, ttlDays: env.TTL_DAYS }));
      }

      if (url.pathname === "/debug-token" && req.method === "GET") {
        try {
          const token = await getAccessToken(env);
          return cors(json({ ok: true, tokenPreview: mask(token) }));
        } catch {
          return cors(json({ ok: false, error: "Token exchange failed" }, 500));
        }
      }

      if (url.pathname === "/debug-token-verbose" && req.method === "GET") {
        const out = await debugAccessToken(env);
        const status = out.ok ? 200 : 500;
        return cors(json(out, status));
      }

      // Upload image
      if (url.pathname === "/upload" && req.method === "POST") {
        const token = await getAccessToken(env);
        const form = await req.formData();
        const file = form.get("file");
        const key = form.get("key");
        if (!file || !key) return cors(json({ error: "file and key required" }, 400));

        const path = `${env.ROOT}/${key}`;
        await dbxUpload(token, path, file);
        const link = await getOrCreateSharedLink(token, path, expiryISO(env.TTL_DAYS));
        return cors(json({ imageUrl: toDirect(link.url) }));
      }

      // Save project JSON
      if (url.pathname === "/save-project" && req.method === "POST") {
        const token = await getAccessToken(env);
        const body = await req.json().catch(() => ({}));
        const { project, comments } = body || {};
        if (!project?.id) return cors(json({ error: "project.id required" }, 400));

        const jsonPath = `${env.ROOT}/projects/${project.id}_project.json`;
        await dbxUpload(token, jsonPath, JSON.stringify({ project, comments }));
        const link = await getOrCreateSharedLink(token, jsonPath, expiryISO(env.TTL_DAYS));
        return cors(json({ sharedJsonUrl: toDirect(link.url) }));
      }

      return cors(json({ error: "Not found" }, 404));
    } catch (e) {
      console.error("Worker error:", e?.message || String(e));
      return cors(json({ error: e?.message || String(e) }, 500));
    }
  },

  // Daily cleanup
  async scheduled(event, env, ctx) {
    try {
      const token = await getAccessToken(env);
      const entries = await listAll(token, env.ROOT);
      const cutoff = Date.now() - Number(env.TTL_DAYS) * 86400000;

      const oldFiles = entries.filter(
        e => e[".tag"] === "file" && new Date(e.client_modified).getTime() < cutoff
      );

      for (const f of oldFiles) {
        try { await dbx(token, "files/delete_v2", { path: f.path_lower }); }
        catch (err) { console.error("Delete failed", f.path_lower, err); }
      }
    } catch (e) {
      console.error("Cron error", e);
    }
  }
};

/* OAuth: refresh token -> short-lived access token
   Secrets required:
   - DROPBOX_REFRESH_TOKEN  from finish.html (refresh_token)
   - DROPBOX_APP_KEY        App key of the same app that issued the refresh token
   Optional secret for fallback:
   - DROPBOX_APP_SECRET     App secret (if present, we will try secret-based exchange second)
   Text vars:
   - ROOT = /ImageAnnotationTool
   - TTL_DAYS = 90
*/
async function getAccessToken(env) {
  // Try PKCE-style refresh first
  const pkceParams = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: env.DROPBOX_REFRESH_TOKEN,
    client_id: env.DROPBOX_APP_KEY
  });

  const pkceRes = await fetch("https://api.dropboxapi.com/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: pkceParams
  });

  let txt = await pkceRes.text();
  if (pkceRes.ok) {
    const data = safeJson(txt, "Token parse error (PKCE)");
    if (!data.access_token) throw new Error("No access_token returned (PKCE)");
    return data.access_token;
  }

  // If PKCE failed and we have a client secret, try secret-based refresh
  if (env.DROPBOX_APP_SECRET) {
    const secretParams = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: env.DROPBOX_REFRESH_TOKEN,
      client_id: env.DROPBOX_APP_KEY,
      client_secret: env.DROPBOX_APP_SECRET
    });

    const secretRes = await fetch("https://api.dropboxapi.com/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: secretParams
    });

    txt = await secretRes.text();
    if (secretRes.ok) {
      const data = safeJson(txt, "Token parse error (secret)");
      if (!data.access_token) throw new Error("No access_token returned (secret)");
      return data.access_token;
    }
  }

  // Both attempts failed
  console.error("Token exchange failed:", txt.slice(0, 300));
  throw new Error("Token exchange failed");
}

// Verbose debug endpoint logic
async function debugAccessToken(env) {
  const pkceParams = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: env.DROPBOX_REFRESH_TOKEN,
    client_id: env.DROPBOX_APP_KEY
  });

  const pkceRes = await fetch("https://api.dropboxapi.com/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: pkceParams
  });

  let pkceText = await pkceRes.text();
  if (pkceRes.ok) return { ok: true, method: "pkce", tokenPreview: mask(safeJson(pkceText).access_token) };

  let out = { ok: false, pkceError: pkceText.slice(0, 400) };

  if (env.DROPBOX_APP_SECRET) {
    const secretParams = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: env.DROPBOX_REFRESH_TOKEN,
      client_id: env.DROPBOX_APP_KEY,
      client_secret: env.DROPBOX_APP_SECRET
    });

    const secretRes = await fetch("https://api.dropboxapi.com/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: secretParams
    });
    let secretText = await secretRes.text();
    if (secretRes.ok) return { ok: true, method: "secret", tokenPreview: mask(safeJson(secretText).access_token) };

    out.secretError = secretText.slice(0, 400);
  }

  return out;
}

/* Dropbox helpers */
async function dbx(token, api, body, content = "application/json") {
  const res = await fetch("https://api.dropboxapi.com/2/" + api, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": content },
    body: content === "application/json" ? JSON.stringify(body) : body
  });
  const txt = await res.text();
  if (!res.ok) {
    console.error("DBX API error", api, txt.slice(0, 300));
    throw new Error(txt);
  }
  return safeJson(txt, "Dropbox response parse error");
}

async function dbxUpload(token, path, content) {
  const res = await fetch("https://content.dropboxapi.com/2/files/upload", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/octet-stream",
      "Dropbox-API-Arg": JSON.stringify({ path, mode: "overwrite", autorename: false })
    },
    body: content
  });
  const txt = await res.text();
  if (!res.ok) {
    console.error("DBX upload error", path, txt.slice(0, 300));
    throw new Error(txt);
  }
  return safeJson(txt, "Dropbox upload parse error");
}

async function getOrCreateSharedLink(token, path, expiresISO) {
  const create = await fetch("https://api.dropboxapi.com/2/sharing/create_shared_link_with_settings", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ path, settings: { requested_visibility: "public", expires: expiresISO } })
  });

  if (create.ok) return create.json();

  const text = await create.text();
  if (!/shared_link_already_exists/i.test(text)) {
    console.error("Create link error", text.slice(0, 300));
    throw new Error(text);
  }

  const list = await dbx(token, "sharing/list_shared_links", { path, direct_only: true });
  if (!list.links?.length) {
    console.error("No existing link found for", path);
    throw new Error("No existing shared link found");
  }
  return list.links[0];
}

async function listAll(token, root) {
  const first = await dbx(token, "files/list_folder", { path: root, recursive: true });
  let entries = [...(first.entries || [])];
  let cursor = first.cursor;
  let has_more = first.has_more;

  while (has_more) {
    const more = await dbx(token, "files/list_folder/continue", { cursor });
    entries.push(...(more.entries || []));
    cursor = more.cursor;
    has_more = more.has_more;
  }
  return entries;
}

/* Utils */
function toDirect(url) {
  return url
    .replace("www.dropbox.com", "dl.dropboxusercontent.com")
    .replace("dropbox.com", "dl.dropboxusercontent.com")
    .replace("?dl=0", "");
}
function expiryISO(days) {
  const d = new Date();
  d.setDate(d.getDate() + Number(days || 90));
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
}
function cors(res) {
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  h.set("Access-Control-Allow-Headers", "Content-Type");
  return new Response(res.body, { status: res.status, headers: h });
}
function mask(s) {
  if (!s) return "";
  return s.slice(0, 6) + "..." + s.slice(-4);
}
function safeJson(txt, msg = "Parse error") {
  try { return JSON.parse(txt); } catch { throw new Error(msg + ": " + txt.slice(0, 200)); }
}
