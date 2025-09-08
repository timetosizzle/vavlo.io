// worker.js - Cloudflare Worker (modules syntax)

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // CORS preflight
    if (req.method === "OPTIONS") return cors(new Response("", { status: 204 }));

    try {
      // Diagnostics
      if (url.pathname === "/health") {
        return cors(json({ ok: true, root: env.ROOT, ttlDays: env.TTL_DAYS }));
      }
      if (url.pathname === "/debug-token") {
        try {
          const token = await getAccessToken(env);
          return cors(json({ ok: true, tokenPreview: mask(token) }));
        } catch (e) {
          console.error("debug-token error:", e?.message || String(e));
          return cors(json({ ok: false, error: "Token exchange failed" }, 500));
        }
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

      // Save project JSON (project + comments)
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

      return cors(new Response("Not found", { status: 404 }));
    } catch (e) {
      console.error("Worker error:", e?.message || String(e));
      return cors(json({ error: e?.message || String(e) }, 500));
    }
  },

  // Daily cleanup of files older than TTL_DAYS
  async scheduled(event, env, ctx) {
    try {
      const token = await getAccessToken(env);
      const entries = await listAll(token, env.ROOT);
      const cutoff = Date.now() - Number(env.TTL_DAYS) * 86400000;

      const oldFiles = entries.filter(
        e => e[".tag"] === "file" && new Date(e.client_modified).getTime() < cutoff
      );

      for (const f of oldFiles) {
        try {
          await dbx(token, "files/delete_v2", { path: f.path_lower });
        } catch (err) {
          console.error("Delete failed", f.path_lower, err);
        }
      }
    } catch (e) {
      console.error("Cron error", e);
    }
  }
};

/* ===== OAuth: exchange refresh token for short-lived access token =====
   Secrets required:
   - DROPBOX_REFRESH_TOKEN  from finish.html (refresh_token value)
   - DROPBOX_APP_KEY        your Dropbox App key
   Text vars:
   - ROOT = /ImageAnnotationTool
   - TTL_DAYS = 90
*/
async function getAccessToken(env) {
  const params = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: env.DROPBOX_REFRESH_TOKEN,
    client_id: env.DROPBOX_APP_KE_
