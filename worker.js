// worker.js - Cloudflare Worker (modules syntax)

export default {
  async fetch(req, env) {
    try {
      const url = new URL(req.url);
      // CORS
      if (req.method === 'OPTIONS') return cors(new Response('', { status: 204 })));

      if (url.pathname === '/upload' && req.method === 'POST') {
        const form = await req.formData();
        const file = form.get('file');
        const key = form.get('key');
        if (!file || !key) return cors(json({ error: 'file and key required' }, 400));

        const path = `${env.ROOT}/${key}`;
        await dbxUpload(env, path, file);
        const share = await getOrCreateSharedLink(env, path, expiryISO(env.TTL_DAYS));
        return cors(json({ imageUrl: toDirect(share.url) }));
      }

      if (url.pathname === '/save-project' && req.method === 'POST') {
        const body = await req.json();
        const { project, comments } = body || {};
        if (!project?.id) return cors(json({ error: 'project.id required' }, 400));

        const jsonPath = `${env.ROOT}/projects/${project.id}_project.json`;
        await dbxUpload(env, jsonPath, JSON.stringify({ project, comments }));

        // Create the link once. If it already exists, reuse it without touching expiration.
        const link = await getOrCreateSharedLink(env, jsonPath, expiryISO(env.TTL_DAYS));
        return cors(json({ sharedJsonUrl: toDirect(link.url) }));
      }

      return cors(new Response('Not found', { status: 404 }));
    } catch (e) {
      return cors(json({ error: e.message || String(e) }, 500));
    }
  },

  // Daily cleanup
  async scheduled(event, env, ctx) {
    try {
      const entries = await listAll(env, env.ROOT);
      const cutoff = Date.now() - Number(env.TTL_DAYS) * 86400000;
      const oldFiles = entries.filter(e => e['.tag'] === 'file' && new Date(e.client_modified).getTime() < cutoff);
      for (const f of oldFiles) {
        await dbx(env, 'files/delete_v2', { path: f.path_lower }).catch(err => console.error('Delete failed', f.path_lower, err));
      }
    } catch (e) {
      console.error('Cron error', e);
    }
  }
};

// Dropbox helpers
async function dbx(env, api, body, content = 'application/json') {
  const res = await fetch('https://api.dropboxapi.com/2/' + api, {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.DROPBOX_TOKEN}`, 'Content-Type': content },
    body: content === 'application/json' ? JSON.stringify(body) : body
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function dbxUpload(env, path, content) {
  const headers = {
    Authorization: `Bearer ${env.DROPBOX_TOKEN}`,
    'Content-Type': 'application/octet-stream',
    'Dropbox-API-Arg': JSON.stringify({ path, mode: 'overwrite', autorename: false })
  };
  const res = await fetch('https://content.dropboxapi.com/2/files/upload', { method: 'POST', headers, body: content });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function getOrCreateSharedLink(env, path, expiresISO) {
  // Try create
  const create = await fetch('https://api.dropboxapi.com/2/sharing/create_shared_link_with_settings', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.DROPBOX_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, settings: { requested_visibility: 'public', expires: expiresISO } })
  });

  if (create.ok) return create.json();

  const text = await create.text();
  if (!/shared_link_already_exists/i.test(text)) throw new Error(text);

  // Reuse existing without modifying expiration
  const list = await dbx(env, 'sharing/list_shared_links', { path, direct_only: true });
  if (!list.links?.length) throw new Error('No existing link found');
  return list.links[0];
}

async function listAll(env, root) {
  const first = await dbx(env, 'files/list_folder', { path: root, recursive: true });
  let entries = [...(first.entries || [])];
  let cursor = first.cursor;
  while (first.has_more) {
    const more = await dbx(env, 'files/list_folder/continue', { cursor });
    entries.push(...(more.entries || []));
    cursor = more.cursor;
    if (!more.has_more) break;
  }
  return entries;
}

// Utils
function toDirect(url) {
  return url.replace('www.dropbox.com', 'dl.dropboxusercontent.com')
            .replace('dropbox.com', 'dl.dropboxusercontent.com')
            .replace('?dl=0', '');
}
function expiryISO(days) {
  const d = new Date(); d.setDate(d.getDate() + Number(days || 90));
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
function cors(res) {
  const h = new Headers(res.headers);
  h.set('Access-Control-Allow-Origin', '*');
  h.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  h.set('Access-Control-Allow-Headers', 'Content-Type');
  return new Response(res.body, { status: res.status, headers: h });
}
