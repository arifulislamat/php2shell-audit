// Backend for the GitHub Pages scanner. Browsers can't read another site's headers (CORS),
// so this Worker fetches them and returns a verdict. Passive GETs only, no exploit payloads.
// Same checks as `check.sh <url>`; keep the two in sync.

const FIXED = { '8.5': 12, '8.4': 27, '8.3': 36, '8.2': 35 };
const PHPINFO_PATHS = ['phpinfo.php', 'info.php', 'php_info.php', 'i.php', 'test.php'];
const VER = /(\d+)\.(\d+)\.(\d+)(-?(?:alpha|beta|RC)\d+)?/;
const UA = 'php2shell-check/1.0 (+https://github.com/arifulislamat/php2shell)';

// "patched" | "eol" | "vulnerable:<fixed version>", same rules as php_status in check.sh.
export function phpStatus(v) {
  const m = VER.exec(v);
  if (!m) return 'unknown';
  const [maj, min, pat] = [+m[1], +m[2], +m[3]], pre = m[4] || '', branch = `${maj}.${min}`;
  if (branch === '8.6') return /alpha|beta|RC[1-3]$/.test(pre) ? 'vulnerable:8.6.0RC4' : 'patched';
  const fix = FIXED[branch];
  if (fix === undefined) return maj > 8 || (maj === 8 && min > 6) ? 'patched' : 'eol';
  return pat > fix || (pat === fix && !pre) ? 'patched' : `vulnerable:${branch}.${fix}`;
}

const get = (url) => fetch(url, { headers: { 'User-Agent': UA }, redirect: 'follow', signal: AbortSignal.timeout(10000) });

async function scan(target) {
  const res = await get(target);
  const h = res.headers, body = (await res.text()).slice(0, 500000);
  const cookies = h.get('set-cookie') || '';
  const powered = h.get('x-powered-by') || '';
  const signals = [];
  let version = /php/i.test(powered) ? (VER.exec(powered) || [])[0] : undefined;
  let app;
  if (/php/i.test(powered)) signals.push('X-Powered-By header');
  if (/(^|[\s,])(PHPSESSID|laravel_session)=/i.test(cookies)) signals.push('PHP session cookie');
  if (/(^|[\s,])laravel_session=/i.test(cookies)) app = 'Laravel';
  if (/\/wp-(content|includes)\//.test(body)) app = 'WordPress';
  if (/^Drupal/i.test(h.get('x-generator') || '') || /name="generator" content="Drupal/i.test(body)) app = 'Drupal';
  if (/name="generator" content="Joomla/i.test(body)) app = 'Joomla';
  if (app) signals.push(app);

  const origin = new URL(res.url).origin;
  const phpinfo = (await Promise.all(PHPINFO_PATHS.map(async (p) => {
    try {
      const r = await get(`${origin}/${p}`);
      const t = r.ok ? await r.text() : '';
      if (!t.includes('phpinfo()')) return null;
      const v = (/PHP Version ([^\s<]+)/.exec(t) || [])[1];
      const up = (/session\.upload_progress\.enabled<\/td><td class="v">([^<]*)/.exec(t) || [])[1];
      return { url: `${origin}/${p}`, version: v, uploadProgress: up };
    } catch { return null; }
  }))).filter(Boolean);
  for (const i of phpinfo) { version ||= i.version; signals.push('phpinfo page'); }

  const status = version ? phpStatus(version) : undefined;
  return {
    url: res.url, headers: Object.fromEntries(h), server: h.get('server'), cloudflare: h.has('cf-ray'), app, signals, version, phpinfo,
    verdict: status === 'eol' || status?.startsWith('vulnerable') ? 'vulnerable' : status === 'patched' ? 'patched' : signals.length ? 'unknown' : 'no-php',
    eol: status === 'eol', fixedIn: status?.split(':')[1],
  };
}

export default {
  async fetch(req) {
    // ponytail: open CORS and no rate limit; restrict the origin to your Pages domain if this gets abused.
    const json = (data, status = 200) => new Response(JSON.stringify(data), {
      status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' },
    });
    let u;
    try {
      const t = (new URL(req.url).searchParams.get('url') || '').trim();
      u = new URL(/^https?:\/\//i.test(t) ? t : `https://${t}`);
    } catch { return json({ error: 'Enter a valid website address.' }, 400); }
    // Public domain names only: no IP literals, no localhost-style names.
    if (!/^https?:$/.test(u.protocol) || !u.hostname.includes('.') || /^[\d.]+$|^\[/.test(u.hostname)) {
      return json({ error: 'Enter a public domain name, like example.com.' }, 400);
    }
    try { return json(await scan(u.href)); }
    catch (e) { return json({ error: `Could not reach ${u.hostname}: ${e.message}` }, 502); }
  },
};
