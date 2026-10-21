// Backend for the GitHub Pages scanner. Browsers can't read another site's headers (CORS),
// so this Worker fetches them and returns a verdict. Same checks as `check.sh <url>`.
// Only GET requests. No multipart probes, credentials, cookies or response bodies in reports.
export const FIXED = { '8.5': 12, '8.4': 27, '8.3': 36, '8.2': 35 };
const PATHS = ['phpinfo.php', 'info.php', 'php_info.php', 'i.php', 'test.php'];
const VERSION = /\b(\d+)\.(\d+)\.(\d+)((?:-?(?:alpha|beta|RC)\d+)?)(?:[-+~][a-zA-Z0-9.+~_-]+)?\b/i;
const UA = 'php2shell-check/2.0 (+https://github.com/arifulislamat/php2shell-audit)';
export const ADVISORIES = [
  'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w',
  'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp',
];

export function phpStatus(value) {
  const m = /^(\d+)\.(\d+)\.(\d+)(-?(?:alpha|beta|RC)\d+)?(?:[-+~][a-zA-Z0-9.+~_-]+)?$/i.exec(String(value));
  if (!m) return 'unknown';
  const [major, minor, patch] = m.slice(1, 4).map(Number);
  // Same rules as php_status in check.sh; keep the two in sync.
  if (major === 8 && minor === 6) return /alpha|beta|RC[1-3]$/i.test(m[4] || '') ? 'vulnerable:8.6.0RC4' : 'patched';
  const fixed = FIXED[`${major}.${minor}`];
  if (fixed === undefined) return major > 8 || (major === 8 && minor > 6) ? 'patched' : 'eol';
  return patch > fixed || (patch === fixed && !m[4]) ? 'patched' : `vulnerable:${major}.${minor}.${fixed}`;
}

export function validateURL(input, { allowedTargets = [] } = {}) {
  const raw = String(input).trim();
  if (!raw || /[\x00-\x20\x7f]/.test(raw)) throw new Error('Enter a valid website address.');
  const u = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  if (!['https:', 'http:'].includes(u.protocol) || u.username || u.password) {
    throw new Error('Use an HTTP(S) address without credentials.');
  }
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  u.hostname = host;
  if (!host.includes('.') || /^[\d.]+$|^\[/.test(host) ||
      /(^|\.)(localhost|local|internal|test|invalid|example|onion)$/.test(host)) {
    throw new Error('Enter a public domain name. Local addresses and IP literals are not allowed.');
  }
  if (allowedTargets.length && !allowedTargets.includes(host)) throw new Error('This hostname is outside the configured target allowlist.');
  u.hash = '';
  return u;
}

async function readLimited(res, limit) {
  if (!res.body) return { text: '', truncated: false };
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let text = '', bytes = 0, truncated = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = limit - bytes;
      text += decoder.decode(value.subarray(0, remaining), { stream: true });
      bytes += value.byteLength;
      if (bytes >= limit) { truncated = true; break; }
    }
    text += decoder.decode();
  } finally { await reader.cancel().catch(() => {}); }
  return { text, truncated };
}

export async function scan(target, options = {}) {
  const { fetchImpl = fetch, timeout = 8000, maxBytes = 500000, maxRequests = 18,
    probePhpinfo = true, allowedTargets = [] } = options;
  const policy = { allowedTargets };
  const input = validateURL(target, policy).href;
  const evidence = [], warnings = [], requests = [], phpinfo = [], signals = [], observations = [];
  let partial = false;
  const started = Date.now();
  // One deadline covers redirects and body reads, as well as individual request timeouts.
  const deadline = AbortSignal.timeout(45000);
  // Redirect responses of the main page: a PHP redirect can expose the version that the final page hides.
  const hops = [];
  async function get(url, root = false) {
    let current = validateURL(url, policy);
    for (let hop = 0; hop <= 4; hop++) {
      if (requests.length >= maxRequests) throw new Error('Request budget reached.');
      const entry = { url: current.href, method: 'GET' };
      requests.push(entry);
      const res = await fetchImpl(current.href, {
        headers: { 'User-Agent': UA, Accept: 'text/html', 'Accept-Encoding': 'identity' },
        redirect: 'manual', signal: AbortSignal.any([deadline, AbortSignal.timeout(timeout)]),
      });
      entry.status = res.status;
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        await res.body?.cancel();
        if (root) hops.push({ headers: res.headers, url: current.href });
        const location = res.headers.get('location');
        if (!location) throw new Error('Redirect has no Location header.');
        const next = validateURL(new URL(location, current).href, policy);
        if (current.protocol === 'https:' && next.protocol !== 'https:') throw new Error('Refusing HTTPS downgrade redirect.');
        // Root may redirect to a canonical site; phpinfo checks stay on that site's origin.
        if (!root && next.origin !== current.origin) throw new Error('Cross-origin phpinfo redirect skipped.');
        current = next;
        continue;
      }
      const body = await readLimited(res, maxBytes);
      if (body.truncated) { partial = true; warnings.push(`Response body limit reached at ${current.href}.`); }
      return { res, body: body.text, url: current.href };
    }
    throw new Error('Too many redirects.');
  }
  const addVersion = (value, source, url) => {
    const version = VERSION.exec(value || '')?.[0];
    if (!version) return;
    const status = phpStatus(version);
    observations.push({ version, status, source, url });
    evidence.push({ kind: 'php-version', value: version, source, url });
  };
  const first = await get(input, true);
  const h = first.res.headers;
  let cookies = '';
  for (const r of [...hops, { headers: h, url: first.url }]) {
    const powered = r.headers.get('x-powered-by') || '';
    if (/\bPHP\b/i.test(powered)) {
      signals.push('X-Powered-By header');
      addVersion(/PHP\s*\/\s*([^\s,;]+)/i.exec(powered)?.[1], 'X-Powered-By', r.url);
    }
    cookies += `${r.headers.get('set-cookie') || ''}\n`;
  }
  if (/(?:^|[\s,;])(PHPSESSID|laravel_session)=/i.test(cookies)) signals.push('PHP session cookie');
  let app;
  if (/laravel_session=/i.test(cookies)) app = 'Laravel';
  if (/\/wp-(content|includes)\//i.test(first.body)) app = 'WordPress';
  if (/^Drupal/i.test(h.get('x-generator') || '') || /name=["']generator["'][^>]*content=["']Drupal/i.test(first.body)) app = 'Drupal';
  if (/name=["']generator["'][^>]*content=["']Joomla/i.test(first.body)) app = 'Joomla';
  if (app) signals.push(app);
  if (first.res.status >= 400) {
    partial = true;
    warnings.push(`The main page returned HTTP ${first.res.status}; it may be blocked, throttled or unavailable.`);
  }
  if (probePhpinfo && first.res.status !== 429) {
    for (const path of PATHS) {
      try {
        const page = await get(new URL(path, new URL(first.url).origin + '/').href);
        if (page.res.status === 429) { partial = true; warnings.push('Rate limited; remaining probes skipped.'); break; }
        if (page.res.status >= 500) { partial = true; warnings.push(`HTTP ${page.res.status} at ${page.url}.`); }
        if (!page.res.ok || !/phpinfo\(\)/i.test(page.body) || !/PHP Version\s+[0-9]/i.test(page.body)) continue;
        const version = /PHP Version\s+([^\s<]+)/i.exec(page.body)?.[1];
        const uploadProgress = /session\.upload_progress\.enabled<\/td>\s*<td class=["']v["']>([^<]*)/i.exec(page.body)?.[1];
        phpinfo.push({ url: page.url, version, uploadProgress });
        signals.push('phpinfo page');
        addVersion(version, 'phpinfo', page.url);
      } catch (err) { partial = true; warnings.push(`Could not inspect ${path}: ${err.message}`); }
    }
  }
  const versions = [...new Set(observations.map(o => o.version))];
  if (versions.length > 1) warnings.push('Multiple PHP versions were observed; check each pool/backend and stale caches.');
  const unsafe = observations.find(o => o.status.startsWith('vulnerable:') || o.status === 'eol');
  const allPatched = observations.length > 0 && observations.every(o => o.status === 'patched');
  const verdict = unsafe ? 'vulnerable' : allPatched && !partial ? 'patched' : partial || signals.length ? 'unknown' : 'no-php';
  const selected = unsafe || observations[0];
  if (observations.length) warnings.push('Remote version strings are self-reported; vendor backports, caches and other PHP pools require server-side verification.');
  if (h.has('cf-ray')) warnings.push('Cloudflare detected. Headers do not establish which WAF rules are enabled or whether the origin is protected.');
  const nextSteps = [];
  if (unsafe) nextSteps.push('Confirm the installed vendor package and upgrade affected PHP runtimes; restart every web worker.');
  if (verdict === 'unknown' || verdict === 'no-php') nextSteps.push('Run bash check.sh on the origin or request the runtime/package version from your host.');
  if (phpinfo.length) nextSteps.push('Remove public phpinfo pages after checking the configuration.');
  nextSteps.push('Verify each PHP pool/container. This passive scan does not prove exploitability or absence of compromise.');
  // Every header but cookies: the page matches providers.tsv against them, so new rules need no redeploy.
  const headers = Object.fromEntries([...h].filter(([key]) => key !== 'set-cookie'));
  return {
    schema: 'php2shell.site/1', scannedAt: new Date().toISOString(), target: input, url: first.url,
    verdict, confidence: observations.length ? 'version-reported' : signals.length ? 'fingerprint-only' : 'none',
    coverage: partial ? 'partial' : 'complete', httpStatus: first.res.status,
    version: selected?.version, eol: selected?.status === 'eol', fixedIn: selected?.status.split(':')[1],
    observations, signals: [...new Set(signals)], evidence, warnings, nextSteps,
    headers, server: h.get('server'), cloudflare: h.has('cf-ray'), app, phpinfo,
    requests, durationMs: Date.now() - started, advisories: ADVISORIES,
  };
}

export default {
  async fetch(req, env = {}) {
    const origin = env.ALLOWED_ORIGIN || '*';
    const json = (body, status = 200) => new Response(JSON.stringify(body), { status,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': origin,
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
    if (req.method !== 'GET') return json({ error: 'Only GET is supported.' }, 405);
    const target = new URL(req.url).searchParams.get('url') || '';
    const allowedTargets = (env.ALLOWED_TARGETS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    try { validateURL(target, { allowedTargets }); }
    catch (err) { return json({ error: err.message }, 400); }
    // Optional Cloudflare rate limiter binding. Configure a platform limit before public promotion.
    if (env.RATE_LIMITER) {
      const { success } = await env.RATE_LIMITER.limit({ key: req.headers.get('CF-Connecting-IP') || 'anonymous' });
      if (!success) return json({ error: 'Scan limit reached. Please try again later.' }, 429);
    }
    try { return json(await scan(target, { allowedTargets })); }
    catch { return json({ error: 'Could not complete the scan. Check the address, network access and redirects.' }, 502); }
  },
};
