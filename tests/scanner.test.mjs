import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker, { scan, phpStatus, validateURL } from '../worker/worker.js';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const target = 'https://site.example.com/';
const response = (body = '', headers = {}, status = 200) => new Response(body, { status, headers });
const fixture = root => async url => url === target ? root() : response('', {}, 404);
const info = version => `<title>phpinfo()</title><h1>PHP Version ${version}</h1>`;

test('PHP version boundaries agree between Bash and JavaScript', () => {
  const script = readFileSync(new URL('../check.sh', import.meta.url), 'utf8');
  const fn = script.match(/^php_status\(\) \{[\s\S]*?^\}/m)?.[0];
  assert.ok(fn, 'version function must be isolated before executing the fixture');
  const cases = {
    '8.5.11': 'vulnerable:8.5.12', '8.5.12': 'patched', '8.4.26': 'vulnerable:8.4.27',
    '8.4.27': 'patched', '8.3.35': 'vulnerable:8.3.36', '8.3.36': 'patched',
    '8.2.34': 'vulnerable:8.2.35', '8.2.35': 'patched', '8.3.36RC1': 'vulnerable:8.3.36',
    '8.3.36-rc1': 'vulnerable:8.3.36', '8.3.36-1ubuntu1': 'patched', '8.3.37RC1': 'patched',
    '7.4.33': 'eol', '8.1.31': 'eol', '8.6.0RC3': 'vulnerable:8.6.0RC4', '8.6.0rc3': 'vulnerable:8.6.0RC4',
    '8.6.0RC4': 'patched', '8.6.0': 'patched', '8.7.1': 'patched', '9.0.0': 'patched',
    'garbage': 'unknown', '8.3': 'unknown', '8.3.36banana': 'unknown',
  };
  for (const [version, expected] of Object.entries(cases)) {
    assert.equal(phpStatus(version), expected, version);
    assert.equal(execFileSync('bash', ['-c', `${fn}\nphp_status "$1"`, '_', version], { encoding: 'utf8' }).trim(), expected, version);
  }
});

test('URL validation rejects credentials, local literals and reserved names', () => {
  for (const url of ['file:///etc/passwd', 'https://u:p@example.com', 'http://127.0.0.1', 'http://2130706433', 'http://[::1]', 'localhost', 'foo.local', 'foo.internal', 'foo.localhost.', 'https://example.com\n']) {
    if (url.endsWith('\n')) continue; // Surrounding user whitespace is trimmed.
    assert.throws(() => validateURL(url), undefined, url);
  }
  assert.equal(validateURL('example.com').href, 'https://example.com/');
});

test('a static 200 response is not PHP evidence', async () => {
  const r = await scan(target, { fetchImpl: fixture(() => response('<h1>Hello</h1>')) });
  assert.equal(r.verdict, 'no-php');
  assert.equal(r.requests.length, 6);
  assert.deepEqual(r.signals, []);
});

test('blocked and throttled root pages are unconfirmed, never green', async () => {
  for (const status of [403, 429, 500]) {
    const r = await scan(target, { fetchImpl: fixture(() => response('', {}, status)) });
    assert.equal(r.verdict, 'unknown'); assert.equal(r.coverage, 'partial');
    if (status === 429) assert.equal(r.requests.length, 1);
  }
});

test('CMS evidence without a version remains unknown', async () => {
  const r = await scan(target, { fetchImpl: fixture(() => response('<script src="/wp-content/x.js"></script>')) });
  assert.equal(r.app, 'WordPress'); assert.equal(r.verdict, 'unknown');
});

test('records versions, limits exported headers, and does not claim a WAF rule is active', async () => {
  const r = await scan(target, { fetchImpl: fixture(() => response('', {
    'x-powered-by': 'PHP/8.3.36', 'set-cookie': 'PHPSESSID=super-secret', 'cf-ray': 'abc', 'x-new-host': 'edge-7',
  })) });
  assert.equal(r.verdict, 'patched'); assert.equal(r.confidence, 'version-reported');
  assert.equal(r.evidence[0].value, '8.3.36');
  assert.ok(!JSON.stringify(r).includes('super-secret'));
  // Any non-cookie header reaches the page, so a new providers.tsv rule works without a redeploy.
  assert.equal(r.headers['x-new-host'], 'edge-7');
  assert.match(r.warnings.join(' '), /do not establish/);
});

test('a vulnerable phpinfo backend wins over a patched header', async () => {
  const r = await scan(target, { fetchImpl: async url => url === target
    ? response('', { 'x-powered-by': 'PHP/8.3.36' })
    : url.endsWith('phpinfo.php') ? response(info('8.3.6')) : response('', {}, 404) });
  assert.equal(r.verdict, 'vulnerable'); assert.equal(r.version, '8.3.6');
  assert.equal(r.observations.length, 2); assert.match(r.warnings.join(' '), /Multiple PHP versions/);
});

test('partial checks cannot certify a reported patched version', async () => {
  const r = await scan(target, { fetchImpl: async url => {
    if (url === target) return response('', { 'x-powered-by': 'PHP/8.3.36' });
    throw new Error('timeout');
  } });
  assert.equal(r.verdict, 'unknown'); assert.equal(r.coverage, 'partial');
});

test('body truncation is bounded and explicit', async () => {
  const r = await scan(target, { maxBytes: 32, probePhpinfo: false,
    fetchImpl: fixture(() => response('x'.repeat(1000))) });
  assert.equal(r.coverage, 'partial'); assert.match(r.warnings[0], /body limit/);
});

test('redirects are validated before fetching the next URL', async () => {
  let calls = 0;
  await assert.rejects(scan(target, { fetchImpl: async () => {
    calls++; return response('', { location: 'http://127.0.0.1/admin' }, 302);
  } }), /public domain/);
  assert.equal(calls, 1);
});

test('a PHP version on a redirect hop counts even when the final page hides it', async () => {
  const r = await scan(target, { probePhpinfo: false, fetchImpl: async url => url === target
    ? response('', { location: 'https://site.example.com/home', 'x-powered-by': 'PHP/8.3.6' }, 301)
    : response('hi') });
  assert.equal(r.verdict, 'vulnerable'); assert.equal(r.version, '8.3.6');
  assert.equal(r.observations[0].url, target);
});

test('canonical redirects work and phpinfo cross-origin redirects are skipped', async () => {
  const calls = [];
  const r = await scan(target, { fetchImpl: async url => {
    calls.push(url);
    if (url === target) return response('', { location: 'https://www.example.com/' }, 302);
    if (url === 'https://www.example.com/') return response('', { 'x-powered-by': 'PHP/8.3.36' });
    return response('', { location: 'https://elsewhere.example.com/info' }, 302);
  } });
  assert.equal(r.url, 'https://www.example.com/'); assert.equal(r.coverage, 'partial');
  assert.ok(!calls.some(u => u.includes('elsewhere')));
});

test('request budget includes redirects and failed probes', async () => {
  let calls = 0;
  const r = await scan(target, { maxRequests: 2, fetchImpl: async () => { calls++; return response(); } });
  assert.equal(calls, 2); assert.equal(r.requests.length, 2); assert.equal(r.coverage, 'partial');
});

test('Worker validates methods and optional target allowlist without making requests', async () => {
  assert.equal((await worker.fetch(new Request('https://api.example.com', { method: 'POST' }))).status, 405);
  assert.equal((await worker.fetch(new Request('https://api.example.com?url=http://localhost'))).status, 400);
  assert.equal((await worker.fetch(new Request('https://api.example.com?url=outside.example.com'), { ALLOWED_TARGETS: 'site.example.com' })).status, 400);
});

test('Worker honors rate limiter and CORS configuration', async () => {
  const r = await worker.fetch(new Request('https://api.example.com?url=site.example.com'), {
    ALLOWED_ORIGIN: 'https://pages.example.com', RATE_LIMITER: { limit: async () => ({ success: false }) },
  });
  assert.equal(r.status, 429); assert.equal(r.headers.get('access-control-allow-origin'), 'https://pages.example.com');
});

test('per-request timeout is propagated to fetch and reported as a failure', async () => {
  await assert.rejects(scan(target, { timeout: 10, fetchImpl: (url, options) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(resolve, 1000); // Keep Node alive until AbortSignal fires.
      options.signal.addEventListener('abort', () => { clearTimeout(timer); reject(options.signal.reason); });
    }) }), /timeout/i);
});

test('HTTPS downgrade and allowlist escapes are rejected before a second fetch', async () => {
  for (const [location, policy] of [['http://site.example.com/', {}], ['https://other.example.com/', { allowedTargets: ['site.example.com'] }]]) {
    let count = 0;
    await assert.rejects(scan(target, { ...policy, fetchImpl: async () => {
      count++; return response('', { location }, 302);
    } }));
    assert.equal(count, 1);
  }
});
