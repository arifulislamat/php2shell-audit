import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    let stdout = '', stderr = '';
    child.stdout.on('data', b => { stdout += b; });
    child.stderr.on('data', b => { stderr += b; });
    child.on('error', reject);
    child.on('close', code => resolve({ code, stdout, stderr }));
  });
}

test('Bash JSON mode emits one parseable report including escaped evidence and findings', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'php2shell-shell-'));
  // Deterministic transport fixture. No external requests or local system audit.
  await writeFile(join(folder, 'curl'), `#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  case "$1" in -D) headers=$2; shift 2;; -o) body=$2; shift 2;; *) url=$1; shift;; esac
done
if [[ "$url" = */phpinfo.php || "$url" = */info.php || "$url" = */php_info.php || "$url" = */i.php || "$url" = */test.php ]]; then
  printf 'HTTP/1.1 404 Not Found\\r\\n\\r\\n' >"$headers"
  printf '' >"$body"
else
  printf 'HTTP/1.1 200 OK\\r\\nX-Powered-By: PHP/8.3.6\\r\\nServer: a"b\\\\c\\r\\n\\r\\n' >"$headers"
  printf '' >"$body"
fi
printf '%s' "$url"
`, { mode: 0o755 });
  try {
    const result = await run('bash', ['check.sh', '--json', '--since', '2026-10-20', 'https://site.example.com'], { env: { ...process.env, PATH: `${folder}:${process.env.PATH}` } });
    assert.equal(result.code, 1, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.schema, 'php2shell.check/1'); assert.equal(report.exitCode, 1);
    assert.equal(report.since, '2026-10-20');
    assert.ok(report.findings.some(f => f.severity === 'vulnerable'));
    assert.ok(report.findings.some(f => f.message.includes('a"b\\c')));
    assert.match(result.stderr, /PHP CORE RCE CHECKER/);
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('Bash reads PHP from redirect hops and ignores catch-all pages that mention phpinfo()', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'php2shell-hops-'));
  // curl -L writes every hop's headers to -D: a PHP 301 first, then a clean final page.
  await writeFile(join(folder, 'curl'), `#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  case "$1" in -D) headers=$2; shift 2;; -o) body=$2; shift 2;; *) url=$1; shift;; esac
done
if [[ "$url" = *.php ]]; then
  printf 'HTTP/1.1 200 OK\\r\\n\\r\\n' >"$headers"
  printf 'Our blog post about phpinfo() tips' >"$body"
else
  printf 'HTTP/1.1 301 Moved\\r\\nLocation: /home\\r\\nX-Powered-By: PHP/8.3.6\\r\\n\\r\\nHTTP/1.1 200 OK\\r\\n\\r\\n' >"$headers"
  printf 'hi' >"$body"
fi
printf '%s' "$url"
`, { mode: 0o755 });
  try {
    const result = await run('bash', ['check.sh', '--json', 'https://site.example.com'], { env: { ...process.env, PATH: `${folder}:${process.env.PATH}` } });
    assert.equal(result.code, 1, result.stderr);
    const { findings } = JSON.parse(result.stdout);
    assert.ok(findings.some(f => f.severity === 'vulnerable' && f.message.includes('8.3.6')));
    assert.ok(!findings.some(f => f.message.includes('public phpinfo()')));
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('Bash rejects impossible dates and unsupported arguments', async () => {
  for (const args of [['--since', '2026-02-30'], ['--since', '2026-13-01'], ['--unknown'], ['https://a.example.com', 'https://b.example.com']]) {
    assert.equal((await run('bash', ['check.sh', ...args])).code, 64);
  }
});
