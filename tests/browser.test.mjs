import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../docs/index.html', import.meta.url), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
function page(hostname = 'localhost') {
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, { innerHTML: '', hidden: true, disabled: false, events: {},
      addEventListener(name, fn) { this.events[name] = fn; } });
    return elements.get(id);
  }
  let download;
  const context = vm.createContext({ location: { hostname },
    document: { querySelector: element, querySelectorAll: () => [], createElement: () => ({ click() {} }) },
    Blob, URL: { createObjectURL(blob) { download = blob; return 'blob:fixture'; }, revokeObjectURL() {} },
    setTimeout(fn) { fn(); } });
  vm.runInContext(source, context);
  return { context, element, get download() { return download; } };
}
const report = { schema: 'php2shell.site/1', url: 'https://example.com', verdict: 'unknown',
  signals: ['WordPress'], phpinfo: [], warnings: ['<script>attack()</script>'],
  coverage: 'partial', confidence: 'fingerprint-only', requests: [{ method: 'GET' }] };

test('renderer escapes remote content and shows incomplete coverage', () => {
  const p = page(); p.context.report = report;
  vm.runInContext('render(report)', p.context);
  const html = p.element('#out').innerHTML;
  assert.ok(!html.includes('<script>')); assert.match(html, /&#60;script&#62;/);
  assert.match(html, /partial/); assert.match(html, /fingerprint-only/);
});

test('provider patched claims and absent fingerprints never render green', () => {
  const p = page();
  for (const r of [{ ...report, provider: { name: 'Host', patched: 'yes' } }, { ...report, verdict: 'no-php', warnings: [], signals: [] }]) {
    p.context.report = r; vm.runInContext('render(report)', p.context);
    assert.match(p.element('#out').innerHTML, /verdict warn/);
  }
});

test('download exports the displayed JSON and the production page uses the deployed Worker', async () => {
  const p = page(); p.context.report = report; vm.runInContext('render(report)', p.context);
  assert.equal(p.element('#download').hidden, false);
  p.element('#download').events.click();
  assert.deepEqual(JSON.parse(await p.download.text()), report);
  const production = page('arifulislamat.github.io');
  assert.equal(vm.runInContext('API', production.context), 'https://php2shell-audit.arifulislamat.workers.dev');
  assert.equal(production.element('#go').disabled, false);
});
