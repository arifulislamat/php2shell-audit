# php2shell checker

Find out if your PHP site is exposed to **php2shell**: CVE-2026-109618 and CVE-2026-109619, an unauthenticated remote code execution flaw in PHP itself.
It affects WordPress, Laravel, Drupal, Joomla and custom PHP alike. Fixed in **PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35**. PHP 8.1 and older get no upstream fix.

![php2shell checker scanning a site](assets/demo.gif)

Both tools are **read-only**: passive GET requests and local inspection. They send no exploit payloads and change nothing. A hidden version, an HTTP 403 or a Cloudflare header is reported as unconfirmed, never as proof of a fix.

Write-up: [php2shell: is your WordPress, Laravel or PHP site affected?](https://dev.to/arifulislamat/php2shell-is-your-wordpress-laravel-or-php-site-affected-how-to-patch-today-3jla)

## Quick start

**On your server.** This is the most accurate check:

```sh
curl -fsSL https://raw.githubusercontent.com/arifulislamat/php2shell-audit/main/check.sh | sudo bash
```

**From your computer, against any site:**

```sh
curl -fsSL https://raw.githubusercontent.com/arifulislamat/php2shell-audit/main/check.sh | bash -s -- https://example.com
```

**Browser interface:** [arifulislamat.github.io/php2shell-audit](https://arifulislamat.github.io/php2shell-audit/). Scanning requires a configured Worker; see deployment below.

Prefer to read the script before running it? Download it, then run it with `bash check.sh` or `bash check.sh https://example.com`.

## Several sites, before and after patching

Put one site per line in `sites.txt`, save a JSON report for each, patch, run it again into `after/`, then compare:

```sh
mkdir -p before
grep -vE '^[[:space:]]*(#|$)' sites.txt | while read -r u; do bash check.sh --json "$u" </dev/null > "before/${u//[^A-Za-z0-9.]/_}.json"; done
# after patching: the same loop into after/, then
diff -r before after
```

The browser page's **Download JSON report** button saves the same kind of evidence for a single site.

## What it checks

### Server mode

**PHP runtimes:**
- Common PHP installs: CLI, FPM, CGI, LiteSpeed, FrankenPHP, and cPanel / Plesk / Remi / CloudLinux builds
- Apache mod_php, the highest-risk setup
- Distro backports, via the Debian/Ubuntu/RHEL changelogs (the version number often stays old)
- Workers still running replaced code after an upgrade, meaning a restart is still needed
- The `session.upload_progress.enabled` mitigation
- Docker and Podman containers

**Heuristic signs of compromise (default file/admin change window starts 2026-10-19):**
- Web-shell code, PHP in upload folders, recently changed PHP files, `auto_prepend_file` backdoors
- New WordPress admins (needs wp-cli)
- Shells running as the web user, web-user crontabs, outbound connections
- Worker crashes, memory errors and POST responses with HTTP 500 in all retained logs (counts, not time-window or burst detection)

### Remote mode

Fingerprints PHP from the outside:
- `X-Powered-By` header and session cookies
- WordPress, Laravel, Drupal and Joomla markers
- Exposed `phpinfo()` pages
- The hosting provider (see below)

If the version is hidden, or might be a distro backport, it says so instead of guessing.

### Exit codes

| code | meaning |
|---|---|
| `0` | nothing found |
| `1` | vulnerable PHP |
| `2` | possible compromise |
| `3` | site unreachable |
| `4` | PHP found, but its version or scan coverage can't be confirmed |
| `64` | invalid arguments or report |

### Options

- **JSON audit:** `bash check.sh --json > server-report.json` (progress stays on stderr). Findings include severity, messages, evidence and recommendations. Schema: `php2shell.check/1`.
- **Investigation window:** `bash check.sh --since 2026-10-20`; this changes file/admin date checks, not the retained-log counts.
- **Custom web roots:** `WEBROOTS="/srv/a /srv/b"` scans those folders.
- **No colours:** `NO_COLOR=1` turns off colours and animation. Both also switch off automatically when output isn't a terminal, so logs and CI get plain text.

## Managed hosts: `docs/providers.tsv`

Most managed hosts (WP Engine, Kinsta, SiteGround and others) hide the PHP version.
For those sites, the script and the page recognise the host from its response headers or temporary domain, then show that host's patch status from this file.
The browser fetches this file with each result. The Bash script prefers its local copy and fetches the published copy only when no local file exists. Keep cloned copies updated.

| column | meaning |
|---|---|
| `header_regex` | ERE matched case-insensitively against each `name: value` response header line |
| `host_regex` | ERE matched against the hostname, e.g. `.wpengine.com` staging domains |
| `patched` | `yes`, `no` or `unknown` |
| `checked` | date the status was confirmed |
| `link` | the host's status page or advisory |
| `note` | shown to users |

Only set `patched=yes` once the host has said so publicly, and put that announcement in `link`. A provider announcement is attributed context, not confirmation of a particular pool. A visible PHP version takes precedence.
The fingerprints were checked against live sites on 2026-10-22. Cloudways is matched by its temporary domain only.

## Web page

`docs/index.html` is served by GitHub Pages, and `worker/` is its backend.
Browsers can't read another site's headers, so a small Cloudflare Worker fetches them. Deploy it once, then point the page at it:

```sh
cd worker && npx wrangler deploy     # prints https://php2shell-check.<you>.workers.dev
```

1. Put that URL in the production branch of the `API` constant in `docs/index.html`. It is deliberately empty in this checkout; the page explains when scanning is unavailable.
2. Enable GitHub Pages: Settings → Pages → Deploy from branch `main`, folder `/docs`.

The Worker accepts only GET and rejects credentials, IP literals and common local hostnames. Redirects are validated again; phpinfo probes stay on the final site's origin. Set `ALLOWED_TARGETS` to a comma-separated exact hostname list for a restricted deployment (include canonical redirect hosts), and `ALLOWED_ORIGIN` to your Pages origin. CORS is not authentication. An optional `RATE_LIMITER` binding is supported; use Cloudflare's [rate limiter configuration](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/) before exposing a public scanner.

Hostname checks are **not DNS pinning** and do not defend against every DNS rebinding scenario. Do not deploy this as a generic fetch service with private network access. Use a controlled target allowlist and network egress restrictions in that environment.

## Local development

```sh
npm test                                        # offline fixtures for check.sh, the Worker and the page
bash check.sh --selftest                        # version logic only
bash check.sh http://localhost:8080             # remote mode against a local site
cd worker && npx wrangler dev                   # Worker on :8787
python3 -m http.server -d docs 8000             # page on :8000, which uses the local Worker automatically
```

The CI workflow is configured for Linux/macOS and Node 22/24. Tests cover version agreement between `check.sh` and the Worker, conflicting backends, blocked/incomplete scans, redirect validation, body budgets and JSON escaping. They do not exercise production PHP installations or execute exploits.

For an isolated, disposable local test only, a vulnerable test target: `docker run -d -p 127.0.0.1:8080:80 php:8.3.6-apache`.

## Responsible use

Scan sites you own or are responsible for. Remote mode only sends ordinary GET requests for a few public paths.
No outside check can prove a site is safe. A `patched` verdict means a reported version meets the advisory boundary within the selected scan coverage; it is not a verified server state. The Bash audit may also flag legitimate application activity and cannot prove absence of compromise. When in doubt, run the server check or ask your host for the PHP version.

## License

[MIT](LICENSE) © Ariful Islam · [arifulislamat.com](https://arifulislamat.com)
