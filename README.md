# php2shell checker

Find out if your PHP site is exposed to **php2shell**: CVE-2026-109618 and CVE-2026-109619, an unauthenticated remote code execution flaw in PHP itself.
It affects WordPress, Laravel, Drupal, Joomla and custom PHP alike. Fixed in **PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35**. PHP 8.1 and older get no upstream fix.

![php2shell checker scanning a site](assets/demo.gif)

The checker is **read-only**. It sends no exploit payloads and changes nothing.

Write-up: [php2shell: is your WordPress, Laravel or PHP site affected?](https://dev.to/arifulislamat/php2shell-is-your-wordpress-laravel-or-php-site-affected-how-to-patch-today-3jla)

## Three ways to check

### 1. On your server (most accurate)

```sh
curl -fsSL https://raw.githubusercontent.com/arifulislamat/php2shell-audit/main/check.sh | sudo bash
```

It checks:
- Every PHP install: CLI, FPM, CGI, LiteSpeed, FrankenPHP, Apache mod_php, cPanel / Plesk / Remi / CloudLinux builds, and Docker / Podman containers
- Distro backports, from the Debian/Ubuntu/RHEL package changelogs (the version number often stays old)
- PHP workers still running old code after an upgrade, which means a restart is still needed
- The `session.upload_progress.enabled` mitigation
- Signs of compromise since 2026-10-19: web shells, PHP in upload folders, recently changed PHP files, `auto_prepend_file` backdoors, new WordPress admins (needs wp-cli), shells and crontabs of the web user, outbound connections, and worker crashes in the logs

### 2. From your computer, against a site

```sh
curl -fsSL https://raw.githubusercontent.com/arifulislamat/php2shell-audit/main/check.sh | bash -s -- https://example.com
```

It reads the PHP version from the `X-Powered-By` header and any public `phpinfo()` page, and spots PHP session cookies, WordPress, Laravel, Drupal, Joomla and the hosting provider.
If the version is hidden, or might be a distro backport, it says so instead of guessing.

### 3. In your browser

**[arifulislamat.github.io/php2shell-audit](https://arifulislamat.github.io/php2shell-audit/)**: the same checks as option 2, with nothing to install.

Prefer to read the script before running it? Download [check.sh](check.sh), then run `bash check.sh` or `bash check.sh https://example.com`.

## Results

| exit code | meaning |
|---|---|
| `0` | nothing found |
| `1` | vulnerable PHP |
| `2` | possible compromise |
| `3` | site unreachable |
| `4` | PHP found, but its version can't be confirmed |

Options for options 1 and 2:
- `--json` prints a machine-readable report, e.g. `bash check.sh --json > report.json`
- `--since 2026-10-20` changes the date that file and admin changes are checked from
- `WEBROOTS="/srv/a /srv/b"` scans those folders
- `NO_COLOR=1` turns off colours and animation

## Managed hosts

WP Engine, Kinsta, SiteGround and other managed hosts usually hide the PHP version. The checker recognises them and shows their patch status from [docs/providers.tsv](docs/providers.tsv).
Know a host has patched? Open a pull request that links their public announcement.

## Responsible use

Scan sites you own or are responsible for. Remote checks only send ordinary GET requests for a few public paths.
No outside check can prove a site is safe: when in doubt, run the server check or ask your host for the PHP version.

## License

[MIT](LICENSE) © Ariful Islam · [arifulislamat.com](https://arifulislamat.com)
