# php-rce-check

One-file, read-only check for the two critical PHP runtime RCEs disclosed on 21 October 2026:

- **CVE-2026-109618** RCE via out-of-memory corruption ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w))
- **CVE-2026-109619** RCE via stale global state across requests ([GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp))

Both are unauthenticated, both CVSS v4 9.2, both affect every PHP serving web requests (FPM, mod_php, cgi, FrankenPHP, LiteSpeed). Fixed in **PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35**. Official advisory: https://www.php.net/archive/2026.php#2026-10-21-5

Built for Magento 2 / Adobe Commerce hosts but works on any Linux or macOS box running PHP.

## Why this exists

`php -v` is not enough. On a typical Magento server the CLI PHP, the FPM PHP serving the storefront, and the PHP used by cron can all be different binaries at different patch levels. Hosts with cPanel, Plesk, Remi or LiteSpeed often have five or more. This script finds all of them, including ones only visible through running processes, and tells you which ones are below the fix line.

It also reads the FPM ini settings the advisory's temporary mitigations depend on, so you can see at a glance whether `memory_limit`, `post_max_size` and `session.upload_progress.enabled` are helping or hurting while you wait for packages.

Adobe Commerce and Magento security patches **do not fix this**. It is the PHP runtime. Your host or sysadmin has to update PHP.

## Run it

```bash
curl -fsSL https://raw.githubusercontent.com/magekwik/php-rce-check/main/php-rce-check.sh | bash
```

Or download and run it as a file if you prefer to read it first (you should):

```bash
curl -fsSLO https://raw.githubusercontent.com/magekwik/php-rce-check/main/php-rce-check.sh
less php-rce-check.sh
bash php-rce-check.sh
```

Options:

```
--json                      machine-readable output, no colour
--no-color                  plain text
--magento-root /path/store  point it at a store if auto-detection misses it
```

Run it as the user that owns the web stack (or with sudo) so it can see FPM processes and read crontabs. It works unprivileged too, it just sees less.

Exit codes: `0` everything found is patched, `1` something is vulnerable, `2` could not determine.

## Example output

```
php-rce-check v1.0.0  CVE-2026-109618 / CVE-2026-109619 (unauthenticated RCE, CVSS 9.2)
https://www.php.net/archive/2026.php#2026-10-21-5

PHP binaries found
  PATH                                           SAPI  VERSION    VERDICT     NOTE
  /usr/bin/php8.4                                cli   8.4.26     VULNERABLE  update to 8.4.27
  /usr/sbin/php-fpm8.4                           fpm   8.4.26     VULNERABLE  update to 8.4.27 (running)
  /usr/bin/php8.1                                cli   8.1.31     EOL         end of life, no official fix. upgrade branch or apply source backport

Web SAPI exposure
  PHP-FPM is running. Every worker must be restarted after the update (systemctl restart, not reload).

Temporary mitigations (reduce exposure only, php.net: "do not make an installation safe")
  Source: /usr/sbin/php-fpm8.4
    memory_limit = 2G  finite limit is the OOM trigger. Set -1 via php_admin_value in the pool, plus a low post_max_size.
    post_max_size = 64M  advisory suggests 8M (no uploads) or 32M (uploads). Magento admin needs uploads: use 32M and enforce at nginx (client_max_body_size).
    session.upload_progress.enabled = On  set to 0 in php.ini or the FPM pool, then restart ALL workers. ini_set/.user.ini do not count.
    pool overrides: [www] php_admin_value[memory_limit] = 756M

Magento
  Store root: /var/www/html
  Cron runs with: /usr/bin/php8.4  (checked above; cron PHP often differs from FPM PHP)
  Adobe Commerce / Magento patches do NOT fix this. It is the PHP runtime. Your host or sysadmin must update PHP.

How to fix
  Ondřej Surý PPA / sury.org detected. Fixed builds usually land within hours of php.net.
  sudo apt update && sudo apt install --only-upgrade 'php8.*' && sudo systemctl restart 'php8.*-fpm'
  Then re-run this script. Required: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or later.

RESULT: VULNERABLE. At least one PHP on this host is below the fix line. Update now.
```

## What it checks

| Check | How |
|---|---|
| Every PHP binary | PATH, versioned names (`php8.4`, `php-fpm8.3`), Remi, cPanel EA, Plesk, LiteSpeed, Homebrew paths, and the executable behind every running `php*` process |
| Version vs fix line | `-v` on each binary, normalised (handles `8.4.27-1+ubuntu24.04.1+deb.sury.org+1`, `8.6.0RC3`, bare `8.4`) |
| Which SAPIs are live | running FPM masters, Apache `mod_php` via `apachectl -M`, LiteSpeed install dir |
| Mitigation ini values | `php-fpm -i` for the FPM php.ini, `php-fpm -tt` for pool `php_admin_value` overrides |
| Magento cron binary | `bin/magento cron:run` entries in crontabs and `/etc/cron.d` |
| Package source | Remi (flagged, no fix today per php.net), Ondřej PPA, distro, Alpine, Docker, Homebrew, with the matching update command |

## What it cannot see

- Containers other than the one it runs in. Run it inside each container, or rebuild from the fixed official image tag.
- Adobe Commerce Cloud, Hypernode and similar managed platforms where you have no shell. Ask the host for the exact PHP patch version.
- A remote store from the outside. For that use the free scanner at https://scan.magekwik.com, which attempts a best-effort external PHP version check.
- Whether the mitigations are sufficient. php.net is explicit that they are not. Only the update is.

## PHP 8.1 and older

No packages from php.net. The security team published source-only backport branches for people building from source:
[PHP-7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619),
[PHP-8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619),
[PHP-8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619).
If you are on a Magento 2.3 or early 2.4 store still on 8.1, this is the push to move.

## Updating for the next advisory

The fix-line table is one block at the top of the script (`MIN_SAFE`). Change the versions, bump `VERSION`, done.

## Contributing

PRs welcome, especially for hosts and SAPIs not covered (FrankenPHP binaries, Windows, BSD, exotic panel layouts). Keep it one file, bash 3.2+ (so the macOS system bash works), no hard dependencies beyond coreutils. `timeout` is used when present and skipped gracefully when it is not.

## Licence

MIT. Built by [Magekwik](https://magekwik.com), Magento 2 security and support.
