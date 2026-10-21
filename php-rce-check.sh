#!/usr/bin/env bash
# php-rce-check: is this server exposed to CVE-2026-109618 / CVE-2026-109619?
#
# Two unauthenticated RCE bugs in the PHP runtime itself, disclosed 21 Oct 2026.
# Fixed in PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35. PHP 8.1 and older are EOL.
# Advisory: https://www.php.net/archive/2026.php#2026-10-21-5
#
# This script is read-only. It runs the PHP binaries it finds with -v / -i / -tt
# to read versions and ini settings. It never modifies anything.
#
# Usage:  bash php-rce-check.sh [--json] [--magento-root /path/to/store] [--no-color]
# Exit:   0 = every PHP found is patched
#         1 = at least one vulnerable PHP found
#         2 = could not determine (no PHP found, or version unreadable)
#
# Maintained by Magekwik (https://magekwik.com). MIT licence.

set -u

VERSION="1.0.0"
ADVISORY_URL="https://www.php.net/archive/2026.php#2026-10-21-5"
CVE_1="CVE-2026-109618"
CVE_2="CVE-2026-109619"

# Minimum safe version per minor branch. Update this on the next advisory.
# A function, not an associative array, so this runs on bash 3.2 (macOS system bash).
min_safe() {
  case "$1" in
    8.5) echo "8.5.12" ;;
    8.4) echo "8.4.27" ;;
    8.3) echo "8.3.36" ;;
    8.2) echo "8.2.35" ;;
    *)   echo "" ;;
  esac
}
# Anything below 8.2 is EOL: no official fix, source-only backports.

JSON=0
MAGENTO_ROOT=""
COLOR=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --json) JSON=1; COLOR=0 ;;
    --no-color) COLOR=0 ;;
    --magento-root=*) MAGENTO_ROOT="${1#*=}" ;;
    --magento-root) shift; MAGENTO_ROOT="${1:-}" ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *)
      printf 'Unknown option: %s\nTry --help.\n' "$1" >&2
      exit 2 ;;
  esac
  shift || true
done
[[ -t 1 ]] || COLOR=0

if [[ $COLOR == 1 ]]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; B=""; D=""; N=""
fi

# ---------- helpers ----------

# version_cmp A B -> prints -1, 0, 1
version_cmp() {
  local a="$1" b="$2"
  local -a pa pb
  IFS=. read -r -a pa <<< "$a"
  IFS=. read -r -a pb <<< "$b"
  local i
  for i in 0 1 2; do
    local x="${pa[$i]:-0}" y="${pb[$i]:-0}"
    x="${x%%[^0-9]*}"; y="${y%%[^0-9]*}"
    x="${x:-0}"; y="${y:-0}"
    if (( 10#$x < 10#$y )); then echo -1; return; fi
    if (( 10#$x > 10#$y )); then echo 1; return; fi
  done
  echo 0
}

# normalise "8.4.27-1ubuntu1" -> "8.4.27", "8.4" -> "8.4"
clean_version() {
  local v="$1"
  v="${v#PHP }"
  v="$(printf '%s' "$v" | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)"
  printf '%s' "$v"
}

# verdict VERSION -> prints one of: SAFE | VULNERABLE | EOL | PARTIAL | UNKNOWN, and the fix version
verdict() {
  local v; v="$(clean_version "$1")"
  [[ -z "$v" ]] && { echo "UNKNOWN|"; return; }
  local minor; minor="$(printf '%s' "$v" | grep -oE '^[0-9]+\.[0-9]+')"
  local fix; fix="$(min_safe "$minor")"
  if [[ -z "$fix" ]]; then
    # 8.6 RC or newer: assume carries the fix (released after advisory). Older: EOL.
    if [[ "$(version_cmp "$minor" "8.5")" == 1 ]]; then echo "SAFE|"; else echo "EOL|"; fi
    return
  fi
  # major.minor only, no patch number
  if [[ "$v" == "$minor" ]]; then echo "PARTIAL|$fix"; return; fi
  if [[ "$(version_cmp "$v" "$fix")" == -1 ]]; then echo "VULNERABLE|$fix"; else echo "SAFE|$fix"; fi
}

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# run_to SECONDS CMD... — like timeout(1), but degrades to running the command
# directly when no timeout binary exists (stock macOS ships neither timeout nor
# gtimeout). On Linux servers the real timeout is used and still bounds hangs.
if command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN="gtimeout"
else TIMEOUT_BIN=""; fi
run_to() {
  local secs="$1"; shift
  if [[ -n "$TIMEOUT_BIN" ]]; then "$TIMEOUT_BIN" "$secs" "$@"; else "$@"; fi
}

# ---------- discovery ----------

declare -a BINS=()
add_bin() {
  local p="$1"
  [[ -x "$p" ]] || return
  local real; real="$(readlink -f "$p" 2>/dev/null || printf '%s' "$p")"
  for b in "${BINS[@]:-}"; do [[ "$b" == "$real" ]] && return; done
  BINS+=("$real")
}

# PATH binaries
for name in php php-fpm php-cgi; do
  while IFS= read -r p; do add_bin "$p"; done < <(type -aP "$name" 2>/dev/null)
done
# versioned names in every PATH dir, plus common vendor locations
IFS=: read -r -a PATH_DIRS <<< "$PATH"
for dir in "${PATH_DIRS[@]}" /usr/sbin /usr/bin /usr/local/bin /usr/local/sbin \
           /opt/remi/php*/root/usr/bin /opt/remi/php*/root/usr/sbin \
           /opt/cpanel/ea-php*/root/usr/bin /opt/cpanel/ea-php*/root/usr/sbin \
           /opt/plesk/php/*/bin /opt/plesk/php/*/sbin \
           /usr/local/lsws/lsphp*/bin \
           /opt/php*/bin /usr/local/php*/bin /opt/homebrew/bin /opt/homebrew/opt/php*/sbin; do
  [[ -d "$dir" ]] || continue
  for f in "$dir"/php "$dir"/php-fpm "$dir"/php-cgi "$dir"/php[0-9]* "$dir"/php-fpm[0-9]* "$dir"/php-cgi[0-9]* "$dir"/lsphp*; do
    [[ -e "$f" ]] && add_bin "$f"
  done
done 2>/dev/null

# running processes: catches binaries not in PATH
declare -a RUNNING=()
while IFS= read -r line; do
  exe="$(printf '%s' "$line" | awk '{print $1}')"
  [[ "$exe" == *php* ]] || continue
  [[ -x "$exe" ]] && { add_bin "$exe"; RUNNING+=("$exe"); }
done < <(ps -eo args= 2>/dev/null | grep -E '^(/[^ ]*php[^ ]*|php[^ ]*)' | awk '{print $1}' | sort -u)
# pids whose /proc exe is php (works even when args are rewritten, e.g. "php-fpm: master process")
for pid in /proc/[0-9]*; do
  exe="$(readlink -f "$pid/exe" 2>/dev/null)" || continue
  case "$exe" in *php*) add_bin "$exe"; RUNNING+=("$exe") ;; esac
done

# Magento root detection
if [[ -z "$MAGENTO_ROOT" ]]; then
  for c in "$PWD" "$PWD/.." /var/www/html /var/www/magento /var/www/*/htdocs /var/www/*/public_html /home/*/public_html /data/web/magento2 /app; do
    [[ -f "$c/app/etc/env.php" && -f "$c/bin/magento" ]] && { MAGENTO_ROOT="$(readlink -f "$c")"; break; }
  done 2>/dev/null
fi

# ---------- checks ----------

declare -a RESULTS=()   # path|sapi|version|verdict|fix|running
OVERALL=0  # 0 safe, 1 vuln, 2 unknown
ANY=0

sapi_of() {
  case "$(basename "$1")" in
    *fpm*) echo fpm ;; *cgi*|lsphp*) echo cgi ;; *) echo cli ;;
  esac
}

is_running() { for r in "${RUNNING[@]:-}"; do [[ "$r" == "$1" ]] && { echo yes; return; }; done; echo no; }

for bin in "${BINS[@]:-}"; do
  [[ -z "$bin" ]] && continue
  ANY=1
  sapi="$(sapi_of "$bin")"
  raw="$(run_to 5 "$bin" -v 2>/dev/null | head -1)"
  ver="$(clean_version "${raw#PHP }")"
  IFS='|' read -r vd fix <<< "$(verdict "$ver")"
  run="$(is_running "$bin")"
  RESULTS+=("$bin|$sapi|${ver:-?}|$vd|$fix|$run")
  case "$vd" in
    VULNERABLE|EOL|PARTIAL) OVERALL=1 ;;
    UNKNOWN) [[ $OVERALL == 0 ]] && OVERALL=2 ;;
  esac
done
[[ $ANY == 0 ]] && OVERALL=2

# ini settings from each FPM binary (php-fpm -i honours the fpm php.ini; pool overrides via -tt)
declare -a INI_RESULTS=()
for bin in "${BINS[@]:-}"; do
  [[ "$(sapi_of "$bin")" == fpm ]] || continue
  info="$(run_to 10 "$bin" -i 2>/dev/null)"
  [[ -z "$info" ]] && continue
  get() { printf '%s' "$info" | grep -iE "^$1 *=>" | head -1 | awk -F'=>' '{gsub(/^ +| +$/,"",$2); print $2}'; }
  ml="$(get memory_limit)"; pm="$(get post_max_size)"; up="$(get 'session.upload_progress.enabled')"; fb="$(get fatal_error_backtraces)"
  # pool-level admin overrides
  pool="$(run_to 10 "$bin" -tt 2>&1 | grep -iE 'php_admin_value\[(memory_limit|post_max_size|session.upload_progress.enabled)\]|php_admin_flag\[session.upload_progress.enabled\]' | sed 's/^[[:space:]]*//' | tr '\n' ';')"
  INI_RESULTS+=("$bin|$ml|$pm|$up|$fb|$pool")
done
# if no fpm binary but a cli exists, show cli ini as a weak signal
if [[ ${#INI_RESULTS[@]} == 0 ]]; then
  for bin in "${BINS[@]:-}"; do
    [[ "$(sapi_of "$bin")" == cli ]] || continue
    ml="$(run_to 5 "$bin" -r 'echo ini_get("memory_limit");' 2>/dev/null)"
    pm="$(run_to 5 "$bin" -r 'echo ini_get("post_max_size");' 2>/dev/null)"
    up="$(run_to 5 "$bin" -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null)"
    INI_RESULTS+=("$bin (cli, not web)|$ml|$pm|$up||")
    break
  done
fi

# mod_php / litespeed
MODPHP=""
for ctl in apachectl apache2ctl httpd; do
  if command -v "$ctl" >/dev/null 2>&1; then
    m="$(run_to 5 "$ctl" -M 2>/dev/null | grep -iE 'php[0-9_]*_module' | head -1 | awk '{print $1}')"
    [[ -n "$m" ]] && MODPHP="$m"
  fi
done
LITESPEED="no"; [[ -d /usr/local/lsws ]] && LITESPEED="yes"

# Magento cron PHP binary
CRON_PHP=""
if [[ -n "$MAGENTO_ROOT" ]]; then
  CRON_PHP="$( (crontab -l 2>/dev/null; cat /etc/cron.d/* 2>/dev/null) | grep -E 'bin/magento cron:run' | grep -oE '(/[^ ]*php[^ ]*|php[0-9.]*)' | head -1)"
  [[ -n "$CRON_PHP" ]] && add_bin "$(type -P "$CRON_PHP" 2>/dev/null || printf '%s' "$CRON_PHP")"
fi

# package source hints
PKG_HINT=""; FIX_CMD=""
if command -v rpm >/dev/null 2>&1; then
  if rpm -q remi-release >/dev/null 2>&1 || ls /etc/yum.repos.d/remi*.repo >/dev/null 2>&1; then
    PKG_HINT="Remi repository detected. php.net says Remi will NOT have today's fix; switch to distro packages or build from source."
  fi
  FIX_CMD="sudo dnf update 'php*' && sudo systemctl restart php-fpm   # or: sudo yum update 'php*'"
elif command -v apt-get >/dev/null 2>&1; then
  if ls /etc/apt/sources.list.d/*ondrej* >/dev/null 2>&1 || grep -rq 'ppa.launchpadcontent.net/ondrej\|ondrej/php\|packages.sury.org' /etc/apt/ 2>/dev/null; then
    PKG_HINT="Ondřej Surý PPA / sury.org detected. Fixed builds usually land within hours of php.net."
  else
    PKG_HINT="Distro PHP packages. Debian/Ubuntu security updates received the patch in advance; run apt update now."
  fi
  FIX_CMD="sudo apt update && sudo apt install --only-upgrade 'php8.*' && sudo systemctl restart 'php8.*-fpm'"
elif command -v apk >/dev/null 2>&1; then
  FIX_CMD="sudo apk update && sudo apk upgrade 'php8*'   # or rebuild your Docker image from php:8.x.y-fpm-alpine with the fixed tag"
elif command -v brew >/dev/null 2>&1; then
  FIX_CMD="brew update && brew upgrade php"
fi
[[ -f /.dockerenv ]] && PKG_HINT="${PKG_HINT:+$PKG_HINT }Running inside Docker: rebuild from an official image tagged php:8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, do not patch in place."

# ---------- output ----------

if [[ $JSON == 1 ]]; then
  printf '{\n  "tool": "php-rce-check",\n  "version": "%s",\n  "advisory": "%s",\n  "cves": ["%s","%s"],\n' "$VERSION" "$ADVISORY_URL" "$CVE_1" "$CVE_2"
  printf '  "overall": "%s",\n  "binaries": [\n' "$([[ $OVERALL == 0 ]] && echo safe || { [[ $OVERALL == 1 ]] && echo vulnerable || echo unknown; })"
  first=1
  for r in "${RESULTS[@]:-}"; do
    [[ -z "$r" ]] && continue
    IFS='|' read -r p s v vd fix run <<< "$r"
    [[ $first == 1 ]] || printf ',\n'; first=0
    printf '    {"path":"%s","sapi":"%s","version":"%s","verdict":"%s","fixed_in":"%s","running":%s}' \
      "$(json_escape "$p")" "$s" "$v" "$vd" "$fix" "$([[ $run == yes ]] && echo true || echo false)"
  done
  printf '\n  ],\n  "ini": [\n'
  first=1
  for r in "${INI_RESULTS[@]:-}"; do
    [[ -z "$r" ]] && continue
    IFS='|' read -r p ml pm up fb pool <<< "$r"
    [[ $first == 1 ]] || printf ',\n'; first=0
    printf '    {"source":"%s","memory_limit":"%s","post_max_size":"%s","session_upload_progress_enabled":"%s","fatal_error_backtraces":"%s","pool_overrides":"%s"}' \
      "$(json_escape "$p")" "$ml" "$pm" "$up" "$fb" "$(json_escape "$pool")"
  done
  printf '\n  ],\n  "mod_php": "%s",\n  "litespeed": "%s",\n  "magento_root": "%s",\n  "magento_cron_php": "%s",\n  "package_hint": "%s",\n  "fix_command": "%s"\n}\n' \
    "$MODPHP" "$LITESPEED" "$(json_escape "$MAGENTO_ROOT")" "$(json_escape "$CRON_PHP")" "$(json_escape "$PKG_HINT")" "$(json_escape "$FIX_CMD")"
  exit $OVERALL
fi

echo "${B}php-rce-check v$VERSION${N}  ${D}$CVE_1 / $CVE_2 (unauthenticated RCE, CVSS 9.2)${N}"
echo "${D}$ADVISORY_URL${N}"
echo

if [[ $ANY == 0 ]]; then
  echo "${Y}No PHP binaries found on this host.${N} If PHP runs in a container or on another box, run this script there."
  exit 2
fi

echo "${B}PHP binaries found${N}"
printf '  %-46s %-5s %-10s %-11s %s\n' "PATH" "SAPI" "VERSION" "VERDICT" "NOTE"
for r in "${RESULTS[@]}"; do
  IFS='|' read -r p s v vd fix run <<< "$r"
  case "$vd" in
    SAFE)       c="$G"; note="ok" ;;
    VULNERABLE) c="$R"; note="update to $fix" ;;
    PARTIAL)    c="$Y"; note="patch level unreadable, treat as vulnerable, need $fix" ;;
    EOL)        c="$R"; note="end of life, no official fix. upgrade branch or apply source backport" ;;
    *)          c="$Y"; note="could not read version" ;;
  esac
  [[ $run == yes ]] && note="$note ${D}(running)${N}"
  if (( ${#p} > 46 )); then
    printf '  %s\n' "$p"
    printf "  %-46s %-5s %-10s ${c}%-11s${N} %b\n" "" "$s" "$v" "$vd" "$note"
  else
    printf "  %-46s %-5s %-10s ${c}%-11s${N} %b\n" "$p" "$s" "$v" "$vd" "$note"
  fi
done
echo

echo "${B}Web SAPI exposure${N}"
if [[ -n "$MODPHP" ]]; then
  echo "  ${R}Apache mod_php loaded ($MODPHP).${N} php.net rates mod_php the highest risk: exploit fires before any application code runs."
fi
[[ "$LITESPEED" == yes ]] && echo "  LiteSpeed detected (/usr/local/lsws). lsphp binaries are listed above if found; LiteSpeed users update via their LiteSpeed/CloudLinux repos."
fpm_running=0; for r in "${RESULTS[@]}"; do [[ "$r" == *"|fpm|"*"|yes" ]] && fpm_running=1; done
[[ $fpm_running == 1 ]] && echo "  PHP-FPM is running. Every worker must be restarted after the update (systemctl restart, not reload)."
[[ -z "$MODPHP" && $fpm_running == 0 ]] && echo "  No running web SAPI detected from here (may be another host/container, or insufficient permissions to see processes)."
echo

echo "${B}Temporary mitigations${N} ${D}(reduce exposure only, php.net: \"do not make an installation safe\")${N}"
if [[ ${#INI_RESULTS[@]} == 0 ]]; then
  echo "  Could not read ini settings (no php-fpm binary readable)."
else
  for r in "${INI_RESULTS[@]}"; do
    IFS='|' read -r p ml pm up fb pool <<< "$r"
    echo "  Source: $p"
    if [[ "$ml" == "-1" ]]; then echo "    ${G}memory_limit = -1${N}  (removes the controllable OOM trigger for $CVE_1)";
    else echo "    ${Y}memory_limit = ${ml:-?}${N}  finite limit is the OOM trigger. Set -1 via php_admin_value in the pool, plus a low post_max_size."; fi
    pmv="${pm:-?}"
    if printf '%s' "$pmv" | grep -qiE '^([0-9]+|[0-9]+K|[0-9]{1,2}M)$'; then echo "    ${G}post_max_size = $pmv${N}";
    else echo "    ${Y}post_max_size = $pmv${N}  advisory suggests 8M (no uploads) or 32M (uploads). Magento admin needs uploads: use 32M and enforce at nginx (client_max_body_size)."; fi
    if [[ "$up" == "0" || "$up" == "Off" || "$up" == "off" ]]; then echo "    ${G}session.upload_progress.enabled = $up${N}  (blocks the confirmed $CVE_2 session path)";
    else echo "    ${R}session.upload_progress.enabled = ${up:-?}${N}  set to 0 in php.ini or the FPM pool, then restart ALL workers. ini_set/.user.ini do not count."; fi
    if [[ -n "$fb" ]]; then
      if [[ "$fb" == "0" || "$fb" == "Off" ]]; then echo "    ${G}fatal_error_backtraces = $fb${N}"; else echo "    ${Y}fatal_error_backtraces = $fb${N}  (PHP 8.5 only) set 0 to block the confirmed backtrace path."; fi
    fi
    [[ -n "$pool" ]] && echo "    ${D}pool overrides: ${pool%;}${N}"
  done
fi
echo

if [[ -n "$MAGENTO_ROOT" ]]; then
  echo "${B}Magento${N}"
  echo "  Store root: $MAGENTO_ROOT"
  if [[ -n "$CRON_PHP" ]]; then echo "  Cron runs with: $CRON_PHP  (checked above; cron PHP often differs from FPM PHP)";
  else echo "  ${Y}No 'bin/magento cron:run' entry readable in crontab${N}. Check the cron user's crontab and which php binary it uses."; fi
  echo "  Adobe Commerce / Magento patches do NOT fix this. It is the PHP runtime. Your host or sysadmin must update PHP."
  echo
fi

echo "${B}How to fix${N}"
[[ -n "$PKG_HINT" ]] && echo "  $PKG_HINT"
[[ -n "$FIX_CMD" ]] && echo "  $FIX_CMD"
echo "  Then re-run this script. Required: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or later."
echo "  PHP 8.1, 8.0, 7.4: no packages from php.net. Source backports: https://github.com/php/php-src/tree/PHP-8.1-$CVE_1-109619"
echo

case $OVERALL in
  0) echo "${G}${B}RESULT: PATCHED.${N} Every PHP binary found is at or above the fix line." ;;
  1) echo "${R}${B}RESULT: VULNERABLE.${N} At least one PHP on this host is below the fix line. Update now." ;;
  2) echo "${Y}${B}RESULT: UNKNOWN.${N} Could not read every version. Check manually." ;;
esac
echo "${D}Free Magento security scan: https://scan.magekwik.com   Managed patching: https://magekwik.com/care-plans${N}"
exit $OVERALL
