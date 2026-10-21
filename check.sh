#!/usr/bin/env bash
# php2shell checker: CVE-2026-109618 / CVE-2026-109619
# by Ariful Islam · https://arifulislamat.com · https://github.com/arifulislamat/php2shell-audit
#
# On your server (checks PHP binaries, mod_php, Docker/Podman, signs of compromise):
#   curl -fsSL https://raw.githubusercontent.com/arifulislamat/php2shell-audit/main/check.sh | sudo bash
# From any machine, against a website (passive fingerprinting):
#   curl -fsSL https://raw.githubusercontent.com/arifulislamat/php2shell-audit/main/check.sh | bash -s -- https://example.com
#
# Read-only: changes nothing and sends no exploit payloads.
# Exit codes: 0 = nothing found, 1 = vulnerable PHP, 2 = possible compromise, 3 = site unreachable,
#             4 = PHP found but its version can't be confirmed from outside.
# Set WEBROOTS="/path/one /path/two" to scan custom web roots. NO_COLOR=1 turns off colors and animation.

SINCE=2026-10-19 # the day before exploit details leaked
UA="php2shell-check/1.0 (+https://github.com/arifulislamat/php2shell-audit)"
PROVIDERS_URL=https://raw.githubusercontent.com/arifulislamat/php2shell-audit/main/docs/providers.tsv
VULN=0 IOC=0 EOL=0 UPLOAD_ON=0 UNCONFIRMED=0 RUNTIMES=0 TMP=''
JSON=0 EVENTS='' MODE='' rc=0

# ── look & feel ──────────────────────────────────────────────────────────────
# Colors and spinners only on a real terminal, so logs and CI output stay clean.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
  FX=1; c() { printf '\033[38;5;%sm' "$1"; }
  P=$(c 198) V=$(c 141) C=$(c 51) G=$(c 48) Y=$(c 220) R=$(c 196) D=$(c 244) B=$'\033[1m' N=$'\033[0m'
else
  FX=0 P='' V='' C='' G='' Y='' R='' D='' B='' N=''
fi
FRAMES=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
SPIN_PID='' TASK='' TASK_OK='' OUTN=0 TASKN=0 SEC=0

spin_on() {
  [ $FX = 1 ] && [ -n "$TASK" ] || return 0
  # Reset inherited traps: bash 3.2 (macOS) mishandles them in background subshells.
  ( trap - INT TERM; i=0; while :; do printf '\r  %s%s%s %s%s...%s' "$P" "${FRAMES[i % 10]}" "$N" "$D" "$TASK" "$N"; i=$((i + 1)); sleep 0.08; done ) </dev/null &
  SPIN_PID=$!
}
spin_off() {
  [ -n "$SPIN_PID" ] || return 0
  kill -HUP "$SPIN_PID" 2>/dev/null; wait "$SPIN_PID" 2>/dev/null; SPIN_PID='' # HUP: a signal this script never traps
  printf '\r\033[K'
}
# Every line goes through here so it never collides with the spinner.
out() { spin_off; printf '%s\n' "$*"; OUTN=$((OUTN + 1)); spin_on; }

# task "label" ["word"]: spinner while a check runs; a check that printed nothing gets an OK line.
task() { endtask; TASK=$1; TASK_OK=${2:-clean}; TASKN=$OUTN; spin_on; }
endtask() {
  [ -n "$TASK" ] || return 0
  spin_off
  [ "$OUTN" = "$TASKN" ] && dots "$TASK" "$TASK_OK"
  TASK=''
}
dots() { local n=$((52 - ${#1})); [ $n -lt 2 ] && n=2; printf '  [%s OK %s] %s %s%s%s %s%s%s\n' "$G" "$N" "$1" "$D" "$(printf '.%.0s' $(seq $n))" "$N" "$G" "$2" "$N"; }

# Structured findings for --json. No external JSON utility required (Bash 3.2+).
json_escape() {
  local text=$1
  text=${text//\\/\\\\}; text=${text//\"/\\\"}
  text=${text//$'\n'/\\n}; text=${text//$'\r'/\\r}; text=${text//$'\t'/\\t}
  # Other control characters are not useful evidence and cannot appear literally in JSON.
  printf '%s' "$text" | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177'
}
record() {
  [ "$JSON" = 1 ] || return 0
  EVENTS="${EVENTS}${EVENTS:+,}{\"severity\":\"$1\",\"message\":\"$(json_escape "$2")\"}"
}
finish() {
  local code=$?
  spin_off
  [ "$FX" = 1 ] && printf '\033[?25h'
  [ -n "$TMP" ] && rm -rf "$TMP"
  if [ "$JSON" = 1 ]; then
    printf '{"schema":"php2shell.check/1","mode":"%s","exitCode":%s,"since":"%s","findings":[%s]}\n' "$MODE" "$code" "$SINCE" "$EVENTS" >&3
  fi
}

ok()    { record ok "$*"; out "  [${G} OK ${N}] $*"; }
warn()  { record warning "$*"; out "  [${Y}WARN${N}] $*"; }
bad()   { record vulnerable "$*"; out "  [${R}${B}VULN${N}] $*"; VULN=1; }
ioc()   { record possible-compromise "$*"; out "  [${P}${B}PWN?${N}] $*"; IOC=1; }
kv()    { record evidence "$1: $2"; out "  [${C} >> ${N}] $(printf '%-12s' "$1")${D}::${N} $2"; }
info()  { record detail "$*"; out "         ${D}│${N} $*"; }
list()  { local l; while IFS= read -r l; do info "$l"; done < <(printf '%s\n' "$1" | head -"${2:-20}"); }
stepn() { out "  ${C}${B}[$1]${N} $2"; }
cmd()   { record recommendation "$*"; out "       ${G}\$ $*${N}"; }
cfg()   { record recommendation "$*"; out "       ${C}$(printf '%-38s' "$1")${N}${D}$2${N}"; }
note()  { out "       ${D}$*${N}"; }

hdr() {
  endtask
  SEC=$((SEC + 1))
  local t n; t=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]'); n=$((60 - ${#t})); [ $n -lt 3 ] && n=3
  printf '\n  %s▌%s%s%02d%s %s▸%s %s%s%s %s%s%s\n' "$P" "$N" "$V$B" "$SEC" "$N" "$C" "$N" "$B" "$t" "$N" "$D" "$(printf '━%.0s' $(seq $n))" "$N"
}

banner() {
  local l i=0 cols=(198 199 163 129 93 63)
  echo
  while IFS= read -r l; do
    if [ $FX = 1 ]; then printf '  \033[38;5;%sm%s%s\n' "${cols[i]}" "$l" "$N"; sleep 0.04; else printf '  %s\n' "$l"; fi
    i=$((i + 1))
  done <<'ART'
██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
██╔═══╝ ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║
██║     ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
ART
  printf '  %s░▒▓%s %sPHP CORE RCE CHECKER%s %s▓▒░%s  %sCVE-2026-109618 · CVE-2026-109619%s\n' "$P" "$N" "$B" "$N" "$P" "$N" "$C" "$N"
  printf '  %scoded by%s %sAriful Islam%s %s·%s arifulislamat.com %s·%s github.com/arifulislamat/php2shell-audit\n\n' "$D" "$N" "$V$B" "$N" "$D" "$N" "$D" "$N"
}

typeit() {
  if [ $FX = 1 ]; then local i; for ((i = 0; i < ${#1}; i++)); do printf '%s' "${1:i:1}"; sleep 0.003; done; echo; else echo "$1"; fi
}
boot() {
  typeit "  ${D}>${N} ${C}mode${N}    $1"
  typeit "  ${D}>${N} ${C}target${N}  $2"
  typeit "  ${D}>${N} ${C}patched${N} 8.5.12 · 8.4.27 · 8.3.36 · 8.2.35  ${D}// read-only, no exploit payloads${N}"
}

verdict_box() {
  local w=60 line; line=$(printf '═%.0s' $(seq $((w + 2))))
  printf '\n  %s╔%s╗%s\n  %s║%s %s%-*s%s %s║%s\n  %s╚%s╝%s\n' \
    "$1" "$line" "$N" "$1" "$N" "$B" "$w" "$2" "$N" "$1" "$N" "$1" "$line" "$N"
}

# ── checks ───────────────────────────────────────────────────────────────────
# Prints "patched", "eol" or "vulnerable:<fixed version>" for a version like 8.3.6 or 8.6.0RC3.
php_status() {
  local maj min pat pre fix re
  re='^([0-9]+)\.([0-9]+)\.([0-9]+)(-?([Aa][Ll][Pp][Hh][Aa]|[Bb][Ee][Tt][Aa]|[Rr][Cc])[0-9]+)?([-+~].*)?$'
  [[ "$1" =~ $re ]] || { echo unknown; return; }
  maj=${BASH_REMATCH[1]}; min=${BASH_REMATCH[2]}; pat=${BASH_REMATCH[3]}; pre=${BASH_REMATCH[4]}
  case "$maj.$min" in
    8.5) fix=12 ;; 8.4) fix=27 ;; 8.3) fix=36 ;; 8.2) fix=35 ;;
    8.6) case $(printf '%s' "$pre" | tr '[:upper:]' '[:lower:]') in *alpha*|*beta*|*rc[1-3]) echo vulnerable:8.6.0RC4 ;; *) echo patched ;; esac; return ;;
    *) if [ "$maj" -gt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -gt 6 ]; }; then echo patched; else echo eol; fi; return ;;
  esac
  if [ "$pat" -gt "$fix" ] || { [ "$pat" -eq "$fix" ] && [ -z "$pre" ]; }; then echo patched; else echo "vulnerable:$maj.$min.$fix"; fi
}

# True if the installed distro package owning $1 lists both CVEs in its changelog (fix backported, version number unchanged).
backported() {
  local pkg log=
  if command -v dpkg >/dev/null 2>&1 && pkg=$(dpkg -S "$1" 2>/dev/null | head -1 | cut -d: -f1) && [ -n "$pkg" ]; then
    log=$(zcat "/usr/share/doc/$pkg/changelog.Debian.gz" 2>/dev/null)
  elif command -v rpm >/dev/null 2>&1 && pkg=$(rpm -qf "$1" 2>/dev/null); then
    log=$(rpm -q --changelog "$pkg" 2>/dev/null)
  fi
  echo "$log" | grep -q CVE-2026-109618 && echo "$log" | grep -q CVE-2026-109619
}

# The PHP version compiled into a binary or libphp.so, read without executing it.
ver_of() { grep -aoE 'X-Powered-By: PHP/[0-9]+\.[0-9]+\.[0-9]+(-?(alpha|beta|RC)[0-9]+)?' "$1" 2>/dev/null | head -1 | cut -d/ -f2; }

# judge <label> <version> [file used for the backport lookup]
judge() {
  local s; s=$(php_status "$2"); RUNTIMES=$((RUNTIMES + 1))
  case $s in
    unknown) warn "$1 :: PHP $2 has no verified version rule; confirm against the advisory."; UNCONFIRMED=1 ;;
    patched) ok "$1 ${D}::${N} PHP $2 ${G}patched${N}" ;;
    *) if [ -n "$3" ] && backported "$3"; then ok "$1 ${D}::${N} PHP $2 ${G}distro build, fix backported${N}"
       elif [ "$s" = eol ]; then bad "$1 ${D}::${N} PHP $2 ${R}end-of-life, no upstream fix${N} (upgrade to 8.2+ or use a vendor backport)"; EOL=1
       else bad "$1 ${D}::${N} PHP $2 ${R}VULNERABLE${N} (fixed in ${s#vulnerable:})"; fi ;;
  esac
}

# Managed-host fingerprints and patch status (edit docs/providers.tsv). Local copy first, else the published one.
providers() {
  local f; f="$(dirname "${BASH_SOURCE[0]}")/docs/providers.tsv"
  if [ -f "$f" ]; then cat "$f"; else curl -fsSL -m 10 "$PROVIDERS_URL" 2>/dev/null; fi
}

server() {
  [ "$(id -u)" = 0 ] || warn "Not running as root: other users' files, processes, logs and Docker may be skipped. Re-run with sudo."

  hdr "PHP runtimes"
  task "enumerating PHP binaries" "none found"
  local b real v seen='' p
  # Binaries of running PHP masters first, so custom builds are caught too.
  for b in $( (pgrep -f 'php-fpm: master|frankenphp|lsphp' 2>/dev/null || true) | sed 's|.*|/proc/&/exe|') \
      $(command -v php php-cgi php-fpm frankenphp lsphp 2>/dev/null) /usr/bin/php[0-9]* /usr/bin/php-cgi* /usr/sbin/php-fpm* \
      /usr/local/bin/php /usr/local/bin/frankenphp /usr/local/sbin/php-fpm /opt/cpanel/ea-php*/root/usr/bin/php \
      /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm \
      /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm /opt/alt/php*/usr/bin/php \
      /usr/local/lsws/lsphp*/bin/lsphp /www/server/php/*/bin/php; do
    real=$(readlink -f "$b" 2>/dev/null) || real=$b
    [ -f "$real" ] || continue
    case $'\n'"$seen" in *$'\n'"$real"$'\n'*) continue ;; esac
    seen="$seen$real"$'\n'
    v=$(ver_of "$real"); [ -n "$v" ] || continue
    judge "$real" "$v" "$real"
    case $(php_status "$v") in patched) ;; *)
      v=$("$real" -i 2>/dev/null </dev/null | grep -m1 '^session.upload_progress.enabled' | awk '{print $NF}')
      [ -n "$v" ] && info "session.upload_progress.enabled = $v"
      [ "$v" = On ] && UPLOAD_ON=1 ;;
    esac
  done

  # Upgraded packages do nothing until the workers restart: the old code stays mapped in memory.
  task "scanning memory for stale PHP code" "none"
  p=$(grep -lE 'php.* \(deleted\)$' /proc/[0-9]*/maps 2>/dev/null | cut -d/ -f3 | tr '\n' ' ')
  [ -n "$p" ] && bad "Processes still running old, replaced PHP code (PIDs: $p). Restart PHP-FPM / Apache / LiteSpeed."

  task "probing Apache for mod_php" "not loaded"
  local mods c so
  for c in apache2ctl apachectl httpd; do command -v $c >/dev/null 2>&1 && { mods=$($c -M 2>/dev/null); break; }; done
  if echo "$mods" | grep -qi php; then
    warn "Apache mod_php is loaded. This is the highest-risk setup: the attack starts before any app code runs."
    for so in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so \
        /etc/httpd/modules/libphp*.so /usr/local/apache2/modules/libphp*.so; do
      [ -f "$so" ] && v=$(ver_of "$so") && [ -n "$v" ] && judge "$so" "$v" "$so"
    done
  fi

  task "reading php.ini / FPM pool overrides" "none"
  c=$(grep -rsHE '^[^;#]*session\.upload_progress\.enabled' /etc/php* /etc/php-fpm.d /etc/opt/remi /opt/cpanel/ea-php*/root/etc /usr/local/etc/php* 2>/dev/null)
  [ -n "$c" ] && { kv "overrides" "session.upload_progress.enabled set in config:"; list "$c" 10; }

  local rt id name image out
  for rt in docker podman; do
    command -v $rt >/dev/null 2>&1 && $rt ps -q >/dev/null 2>&1 || continue
    hdr "$rt containers"
    task "interrogating $rt containers" "no PHP containers"
    while read -r id name image; do
      v=$($rt exec "$id" sh -c 'for b in php php-fpm frankenphp /usr/local/sbin/php-fpm; do command -v $b >/dev/null 2>&1 && { $b -v; break; }; done' 2>/dev/null </dev/null \
          | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+(-?(alpha|beta|RC)[0-9]+)?' | head -1 | cut -d' ' -f2)
      [ -n "$v" ] || v=$($rt inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$id" 2>/dev/null | sed -n 's/^PHP_VERSION=//p')
      [ -n "$v" ] || continue
      judge "$name ($image)" "$v"
      # PHP files added or changed inside the container since it started (bind mounts and volumes are not covered).
      out=$($rt diff "$id" 2>/dev/null | grep -E '^[AC] .*\.(php[0-9]?|phtml|phar)$')
      [ -n "$out" ] && { warn "$name: PHP files added/changed inside the container since it started:"; list "$out"; }
    done < <($rt ps --format '{{.ID}} {{.Names}} {{.Image}}')
  done

  [ "$RUNTIMES" -gt 0 ] || { warn "No PHP runtime could be inspected; this does not establish that the server is safe."; UNCONFIRMED=1; }

  hdr "Signs of compromise (file-change window: $SINCE)"
  local roots
  roots=${WEBROOTS:-$(ls -d /var/www /srv/www /srv/http /usr/share/nginx/html /home/*/public_html /home/*/domains \
                           /home/*/htdocs /home/*/web /opt/bitnami/wordpress /www/wwwroot 2>/dev/null)}
  if [ -z "$roots" ]; then
    warn "No web roots found. Re-run with WEBROOTS=\"/path/to/site\" to scan your files."
  else
    kv "web roots" "$(echo $roots)"
    task "grepping for web-shell signatures"
    # ponytail: grep over every PHP file. Fine for typical hosts; restrict WEBROOTS on servers with millions of files.
    out=$(grep -rlIE --include='*.php' --include='*.php[0-9]' --include='*.phtml' --include='*.phar' \
      'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(GET|POST|REQUEST|COOKIE))|assert[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|(system|shell_exec|passthru|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)|\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\([[:space:]]*\$_' \
      $roots 2>/dev/null)
    [ -n "$out" ] && { ioc "Files containing web-shell patterns ($(echo "$out" | wc -l | tr -d ' ')):"; list "$out" 50; }

    task "sweeping upload folders for PHP"
    out=$(find $roots -type f -path '*/uploads/*' \( -name '*.php*' -o -name '*.phtml' -o -name '*.phar' \) ! \( -name index.php -size -2k \) 2>/dev/null)
    [ -n "$out" ] && { ioc "PHP files inside upload folders:"; list "$out"; }

    # ctime catches files whose mtime was backdated with touch.
    task "diffing PHP files changed since $SINCE" "none"
    out=$(find $roots -type f \( -name '*.php*' -o -name '*.phtml' \) -newerct "$SINCE" 2>/dev/null)
    [ -n "$out" ] && { warn "PHP files created/changed since $SINCE ($(echo "$out" | wc -l | tr -d ' '); plugin updates also show here):"; list "$out" 30; }

    task "checking .user.ini / .htaccess hooks"
    out=$(grep -rsHE 'auto_(prepend|append)_file' --include=.user.ini --include=.htaccess $roots 2>/dev/null)
    [ -n "$out" ] && { warn "auto_prepend/append_file set (legit for Wordfence etc., also a common backdoor):"; list "$out" 10; }

    task "auditing WordPress admins"
    if command -v wp >/dev/null 2>&1; then
      local cfg login reg
      while read -r cfg; do
        while IFS=, read -r login reg; do
          [[ "$reg" > "$SINCE" ]] && ioc "$(dirname "$cfg"): WordPress admin '$login' created $reg"
        done < <(wp --path="$(dirname "$cfg")" --allow-root --skip-plugins --skip-themes user list --role=administrator \
                   --fields=user_login,user_registered --format=csv 2>/dev/null </dev/null | tail -n +2)
      done < <(find $roots -maxdepth 4 -name wp-config.php 2>/dev/null)
    else
      warn "wp-cli not installed, skipped the new-admin check (check Users → Administrators by hand)."
    fi
  fi

  task "inspecting /tmp, /var/tmp, /dev/shm"
  out=$(find /tmp /var/tmp /dev/shm -xdev -maxdepth 3 -type f \( -name '*.php*' -o -name '*.sh' -o -perm -u=x \) -newerct "$SINCE" 2>/dev/null)
  [ -n "$out" ] && { warn "Scripts/executables in temp folders since $SINCE:"; list "$out"; }

  task "watching web-user processes"
  out=$(ps -eo user=,pid=,args= 2>/dev/null | awk '$1 ~ /^(www-data|apache|nginx|http|nobody|wwwrun|lsadm)$/' \
        | grep -E '(^|[ /])(sh|bash|dash|nc|ncat|netcat|socat|perl|python[0-9.]*|ruby|curl|wget|base64|xmrig|kinsing|kdevtmpfsi)( |$)|/tmp/|/dev/shm/')
  [ -n "$out" ] && { ioc "Shells/downloaders running as the web user:"; list "$out"; }

  task "reading web-user crontabs" "none"
  local u
  for u in www-data apache nginx http nobody; do
    out=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
    [ -n "$out" ] && { warn "Crontab for $u (review, attackers use this for persistence):"; list "$out" 10; }
  done

  if command -v ss >/dev/null 2>&1; then
    task "tracing outbound PHP connections" "none"
    out=$(ss -tnpH state established 2>/dev/null | grep -E '"(php[^"]*|lsphp|frankenphp|httpd|apache2)"' \
          | awk '$3 !~ /:(80|443)$/ && $4 !~ /^(127\.|\[::1\]|\[::ffff:127\.)/ {print $3, "->", $4, $5}')
    [ -n "$out" ] && { warn "Outbound connections from PHP/web processes (DB and API calls are normal, unknown IPs are not):"; list "$out"; }
  fi

  task "parsing available logs (all retained dates)"
  local f n
  for f in /var/log/php*fpm*.log /var/log/php-fpm/*.log /var/log/nginx/error.log /var/log/apache2/error.log \
      /var/log/httpd/error_log /usr/local/lsws/logs/error.log /opt/cpanel/ea-php*/root/usr/var/log/php-fpm.log; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    n=$(grep -cE 'Allowed memory size|exited on signal|SIGSEGV|SIGBUS|segfault' "$f")
    [ "$n" -gt 0 ] && warn "$f: $n memory-limit errors / worker crashes"
  done
  for f in /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log /usr/local/lsws/logs/access.log; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    n=$(grep -cE '"POST [^"]*" 500 ' "$f")
    [ "$n" -gt 0 ] && warn "$f: $n POST requests answered with HTTP 500 (can mean exploit attempts)"
  done
  n=$(dmesg 2>/dev/null | grep -ciE '(php|lsphp|frankenphp|apache2|httpd).*segfault')
  [ "${n:-0}" -gt 0 ] && warn "Kernel log: $n PHP/web server segfaults"
  endtask
}

remote() {
  local url=$1 origin H v s observed p php='' app='' host pv='' name hre hostre patched checked link note srv
  case $url in http://*|https://*) ;; *) url="https://$url" ;; esac
  origin=$(printf '%s' "$url" | grep -oE '^https?://[^/]+')
  TMP=$(mktemp -d)
  get() { curl -sSL --proto '=http,https' --proto-redir '=http,https' --max-redirs 4 -m 15 -A "$UA" -D "$TMP/h" -o "$TMP/b" -w '%{url_effective}' "$1" >"$TMP/e" 2>/dev/null; }

  hdr "Recon"
  task "connecting to $origin" "online"
  get "$url" || { bad "Could not reach $url"; exit 3; }
  # Headers of every hop: a PHP redirect can expose the version that the final page hides.
  H=$(tr -d '\r' <"$TMP/h")
  origin=$(grep -oE '^https?://[^/]+' "$TMP/e")
  s=$(echo "$H" | awk '/^HTTP\// {code=$2} END {print code}')
  if [ "${s:-0}" -ge 400 ]; then warn "Main page returned HTTP $s; coverage is incomplete."; UNCONFIRMED=1; fi

  task "fingerprinting response headers"
  srv=$(echo "$H" | grep -i '^server:' | tail -1 | cut -d' ' -f2-)
  kv "server" "${srv:-hidden}"
  echo "$H" | grep -qi '^cf-ray:' && kv "waf" "Cloudflare detected; WAF rule activation and origin protection cannot be verified from headers"
  v=$(echo "$H" | grep -iE '^x-powered-by:.*PHP/' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-?(alpha|beta|RC)[0-9]+)?' | tail -1)
  echo "$H" | grep -qiE '^x-powered-by:.*php' && php="X-Powered-By header"
  echo "$H" | grep -qiE '^set-cookie:[[:space:]]*(PHPSESSID|laravel_session)=' && php="${php:+$php, }PHP session cookie"
  echo "$H" | grep -qiE '^set-cookie:[[:space:]]*laravel_session=' && app=Laravel
  grep -qE '/wp-(content|includes)/' "$TMP/b" && app=WordPress
  { echo "$H" | grep -qiE '^x-generator:[[:space:]]*Drupal'; } || grep -qiE 'name="generator" content="Drupal' "$TMP/b" && app=Drupal
  grep -qiE 'name="generator" content="Joomla' "$TMP/b" && app=Joomla
  [ -n "$app" ] && php="${php:+$php, }$app"
  kv "php signals" "${php:-none}"
  [ -n "$v" ] && kv "php version" "$v ${D}(exposed in headers)${N}"

  task "matching hosting provider" "no match"
  host=${origin#*://}; host=${host%%:*}
  # \037 as separator: bash's read would merge empty tab-separated fields.
  while IFS=$'\037' read -r name hre hostre patched checked link note; do
    case $name in ''|'#'*) continue ;; esac
    { [ -n "$hre" ] && echo "$H" | grep -qiE "$hre"; } || { [ -n "$hostre" ] && echo "$host" | grep -qiE "$hostre"; } || continue
    pv=$name; break
  done < <(providers | awk -F'\t' -v OFS=$'\037' '{$1=$1; print}')
  [ -n "$pv" ] && kv "hosting" "$pv ${D}(managed host)${N}"

  task "probing common phpinfo() paths" "none exposed"
  for p in phpinfo.php info.php php_info.php i.php test.php; do
    get "$origin/$p" || { warn "Could not inspect $origin/$p"; UNCONFIRMED=1; continue; }
    s=$(tr -d '\r' <"$TMP/h" | awk '/^HTTP\// {code=$2} END {print code}')
    if [ "$s" = 429 ]; then warn "Rate limited; stopping probes."; UNCONFIRMED=1; break; fi
    if [ "${s:-0}" -ge 500 ]; then warn "HTTP $s at $origin/$p"; UNCONFIRMED=1; fi
    [ "${s:-0}" -ge 200 ] && [ "${s:-0}" -lt 300 ] || continue
    # Both markers, so a catch-all 200 page that merely mentions phpinfo() isn't reported.
    grep -q 'phpinfo()' "$TMP/b" && grep -qE 'PHP Version [0-9]' "$TMP/b" || continue
    observed=$(grep -oE 'PHP Version [0-9]+\.[0-9]+\.[0-9]+(-?(alpha|beta|RC)[0-9]+)?' "$TMP/b" | head -1 | cut -d' ' -f3)
    warn "$origin/$p is a public phpinfo() page${observed:+ (PHP $observed)}. Delete it, it helps attackers."
    if [ -n "$observed" ] && [ -n "$v" ] && [ "$observed" != "$v" ]; then
      warn "Conflicting PHP versions: header/previous page $v; $origin/$p $observed. Check every backend."
      judge "$origin/$p" "$observed"
    fi
    s=$(grep -oE 'session\.upload_progress\.enabled</td><td class="v">[^<]*' "$TMP/b" | head -1 | sed 's/.*>//')
    [ -n "$s" ] && info "session.upload_progress.enabled = $s"
    [ "$s" = On ] && UPLOAD_ON=1
    [ -n "$v" ] || v=$(grep -oE 'PHP Version [0-9]+\.[0-9]+\.[0-9]+(-?(alpha|beta|RC)[0-9]+)?' "$TMP/b" | head -1 | cut -d' ' -f3)
    php="${php:+$php, }phpinfo page"
  done

  hdr "Verdict"
  if [ -n "$v" ]; then
    judge "$origin" "$v"
    [ $VULN = 1 ] && info "Ubuntu/Debian/RHEL packages can carry the fix without changing the version number. Run the server check to confirm."
  elif [ -n "$php" ] && [ -n "$pv" ]; then
    case $patched in
      yes) warn "Hosted on $pv, which reports patched PHP${checked:+ (checked $checked)}. Confirm this site and pool with your host."; UNCONFIRMED=1 ;;
      no) bad "Hosted on $pv, which has NOT patched PHP yet${checked:+ (checked $checked)}." ;;
      *) warn "PHP detected ($php), version hidden. Hosted on $pv: patch status not confirmed yet."; UNCONFIRMED=1 ;;
    esac
    [ -n "$link" ] && info "Status page: $link"
    [ -n "$note" ] && info "$note"
    info "$pv updates PHP for you. Ask their support whether your site's PHP includes the fixes for CVE-2026-109618 / CVE-2026-109619."
  elif [ -n "$php" ]; then
    warn "PHP detected ($php) but the version is hidden. That can't be judged from outside: run the server check or ask your host."
    UNCONFIRMED=1
  else
    ok "No PHP fingerprints found. The site may still run PHP behind a proxy or cache."
  fi
  if [ -z "$v" ] || [ $VULN = 1 ]; then
    out ""
    if [ -z "$pv" ]; then
      note "server check (real version, Docker containers, signs of compromise):"
      cmd "curl -fsSL https://raw.githubusercontent.com/arifulislamat/php2shell-audit/main/check.sh | sudo bash"
    fi
    note "shared hosting without SSH: WordPress → Tools → Site Health → Info → Server shows the PHP version."
  fi
}

fixes() {
  [ $VULN = 1 ] || [ $IOC = 1 ] || [ $UPLOAD_ON = 1 ] || return 0
  hdr "How to fix"
  local s
  if [ $VULN = 1 ]; then
    stepn 1 "Back up files and database."
    stepn 2 "Update PHP to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or newer:"
    if [ "$MODE" = server ] && { [ -f /.dockerenv ] || [ -f /run/.containerenv ]; }; then
      note "This is a container: rebuild from a patched image (e.g. php:8.3.36-apache) and redeploy. apt won't update an image's PHP."
    elif [ "$MODE" = server ]; then
      if command -v apt-get >/dev/null 2>&1; then cmd "sudo apt update && apt list --upgradable | grep php && sudo apt upgrade"
      elif command -v dnf >/dev/null 2>&1; then cmd "sudo dnf upgrade 'php*' 'ea-php*'"
      elif command -v yum >/dev/null 2>&1; then cmd "sudo yum update 'php*' 'ea-php*'"
      elif command -v apk >/dev/null 2>&1; then cmd "apk update && apk upgrade"; fi
      note "Still the old version in apt-cache policy / dnf? Your distro hasn't shipped the fix yet: use the interim steps below."
      if command -v docker >/dev/null 2>&1; then
        note "Docker: bump the image tag (e.g. php:8.3.36-fpm), then:"
        cmd "docker compose pull && docker compose up -d --build"
      fi
    else
      note "VPS: apt/dnf upgrade · Docker: rebuild the image · shared hosting, Forge, panels: use their PHP update or ask your host."
    fi
    [ $EOL = 1 ] && note "PHP 8.1 and older get no upstream fix: move to 8.2+, or use a vendor backport (Ubuntu Pro, Debian LTS, CloudLinux...)."
    stepn 3 "Restart PHP workers, otherwise the old code keeps running:"
    if [ "$MODE" = server ] && { [ -f /.dockerenv ] || [ -f /run/.containerenv ]; }; then
      note "Redeploying the rebuilt container restarts them."
    elif [ "$MODE" = server ] && command -v systemctl >/dev/null 2>&1; then
      s=$(systemctl list-units --type=service --state=running --no-legend 'php*' 'apache2*' 'httpd*' 'lsws*' 'lshttpd*' 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
      cmd "sudo systemctl restart ${s:-php8.3-fpm apache2}"
    else
      cmd "sudo systemctl restart php8.x-fpm"
      note "(or apache2 / httpd for mod_php)"
    fi
    stepn 4 "Re-run this check, then test forms, uploads, logins and admin pages."
    note "Updating WordPress, Laravel, Drupal or plugins does NOT fix this. Only the PHP runtime does."
  fi
  if [ $VULN = 1 ] || [ $UPLOAD_ON = 1 ]; then
    out ""
    out "  ${Y}${B}INTERIM MITIGATION${N} ${D}// can't patch yet? reduces exposure, not a fix${N}"
    cfg "session.upload_progress.enabled = 0" "php.ini or FPM pool (ini_set() and .user.ini don't work)"
    cfg "fatal_error_backtraces = 0" "PHP 8.5"
    cfg "memory_limit = -1" "non-overridable; cap memory with container/cgroup limits"
    cfg "post_max_size = 8M" "32M if you need uploads"
    note "Then restart all PHP workers, keep the WAF on, take high-risk public services offline."
  fi
  if [ $IOC = 1 ]; then
    out ""
    out "  ${P}${B}INCIDENT RESPONSE${N} ${D}// patching alone won't remove a backdoor${N}"
    stepn 1 "Block traffic or take the site offline. Copy logs and suspicious files before deleting anything."
    stepn 2 "Restore from a backup made before $SINCE, or remove the backdoors and reinstall core/plugins."
    stepn 3 "Rotate DB passwords, WordPress salts / Laravel APP_KEY, API keys and admin passwords. Remove unknown admins."
    stepn 4 "Then patch PHP and restart the workers."
  fi
}

# ── main ─────────────────────────────────────────────────────────────────────
while [ "$1" = -s ] || [ "$1" = -- ]; do shift; done # tolerate `bash check.sh -s -- URL`

while [ "$#" -gt 0 ]; do
  case "$1" in
    --json) JSON=1; shift ;;
    --since)
      [[ "$2" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo "--since requires YYYY-MM-DD" >&2; exit 64; }
      year=$((10#${2:0:4})); month=$((10#${2:5:2})); day=$((10#${2:8:2})); days=31
      case "$month" in
        4|6|9|11) days=30 ;;
        2) days=28; if (( year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) )); then days=29; fi ;;
      esac
      if (( year < 1970 || month < 1 || month > 12 || day < 1 || day > days )); then echo 'Invalid investigation date' >&2; exit 64; fi
      SINCE=$2; shift 2 ;;
    --help|-h)
      printf '%s\n' 'Usage: bash check.sh [--json] [--since YYYY-MM-DD] [URL]' \
        'No URL: local server audit. URL: passive remote fingerprinting.' \
        '--json: structured findings on stdout; progress on stderr.' \
        '--since: file/admin change window; logs cover all retained dates.' \
        'Exit: 0 no findings; 1 affected version; 2 possible compromise; 3 unreachable; 4 incomplete; 64 usage.'
      exit 0 ;;
    --selftest) break ;;
    --) shift; break ;;
    -*) echo "Unknown option: $1" >&2; exit 64 ;;
    *) break ;;
  esac
done
[ "$#" -le 1 ] || { echo 'Expected at most one URL' >&2; exit 64; }
if [ "$JSON" = 1 ]; then
  FX=0 P='' V='' C='' G='' Y='' R='' D='' B='' N=''
  exec 3>&1 1>&2
fi

if [ "$1" = --selftest ]; then
  for t in 8.5.11:vulnerable:8.5.12 8.5.12:patched 8.4.26:vulnerable:8.4.27 8.4.30:patched 8.3.6:vulnerable:8.3.36 \
      8.3.36:patched 8.2.35:patched 8.1.31:eol 7.4.33:eol 5.4.45:eol 8.6.0RC3:vulnerable:8.6.0RC4 8.6.0RC4:patched 8.6.0:patched 8.7.1:patched 9.0.0:patched invalid:unknown 8.3.36-1ubuntu1:patched 8.3.36RC1:vulnerable:8.3.36 8.3.37RC1:patched; do
    [ "$(php_status "${t%%:*}")" = "${t#*:}" ] || { echo "FAIL $t -> $(php_status "${t%%:*}")"; exit 1; }
  done
  echo "selftest ok"; exit 0
fi

trap finish EXIT
trap 'exit 130' INT TERM
[ $FX = 1 ] && printf '\033[?25l' # hide the cursor while spinners run

banner
if [ -n "$1" ]; then
  MODE=remote; boot "remote ${D}(passive fingerprinting)${N}" "$1"; remote "$1"
else
  MODE=server; boot "server ${D}(local deep scan)${N}" "$(hostname 2>/dev/null) as $(id -un)"; server
fi
fixes
hdr "Summary"
if [ $IOC = 1 ]; then verdict_box "$P" ">> POSSIBLE COMPROMISE :: treat it as an incident"; rc=2
elif [ $VULN = 1 ]; then verdict_box "$R" ">> VULNERABLE :: patch PHP, then restart the workers"; rc=1
elif [ $UNCONFIRMED = 1 ]; then verdict_box "$Y" ">> UNCONFIRMED :: version or scan coverage incomplete"; rc=4
else verdict_box "$G" ">> NO VULNERABLE PHP FOUND :: stay patched"; rc=0; fi
printf '\n  %s// php2shell by%s %sAriful Islam%s %s· https://arifulislamat.com%s\n\n' "$D" "$N" "$V" "$N" "$D" "$N"
exit $rc
