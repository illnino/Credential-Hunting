#!/usr/bin/env bash
# HomeHunter - read-only home-directory clue and credential scanner.
# Bash 4+ (validated with Bash 5). Does not follow symbolic links.

set -uo pipefail
shopt -s nocasematch

VERSION="1.0.0"
MAX_SIZE_MB=5
MAX_BYTES=$((5 * 1024 * 1024))
QUIET=0
NO_COLOR=0
ONLY_SPECIFIED=0
OUTPUT_FILE=""
EXIT_CODE=0
declare -a SPECIFIED_HOMES=()
declare -a HOMES=()
declare -A SEEN_HOMES=()
declare -A REPORTED=()
declare -A SEEN_FILES=()
REPORT_ADDED=0

N_HOMES_DISCOVERED=0
N_HOMES_SCANNED=0
N_FILES=0
N_TEXT=0
N_HIDDEN=0
N_HIGH=0
N_KEY=0
N_LARGE=0
N_BINARY=0
N_DENIED=0

usage() {
    cat <<'EOF'
Usage: ./homehunter.sh [options]

Scan all local user homes for hidden clues and reusable credentials.

Options:
  --max-size N              Maximum text file size in MiB (default: 5)
  -o, --output FILE         Append findings to a mode-600 text log
  --home PATH               Add an explicit home path (repeatable)
  --only-specified-homes    Scan only paths supplied with --home
  -q, --quiet               Suppress progress; findings and summary remain
  --no-color                Disable ANSI colours
  -h, --help                Show help
  -V, --version             Show version

No options are required. Run with sudo for the widest coverage.
EOF
}

die() { printf '[ERROR] %s\n' "$*" >&2; exit 2; }
need_arg() { [ "$1" -ge 2 ] || die "Option $2 requires a value"; }

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --max-size) need_arg "$#" "$1"; MAX_SIZE_MB="$2"; shift 2 ;;
            -o|--output) need_arg "$#" "$1"; OUTPUT_FILE="$2"; shift 2 ;;
            --home) need_arg "$#" "$1"; SPECIFIED_HOMES+=("$2"); shift 2 ;;
            --only-specified-homes) ONLY_SPECIFIED=1; shift ;;
            -q|--quiet) QUIET=1; shift ;;
            --no-color) NO_COLOR=1; shift ;;
            -h|--help) usage; exit 0 ;;
            -V|--version) printf 'homehunter %s\n' "$VERSION"; exit 0 ;;
            --) shift; while [ "$#" -gt 0 ]; do SPECIFIED_HOMES+=("$1"); shift; done ;;
            -*) die "Unknown option: $1" ;;
            *) SPECIFIED_HOMES+=("$1"); shift ;;
        esac
    done
    [[ "$MAX_SIZE_MB" =~ ^[1-9][0-9]*$ ]] || die "--max-size must be a positive integer"
    [ "$MAX_SIZE_MB" -le 512 ] || die "--max-size cannot exceed the 512 MiB safety ceiling"
    MAX_BYTES=$((MAX_SIZE_MB * 1024 * 1024))
    [ "$ONLY_SPECIFIED" -eq 0 ] || [ "${#SPECIFIED_HOMES[@]}" -gt 0 ] || die "--only-specified-homes requires --home PATH"
}

setup_output() {
    [ -z "$OUTPUT_FILE" ] && return
    umask 077
    : >>"$OUTPUT_FILE" 2>/dev/null || die "Cannot write output file: $OUTPUT_FILE"
    chmod 600 "$OUTPUT_FILE" 2>/dev/null || true
    OUTPUT_FILE=$(cd "$(dirname "$OUTPUT_FILE")" 2>/dev/null && printf '%s/%s' "$PWD" "$(basename "$OUTPUT_FILE")")
}

emit() {
    local line="$1"
    printf '%s\n' "$line"
    [ -n "$OUTPUT_FILE" ] && printf '%s\n' "$line" >>"$OUTPUT_FILE"
}
progress() { [ "$QUIET" -eq 1 ] || printf '[*] %s\n' "$*" >&2; }

clean_path() {
    local p="$1"
    p=${p//$'\n'/ }
    p=${p//$'\r'/ }
    p=${p//$'\t'/ }
    printf '%s' "$p"
}

report_once() {
    local tag="$1" path="$2" detail="${3:-}" key clean
    REPORT_ADDED=0
    clean=$(clean_path "$path")
    key="$tag|$clean|$detail"
    [ -n "${REPORTED[$key]:-}" ] && return
    REPORTED["$key"]=1
    REPORT_ADDED=1
    if [ -n "$detail" ]; then emit "[$tag] $clean  $detail"; else emit "[$tag] $clean"; fi
}

add_home() {
    local p="$1" abs
    [ -n "$p" ] || return
    case "$p" in /*) ;; *) return ;; esac
    case "$p" in /|/bin|/sbin|/usr/bin|/usr/sbin|/dev|/proc|/sys|/nonexistent) return ;; esac
    [ -d "$p" ] || return
    abs=$(cd "$p" 2>/dev/null && pwd -P) || abs="$p"
    [ -n "${SEEN_HOMES[$abs]:-}" ] && return
    SEEN_HOMES["$abs"]=1
    HOMES+=("$abs")
}

discover_homes() {
    local h
    if [ "$ONLY_SPECIFIED" -eq 0 ]; then
        if command -v getent >/dev/null 2>&1; then
            while IFS=: read -r _ _ _ _ _ h _; do add_home "$h"; done < <(getent passwd 2>/dev/null || true)
        elif [ -r /etc/passwd ]; then
            while IFS=: read -r _ _ _ _ _ h _; do add_home "$h"; done </etc/passwd
        fi
        for h in /home/*; do [ -d "$h" ] && add_home "$h"; done
        [ -n "${HOME:-}" ] && add_home "$HOME"
        [ -d /root ] && add_home /root
    fi
    for h in "${SPECIFIED_HOMES[@]}"; do add_home "$h"; done
    N_HOMES_DISCOVERED=${#HOMES[@]}
}

file_size() {
    stat -c '%s' -- "$1" 2>/dev/null || stat -f '%z' -- "$1" 2>/dev/null || printf '%s' -1
}

human_size() {
    awk -v n="$1" 'BEGIN { if(n>=1073741824) printf "%.1f GB",n/1073741824; else if(n>=1048576) printf "%.1f MB",n/1048576; else if(n>=1024) printf "%.1f KB",n/1024; else printf "%d B",n }'
}

classify_type() {
    local name="${1##*/}" ext=""
    [[ "$name" == *.* ]] && ext="${name##*.}"
    ext="${ext,,}"
    case "$ext" in
        doc|docx|docm|dot|dotx|dotm|xls|xlsx|xlsm|xlsb|xlt|xltx|xltm|ppt|pptx|pptm|pot|potx|potm|pps|ppsx|ppsm|vsd|vsdx|pub|mdb|accdb) printf OFFICE ;;
        sql|ddl|dump|psql|pgsql|plsql|tsql|mdf|ndf|ldf|db|sqlite|sqlite3) printf SQL ;;
        zip|7z|rar|tar|tgz|gz|bz2|xz|cab) printf ARCHIVE ;;
        kdbx|kdb|psafe3|opvault|1pif|1pux|pfx|p12|jks|keystore|keytab|ppk) printf INTEREST ;;
        pcap|pcapng) printf INTEREST ;;
        pem|key|priv|pvk) printf INTEREST ;;
        *) printf '' ;;
    esac
}

is_placeholder_line() {
    local v="${1,,}"
    [[ "$v" =~ (example|sample|dummy|changeme|replace[_-]?me|your[_-]?(password|secret)|password[_-]?here|redacted|masked|\*\*\*|integrated[[:space:]_]?security[[:space:]]*=[[:space:]]*(true|sspi)|trusted_connection[[:space:]]*=[[:space:]]*(yes|true)) ]]
}

declare -a RULES=(
    $'password_assign\t(password|passwd|passphrase|pwd|secret)["\']?[[:space:]]*[:=][[:space:]]*["\']?[^[:space:]"\'#<>{}]{3,}'
    $'prefixed_password\t(db|database|mysql|postgres|mssql|sql|sa|oracle|redis|ldap|smtp|smb|ftp|admin|root|svc|service)[_-]?(password|passwd|passphrase|pwd|pass)["\']?[[:space:]]*[:=]'
    $'connection_string\t(server|host|data[ _-]?source)[[:space:]]*=.{1,200}(password|pwd)[[:space:]]*='
    $'jdbc_password\tjdbc:[a-z]+://.*(password|pwd)='
    $'uri_credentials\t[a-z][a-z0-9+.-]*://[^[:space:]/:@]+:[^[:space:]/@]+@'
    $'gpp_cpassword\tcpassword[[:space:]]*=[[:space:]]*"[A-Za-z0-9+/=]{20,}"'
    $'autologon_password\t(DefaultPassword|AltDefaultPassword)["\']?[[:space:]]*[:=]'
    $'command_password\t(sshpass|sqlcmd|mysql|psql|mongosh|smbclient|xfreerdp|rdesktop|plink|curl|wget|7z|zip).*(-p|-P|-pw|--password|/p:)[[:space:]=]*[^[:space:]]{2,}'
    $'net_use_credential\tnet[[:space:]]+use[[:space:]]+\\\\[^[:space:]]+.*(/user:|[[:space:]][^/[:space:]][^[:space:]]{2,})'
    $'powershell_password\t-(Password|Pass|AccountPassword|NewPassword|DefaultPassword)[[:space:]]+["\'][^"\']{3,}["\']'
    $'pgpassword\tPGPASSWORD[[:space:]]*=[[:space:]]*[^[:space:]#]{3,}'
    $'mysql_pwd\tMYSQL_PWD[[:space:]]*=[[:space:]]*[^[:space:]#]{3,}'
    $'netrc_password\t(machine[[:space:]]+[^[:space:]]+[[:space:]]+)?(login|user)[[:space:]]+[^[:space:]]+[[:space:]]+password[[:space:]]+[^[:space:]]{2,}'
    $'ntlm_hash\t[[:alnum:]_.@$-]+:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:'
    $'password_hash\t\$(1|2a|2b|2y|5|6|y|argon2(id|i|d))\$[^[:space:]]{10,}'
    $'kerberos_hash\t\$krb5(tgs|asrep)\$[^[:space:]]{10,}'
    $'wifi_psk\t(psk|pre-shared-key|wpa-passphrase)[[:space:]]*[:=][[:space:]]*[^[:space:]#]{8,}'
)

scan_text_file() {
    local file="$1" bom source line lineno=0 item label regex preview key
    bom=$(od -An -tx1 -N4 "$file" 2>/dev/null | tr -d ' \n')
    source=(cat -- "$file")
    case "$bom" in
        fffe*) command -v iconv >/dev/null 2>&1 && source=(iconv -f UTF-16LE -t UTF-8 -- "$file") ;;
        feff*) command -v iconv >/dev/null 2>&1 && source=(iconv -f UTF-16BE -t UTF-8 -- "$file") ;;
        efbbbf*) source=(tail -c +4 -- "$file") ;;
    esac
    while IFS= read -r line || [ -n "$line" ]; do
        lineno=$((lineno + 1))
        [ "${#line}" -le 16384 ] || continue
        if [[ "$line" =~ -----BEGIN[[:space:]]+(RSA[[:space:]]+|EC[[:space:]]+|DSA[[:space:]]+|OPENSSH[[:space:]]+)?PRIVATE[[:space:]]+KEY-----|PuTTY-User-Key-File- ]]; then
            key="KEY|$file|$lineno"
            if [ -z "${REPORTED[$key]:-}" ]; then
                REPORTED["$key"]=1; preview=${line:0:180}
                emit "[KEY] private_key $file:$lineno  $preview"; N_KEY=$((N_KEY+1)); EXIT_CODE=1
            fi
        fi
        is_placeholder_line "$line" && continue
        for item in "${RULES[@]}"; do
            IFS=$'\t' read -r label regex <<<"$item"
            if [[ "$line" =~ $regex ]]; then
                key="HIGH|$label|$file|$lineno"
                [ -n "${REPORTED[$key]:-}" ] && break
                REPORTED["$key"]=1; preview=${line:0:180}
                emit "[HIGH] $label $file:$lineno  $preview"
                N_HIGH=$((N_HIGH+1)); EXIT_CODE=1
                break
            fi
        done
    done < <("${source[@]}" 2>/dev/null)
}

handle_file() {
    local file="$1" size type base bom
    [ -n "${SEEN_FILES[$file]:-}" ] && return
    SEEN_FILES["$file"]=1
    N_FILES=$((N_FILES+1))
    base=${file##*/}
    if [[ "$base" == .* && "$base" != . && "$base" != .. ]]; then
        report_once HIDDEN "$file"; [ "$REPORT_ADDED" -eq 0 ] || N_HIDDEN=$((N_HIDDEN+1))
    fi
    type=$(classify_type "$file")
    [ -z "$type" ] || report_once "$type" "$file"
    [ -r "$file" ] || { report_once DENIED "$file"; [ "$REPORT_ADDED" -eq 0 ] || N_DENIED=$((N_DENIED+1)); return; }
    size=$(file_size "$file")
    [ "$size" -ge 0 ] 2>/dev/null || { report_once DENIED "$file" "cannot stat"; [ "$REPORT_ADDED" -eq 0 ] || N_DENIED=$((N_DENIED+1)); return; }
    [ "$size" -gt 0 ] || return
    if [ "$size" -gt "$MAX_BYTES" ]; then
        report_once "SKIP:size>${MAX_SIZE_MB}MB" "$file" "$(human_size "$size")"
        [ "$REPORT_ADDED" -eq 0 ] || N_LARGE=$((N_LARGE+1)); return
    fi
    bom=$(od -An -tx1 -N4 "$file" 2>/dev/null | tr -d ' \n')
    case "$bom" in fffe*|feff*) ;; *)
        if od -An -tx1 -N8192 -- "$file" 2>/dev/null | grep -Eq '(^|[[:space:]])00([[:space:]]|$)'; then
            report_once 'SKIP:binary' "$file"; [ "$REPORT_ADDED" -eq 0 ] || N_BINARY=$((N_BINARY+1)); return
        fi
    esac
    N_TEXT=$((N_TEXT+1))
    scan_text_file "$file"
}

scan_home() {
    local home="$1" err item base
    progress "Scanning $home"
    if [ ! -r "$home" ] || [ ! -x "$home" ]; then
        report_once DENIED "$home"; [ "$REPORT_ADDED" -eq 0 ] || N_DENIED=$((N_DENIED+1)); return
    fi
    N_HOMES_SCANNED=$((N_HOMES_SCANNED+1))
    err=$(mktemp "${TMPDIR:-/tmp}/homehunter-find.XXXXXX") || die "Cannot create temporary file"
    while IFS= read -r -d '' item; do
        [ "$item" = "$home" ] && continue
        [ -L "$item" ] && continue
        if [ -d "$item" ]; then
            base=${item##*/}
            if [[ "$base" == .* && "$base" != . && "$base" != .. ]]; then
                report_once HIDDEN "$item"; [ "$REPORT_ADDED" -eq 0 ] || N_HIDDEN=$((N_HIDDEN+1))
            fi
        elif [ -f "$item" ]; then
            [ -n "$OUTPUT_FILE" ] && [ "$item" = "$OUTPUT_FILE" ] && continue
            handle_file "$item"
        fi
    done < <(find "$home" -print0 2>"$err")
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        line=${line#find: }
        report_once DENIED "$line"; [ "$REPORT_ADDED" -eq 0 ] || N_DENIED=$((N_DENIED+1))
    done <"$err"
    rm -f "$err"
}

print_summary() {
    emit ""
    emit "=== HomeHunter Summary ==="
    emit "Homes discovered:       $N_HOMES_DISCOVERED"
    emit "Homes scanned:          $N_HOMES_SCANNED"
    emit "Files enumerated:       $N_FILES"
    emit "Text files scanned:     $N_TEXT"
    emit "Hidden items:           $N_HIDDEN"
    emit "Credential findings:    $N_HIGH"
    emit "Private-key findings:   $N_KEY"
    emit "Large files skipped:    $N_LARGE"
    emit "Binary files skipped:   $N_BINARY"
    emit "Permission denied:      $N_DENIED"
}

main() {
    parse_args "$@"
    setup_output
    discover_homes
    [ "$N_HOMES_DISCOVERED" -gt 0 ] || die "No home directories discovered"
    progress "Discovered $N_HOMES_DISCOVERED home directories; text limit ${MAX_SIZE_MB} MiB"
    local h
    for h in "${HOMES[@]}"; do scan_home "$h"; done
    print_summary
    exit "$EXIT_CODE"
}

main "$@"
