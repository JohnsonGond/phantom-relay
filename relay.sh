#!/bin/sh
# ==============================================================================
# PhantomRelay (幽灵中转) - Stealth nftables L4 Traffic Relay Manager
# Target : Alpine LXC / Debian / Ubuntu (POSIX sh, zero user-space daemon)
# Repo   : https://github.com/JohnsonGond/phantom-relay
# Usage  : relay [menu|apply|force-apply|status|stop|update|cron|version]
# ==============================================================================

PHANTOM_RELAY_SIGNATURE="phantom-relay"
VERSION="2.0.0"
REPO="JohnsonGond/phantom-relay"
RAW_URL="${RELAY_UPDATE_URL:-https://raw.githubusercontent.com/${REPO}/main/relay.sh}"

# 路径与状态文件
NFT_DIR="/etc/nftables.d"
DB_FILE="${NFT_DIR}/relay.db"
MSS_FILE="${NFT_DIR}/relay.mss"
SNAT_FILE="${NFT_DIR}/relay.snat"
POLICY_FILE="${NFT_DIR}/relay.policy"
STEALTH_FILE="${NFT_DIR}/relay.stealth"
DNS_CACHE="${NFT_DIR}/relay.dns.cache"
NFT_CONF="${NFT_DIR}/relay.nft"
COMPAT_NFT="${NFT_DIR}/99-phantom-compat.nft"
MAIN_NFT="/etc/nftables.nft"
SYSCTL_CONF="/etc/sysctl.d/99-phantom-relay.conf"
LOCK_DIR="/var/lock/phantom-relay.lock"
TABLE_NAME="relay_nat"

# 解析脚本自身绝对路径
resolve_script_path() {
    if command -v readlink >/dev/null 2>&1; then
        rp=$(readlink -f "$0" 2>/dev/null)
        [ -n "$rp" ] && { echo "$rp"; return; }
    fi
    case "$0" in
        /*) echo "$0" ;;
        *)  echo "/root/relay.sh" ;;
    esac
}
SCRIPT_PATH=$(resolve_script_path)

# 终端颜色
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
CYAN="\033[36m"
BOLD="\033[1m"
DIM="\033[2m"
RESET="\033[0m"

# ==============================================================================
# Banner 字符画
# ==============================================================================
show_banner() {
    printf "${CYAN}"
    cat << 'BANNER_EOF'
  ____  _                 _                  ____      _
 |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___ |  _ \ ___| | __ _ _   _
 | |_) | '_ \ / _` | '_ \| __/ _ \| '_ ` _ \| |_) / _ \ |/ _` | | | |
 |  __/| | | | (_| | | | | || (_) | | | | | |  _ <  __/ | (_| | |_| |
 |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|_| \_\___|_|\__,_|\__, |
                                                               |___/
BANNER_EOF
    printf "${RESET}"
    printf "  ${BOLD}${GREEN}PhantomRelay (幽灵中转) v%s${RESET}  ${DIM}|  Stealth Kernel-Space nftables Relay${RESET}\n" "$VERSION"
    printf "  ${DIM}Repo: https://github.com/%s${RESET}\n" "$REPO"
}

# ==============================================================================
# 基础工具函数：锁、校验、包管理、DNS
# ==============================================================================

acquire_lock() {
    mkdir -p "$(dirname "$LOCK_DIR")" 2>/dev/null || true
    retry=0
    while ! mkdir "$LOCK_DIR" 2>/dev/null; do
        if [ -f "${LOCK_DIR}/pid" ]; then
            old_pid=$(cat "${LOCK_DIR}/pid" 2>/dev/null)
            if [ -n "$old_pid" ] && ! kill -0 "$old_pid" 2>/dev/null; then
                rm -rf "$LOCK_DIR" 2>/dev/null || true
                continue
            fi
        fi
        retry=$((retry + 1))
        if [ "$retry" -ge 30 ]; then
            printf "${RED}[!] 获取并发锁超时 (%s)，请稍后重试。${RESET}\n" "$LOCK_DIR"
            return 1
        fi
        sleep 1
    done
    echo "$$" > "${LOCK_DIR}/pid"
    return 0
}

release_lock() {
    if [ -f "${LOCK_DIR}/pid" ] && [ "$(cat "${LOCK_DIR}/pid" 2>/dev/null)" = "$$" ]; then
        rm -rf "$LOCK_DIR" 2>/dev/null || true
    fi
}

is_valid_ipv4() {
    printf '%s\n' "$1" | awk -F'.' '
        NF == 4 && $0 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
            for (i = 1; i <= 4; i++) {
                if ($i + 0 < 0 || $i + 0 > 255) exit 1
                if (length($i) > 1 && substr($i, 1, 1) == "0") exit 1
            }
            exit 0
        }
        { exit 1 }
    '
}

# 校验端口或端口段 (例如 443 或 20000-20050)
is_valid_port_spec() {
    printf '%s\n' "$1" | awk '
        /^[0-9]+$/ {
            p = $0 + 0
            exit (p >= 1 && p <= 65535) ? 0 : 1
        }
        /^[0-9]+-[0-9]+$/ {
            split($0, a, "-")
            s = a[1] + 0; e = a[2] + 0
            exit (s >= 1 && e <= 65535 && s < e) ? 0 : 1
        }
        { exit 1 }
    '
}

sanitize_remark() {
    r=$(printf '%s' "${1:-Node}" | sed 's/[^a-zA-Z0-9._-]/_/g' | cut -c1-32)
    [ -z "$r" ] && r="Node"
    printf '%s' "$r"
}

# 检测本地端口及协议是否与已有规则冲突
# 参数: $1=l_port, $2=proto, $3=skip_line_num(0表示不跳过)
check_port_conflict() {
    new_port="$1"
    new_proto="$2"
    skip_nr="${3:-0}"
    [ ! -s "$DB_FILE" ] && return 0

    conflict=$(awk -F'|' -v np="$new_port" -v npr="$new_proto" -v skip="$skip_nr" '
        function parse_range(spec, arr,   parts) {
            if (index(spec, "-") > 0) {
                split(spec, parts, "-")
                arr[1] = parts[1] + 0; arr[2] = parts[2] + 0
            } else {
                arr[1] = spec + 0; arr[2] = spec + 0
            }
        }
        function proto_overlap(p1, p2) {
            if (p1 == "both" || p2 == "both" || p1 == p2) return 1
            return 0
        }
        BEGIN { parse_range(np, nr) }
        NR == skip { next }
        /^[[:space:]]*#/ || NF < 4 { next }
        {
            parse_range($1, er)
            if (proto_overlap(npr, $4) && nr[1] <= er[2] && er[1] <= nr[2]) {
                printf "第 %d 条规则 (端口 %s / 协议 %s / 备注 %s)", NR, $1, $4, $5
                exit 0
            }
        }
    ' "$DB_FILE")

    if [ -n "$conflict" ]; then
        printf "${RED}[!] 端口冲突: 与 %s 重叠！${RESET}\n" "$conflict"
        return 1
    fi
    return 0
}

install_pkg() {
    pkg="$1"
    if command -v apk >/dev/null 2>&1; then
        apk update >/dev/null 2>&1 && apk add --no-cache "$pkg"
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q "$pkg"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q "$pkg"
    else
        return 1
    fi
}

# 读取配置默认值
get_mss_mode()     { cat "$MSS_FILE" 2>/dev/null || echo "1360"; }
get_snat_mode()    { cat "$SNAT_FILE" 2>/dev/null || echo "auto"; }
get_fwd_policy()   { cat "$POLICY_FILE" 2>/dev/null || echo "drop"; }
get_stealth_mode() { cat "$STEALTH_FILE" 2>/dev/null || echo "on"; }

# 探测到达指定目标 IP 的本机出站 IPv4 (支持多网卡/隧道路由)
detect_egress_ip() {
    probe_dst="${1:-1.1.1.1}"
    lip=$(ip -4 route get "$probe_dst" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
    if [ -z "$lip" ]; then
        lip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
    fi
    if [ -z "$lip" ]; then
        lip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')
    fi
    echo "$lip"
}

# Alpine (musl) + glibc 全兼容 IPv4 域名解析
resolve_ip_live() {
    target="$1"
    if is_valid_ipv4 "$target"; then
        echo "$target"
        return 0
    fi

    rip=""
    # 1. glibc getent ahostsv4
    if command -v getent >/dev/null 2>&1; then
        rip=$(getent ahostsv4 "$target" 2>/dev/null | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}')
        # 2. musl-utils getent hosts (过滤 IPv4)
        if [ -z "$rip" ]; then
            rip=$(getent hosts "$target" 2>/dev/null | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}')
        fi
    fi

    # 3. BusyBox / bind-tools nslookup (跳过 Server 行，仅解析 Name 之后的 Address)
    if [ -z "$rip" ] && command -v nslookup >/dev/null 2>&1; then
        rip=$(nslookup -type=A "$target" 2>/dev/null | awk '
            /^Name:/ { found = 1; next }
            found && /^Address/ {
                for (i = 1; i <= NF; i++) {
                    if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; exit }
                }
            }
        ')
        # 兼容部分极简 BusyBox nslookup 不带 -type=A
        if [ -z "$rip" ]; then
            rip=$(nslookup "$target" 2>/dev/null | awk '
                /^Name:/ { found = 1; next }
                found && /^Address/ {
                    for (i = 1; i <= NF; i++) {
                        if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; exit }
                    }
                }
            ')
        fi
    fi

    # 4. dig / drill 兜底
    if [ -z "$rip" ] && command -v dig >/dev/null 2>&1; then
        rip=$(dig +short +time=3 +tries=1 A "$target" 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $0; exit}')
    fi
    if [ -z "$rip" ] && command -v drill >/dev/null 2>&1; then
        rip=$(drill "$target" A 2>/dev/null | awk '/IN[[:space:]]+A[[:space:]]+/ {print $NF; exit}')
    fi

    if [ -n "$rip" ] && is_valid_ipv4 "$rip"; then
        echo "$rip"
        return 0
    fi
    return 1
}

get_cached_ip() {
    [ ! -f "$DNS_CACHE" ] && return 1
    awk -F'|' -v h="$1" '$1 == h {print $2; exit}' "$DNS_CACHE"
}

set_cached_ip() {
    host="$1"
    ip="$2"
    [ ! -f "$DNS_CACHE" ] && touch "$DNS_CACHE"
    awk -F'|' -v h="$host" '$1 != h {print}' "$DNS_CACHE" > "${DNS_CACHE}.tmp.$$" 2>/dev/null || true
    printf '%s|%s\n' "$host" "$ip" >> "${DNS_CACHE}.tmp.$$"
    mv "${DNS_CACHE}.tmp.$$" "$DNS_CACHE"
}

# 解析域名并带缓存回退（防止 DDNS 瞬时抖动导致规则被误删）
resolve_ip_with_cache() {
    host="$1"
    if is_valid_ipv4 "$host"; then
        echo "$host"
        return 0
    fi

    old_ip=$(get_cached_ip "$host" 2>/dev/null || true)
    new_ip=$(resolve_ip_live "$host" 2>/dev/null || true)

    if [ -n "$new_ip" ]; then
        set_cached_ip "$host" "$new_ip"
        # 若 DDNS IP 变更且系统安装了 conntrack，记录旧 IP 以便后续清理粘滞 UDP 会话
        if [ -n "$old_ip" ] && [ "$old_ip" != "$new_ip" ]; then
            echo "$old_ip" >> "/tmp/phantom_changed_ips.$$"
        fi
        echo "$new_ip"
        return 0
    elif [ -n "$old_ip" ]; then
        printf "${YELLOW}[!] 警告: DNS 解析 [%s] 失败，已沿用上次缓存 IP: %s${RESET}\n" "$host" "$old_ip" >&2
        echo "$old_ip"
        return 0
    fi
    return 1
}

flush_conntrack_for_ip() {
    target_ip="$1"
    [ -z "$target_ip" ] && return 0
    if command -v conntrack >/dev/null 2>&1; then
        conntrack -D -r "$target_ip" >/dev/null 2>&1 || true
    fi
}

# ==============================================================================
# 1. 环境初始化（不破坏宿主原有 inet filter input 防火墙）
# ==============================================================================
init_env() {
    mkdir -p "$NFT_DIR"
    [ ! -f "$DB_FILE" ]      && touch "$DB_FILE"
    [ ! -f "$MSS_FILE" ]     && echo "1360" > "$MSS_FILE"
    [ ! -f "$SNAT_FILE" ]    && echo "auto" > "$SNAT_FILE"
    [ ! -f "$POLICY_FILE" ]  && echo "drop" > "$POLICY_FILE"
    [ ! -f "$STEALTH_FILE" ] && echo "on"   > "$STEALTH_FILE"

    if ! command -v nft >/dev/null 2>&1; then
        printf "${YELLOW}[*] 正在安装 nftables...${RESET}\n"
        install_pkg nftables || {
            printf "${RED}[✗] 无法自动安装 nftables，请手动安装后重试。${RESET}\n"
            return 1
        }
    fi

    # 持久化并实时应用内核转发与 conntrack 参数（仅保留 L4 NAT 有效参数）
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1 >/dev/null 2>&1 || true

    if [ -d /etc/sysctl.d ]; then
        cat << 'SYSCTL_EOF' > "$SYSCTL_CONF" 2>/dev/null || true
# Managed by PhantomRelay
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_tcp_be_liberal = 1
SYSCTL_EOF
    fi
    if ! grep -q "^net.ipv4.ip_forward[[:space:]]*=[[:space:]]*1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf 2>/dev/null || true
    fi

    # 启用开机 sysctl 与 nftables 服务
    if command -v rc-update >/dev/null 2>&1; then
        rc-update add sysctl boot >/dev/null 2>&1 || true
        rc-update add nftables default >/dev/null 2>&1 || true
    elif command -v systemctl >/dev/null 2>&1; then
        systemctl enable nftables >/dev/null 2>&1 || true
    fi

    # 保护原有 /etc/nftables.nft：仅追加 include，不暴力删除 inet filter (保护 input 链安全)
    if [ ! -f "$MAIN_NFT" ]; then
        cat << 'MAIN_EOF' > "$MAIN_NFT"
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.nft"
MAIN_EOF
    elif ! grep -q '/etc/nftables.d/\*.nft' "$MAIN_NFT" 2>/dev/null; then
        printf '\ninclude "/etc/nftables.d/*.nft"\n' >> "$MAIN_NFT"
    fi

    # 兼容系统自带的 table inet filter (forward policy drop)：外科手术式仅放行 ct status dnat
    if nft list chain inet filter forward 2>/dev/null | grep -q "policy drop"; then
        if ! nft list chain inet filter forward 2>/dev/null | grep -q "phantom-relay-allow"; then
            nft insert rule inet filter forward ct status dnat accept comment \"phantom-relay-allow\" 2>/dev/null || true
            printf "${YELLOW}[*] 检测到 table inet filter (forward policy drop)，已无损插入 DNAT 放行规则（保留原有 input 防火墙）。${RESET}\n"
        fi
    fi

    # 持久化兼容规则（仅当 /etc/nftables.nft 自身包含 table inet filter 时生成）
    if grep -q "table inet filter" "$MAIN_NFT" 2>/dev/null; then
        cat << 'COMPAT_EOF' > "$COMPAT_NFT"
# Auto-generated by PhantomRelay to coexist with host table inet filter
insert rule inet filter forward ct status dnat accept comment "phantom-relay-allow"
COMPAT_EOF
    else
        rm -f "$COMPAT_NFT" 2>/dev/null || true
    fi

    # 注册全局快捷命令 relay
    if [ "$SCRIPT_PATH" != "/usr/bin/relay" ]; then
        ln -sf "$SCRIPT_PATH" /usr/bin/relay 2>/dev/null || true
    fi
}

# ==============================================================================
# 2. 编译、校验并原子加载 nftables 规则
# ==============================================================================
apply_rules() {
    FORCE_RELOAD="${1:-0}"
    init_env || return 1
    acquire_lock || return 1

    tmp_pre="/tmp/phantom_pre.$$"
    tmp_fwd="/tmp/phantom_fwd.$$"
    tmp_post="/tmp/phantom_post.$$"
    tmp_ips="/tmp/phantom_seen_ips.$$"
    tmp_changed="/tmp/phantom_changed_ips.$$"
    tmp_nft="${NFT_CONF}.tmp.$$"

    rm -f "$tmp_pre" "$tmp_fwd" "$tmp_post" "$tmp_ips" "$tmp_changed" "$tmp_nft"
    touch "$tmp_pre" "$tmp_fwd" "$tmp_post" "$tmp_ips"

    SNAT_MODE=$(get_snat_mode)
    MSS_MODE=$(get_mss_mode)
    FWD_POLICY=$(get_fwd_policy)
    STEALTH_MODE=$(get_stealth_mode)

    # 校验 SNAT 模式
    if [ "$SNAT_MODE" != "auto" ] && [ "$SNAT_MODE" != "masquerade" ]; then
        if ! is_valid_ipv4 "$SNAT_MODE"; then
            printf "${RED}[!] 无效的静态 SNAT IP: %s，请进入菜单 8 重新配置。${RESET}\n" "$SNAT_MODE"
            rm -f "$tmp_pre" "$tmp_fwd" "$tmp_post" "$tmp_ips" "$tmp_changed" "$tmp_nft"
            release_lock
            return 1
        fi
    fi

    rule_idx=0
    mark_seq=1
    skipped=0

    while IFS='|' read -r l_port r_host r_port proto remark; do
        [ -z "$l_port" ] && continue
        case "$l_port" in \#*) continue ;; esac

        if ! is_valid_port_spec "$l_port"; then
            printf "${YELLOW}[!] 跳过非法本地端口 [%s] (%s)${RESET}\n" "$l_port" "$remark"
            skipped=$((skipped + 1))
            continue
        fi

        if [ "$r_port" != "same" ] && ! is_valid_port_spec "$r_port"; then
            printf "${YELLOW}[!] 跳过非法目标端口 [%s] (%s)${RESET}\n" "$r_port" "$remark"
            skipped=$((skipped + 1))
            continue
        fi

        r_ip=$(resolve_ip_with_cache "$r_host")
        if [ -z "$r_ip" ]; then
            printf "${YELLOW}[!] 警告: 无法解析 [%s] 且无缓存记录 (%s)，已跳过。${RESET}\n" "$r_host" "$remark"
            skipped=$((skipped + 1))
            continue
        fi

        rule_idx=$((rule_idx + 1))
        safe_remark=$(sanitize_remark "$remark")

        if [ "$r_port" = "same" ] || [ "$r_port" = "$l_port" ]; then
            if printf '%s' "$l_port" | grep -q "-"; then
                dnat_target="$r_ip"
                disp_target="${r_ip}:${l_port}"
            else
                dnat_target="${r_ip}:${l_port}"
                disp_target="${r_ip}:${l_port}"
            fi
        else
            dnat_target="${r_ip}:${r_port}"
            disp_target="${r_ip}:${r_port}"
        fi

        # 写入 prerouting (带 __FIB__ 占位符) + forward 真实双向流量统计规则
        add_proto_pair() {
            p_lower="$1"
            p_upper="$2"
            mark_hex=$(printf '0x%x' $((65536 + mark_seq)))
            rid="r${mark_seq}"
            mark_seq=$((mark_seq + 1))

            printf '        __FIB__%s dport %s ct mark set %s dnat to %s comment "%s-%s"\n' \
                "$p_lower" "$l_port" "$mark_hex" "$dnat_target" "$safe_remark" "$p_upper" >> "$tmp_pre"

            # forward 链真实双向计数 (filter hook 统计所有数据包而非仅首包)
            printf '        ct status dnat ct mark %s ct direction original counter accept comment "%s|%s|%s|%s|%s|UP"\n' \
                "$mark_hex" "$rid" "$p_upper" "$l_port" "$disp_target" "$safe_remark" >> "$tmp_fwd"
            printf '        ct status dnat ct mark %s ct direction reply counter accept comment "%s|%s|%s|%s|%s|DOWN"\n' \
                "$mark_hex" "$rid" "$p_upper" "$l_port" "$disp_target" "$safe_remark" >> "$tmp_fwd"
        }

        case "$proto" in
            tcp|TCP)
                add_proto_pair "tcp" "TCP"
                ;;
            udp|UDP)
                add_proto_pair "udp" "UDP"
                ;;
            both|BOTH|*)
                add_proto_pair "tcp" "TCP"
                add_proto_pair "udp" "UDP"
                ;;
        esac

        # 为 auto 模式按目标 IP 去重探测最佳出站源 IP
        if [ "$SNAT_MODE" = "auto" ]; then
            if ! grep -qx "$r_ip" "$tmp_ips" 2>/dev/null; then
                echo "$r_ip" >> "$tmp_ips"
                egress_ip=$(detect_egress_ip "$r_ip")
                if [ -n "$egress_ip" ] && is_valid_ipv4 "$egress_ip"; then
                    printf '        ct status dnat ip daddr %s counter snat to %s comment "SNAT-Auto-%s"\n' \
                        "$r_ip" "$egress_ip" "$r_ip" >> "$tmp_post"
                fi
            fi
        fi
    done < "$DB_FILE"

    # 生成 postrouting 终极兜底规则（确保 100% DNAT 流量均做 SNAT，杜绝客户端 IP 直达落地机）
    case "$SNAT_MODE" in
        auto)
            printf '        ct status dnat counter masquerade comment "SNAT-Failsafe"\n' >> "$tmp_post"
            ;;
        masquerade)
            printf '        ct status dnat counter masquerade comment "SNAT-Masquerade"\n' >> "$tmp_post"
            ;;
        *)
            printf '        ct status dnat counter snat to %s comment "SNAT-Static-%s"\n' "$SNAT_MODE" "$SNAT_MODE" >> "$tmp_post"
            ;;
    esac

    PRE_RAW=$(cat "$tmp_pre")
    FWD_ACCT=$(cat "$tmp_fwd")
    POST_CONTENT=$(cat "$tmp_post")

    # 渲染完整 nftables 配置文件（支持特性逐级降级兼容旧内核）
    render_nft() {
        opt_fib="$1"
        opt_ttl="$2"
        opt_mss_range="$3"
        out_path="$4"

        if [ "$opt_fib" = "1" ]; then
            pre_body=$(printf '%s\n' "$PRE_RAW" | sed 's/__FIB__/fib daddr type local /g')
        else
            pre_body=$(printf '%s\n' "$PRE_RAW" | sed 's/__FIB__//g')
        fi

        stealth_block=""
        if [ "$STEALTH_MODE" = "on" ]; then
            stealth_block="        # Anti-Traceroute & ICMP Leak Protection
        ct status dnat ct direction reply icmp type { time-exceeded, redirect } counter drop comment \"Anti-Traceroute-ICMP\""
            if [ "$opt_ttl" = "1" ]; then
                stealth_block="${stealth_block}
        ct status dnat ct direction original ip ttl < 64 ip ttl set 64 comment \"Anti-Traceroute-TTL\""
            fi
        fi

        mss_block=""
        if printf '%s' "$MSS_MODE" | grep -Eq '^[0-9]+$'; then
            if [ "$opt_mss_range" = "1" ]; then
                next_mss=$((MSS_MODE + 1))
                mss_block="        # Bidirectional TCP MSS Clamping (with min-MSS protection)
        ct status dnat tcp flags & (syn | rst) == syn tcp option maxseg size ${next_mss}-65535 counter tcp option maxseg size set ${MSS_MODE} comment \"MSS-Clamp-${MSS_MODE}\""
            else
                mss_block="        # Bidirectional TCP MSS Clamping (legacy kernel fallback)
        ct status dnat tcp flags & (syn | rst) == syn counter tcp option maxseg size set ${MSS_MODE} comment \"MSS-Clamp-${MSS_MODE}-Legacy\""
            fi
        fi

        cat << NFT_EOF > "$out_path"
# Generated by PhantomRelay v${VERSION}
table ip ${TABLE_NAME}
flush table ip ${TABLE_NAME}

table ip ${TABLE_NAME} {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
${pre_body}
    }

    chain forward {
        type filter hook forward priority filter; policy ${FWD_POLICY};
        ct state invalid counter drop comment "Drop-Invalid"
${stealth_block}
${mss_block}
        # Per-Rule Real Bidirectional Traffic Accounting
${FWD_ACCT}
        ct status dnat ct state established,related accept comment "DNAT-Est-Rel"
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
${POST_CONTENT}
    }
}
NFT_EOF
    }

    # 预检与智能降级（绝不破坏磁盘上原有的合法 $NFT_CONF）
    use_fib=1
    use_ttl=1
    use_mss_range=1
    render_nft "$use_fib" "$use_ttl" "$use_mss_range" "$tmp_nft"

    if ! nft -c -f "$tmp_nft" >/dev/null 2>&1; then
        # 逐项检测哪项高级特性不被当前宿主机内核支持
        if printf '%s' "$MSS_MODE" | grep -Eq '^[0-9]+$'; then
            render_nft "$use_fib" "$use_ttl" 0 "$tmp_nft"
            if nft -c -f "$tmp_nft" >/dev/null 2>&1; then
                use_mss_range=0
                printf "${YELLOW}[!] 提示: 宿主机内核不支持 maxseg 范围匹配，已自动回退为标准双向钳制（注意: 若客户端 MSS 小于 %s 也会被设为 %s）。${RESET}\n" "$MSS_MODE" "$MSS_MODE"
            fi
        fi
    fi

    if ! nft -c -f "$tmp_nft" >/dev/null 2>&1 && [ "$STEALTH_MODE" = "on" ]; then
        render_nft "$use_fib" 0 "$use_mss_range" "$tmp_nft"
        if nft -c -f "$tmp_nft" >/dev/null 2>&1; then
            use_ttl=0
            printf "${YELLOW}[!] 提示: 宿主机内核不支持 ip ttl set，已保留 ICMP Time-Exceeded 隐身拦截。${RESET}\n"
        fi
    fi

    if ! nft -c -f "$tmp_nft" >/dev/null 2>&1; then
        render_nft 0 "$use_ttl" "$use_mss_range" "$tmp_nft"
        if nft -c -f "$tmp_nft" >/dev/null 2>&1; then
            use_fib=0
            printf "${YELLOW}[!] 提示: 宿主机内核不支持 fib daddr type local，已自动兼容降级。${RESET}\n"
        fi
    fi

    if ! nft -c -f "$tmp_nft" >/dev/null 2>&1; then
        render_nft 0 0 0 "$tmp_nft"
    fi

    # 最终语法与内核校验
    err_out=$(nft -c -f "$tmp_nft" 2>&1)
    if [ $? -ne 0 ]; then
        printf "${RED}[✗] 规则预检失败，已保留原运行状态与原配置文件！错误详情:${RESET}\n%s\n" "$err_out"
        rm -f "$tmp_pre" "$tmp_fwd" "$tmp_post" "$tmp_ips" "$tmp_changed" "$tmp_nft"
        release_lock
        return 1
    fi

    # 变更对比：crontab 定时执行时若规则和 IP 无变化且表已在运行，跳过重载以保留流量计数器！
    if [ "$FORCE_RELOAD" != "1" ] && [ -f "$NFT_CONF" ] && cmp -s "$tmp_nft" "$NFT_CONF" \
       && nft list table ip "$TABLE_NAME" >/dev/null 2>&1; then
        printf "${CYAN}[=] 规则与 DDNS 解析均无变化，跳过重载（保留现有流量计数）。${RESET}\n"
        rm -f "$tmp_pre" "$tmp_fwd" "$tmp_post" "$tmp_ips" "$tmp_changed" "$tmp_nft"
        release_lock
        return 0
    fi

    # 原子替换配置并加载入内核
    mv "$tmp_nft" "$NFT_CONF"
    if nft -f "$NFT_CONF"; then
        # 若 DDNS 发生了 IP 变动，主动清理旧 IP 的粘滞 conntrack (解决 UDP/WG/Hy2 切换卡死)
        if [ -s "$tmp_changed" ]; then
            while read -r old_ip; do
                [ -n "$old_ip" ] && flush_conntrack_for_ip "$old_ip"
            done < "$tmp_changed"
            if command -v conntrack >/dev/null 2>&1; then
                printf "${GREEN}[✓] 检测到 DDNS IP 变动，已清理旧目标的 conntrack 粘滞会话。${RESET}\n"
            else
                printf "${YELLOW}[!] 检测到 DDNS IP 变动；建议安装 conntrack-tools 以便自动踢出旧 UDP 粘滞连接。${RESET}\n"
            fi
        fi

        printf "${GREEN}[✓] 规则已生效！(规则数: %d | SNAT: %s | MSS: %s | 隐身: %s | Forward: %s)${RESET}\n" \
            "$rule_idx" "$SNAT_MODE" "$MSS_MODE" "$STEALTH_MODE" "$FWD_POLICY"
    else
        printf "${RED}[✗] nftables 规则加载失败，请检查内核模块。${RESET}\n"
        rm -f "$tmp_pre" "$tmp_fwd" "$tmp_post" "$tmp_ips" "$tmp_changed"
        release_lock
        return 1
    fi

    rm -f "$tmp_pre" "$tmp_fwd" "$tmp_post" "$tmp_ips" "$tmp_changed"
    release_lock
    return 0
}

# ==============================================================================
# 3. 展示配置列表与真实双向流量面板
# ==============================================================================
list_rules() {
    MSS_MODE=$(get_mss_mode)
    SNAT_MODE=$(get_snat_mode)
    FWD_POLICY=$(get_fwd_policy)
    STEALTH_MODE=$(get_stealth_mode)
    DEF_IP=$(detect_egress_ip 1.1.1.1)

    printf "\n${CYAN}======================== 已配置的转发规则 ========================${RESET}\n"
    active_count=$(awk -F'|' '!/^[[:space:]]*#/ && NF>=4 {c++} END{print c+0}' "$DB_FILE" 2>/dev/null)
    if [ "$active_count" -eq 0 ]; then
        printf "${YELLOW}  (暂无转发规则，请按 1 添加)${RESET}\n"
    else
        printf "%-5s %-14s %-22s %-10s %-6s %-s\n" "序号" "本地端口" "落地机地址" "目标端口" "协议" "备注"
        printf -- "------------------------------------------------------------------------\n"
        awk -F'|' '!/^[[:space:]]*#/ && NF>=4 {printf "[%-2d]  %-14s %-22s %-10s %-6s %-s\n", NR, $1, $2, $3, $4, $5}' "$DB_FILE"
    fi

    printf "\n${CYAN}====================== 隐身、MSS 与 SNAT 状态 ====================${RESET}\n"
    if [ "$SNAT_MODE" = "auto" ]; then
        printf "  SNAT 出站模式       : ${GREEN}auto (按目标路由智能静态 SNAT + Masquerade 兜底)${RESET}\n"
        printf "  默认主出站 IPv4     : ${GREEN}%s${RESET}\n" "${DEF_IP:-未探测到}"
    elif [ "$SNAT_MODE" = "masquerade" ]; then
        printf "  SNAT 出站模式       : ${GREEN}masquerade (动态源地址伪装)${RESET}\n"
    else
        printf "  SNAT 出站模式       : ${GREEN}静态指定 (%s)${RESET}\n" "$SNAT_MODE"
    fi
    if [ "$FWD_POLICY" = "drop" ]; then
        fwd_desc="(严密模式: 仅放行 DNAT 流量)"
    else
        fwd_desc="(兼容模式: 允许其他容器/VPN转发)"
    fi
    printf "  Forward 链安全策略  : ${GREEN}%s${RESET} %s\n" "$FWD_POLICY" "$fwd_desc"

    if nft list chain ip "$TABLE_NAME" forward >/dev/null 2>&1; then
        fwd_dump=$(nft list chain ip "$TABLE_NAME" forward 2>/dev/null)

        mss_stat=$(printf '%s\n' "$fwd_dump" | awk '
            /maxseg size set/ {
                for(i=1;i<=NF;i++) {
                    if($i=="packets") pkts=$(i+1)
                    if($i=="bytes") bytes=$(i+1)
                }
                printf "已双向钳制 SYN/SYN-ACK: %s 包 (%s B)", pkts, bytes
            }')
        if [ -n "$mss_stat" ]; then
            printf "  双向 TCP MSS 钳制   : ${GREEN}%s${RESET} | %s\n" "$MSS_MODE" "$mss_stat"
        else
            printf "  双向 TCP MSS 钳制   : ${YELLOW}已关闭${RESET}\n"
        fi

        icmp_drop=$(printf '%s\n' "$fwd_dump" | awk '
            /Anti-Traceroute-ICMP/ {
                for(i=1;i<=NF;i++) if($i=="packets") { print $(i+1); exit }
            }')
        if [ "$STEALTH_MODE" = "on" ]; then
            printf "  防路由追踪隐身模式  : ${GREEN}已开启${RESET} | 已拦截回程探针 ICMP: ${YELLOW}%s${RESET} 包\n" "${icmp_drop:-0}"
        else
            printf "  防路由追踪隐身模式  : ${YELLOW}已关闭${RESET}\n"
        fi
    else
        printf "  ${YELLOW}(Forward 链未运行)${RESET}\n"
    fi

    printf "\n${CYAN}================== 真实双向实时流量统计 (Filter 链) ==================${RESET}\n"
    if nft list chain ip "$TABLE_NAME" forward >/dev/null 2>&1; then
        nft list chain ip "$TABLE_NAME" forward 2>/dev/null | awk '
        function human(x) {
            if (x < 1024) return sprintf("%d B", x)
            x /= 1024; if (x < 1024) return sprintf("%.2f KB", x)
            x /= 1024; if (x < 1024) return sprintf("%.2f MB", x)
            x /= 1024; if (x < 1024) return sprintf("%.2f GB", x)
            x /= 1024; return sprintf("%.2f TB", x)
        }
        BEGIN {
            printf "%-5s %-12s %-21s %-11s %-11s %-11s %-s\n", "协议", "本地端口", "转发目标(DNAT)", "上行(↑)", "下行(↓)", "总计流量", "备注"
            printf "------------------------------------------------------------------------------------\n"
            cnt = 0; sum_up = 0; sum_dn = 0
        }
        /counter packets/ && /comment "r[0-9]+\|/ {
            bytes = 0; cmt = ""
            for (i = 1; i <= NF; i++) {
                if ($i == "bytes") bytes = $(i+1) + 0
                if ($i == "comment") {
                    cmt = $(i+1)
                    gsub(/"/, "", cmt)
                }
            }
            n = split(cmt, f, "|")
            if (n == 6) {
                rid = f[1]
                if (!(rid in seen)) {
                    seen[rid] = 1
                    order[++cnt] = rid
                    m_proto[rid]  = f[2]
                    m_lport[rid]  = f[3]
                    m_target[rid] = f[4]
                    m_remark[rid] = f[5]
                }
                if (f[6] == "UP")   { up_b[rid] += bytes; sum_up += bytes }
                if (f[6] == "DOWN") { dn_b[rid] += bytes; sum_dn += bytes }
            }
        }
        END {
            if (cnt == 0) {
                print "  (当前无活动转发规则)"
            } else {
                for (k = 1; k <= cnt; k++) {
                    id = order[k]
                    ub = up_b[id] + 0
                    db = dn_b[id] + 0
                    printf "%-5s %-12s %-21s %-11s %-11s %-11s %-s\n", \
                        m_proto[id], m_lport[id], m_target[id], human(ub), human(db), human(ub + db), m_remark[id]
                }
                printf "------------------------------------------------------------------------------------\n"
                printf "%-40s %-11s %-11s %-11s\n", "合计总流量:", human(sum_up), human(sum_dn), human(sum_up + sum_dn)
            }
        }'
    else
        printf "${YELLOW}  (转发服务当前未运行)${RESET}\n"
    fi
    printf "====================================================================================\n"
}

# ==============================================================================
# 4. 交互式规则增删改
# ==============================================================================
add_rule() {
    printf "\n${CYAN}--- 新增转发规则 ---${RESET}\n"
    printf "1. 请输入本地监听端口或端口段 (如 10001 或 20000-20050): "
    read -r l_port
    if ! is_valid_port_spec "$l_port"; then
        printf "${RED}[!] 本地端口格式无效 (单端口 1-65535 或范围 起始-结束，如 20000-20050)${RESET}\n"
        return
    fi

    printf "2. 请输入落地机 IPv4 或 DDNS 域名: "
    read -r r_host
    r_host=$(printf '%s' "$r_host" | tr -d ' \t\r\n')
    [ -z "$r_host" ] && { printf "${RED}[!] 落地机地址不能为空${RESET}\n"; return; }

    printf "3. 请输入落地机目标端口 [直接回车默认与本地端口相同 (same)]: "
    read -r r_port
    [ -z "$r_port" ] && r_port="same"
    if [ "$r_port" != "same" ] && ! is_valid_port_spec "$r_port"; then
        printf "${RED}[!] 目标端口格式无效${RESET}\n"
        return
    fi

    printf "4. 请选择转发协议 [1: TCP+UDP(默认) | 2: 仅TCP | 3: 仅UDP]: "
    read -r proto_num
    case "$proto_num" in
        2) proto="tcp" ;;
        3) proto="udp" ;;
        *) proto="both" ;;
    esac

    check_port_conflict "$l_port" "$proto" 0 || return

    printf "5. 请输入节点备注 (仅限字母/数字/.-_，默认 Node): "
    read -r remark
    remark=$(sanitize_remark "$remark")

    printf '%s|%s|%s|%s|%s\n' "$l_port" "$r_host" "$r_port" "$proto" "$remark" >> "$DB_FILE"
    printf "${GREEN}[+] 规则已添加，正在应用...${RESET}\n"
    apply_rules 1
}

edit_rule() {
    list_rules
    [ ! -s "$DB_FILE" ] && return
    total=$(wc -l < "$DB_FILE")
    printf "请输入要修改的规则序号 (直接回车取消): "
    read -r idx
    [ -z "$idx" ] && return
    if ! printf '%s' "$idx" | grep -Eq '^[0-9]+$' || [ "$idx" -lt 1 ] || [ "$idx" -gt "$total" ]; then
        printf "${RED}[!] 无效的序号${RESET}\n"
        return
    fi

    old_line=$(sed -n "${idx}p" "$DB_FILE")
    case "$old_line" in
        ""|\#*) printf "${RED}[!] 该行是注释或空行，请选择有效规则序号${RESET}\n"; return ;;
    esac

    old_lport=$(printf '%s' "$old_line" | cut -d'|' -f1)
    old_rhost=$(printf '%s' "$old_line" | cut -d'|' -f2)
    old_rport=$(printf '%s' "$old_line" | cut -d'|' -f3)
    old_proto=$(printf '%s' "$old_line" | cut -d'|' -f4)
    old_remark=$(printf '%s' "$old_line" | cut -d'|' -f5)

    printf "\n${YELLOW}提示: 直接按回车键表示保持原值不变${RESET}\n"
    printf "本地端口 [当前: %s]: " "$old_lport"
    read -r l_port
    l_port="${l_port:-$old_lport}"
    if ! is_valid_port_spec "$l_port"; then
        printf "${RED}[!] 本地端口格式无效${RESET}\n"
        return
    fi

    printf "落地机地址 [当前: %s]: " "$old_rhost"
    read -r r_host
    r_host="${r_host:-$old_rhost}"

    printf "目标端口 [当前: %s]: " "$old_rport"
    read -r r_port
    r_port="${r_port:-$old_rport}"
    if [ "$r_port" != "same" ] && ! is_valid_port_spec "$r_port"; then
        printf "${RED}[!] 目标端口格式无效${RESET}\n"
        return
    fi

    printf "转发协议 (both/tcp/udp) [当前: %s]: " "$old_proto"
    read -r proto
    proto=$(printf '%s' "${proto:-$old_proto}" | tr '[:upper:]' '[:lower:]')
    case "$proto" in
        both|tcp|udp) ;;
        *) printf "${RED}[!] 协议只能为 both / tcp / udp${RESET}\n"; return ;;
    esac

    check_port_conflict "$l_port" "$proto" "$idx" || return

    printf "节点备注 [当前: %s]: " "$old_remark"
    read -r remark
    remark=$(sanitize_remark "${remark:-$old_remark}")

    awk -v n="$idx" -v new="${l_port}|${r_host}|${r_port}|${proto}|${remark}" \
        'NR == n {print new; next} {print}' "$DB_FILE" > "${DB_FILE}.tmp.$$" && mv "${DB_FILE}.tmp.$$" "$DB_FILE"

    # 若旧落地机地址发生变化，清理旧 IP 的 conntrack
    if [ "$old_rhost" != "$r_host" ]; then
        old_ip=$(resolve_ip_with_cache "$old_rhost" 2>/dev/null || true)
        [ -n "$old_ip" ] && flush_conntrack_for_ip "$old_ip"
    fi

    printf "${GREEN}[✓] 第 %s 条规则已更新，正在重载...${RESET}\n" "$idx"
    apply_rules 1
}

del_rule() {
    list_rules
    [ ! -s "$DB_FILE" ] && return
    total=$(wc -l < "$DB_FILE")
    printf "请输入要删除的规则序号 (直接回车取消): "
    read -r idx
    [ -z "$idx" ] && return
    if ! printf '%s' "$idx" | grep -Eq '^[0-9]+$' || [ "$idx" -lt 1 ] || [ "$idx" -gt "$total" ]; then
        printf "${RED}[!] 无效的序号${RESET}\n"
        return
    fi

    old_line=$(sed -n "${idx}p" "$DB_FILE")
    old_rhost=$(printf '%s' "$old_line" | cut -d'|' -f2)

    awk -v n="$idx" 'NR != n {print}' "$DB_FILE" > "${DB_FILE}.tmp.$$" && mv "${DB_FILE}.tmp.$$" "$DB_FILE"

    old_ip=$(get_cached_ip "$old_rhost" 2>/dev/null || true)
    [ -z "$old_ip" ] && is_valid_ipv4 "$old_rhost" && old_ip="$old_rhost"
    [ -n "$old_ip" ] && flush_conntrack_for_ip "$old_ip"

    printf "${GREEN}[-] 第 %s 条规则已删除，正在重载...${RESET}\n" "$idx"
    apply_rules 1
}

# ==============================================================================
# 5. 高级配置：MSS、SNAT、隐身与安全策略、Crontab、停止
# ==============================================================================
config_mss() {
    cur_mss=$(get_mss_mode)
    printf "\n${CYAN}--- 配置双向 TCP MSS 钳制 (syn | rst == syn) ---${RESET}\n"
    printf "当前设置: ${GREEN}%s${RESET}\n" "$cur_mss"
    printf "${DIM}提示: TCP MSS 钳制可解决非对称 MTU 与 TLS ML-KEM768 握手卡死；对 UDP 协议无效。${RESET}\n"
    printf "  1. 固定为 1360 字节 [推荐: 兼顾 PPPoE / 隧道 / 1450 MTU 环境]\n"
    printf "  2. 自定义固定字节数 (范围: 536 - 1460，常用 1280-1410)\n"
    printf "  3. 关闭 MSS 钳制\n"
    printf "请选择 [1-3，直接回车保持不变]: "
    read -r m_choice
    case "$m_choice" in
        1) echo "1360" > "$MSS_FILE" ;;
        2)
            printf "请输入自定义 MSS 值 (如 1380): "
            read -r custom_mss
            if printf '%s' "$custom_mss" | grep -Eq '^[0-9]+$' && [ "$custom_mss" -ge 536 ] && [ "$custom_mss" -le 1460 ]; then
                echo "$custom_mss" > "$MSS_FILE"
            else
                printf "${RED}[!] 输入无效，需在 536-1460 之间${RESET}\n"
                return
            fi
            ;;
        3) echo "off" > "$MSS_FILE" ;;
        *) return ;;
    esac
    apply_rules 1
}

config_snat() {
    cur_snat=$(get_snat_mode)
    def_ip=$(detect_egress_ip 1.1.1.1)
    printf "\n${CYAN}--- 配置 Postrouting SNAT 模式 (全程绑定 ct status dnat 防泄漏) ---${RESET}\n"
    printf "当前模式: ${GREEN}%s${RESET} (探测主出站 IP: %s)\n" "$cur_snat" "${def_ip:-未知}"
    printf "  1. auto       - 按每条落地机路由智能探测静态 SNAT + Masquerade 兜底 [推荐]\n"
    printf "  2. masquerade - 动态源地址伪装 (适合 DHCP / PPPoE 动态公网 IP)\n"
    printf "  3. 手动指定静态 SNAT IPv4 (适合多公网 IP VPS 指定出口)\n"
    printf "请选择 [1-3，直接回车保持不变]: "
    read -r s_choice
    case "$s_choice" in
        1) echo "auto" > "$SNAT_FILE" ;;
        2) echo "masquerade" > "$SNAT_FILE" ;;
        3)
            printf "请输入本机用于出站 SNAT 的 IPv4 地址: "
            read -r manual_ip
            if is_valid_ipv4 "$manual_ip"; then
                echo "$manual_ip" > "$SNAT_FILE"
            else
                printf "${RED}[!] IPv4 地址格式无效${RESET}\n"
                return
            fi
            ;;
        *) return ;;
    esac
    apply_rules 1
}

config_security() {
    cur_stealth=$(get_stealth_mode)
    cur_policy=$(get_fwd_policy)
    printf "\n${CYAN}--- 安全与防落地机 IP 暴露策略 ---${RESET}\n"
    printf "当前防路由追踪隐身 (反 tcptraceroute / ICMP 拦截): ${GREEN}%s${RESET}\n" "$cur_stealth"
    printf "当前 Forward 链默认策略                              : ${GREEN}%s${RESET}\n" "$cur_policy"
    printf "  1. 开启隐身模式 (TTL 归一化 + 丢弃回程 Time-Exceeded/Redirect) [强烈推荐]\n"
    printf "  2. 关闭隐身模式\n"
    printf "  3. Forward 策略设为 drop   [推荐: 仅放行本脚本 DNAT 流量，杜绝开放路由]\n"
    printf "  4. Forward 策略设为 accept [仅当本机同跑 Docker/WireGuard/Tailscale 时使用]\n"
    printf "请选择 [1-4，直接回车保持不变]: "
    read -r sec_choice
    case "$sec_choice" in
        1) echo "on"     > "$STEALTH_FILE" ;;
        2) echo "off"    > "$STEALTH_FILE" ;;
        3) echo "drop"   > "$POLICY_FILE" ;;
        4) echo "accept" > "$POLICY_FILE" ;;
        *) return ;;
    esac
    apply_rules 1
}

setup_cron() {
    printf "\n${CYAN}--- 配置 DDNS 定时自动刷新 (Crontab) ---${RESET}\n"
    printf "${DIM}说明: 定时任务仅在 DDNS 解析 IP 发生变化时才会重载 nftables，不会清零流量统计。${RESET}\n"
    cur_cron=$(crontab -l 2>/dev/null | grep "phantom-relay" || true)
    if [ -n "$cur_cron" ]; then
        printf "当前任务: ${GREEN}%s${RESET}\n" "$cur_cron"
    else
        printf "当前任务: ${YELLOW}未启用${RESET}\n"
    fi
    printf "  1. 启用定时刷新 (每 5 分钟检查一次 DDNS)\n"
    printf "  2. 启用定时刷新 (每 1 分钟检查一次 DDNS)\n"
    printf "  3. 移除定时刷新任务\n"
    printf "请选择 [1-3，直接回车取消]: "
    read -r c_choice
    case "$c_choice" in
        1) cron_expr="*/5 * * * * /usr/bin/relay apply >/dev/null 2>&1 # phantom-relay" ;;
        2) cron_expr="* * * * * /usr/bin/relay apply >/dev/null 2>&1 # phantom-relay" ;;
        3)
            (crontab -l 2>/dev/null | grep -v "phantom-relay") | crontab - 2>/dev/null || true
            printf "${GREEN}[✓] 已移除 DDNS 定时任务。${RESET}\n"
            return
            ;;
        *) return ;;
    esac

    (crontab -l 2>/dev/null | grep -v "phantom-relay"; echo "$cron_expr") | crontab - 2>/dev/null || {
        printf "${RED}[!] 写入 crontab 失败，请检查 crond 服务是否安装。${RESET}\n"
        return 1
    }
    if command -v rc-update >/dev/null 2>&1; then
        rc-update add crond default >/dev/null 2>&1 || true
        rc-service crond start >/dev/null 2>&1 || true
    fi
    printf "${GREEN}[✓] 已设置定时任务: %s${RESET}\n" "$cron_expr"
}

stop_rules() {
    if nft list table ip "$TABLE_NAME" >/dev/null 2>&1; then
        nft flush table ip "$TABLE_NAME"
        nft delete table ip "$TABLE_NAME"
    fi
    rm -f "$NFT_CONF"

    # 若安装了 conntrack，仅主动清理本脚本目标落地机对应的转发会话（绝不影响 SSH 等其他连接）
    if command -v conntrack >/dev/null 2>&1; then
        while IFS='|' read -r _ r_host _ _ _; do
            [ -z "$r_host" ] && continue
            case "$r_host" in \#*) continue ;; esac
            old_ip=$(get_cached_ip "$r_host" 2>/dev/null || true)
            [ -z "$old_ip" ] && is_valid_ipv4 "$r_host" && old_ip="$r_host"
            [ -n "$old_ip" ] && flush_conntrack_for_ip "$old_ip"
        done < "$DB_FILE"
        printf "${GREEN}[✓] 已停止所有转发规则并清理相关转发会话（规则库已保留，随时可按 5 恢复）。${RESET}\n"
    else
        printf "${GREEN}[✓] 已停止新连接转发（规则库已保留）。${RESET}\n"
        printf "${YELLOW}[!] 提示: 未安装 conntrack-tools，已建立的长连接可能会持续到自然断开。${RESET}\n"
    fi
}

# ==============================================================================
# 6. 脚本在线自更新升级 (支持代理加速 / 语法与签名完整性校验)
# ==============================================================================
download_file() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 10 --max-time 30 "$url" -o "$dest"
        return $?
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 20 -O "$dest" "$url"
        return $?
    else
        printf "${YELLOW}[*] 未找到 curl/wget，正在尝试安装 curl...${RESET}\n"
        install_pkg curl && install_pkg ca-certificates >/dev/null 2>&1 || true
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL --connect-timeout 10 --max-time 30 "$url" -o "$dest"
            return $?
        fi
        return 1
    fi
}

self_update() {
    check_only=0
    force_upd=0
    proxy_prefix="${GH_PROXY:-}"

    while [ $# -gt 0 ]; do
        case "$1" in
            --check) check_only=1 ;;
            --force) force_upd=1 ;;
            --proxy)
                shift
                proxy_prefix="$1"
                ;;
        esac
        shift
    done

    # 处理可选 GitHub 加速前缀（确保末尾带 /）
    target_url="$RAW_URL"
    if [ -n "$proxy_prefix" ]; then
        case "$proxy_prefix" in
            */) target_url="${proxy_prefix}${RAW_URL}" ;;
            *)  target_url="${proxy_prefix}/${RAW_URL}" ;;
        esac
    fi

    printf "\n${CYAN}[*] 正在检查 PhantomRelay 更新...${RESET}\n"
    printf "    当前版本: ${YELLOW}v%s${RESET}\n" "$VERSION"
    printf "    更新源  : ${DIM}%s${RESET}\n" "$target_url"

    tmp_new="${SCRIPT_PATH}.new.$$"
    rm -f "$tmp_new"

    if ! download_file "$target_url" "$tmp_new"; then
        rm -f "$tmp_new"
        printf "${RED}[✗] 下载更新失败！请检查网络或使用代理: GH_PROXY=https://你的加速前缀 relay update${RESET}\n"
        return 1
    fi

    # 完整性与安全校验（防止下载到 404/代理报错页面覆盖原脚本）
    if [ ! -s "$tmp_new" ] \
       || ! head -n 1 "$tmp_new" | grep -q '^#!/bin/sh' \
       || ! grep -q "PHANTOM_RELAY_SIGNATURE=\"${PHANTOM_RELAY_SIGNATURE}\"" "$tmp_new"; then
        rm -f "$tmp_new"
        printf "${RED}[✗] 更新文件签名校验失败，已中止更新以保护本地脚本！${RESET}\n"
        return 1
    fi

    if ! sh -n "$tmp_new" >/dev/null 2>&1; then
        rm -f "$tmp_new"
        printf "${RED}[✗] 新版本脚本语法自检失败，已中止更新！${RESET}\n"
        return 1
    fi

    remote_ver=$(awk -F'"' '/^VERSION="/ {print $2; exit}' "$tmp_new")
    printf "    远程版本: ${GREEN}v%s${RESET}\n" "${remote_ver:-unknown}"

    if [ "$remote_ver" = "$VERSION" ] && [ "$force_upd" != "1" ]; then
        rm -f "$tmp_new"
        printf "${GREEN}[✓] 当前已是最新版本 (v%s)，无需升级。（如需强制覆写请用: relay update --force）${RESET}\n" "$VERSION"
        return 0
    fi

    if [ "$check_only" = "1" ]; then
        rm -f "$tmp_new"
        printf "${YELLOW}[!] 发现新版本 v%s！运行 'relay update' 即可无缝升级。${RESET}\n" "$remote_ver"
        return 0
    fi

    # 原子替换并保留备份（绝不改动 /etc/nftables.d/ 下的任何用户配置与规则）
    cp "$SCRIPT_PATH" "${SCRIPT_PATH}.bak" 2>/dev/null || true
    chmod +x "$tmp_new"
    mv "$tmp_new" "$SCRIPT_PATH"
    ln -sf "$SCRIPT_PATH" /usr/bin/relay 2>/dev/null || true

    printf "${GREEN}[✓] PhantomRelay 已升级至 v%s！（旧版本备份在 %s.bak）${RESET}\n" "$remote_ver" "$SCRIPT_PATH"
    printf "${CYAN}[*] 正在使用新版本平滑重载转发规则...${RESET}\n"
    "$SCRIPT_PATH" force-apply
    return 0
}

# ==============================================================================
# 7. 主交互菜单
# ==============================================================================
show_menu() {
    init_env || true
    while true; do
        cur_mss=$(get_mss_mode)
        cur_snat=$(get_snat_mode)
        cur_stealth=$(get_stealth_mode)
        cur_pol=$(get_fwd_policy)

        printf "\n"
        show_banner
        printf "${CYAN}====================================================================${RESET}\n"
        printf "  SNAT: ${YELLOW}%s${RESET} | MSS: ${YELLOW}%s${RESET} | 隐身: ${YELLOW}%s${RESET} | Forward: ${YELLOW}%s${RESET}\n" \
            "$cur_snat" "$cur_mss" "$cur_stealth" "$cur_pol"
        printf "${CYAN}====================================================================${RESET}\n"
        printf "  ${GREEN}1.${RESET} 添加转发规则               ${GREEN}7.${RESET} 配置双向 TCP MSS 钳制\n"
        printf "  ${GREEN}2.${RESET} 修改已有规则               ${GREEN}8.${RESET} 配置出站 SNAT 模式\n"
        printf "  ${GREEN}3.${RESET} 删除转发规则               ${GREEN}9.${RESET} 安全与防 IP 暴露策略\n"
        printf "  ${GREEN}4.${RESET} 查看规则与双向实时流量    ${GREEN}10.${RESET} 配置 DDNS 定时自动刷新\n"
        printf "  ${GREEN}5.${RESET} 强制重载规则 (重置计数)   ${GREEN}11.${RESET} 暂停所有转发 (清空活动表)\n"
        printf "  ${GREEN}6.${RESET} 使用 vi 批量编辑规则库    ${GREEN}12.${RESET} 检查并升级 PhantomRelay\n"
        printf "  ${RED}0.${RESET} 退出面板\n"
        printf "${CYAN}====================================================================${RESET}\n"
        printf "请输入选项 [0-12]: "
        read -r choice
        case "$choice" in
            1)  add_rule ;;
            2)  edit_rule ;;
            3)  del_rule ;;
            4)  list_rules ;;
            5)  apply_rules 1 ;;
            6)  ${EDITOR:-vi} "$DB_FILE" && apply_rules 1 ;;
            7)  config_mss ;;
            8)  config_snat ;;
            9)  config_security ;;
            10) setup_cron ;;
            11) stop_rules ;;
            12)
                printf "如需使用 GitHub 加速前缀请粘贴 (直接回车直连 GitHub): "
                read -r p_url
                if [ -n "$p_url" ]; then
                    self_update --proxy "$p_url" && exec "$SCRIPT_PATH" menu
                else
                    self_update && exec "$SCRIPT_PATH" menu
                fi
                ;;
            0|q|exit) printf "已退出 PhantomRelay。\n"; exit 0 ;;
            *) printf "${RED}[!] 请输入 0-12 之间的数字${RESET}\n" ;;
        esac
    done
}

# ==============================================================================
# 8. CLI 入口
# ==============================================================================
cmd="${1:-menu}"
[ $# -gt 0 ] && shift

case "$cmd" in
    menu)        show_menu ;;
    apply)       apply_rules 0 ;;
    force-apply) apply_rules 1 ;;
    status)      list_rules ;;
    stop)        stop_rules ;;
    update)      self_update "$@" ;;
    cron)        setup_cron ;;
    version|-v|--version)
        show_banner
        ;;
    help|-h|--help)
        show_banner
        printf "\n用法: relay <命令> [选项]\n"
        printf "  menu                  打开交互式管理面板 (默认)\n"
        printf "  apply                 增量应用规则 (DDNS 无变化不重置流量计数，适合 crontab)\n"
        printf "  force-apply           强制重载规则并重置流量计数器\n"
        printf "  status                查看已配置规则与真实双向流量统计\n"
        printf "  stop                  停止转发并清理活动 nftables 表\n"
        printf "  update [--check|--force|--proxy <前缀>]\n"
        printf "                        检查或在线升级脚本自身\n"
        printf "  cron                  交互式配置 DDNS 定时刷新任务\n"
        printf "  version               显示版本信息\n"
        ;;
    *)
        printf "未知命令: %s\n用法: relay [menu|apply|force-apply|status|stop|update|cron|version]\n" "$cmd"
        exit 1
        ;;
esac
