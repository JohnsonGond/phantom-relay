# PhantomRelay (幽灵中转)

```text
  ____  _                 _                  ____      _
 |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___ |  _ \ ___| | __ _ _   _
 | |_) | '_ \ / _` | '_ \| __/ _ \| '_ ` _ \| |_) / _ \ |/ _` | | | |
 |  __/| | | | (_| | | | | || (_) | | | | | |  _ <  __/ | (_| | |_| |
 |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|_| \_\___|_|\__,_|\__, |
                                                               |___/
```

**专为 Alpine LXC 与轻量级 Linux 打造的纯内核态 `nftables` 隐身 L4 流量中转管理工具。**  
零用户态常驻进程、零内存占用、原生 POSIX `sh`（完美兼容 BusyBox `ash` / `dash`），并内置防路由追踪隐身、真实双向流量统计、双向 TCP MSS 钳制、DDNS 智能缓存及在线自升级能力。

---

## 核心特性

- **零用户态守护进程**：纯内核态 `nftables` DNAT + SNAT 转发，转发性能直达内核极限，重启自动生效。
- **防落地机 IP / 路由泄露（隐身模式）**：
  - `forward` 链主动丢弃回程 `ICMP Time-Exceeded` 与 `Redirect` 探针，并对入向转发包执行 TTL 归一化（`ip ttl < 64 -> set 64`），让 `tcptraceroute` / `traceroute` 彻底止步于中转机。
  - `postrouting` 全程绑定 `ct status dnat` + `masquerade` 兜底，彻底杜绝 DNAT 漏做 SNAT 导致客户端直连落地机的 IP 泄露风险。
  - `prerouting` 绑定 `fib daddr type local`，避免劫持 Docker / WireGuard / Tailscale 过路流量。
  - `forward` 默认采用严密 `policy drop`（仅放行本脚本 DNAT 流量），杜绝开放路由滥用，同时支持一键切换 `accept` 兼容多业务共存。
  - 不暴力删除系统原有 `table inet filter`，无损保留主机 `input` 防火墙（SSH 防护等）。
- **真实双向实时流量统计**：
  - 通过 `prerouting` 打 `ct mark` 标记 + `forward`（`type filter`）分方向（`original` / `reply`）计数，彻底修复传统 `type nat` 链仅统计首包的缺陷，精确展示每条规则的 **上行 (↑) / 下行 (↓) / 总计流量**。
- **双向 TCP MSS 钳制（抗 PMTU 黑洞）**：
  - 使用位掩码 `tcp flags & (syn | rst) == syn` 同时钳制双向 `SYN` 与 `SYN,ACK`，配合 `maxseg size` 范围保护防止将小 MSS 改大；旧内核不支持时自动平滑降级并提示。
  - 有效解决非对称 MTU（1450 / PPPoE / 隧道）及 TLS ML-KEM768 大包握手卡死。
- **Alpine (musl) DDNS 全兼容与高可用**：
  - 自动适配 `getent ahostsv4` -> `getent hosts` -> BusyBox `nslookup` -> `dig/drill`。
  - 内置解析缓存（`/etc/nftables.d/relay.dns.cache`），DNS 瞬时抖动时自动沿用上次有效 IP，绝不误删规则。
  - 变更对比机制：`crontab` 定时刷新时若规则与 DDNS IP 均无变化，**自动跳过重载，不重置流量统计**。
  - 检测到 DDNS 换 IP 且安装 `conntrack-tools` 时，自动清理旧落地机 IP 的粘滞会话（解决 WireGuard / Hysteria2 / QUIC 切换卡死）。
- **多网卡 / 多路由智能 SNAT**：
  - `auto` 模式按每条落地机目标 IP 单独 `ip -4 route get` 探测最优出站源 IP；另支持 `masquerade`（动态公网 IP）与手动指定静态 SNAT IP（多公网 IP VPS）。
- **安全原子更新 & 在线自升级**：
  - 并发文件锁 + 临时文件 `nft -c -f` 预检 + 原子替换，绝不损坏运行中的配置。
  - 支持 `relay update` 一键在线升级（含签名校验、语法自检、旧版自动备份、可选 GitHub 加速前缀，且不改动用户规则库）。

---

## 一键部署

### Alpine Linux / Debian / Ubuntu

使用 `wget`（Alpine BusyBox 原生内置，无需先装 curl）：

```sh
wget -qO /root/relay.sh https://raw.githubusercontent.com/JohnsonGond/phantom-relay/main/relay.sh && chmod +x /root/relay.sh && ln -sf /root/relay.sh /usr/bin/relay && relay
```

或使用 `curl`：

```sh
curl -fsSL https://raw.githubusercontent.com/JohnsonGond/phantom-relay/main/relay.sh -o /root/relay.sh && chmod +x /root/relay.sh && ln -sf /root/relay.sh /usr/bin/relay && relay
```

> **提示**：如果需要支持 DDNS 变更或删除规则时立即断开已建立的 UDP/TCP 长连接，建议额外安装 `conntrack-tools`：
> - Alpine: `apk add conntrack-tools`
> - Debian/Ubuntu: `apt-get install -y conntrack`

---

## 命令速查

```sh
relay                         # 打开交互式管理面板
relay apply                   # 增量应用规则（DDNS 无变化跳过重载，不重置计数，适合 crontab）
relay force-apply             # 强制重载规则并重置流量计数器
relay status                  # 查看已配置规则与真实双向流量面板
relay stop                    # 暂停转发并清空活动 nftables 表（保留规则库）
relay cron                    # 交互式配置/移除 DDNS 定时自动刷新任务
relay update                  # 在线检查并升级到最新版本
relay update --check          # 仅检查是否有新版本
relay update --proxy <前缀>   # 通过自定义 GitHub 加速前缀升级（或设置环境变量 GH_PROXY）
relay version                 # 查看当前版本
```

### 多节点批量升级示例

```sh
# 直连 GitHub 升级
relay update

# 使用加速镜像前缀升级
GH_PROXY="https://你的加速域名/" relay update
```

---

## 配置文件说明

所有持久化状态均存放在 `/etc/nftables.d/` 下，升级脚本时**完全保留**：

| 文件路径 | 说明 |
| :--- | :--- |
| `/etc/nftables.d/relay.db` | 转发规则库（格式：`本地端口\|落地机\|目标端口\|协议\|备注`） |
| `/etc/nftables.d/relay.nft` | 自动编译生成的 `nftables` 活动配置 |
| `/etc/nftables.d/relay.mss` | 双向 TCP MSS 钳制值（默认 `1360`，或 `off`） |
| `/etc/nftables.d/relay.snat` | SNAT 模式（`auto` / `masquerade` / 静态 IPv4） |
| `/etc/nftables.d/relay.policy` | `forward` 链策略（`drop` 严密模式 / `accept` 兼容模式） |
| `/etc/nftables.d/relay.stealth` | 隐身模式开关（`on` / `off`） |
| `/etc/nftables.d/relay.dns.cache` | DDNS 最近一次成功解析的 IPv4 缓存 |

---

## 安全与运维建议

1. **落地机防火墙白名单**：强烈建议在落地机防火墙上配置目标端口**仅允许中转机公网 IP 访问**，避免全网测绘（Censys / Shodan）通过证书或服务指纹关联出落地机真实 IP。
2. **关于 UDP 协议的 MTU**：TCP MSS 钳制仅作用于 TCP 握手阶段；若转发 Hysteria2 / TUIC / WireGuard / QUIC 等 UDP 协议并遇到分片问题，请在对应客户端/服务端调低 MTU（如 `1280` - `1380`）。
3. **本机同跑 Docker / WireGuard**：若中转机同时承担 Docker 容器或 VPN 网关转发，请在菜单 `9. 安全与防 IP 暴露策略` 中将 `Forward` 策略设为 `accept`。

---

## License

[MIT License](LICENSE)
