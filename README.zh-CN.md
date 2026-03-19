# PktAnalyzer

[English](./README.md) | [简体中文](./README.zh-CN.md)

一个用 Go 语言编写的 MCP（Model Context Protocol）网络数据包分析服务器。提供 18 个结构化工具，支持 pcap/pcapng 分析、TCP 流重组、TLS 解密、显示过滤和异常检测——专为 Claude Code 等 AI 智能体设计。

## 功能特性

- **MCP 服务器**: 5 大类 18 个工具，支持 stdio 和 SSE 传输
- **AI 原生**: 为 AI 智能体设计——结构化 JSON 响应、证据引用、有界输出
- **Pcap 分析**: 读取 pcap/pcapng 文件，自动 SQLite 索引以实现快速查询
- **实时抓包**: 从网络接口捕获数据包（需要 root 权限）
- **TLS 解密**: 使用 `SSLKEYLOGFILE` 解密 HTTPS 流量
- **TCP 流重组**: 从 TCP 流中重建应用层内容
- **HTTP 追踪**: 从 TCP 流中解析 HTTP 请求/响应对
- **显示过滤器**: Wireshark 兼容过滤语法 (`tcp.dstport == 443`, `ip.src == "1.2.3.4"`)
- **字段提取**: 100+ 协议字段，类型安全的提取
- **异常检测**: TCP/DNS/HTTP 专家分析引擎
- **安全**: 输出脱敏、原始数据访问控制、速率限制

### 支持的协议

| 层级       | 协议                                                                                                                |
| ---------- | ------------------------------------------------------------------------------------------------------------------- |
| 数据链路层 | Ethernet                                                                                                            |
| 网络层     | IPv4, IPv6, ARP, ICMP, ICMPv6, IGMP                                                                                 |
| 传输层     | TCP, UDP                                                                                                            |
| 应用层     | DNS, HTTP/1.1, HTTP/2, WebSocket, TLS/HTTPS, NBNS, LLMNR, mDNS, SSDP, SRVLOC, WS-Discovery, DHCP, NTP, SNMP       |

## 安装

### 下载预编译二进制（推荐）

从 [GitHub Releases](https://github.com/Zerofisher/pktanalyzer/releases) 下载最新版本：

```bash
# macOS (Apple Silicon)
curl -L https://github.com/Zerofisher/pktanalyzer/releases/latest/download/pktanalyzer_v0.1.0_darwin_arm64.tar.gz | tar xz
sudo mv pktanalyzer /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/Zerofisher/pktanalyzer/releases/latest/download/pktanalyzer_v0.1.0_darwin_amd64.tar.gz | tar xz
sudo mv pktanalyzer /usr/local/bin/

# Linux (amd64)
curl -L https://github.com/Zerofisher/pktanalyzer/releases/latest/download/pktanalyzer_v0.1.0_linux_amd64.tar.gz | tar xz
sudo mv pktanalyzer /usr/local/bin/

# 验证
pktanalyzer --version
```

> **注意：** 请将 `v0.1.0` 替换为 Releases 页面上的实际版本号。

### 前置依赖（实时抓包需要）

```bash
# macOS — libpcap 已包含在 macOS SDK 中，无需额外安装

# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel
```

### 从源码编译

```bash
# 需要 Go 1.24+ 和 libpcap
cd pktanalyzer
go mod tidy
go build -o pktanalyzer
```

## 快速开始

### 启动 MCP 服务器

```bash
# 预加载 pcap 文件启动（stdio 传输，默认）
./pktanalyzer mcp capture.pcap

# 使用 SSE 传输
./pktanalyzer mcp capture.pcap --transport sse --port 9090

# 不预加载文件启动（之后通过 open_pcap 工具加载）
./pktanalyzer mcp

# 配合 TLS 解密
./pktanalyzer mcp capture.pcap --keylog-file ~/sslkeys.log

# 配合安全选项
./pktanalyzer mcp capture.pcap --enable-raw --redact-ips --rate-limit 50
```

### 列出网络接口

```bash
./pktanalyzer list interfaces
```

## 集成 Claude Code

PktAnalyzer 设计为 Claude Code 的 MCP 服务器。将其添加到 Claude Code 配置中即可使用：

### 配置方法

在 Claude Code MCP 设置文件（`~/.claude/settings.json` 或项目级 `.mcp.json`）中添加：

```json
{
  "mcpServers": {
    "pktanalyzer": {
      "command": "/path/to/pktanalyzer",
      "args": ["mcp", "/path/to/capture.pcap"]
    }
  }
}
```

配合 TLS 解密和安全选项：

```json
{
  "mcpServers": {
    "pktanalyzer": {
      "command": "/path/to/pktanalyzer",
      "args": [
        "mcp",
        "/path/to/capture.pcap",
        "--keylog-file", "/path/to/sslkeys.log",
        "--enable-raw",
        "--verbose"
      ]
    }
  }
}
```

不预加载文件（按需通过 `open_pcap` 工具加载）：

```json
{
  "mcpServers": {
    "pktanalyzer": {
      "command": "/path/to/pktanalyzer",
      "args": ["mcp"]
    }
  }
}
```

### 与 Claude Code 对话示例

配置完成后，可以直接让 Claude 分析网络流量：

```
你: 打开 examples/http_google.pcapng 并给我一个概览

Claude: [调用 open_pcap，然后 get_overview]
       该抓包文件包含 43 个数据包，时长 2.3 秒。
       协议分布：TCP 82%、UDP 14%、DNS 4%。
       ...

你: 展示 DNS 查询

Claude: [调用 filter_packets，protocol="DNS"]
       找到 4 个 DNS 数据包：
       1. 查询: www.google.com (A 记录)
       2. 响应: 74.125.95.104
       ...

你: 有异常吗？

Claude: [调用 detect_anomalies]
       发现 2 个警告：
       - 第 12 个包 TCP 重传（流 192.168.1.1:1606 → 74.125.95.104:80）
       - 第 8 个包 DNS 查询无响应
       ...

你: 追踪主要流的 HTTP 流量

Claude: [调用 list_flows，然后 follow_http]
       HTTP 会话（流 abc123）：
       请求: GET / HTTP/1.1 Host: www.google.com
       响应: HTTP/1.1 200 OK Content-Type: text/html ...
```

### 安装 Skill（可选）

PktAnalyzer 提供了一个 [Claude Code Skill](./SKILL.md) —— 一份结构化参考文档，帮助 Claude 自动理解全部 18 个 MCP 工具、常见分析工作流和显示过滤器语法。安装后，当你提到网络分析、pcap、Wireshark 等关键词时，Claude 会自动加载该 skill。

**安装方法：**

```bash
# 复制 skill 到 Claude Code 个人技能目录
mkdir -p ~/.claude/skills/pktanalyzer
cp SKILL.md ~/.claude/skills/pktanalyzer/SKILL.md
```

安装后重启 Claude Code 会话即可生效。当检测到相关关键词（pcap、网络流量、Wireshark、TCP 流等）时，skill 会自动加载。

**手动调用：**

```
/skill pktanalyzer
```

## MCP 工具参考

### 数据源工具 (4)

| 工具 | 描述 | 关键参数 |
|------|------|----------|
| `open_pcap` | 打开并索引 pcap/pcapng 文件 | `path`（必填） |
| `capture_live` | 在网络接口上实时抓包 | `interface`（必填）、`bpf`、`count`、`duration` |
| `list_interfaces` | 列出可用网络接口 | — |
| `get_overview` | 抓包概览：包数、时间跨度、协议分布 | — |

### 数据包工具 (5)

| 工具 | 描述 | 关键参数 |
|------|------|----------|
| `list_packets` | 分页排序列出数据包 | `limit`、`offset`、`sort_by`、`sort_order` |
| `filter_packets` | 按条件过滤数据包 | `src_ip`、`dst_ip`、`protocol`、`src_port`、`dst_port`、`search` |
| `get_packet` | 单个数据包详细分析 | `number`（必填） |
| `get_statistics` | 协议分布、Top IP、Top 端口 | — |
| `detect_anomalies` | 使用专家分析引擎检测异常 | `severity` |

### 流工具 (5)

| 工具 | 描述 | 关键参数 |
|------|------|----------|
| `list_flows` | 列出 TCP/UDP 流 | `protocol`、`ip`、`limit`、`sort_by` |
| `get_flow` | 获取单个流的详情 | `flow_id`（必填） |
| `get_flow_packets` | 列出流内的数据包 | `flow_id`（必填）、`limit` |
| `reassemble_stream` | TCP 流重组——重建应用层内容 | `flow_id`（必填）、`format`（text/hex/http） |
| `follow_http` | 追踪 HTTP 会话——解析请求/响应对 | `flow_id`（必填） |

### 字段工具 (3)

| 工具 | 描述 | 关键参数 |
|------|------|----------|
| `list_fields` | 列出可用协议字段及类型 | `prefix` |
| `extract_field` | 从指定数据包提取字段值 | `field`（必填）、`packet_number`（必填） |
| `apply_display_filter` | 应用 Wireshark 兼容显示过滤器 | `expression`（必填）、`limit` |

### 导出工具 (1)

| 工具 | 描述 | 关键参数 |
|------|------|----------|
| `export_packets` | 将过滤后的数据包导出为新 pcap 文件 | `output_path`（必填）、`packet_numbers`、`display_filter` |

## CLI 参数

```
pktanalyzer mcp [pcap-file] [flags]

Flags:
      --transport string     传输方式: stdio 或 sse（默认 "stdio"）
      --bind string          SSE 绑定地址（默认 "127.0.0.1"）
      --port int             SSE 监听端口（默认 8080）
      --live                 实时抓包模式（无需 pcap 文件）
      --interface string     抓包接口（配合 --live 使用，必填）
      --bpf string           BPF 过滤表达式
      --keylog-file string   SSLKEYLOGFILE 路径，用于 TLS 解密
      --enable-raw           允许访问原始数据包数据
      --raw-max-bytes int    每个包最大原始字节数（默认 1024）
      --redact-ips           脱敏输出中的 IP 地址
      --redact-macs          脱敏 MAC 地址
      --redact-creds         脱敏 HTTP 凭据
      --rate-limit int       每分钟最大工具调用次数（默认 100）
      --verbose              启用调试日志
```

## TLS/HTTPS 解密

1. 设置环境变量让浏览器导出 TLS 密钥：

```bash
export SSLKEYLOGFILE=~/sslkeys.log
```

2. 从终端启动浏览器：

```bash
# Chrome
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Firefox
/Applications/Firefox.app/Contents/MacOS/firefox
```

3. 浏览网站后，使用密钥文件解密：

```bash
./pktanalyzer mcp capture.pcap --keylog-file ~/sslkeys.log
```

## 异常检测

`detect_anomalies` 工具使用专家分析引擎识别网络问题：

### TCP 异常

| 类型 | 严重级别 | 说明 |
|------|----------|------|
| TCP Retransmission | Warning | 200ms+ 后重发相同序列号 |
| TCP Fast Retransmission | Warning | 收到 3 个重复 ACK 后触发 |
| TCP Out-of-Order | Warning | 序列号小于预期 |
| TCP Zero Window | Warning | 接收方缓冲区满 |
| TCP RST | Warning | 连接重置 |
| TCP Connection Refused | Error | SYN 后收到 RST |
| TCP SYN Flood Suspected | Error | 疑似 SYN 洪泛攻击 |

### DNS 异常

| 类型 | 严重级别 | 说明 |
|------|----------|------|
| DNS Query No Response | Warning | 5 秒内无响应 |
| DNS NXDOMAIN | Note | 域名不存在 |
| DNS SERVFAIL | Warning | 服务器错误 |

### HTTP 异常

| 类型 | 严重级别 | 说明 |
|------|----------|------|
| HTTP 4xx Client Error | Warning | 客户端错误（400-499） |
| HTTP 5xx Server Error | Error | 服务器错误（500-599） |
| HTTP Slow Response | Warning | 响应超过 3 秒 |

## 显示过滤器语法

`apply_display_filter` 工具支持 Wireshark 兼容的过滤表达式：

```
# 基础比较
tcp.dstport == 80
ip.src == "192.168.1.1"

# 逻辑运算
ip.src == "192.168.1.1" and tcp
tcp or udp

# 字符串包含
dns.qry.name contains "google"

# 协议过滤
dns
http
tls

# 范围匹配
tcp.dstport in [80, 443, 8080]
```

使用 `list_fields` 查看所有可用过滤字段。

## 项目结构

```
pktanalyzer/
├── main.go                  # 程序入口
├── cmd/                     # CLI 命令（Cobra）
│   ├── root.go              # 根命令
│   ├── mcp.go               # MCP 服务器命令
│   └── list.go              # 列出接口命令
├── mcp/                     # MCP 服务层
│   ├── server.go            # 服务器组装（18 个工具）
│   ├── middleware.go         # 输出脱敏、日志
│   └── tools/               # 工具处理函数
│       ├── context.go       # 共享依赖容器
│       ├── helpers.go       # 参数提取
│       ├── source.go        # 数据源工具 (4)
│       ├── packet.go        # 数据包工具 (5)
│       ├── stream.go        # 流工具 (5)
│       ├── fields.go        # 字段工具 (3)
│       └── export.go        # 导出工具 (1)
├── pkg/                     # 核心包
│   ├── capture/             # 数据包捕获/解析
│   ├── stream/              # TCP 重组、HTTP/H2/WS
│   ├── tls/                 # TLS 解析、解密
│   ├── filter/              # 显示过滤器 (expr-lang)
│   ├── fields/              # 协议字段注册表
│   ├── expert/              # 异常检测
│   ├── stats/               # 统计分析
│   ├── export/              # Pcap 写入
│   ├── ingest/              # Pcap → SQLite 索引
│   ├── query/               # 查询引擎
│   ├── store/               # SQLite 存储
│   ├── model/               # 数据模型
│   ├── replay/              # 原始包重读
│   └── security/            # 校验、脱敏
└── examples/                # 测试抓包文件
```

## 技术栈

- [mcp-go](https://github.com/mark3labs/mcp-go) - MCP 服务器 SDK
- [cobra](https://github.com/spf13/cobra) - CLI 框架
- [gopacket](https://github.com/google/gopacket) - 数据包捕获和解析
- [expr-lang/expr](https://github.com/expr-lang/expr) - 显示过滤器表达式引擎
- [go-sqlite3](https://github.com/mattn/go-sqlite3) - SQLite 索引后端

## 注意事项

- 实时抓包需要 root 权限
- TLS 解密仅支持有密钥的会话
- 需要捕获完整的 TLS 握手过程才能解密
- 支持的加密套件：AES-128/256-GCM, AES-128/256-CBC
- 输出受安全配置约束（默认每次响应最多 200 个数据包）
- 原始数据包访问需要 `--enable-raw` 标志

## License

MIT
