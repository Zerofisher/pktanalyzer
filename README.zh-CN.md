# PktAnalyzer

[English](./README.md) | [简体中文](./README.zh-CN.md)

一个用 Go 语言编写的网络数据包命令行分析工具，类似 tshark/Wireshark，支持实时抓包、pcap 文件分析、TLS/HTTPS 解密、TCP 流重组、CLI 导出和 AI 智能分析。

## 功能特性

- **实时抓包**: 从网络接口捕获数据包（需要 root 权限）
- **文件分析**: 读取 pcap/pcapng 格式的抓包文件
- **TLS 解密**: 使用 SSLKEYLOGFILE 解密 HTTPS 流量
- **TCP 流重组**: 跟踪和重组 TCP 会话，查看完整的数据流
- **显示过滤器**: 类 Wireshark 语法的显示过滤 (`-Y`)
- **CLI 导出**: tshark 兼容的命令行输出 (`text`, `json`, `fields`)
- **统计分析**: 端点统计、会话统计、I/O 统计 (`stats` 命令)
- **流追踪**: 导出 TCP 流数据 (`follow` 命令)
- **专家信息系统**: TCP/DNS/HTTP 异常检测，类似 Wireshark Expert Info (`stats expert`)
- **AI 智能分析**: 集成 Claude/OpenAI，智能解释数据包和网络行为
- **TUI 界面**: 交互式终端界面，支持滚动、过滤、详情查看、分屏显示

### 支持的协议

| 层级       | 协议                                                                                                                |
| ---------- | ------------------------------------------------------------------------------------------------------------------- |
| 数据链路层 | Ethernet                                                                                                            |
| 网络层     | IPv4, IPv6, ARP, ICMP, ICMPv6, IGMP                                                                                 |
| 传输层     | TCP, UDP                                                                                                            |
| 应用层     | DNS, HTTP/1.1, **HTTP/2**, **WebSocket**, TLS/HTTPS, NBNS, LLMNR, mDNS, SSDP, SRVLOC, WS-Discovery, DHCP, NTP, SNMP |

### HTTP/2 支持

pktanalyzer 支持完整的 HTTP/2 协议解析：

- **帧解析**: 支持所有 9 种 HTTP/2 帧类型 (DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION)
- **HPACK 解压**: 完整实现 RFC 7541 头部压缩，包括静态表、动态表和 Huffman 编码
- **流多路复用**: 跟踪和管理 HTTP/2 连接中的多个并发流
- **请求/响应配对**: 自动将请求和响应关联到对应的流
- **ALPN 检测**: 通过 TLS ALPN 扩展自动检测 HTTP/2 协议协商

### WebSocket 支持

pktanalyzer 支持完整的 WebSocket 协议解析（RFC 6455）：

- **握手检测**: 自动检测 HTTP Upgrade 握手，验证 Sec-WebSocket-Key/Accept
- **帧解析**: 支持所有 WebSocket 帧类型 (TEXT, BINARY, CLOSE, PING, PONG, CONTINUATION)
- **掩码处理**: 自动解码客户端发送的掩码数据
- **消息重组**: 将分片帧重组为完整消息
- **扩展长度**: 支持 16 位和 64 位扩展 payload 长度
- **关闭码解析**: 解析并显示 WebSocket 关闭状态码和原因

## 安装

### 前置依赖

```bash
# macOS
brew install libpcap

# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel
```

### 编译

```bash
cd pktanalyzer
go mod tidy
go build -o pktanalyzer
```

## 使用方法

pktanalyzer 使用基于命令的结构。使用 `pktanalyzer --help` 查看所有可用命令。

### 基本用法

```bash
# 查看帮助
./pktanalyzer --help

# 列出可用网络接口
./pktanalyzer list interfaces

# 列出可用字段
./pktanalyzer list fields

# 读取 pcap 文件 (TUI 模式)
./pktanalyzer read capture.pcapng

# 实时抓包（需要 root 权限）
sudo ./pktanalyzer capture en0

# 使用 BPF 过滤器 (抓包过滤)
./pktanalyzer read capture.pcapng --bpf "tcp port 80"
sudo ./pktanalyzer capture en0 --bpf "host 192.168.1.1"
```

### 索引模式（大文件支持）

对于大型 pcap 文件，使用索引模式 (`-I`) 会创建 SQLite 数据库以实现高效查询：

```bash
# 启用索引模式
./pktanalyzer read capture.pcapng -I

# 首次运行会创建索引文件（~capture.pktindex），后续运行使用缓存的索引
./pktanalyzer read large_capture.pcapng -I

# 配合 AI 分析
./pktanalyzer read capture.pcapng -I -A
```

**索引模式的优势**：
- 内存高效：按需加载数据包，而不是将所有数据加载到内存
- 快速随机访问：可以快速跳转到任意编号的数据包
- 流跟踪：自动检测和统计网络流
- 专家事件：持久存储检测到的异常
- 适合处理数 GB 的抓包文件

### 保存数据包

实时抓包并保存到 pcapng 文件：

```bash
# 实时抓包并保存到文件
sudo ./pktanalyzer capture write en0 capture.pcapng

# 限制抓包数量
sudo ./pktanalyzer capture write en0 capture.pcapng -c 100

# 配合显示过滤器
sudo ./pktanalyzer capture write en0 capture.pcapng -Y 'tcp.dstport == 443'
```

**TUI 模式保存**：在 TUI 界面（通过 `capture` 或 `read` 启动）中，按 `w` 键可以将当前（过滤后的）数据包保存到文件。文件名自动生成，格式为 `capture_YYYYMMDD_HHMMSS.pcapng`。

### CLI 导出模式 (tshark 兼容)

```bash
# 文本格式输出（一行摘要）
./pktanalyzer read text capture.pcapng -c 10

# JSON 格式输出
./pktanalyzer read json capture.pcapng -c 5

# 字段提取
./pktanalyzer read fields capture.pcapng -e frame.number -e ip.src -e ip.dst -e tcp.dstport

# 详细输出（协议层信息）
./pktanalyzer read text capture.pcapng -V -c 1

# 十六进制 dump
./pktanalyzer read text capture.pcapng -x -c 1
```

### 显示过滤器 (`-Y` / `--filter`)

使用类 Wireshark 语法过滤数据包：

```bash
# 基础比较
./pktanalyzer read text capture.pcapng -Y 'tcp.dstport == 80'

# IP 地址过滤
./pktanalyzer read text capture.pcapng -Y 'ip.src == "192.168.1.1"'

# 逻辑组合
./pktanalyzer read text capture.pcapng -Y 'ip.src == "192.168.1.1" and tcp'
./pktanalyzer read text capture.pcapng -Y 'tcp or udp'

# 字符串包含
./pktanalyzer read text dns.pcapng -Y 'dns.qry.name contains "google"'

# 协议过滤
./pktanalyzer read text capture.pcapng -Y 'dns'
./pktanalyzer read text capture.pcapng -Y 'http'

# 范围匹配
./pktanalyzer read text capture.pcapng -Y 'tcp.dstport in [80, 443, 8080]'

# 与 JSON 导出联动
./pktanalyzer read json capture.pcapng -Y 'tcp.dstport == 443' -c 10
```

支持的过滤字段可以通过 `pktanalyzer list fields` 查看。

### 统计分析 (`stats`)

```bash
# 端点统计
./pktanalyzer stats endpoints -r capture.pcapng

# TCP 会话统计
./pktanalyzer stats conversations -r capture.pcapng --proto tcp

# UDP 会话统计
./pktanalyzer stats conversations -r capture.pcapng --proto udp

# I/O 统计（1秒间隔）
./pktanalyzer stats io -r capture.pcapng --interval 1

# I/O 统计（0.5秒间隔）
./pktanalyzer stats io -r capture.pcapng --interval 0.5
```

### TCP 流追踪 (`follow`)

首先通过 TUI 或分析工具确定流 ID，然后追踪它：

```bash
# ASCII 格式导出流 #1
./pktanalyzer follow 1 -r capture.pcapng --format ascii

# Hex 格式导出
./pktanalyzer follow 1 -r capture.pcapng --format hex

# Raw 格式（直接输出字节）
./pktanalyzer follow 1 -r capture.pcapng --format raw > stream.bin
```

### 专家信息系统 (`stats expert`)

分析网络数据包中的异常和问题，类似 Wireshark 的 Expert Information 功能：

```bash
# 显示所有专家信息
./pktanalyzer stats expert -r capture.pcapng

# 只显示警告和错误
./pktanalyzer stats expert -r capture.pcapng --severity warning

# 只显示错误
./pktanalyzer stats expert -r capture.pcapng --severity error
```

**检测的 TCP 异常**:

| 异常类型                    | 严重级别 | 说明                                 |
| --------------------------- | -------- | ------------------------------------ |
| TCP Retransmission          | Warning  | TCP 重传（200ms+ 后重发相同序列号）  |
| TCP Fast Retransmission     | Warning  | 快速重传（收到 3 个重复 ACK 后触发） |
| TCP Spurious Retransmission | Note     | 伪重传（数据已被确认后再次发送）     |
| TCP Duplicate ACK           | Note     | 重复 ACK（相同确认号的 ACK）         |
| TCP Triple Duplicate ACK    | Warning  | 三次重复 ACK（触发快速重传信号）     |
| TCP Out-of-Order            | Warning  | 乱序包（序列号小于预期）             |
| TCP Zero Window             | Warning  | 零窗口（接收方缓冲区满）             |
| TCP Window Update           | Note     | 窗口更新（零窗口后恢复）             |
| TCP Zero Window Probe       | Note     | 零窗口探测                           |
| TCP Keep-Alive              | Note     | 保活探测                             |
| TCP Keep-Alive ACK          | Note     | 保活响应                             |
| TCP RST                     | Warning  | 连接重置                             |
| TCP Connection Refused      | Error    | 连接被拒绝（SYN 后收到 RST）         |
| TCP SYN Flood Suspected     | Error    | 疑似 SYN 洪泛攻击                    |
| TCP Port Scan Suspected     | Warning  | 疑似端口扫描                         |

**检测的 DNS 异常**:

| 异常类型              | 严重级别 | 说明                        |
| --------------------- | -------- | --------------------------- |
| DNS Query No Response | Warning  | DNS 查询无响应（超时 5 秒） |
| DNS NXDOMAIN          | Note     | 域名不存在                  |
| DNS SERVFAIL          | Warning  | 服务器错误                  |
| DNS Query Refused     | Warning  | 查询被拒绝                  |

**检测的 HTTP 异常**:

| 异常类型                 | 严重级别 | 说明                  |
| ------------------------ | -------- | --------------------- |
| HTTP 4xx Client Error    | Warning  | 客户端错误（400-499） |
| HTTP 5xx Server Error    | Error    | 服务器错误（500-599） |
| HTTP Redirect            | Note     | 重定向（300-399）     |
| HTTP Slow Response       | Warning  | 响应缓慢（> 3 秒）    |
| HTTP Request No Response | Warning  | 请求无响应            |

### 生成分析报告 (`report`)

从 pcap 文件生成完整的 Markdown 分析报告：

```bash
# 生成报告输出到标准输出
./pktanalyzer report capture.pcapng

# 保存报告到文件
./pktanalyzer report capture.pcapng -o report.md

# 报告包含：
# - 概览（数据包数、字节数、持续时间、流数量）
# - 协议分布
# - 流量最大的流
# - 最活跃的 IP
# - 专家事件摘要
```

**报告输出示例**：
```markdown
# Network Analysis Report
**Generated:** 2025-01-28 10:30:00
**File:** capture.pcapng

## Overview
| Metric | Value |
|--------|-------|
| Total Packets | 15234 |
| Total Bytes | 12.5 MB |
| Duration | 5m30s |
...
```

### TCP 流重组 (TUI)

在 TUI 中查看 TCP 会话的完整数据流：

```bash
# 读取文件并启用流重组
./pktanalyzer read capture.pcapng -S

# 在 TUI 中按 's' 键可切换到流列表视图
```

### HTTP/2 流分析 (TUI)

在 TCP 流重组模式下，pktanalyzer 会自动检测并解析 HTTP/2 流量：

```bash
# 启用流重组分析 HTTP/2 流量
./pktanalyzer read https_capture.pcapng -S

# 配合 TLS 解密分析加密的 HTTP/2 流量
./pktanalyzer read https_capture.pcapng -S -k ~/sslkeys.log
```

**TUI 操作步骤**:

1. 按 `s` 键进入 TCP 流列表视图
2. 流列表会显示检测到的协议类型 (HTTP/1.1, HTTP/2, TLS 等)
3. HTTP/2 流会以粉色高亮显示
4. 选择一个流后按 `Enter` 查看详情

**HTTP/2 流详情视图显示**:

- **连接概要**: 流数量、帧数量
- **帧列表**: 所有 HTTP/2 帧的摘要 (类型、流 ID、标志位)
  - 例如: `[1] SETTINGS len=18`
  - 例如: `[2] HEADERS stream=1 len=45 flags=END_HEADERS`
  - 例如: `[3] DATA stream=1 len=1024 flags=END_STREAM`
- **流详情**: 每个 HTTP/2 流的请求和响应
  - 请求: 方法、路径、主机、头部
  - 响应: 状态码、头部
  - 数据: 请求/响应体大小

**HTTP/2 帧类型说明**:

| 帧类型        | 说明                        |
| ------------- | --------------------------- |
| DATA          | 传输请求/响应体数据         |
| HEADERS       | 传输 HTTP 头部 (HPACK 压缩) |
| PRIORITY      | 设置流优先级                |
| RST_STREAM    | 异常终止流                  |
| SETTINGS      | 连接配置参数                |
| PUSH_PROMISE  | 服务器推送预告              |
| PING          | 连接保活/延迟测量           |
| GOAWAY        | 优雅关闭连接                |
| WINDOW_UPDATE | 流量控制窗口更新            |
| CONTINUATION  | HEADERS/PUSH_PROMISE 的延续 |

### TLS/HTTPS 解密

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
# 分析已保存的抓包文件
./pktanalyzer read https_capture.pcapng -k ~/sslkeys.log

# 实时抓包并解密
sudo ./pktanalyzer capture en0 -k ~/sslkeys.log
```

### AI 智能分析

使用 AI 助手分析网络数据包。支持多种 LLM 提供商，采用 ReAct (Reasoning and Acting) 模式进行智能分析。

#### 支持的 LLM 提供商

| 提供商     | 环境变量             | 默认模型                  | 说明                 |
| ---------- | -------------------- | ------------------------- | -------------------- |
| Claude     | `ANTHROPIC_API_KEY`  | claude-sonnet-4-20250514  | Anthropic Claude API |
| OpenAI     | `OPENAI_API_KEY`     | gpt-4o                    | OpenAI GPT API       |
| OpenRouter | `OPENROUTER_API_KEY` | anthropic/claude-sonnet-4 | 聚合多模型平台       |
| Ollama     | `OLLAMA_BASE_URL`    | llama3.2                  | 本地部署模型         |

**Provider 检测优先级**: `AI_PROVIDER` 环境变量 > `OPENROUTER_API_KEY` > `ANTHROPIC_API_KEY` > `OPENAI_API_KEY` > `OLLAMA_BASE_URL`

#### 基本用法

```bash
# 使用 Claude
export ANTHROPIC_API_KEY="your-claude-api-key"
./pktanalyzer read capture.pcapng -A

# 使用 OpenAI
export OPENAI_API_KEY="your-openai-api-key"
./pktanalyzer read capture.pcapng -A

# 使用 OpenRouter
export OPENROUTER_API_KEY="your-openrouter-api-key"
./pktanalyzer read capture.pcapng -A

# 使用本地 Ollama
export OLLAMA_BASE_URL="http://localhost:11434/v1"
./pktanalyzer read capture.pcapng -A

# 显式指定 Provider
export AI_PROVIDER="ollama"
export OLLAMA_BASE_URL="http://localhost:11434/v1"
./pktanalyzer read capture.pcapng -A

# 实时抓包 + AI 分析
sudo ./pktanalyzer capture en0 -A
```

#### AI 工具能力

AI 助手通过以下内置工具与数据包交互：

| 工具                 | 功能                     | 参数                                                                        |
| -------------------- | ------------------------ | --------------------------------------------------------------------------- |
| `get_packets`        | 获取已捕获的数据包列表   | `limit`, `offset`, `protocol`                                               |
| `filter_packets`     | 按条件过滤数据包         | `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `contains`, `limit` |
| `analyze_packet`     | 分析特定数据包的协议详情 | `packet_number` (必填)                                                      |
| `get_statistics`     | 获取流量统计信息         | -                                                                           |
| `explain_protocol`   | 解释协议工作原理         | `protocol` (必填), `topic`                                                  |
| `find_connections`   | 查找 TCP 连接            | `ip`, `port`                                                                |
| `find_dns_queries`   | 查找 DNS 查询记录        | `domain`, `limit`                                                           |
| `find_http_requests` | 查找 HTTP 请求           | `url`, `method`, `limit`                                                    |
| `detect_anomalies`   | 检测异常模式             | -                                                                           |

#### 示例对话

在 TUI 中按 `a` 进入 AI 聊天模式后，可以进行如下对话：

```
你: 这个抓包文件中有哪些 HTTP 请求？
AI: [调用 find_http_requests 工具]
    找到 5 个 HTTP 请求：
    1. GET / HTTP/1.1 (google.com)
    2. GET /images/logo.png HTTP/1.1
    ...

你: 分析第 4 个数据包
AI: [调用 analyze_packet 工具]
    第 4 个数据包是一个 HTTP GET 请求：
    - 源: 172.16.16.128:1606
    - 目的: 74.125.95.104:80
    - 方法: GET
    - URI: /
    - Host: www.google.com
    ...

你: 有没有异常流量？
AI: [调用 detect_anomalies 工具]
    未检测到明显异常。流量模式正常：
    - 无端口扫描迹象
    - TCP 重传率在正常范围
    - 无异常连接模式

你: 解释一下 TCP 三次握手
AI: [调用 explain_protocol 工具]
    TCP 三次握手是建立可靠连接的过程：
    1. SYN: 客户端发送 SYN 包，请求建立连接
    2. SYN-ACK: 服务器响应 SYN-ACK，确认请求
    3. ACK: 客户端发送 ACK，连接建立完成
    ...
```

#### ReAct Agent 配置

AI 使用 ReAct 模式运行，内置以下安全策略：

| 配置            | 默认值 | 说明                     |
| --------------- | ------ | ------------------------ |
| MaxIterations   | 10     | 单次对话最大推理循环次数 |
| MaxToolsPerTurn | 5      | 每轮最多调用工具数       |
| ToolTimeout     | 30s    | 单个工具执行超时         |
| ContinueOnError | true   | 工具出错时继续执行       |

#### AI 可观测性 (Langfuse)

pktanalyzer 支持 [Langfuse](https://langfuse.com) 进行 LLM 可观测性监控，可追踪 AI Agent 行为、Token 使用量和工具调用。

**配置步骤：**

1. 在 [langfuse.com](https://langfuse.com) 注册账号（或自托管）
2. 在 Settings → API Keys 获取密钥
3. 设置环境变量：

```bash
# 必填 - 设置后自动开启追踪
export LANGFUSE_PUBLIC_KEY="pk-lf-..."
export LANGFUSE_SECRET_KEY="sk-lf-..."

# 可选 - US 区域或自托管
export LANGFUSE_HOST="us.cloud.langfuse.com"  # US 区域
# export LANGFUSE_HOST="localhost:3000"       # 自托管
```

**使用方式：**

```bash
# 设置 LANGFUSE_* 环境变量后自动开启追踪
export LANGFUSE_PUBLIC_KEY="pk-lf-xxx"
export LANGFUSE_SECRET_KEY="sk-lf-xxx"
./pktanalyzer read capture.pcapng -A

# Trace 数据将显示在 Langfuse 控制台
```

**追踪内容：**

| Span 类型         | 属性                                           |
| ----------------- | ---------------------------------------------- |
| `agent.chat`      | 用户输入、最终输出、迭代次数、工具调用数       |
| `llm.chat_stream` | 模型、提供商、输入/输出预览、Token 使用量      |
| `tool.<name>`     | 工具名称、输入参数、输出预览                   |

**注意：** 未设置 LANGFUSE_PUBLIC_KEY 和 LANGFUSE_SECRET_KEY 时，追踪功能禁用（noop），无额外开销。

## 命令行参数

pktanalyzer 现在使用子命令结构。

- `read`: 读取并分析 pcap/pcapng 文件
  - `text`: 以文本格式输出数据包
  - `json`: 以 JSON 格式输出数据包
  - `fields`: 提取指定字段
  - `-I, --index`: 使用索引模式处理大文件
- `capture`: 实时抓包
  - `write`: 将捕获的数据包写入文件
- `stats`: 数据包统计和分析
  - `endpoints`: 显示端点统计
  - `conversations`: 显示会话统计
  - `io`: 显示 I/O 统计
  - `expert`: 专家分析
- `report`: 从 pcap 文件生成分析报告
- `follow`: 追踪 TCP 流
- `list`: 列出可用资源
  - `interfaces`: 列出网络接口
  - `fields`: 列出可用数据包字段

使用 `pktanalyzer [command] --help` 查看每个命令的详细用法。

## TUI 快捷键

### 通用快捷键

| 按键         | 功能                      |
| ------------ | ------------------------- |
| `↑` / `k`    | 向上移动                  |
| `↓` / `j`    | 向下移动                  |
| `PgUp`       | 向上翻页                  |
| `PgDn`       | 向下翻页                  |
| `Home` / `g` | 跳到第一个包              |
| `End` / `G`  | 跳到最后一个包            |
| `Enter`      | 查看数据包详情            |
| `x`          | 查看 Hex dump             |
| `w`          | 保存数据包到 pcapng 文件  |
| `Esc`        | 返回列表视图              |
| `/`          | 输入过滤器                |
| `Space`      | 暂停/继续抓包（实时模式） |
| `?`          | 显示帮助                  |
| `q`          | 退出                      |

### TCP 流重组快捷键

| 按键    | 功能              |
| ------- | ----------------- |
| `s`     | 切换到 TCP 流列表 |
| `Enter` | 查看流详情        |
| `c`     | 查看客户端数据    |
| `S`     | 查看服务端数据    |
| `Esc`   | 返回上一视图      |

### AI 助手快捷键（需启用 -A）

| 按键    | 功能              |
| ------- | ----------------- |
| `a`     | 打开/关闭 AI 聊天 |
| `Tab`   | 切换分屏视图      |
| `i`     | 进入输入模式      |
| `Enter` | 发送消息          |
| `Esc`   | 退出输入模式      |

### 专家信息快捷键

| 按键  | 功能                 |
| ----- | -------------------- |
| `e`   | 切换到专家信息视图   |
| `1`   | 显示所有级别 (Chat+) |
| `2`   | 显示 Note 及以上     |
| `3`   | 显示 Warning 及以上  |
| `4`   | 只显示 Error         |
| `Esc` | 返回数据包列表       |

## 界面说明

### 数据包列表视图

显示所有捕获的数据包，包含：

- 编号、时间戳
- 源/目的地址
- 协议类型
- 摘要信息

协议颜色：

- TCP: 蓝色
- UDP: 绿色
- ICMP: 橙色
- ARP: 紫色
- DNS: 天蓝色
- HTTP: 浅绿色
- HTTP/2: 粉色
- WebSocket: 紫色
- TLS: 金色
- HTTPS (已解密): 亮绿色

### 详情视图

按 `Enter` 查看选中数据包的详细信息：

- 各协议层的解析结果
- TLS 握手信息（ClientHello, ServerHello, SNI 等）
- 解密后的 HTTP 请求/响应

### Hex 视图

按 `x` 查看原始数据的十六进制和 ASCII 表示。

## 项目结构

```
pktanalyzer/
├── main.go              # 程序入口
├── cmd/                 # CLI 命令定义 (Cobra)
│   ├── root.go          # 根命令
│   ├── capture.go       # 抓包命令
│   ├── read.go          # 读取命令
│   ├── stats.go         # 统计命令
│   ├── report.go        # 报告命令
│   ├── follow.go        # 追踪命令
│   └── list.go          # 列表命令
├── internal/            # 内部包（不对外暴露）
│   ├── app/             # 应用程序初始化逻辑
│   │   ├── capture.go   # 抓包器设置
│   │   ├── export.go    # 导出执行器
│   │   └── ai.go        # AI 助手设置
│   └── report/          # 报告生成
│       ├── report.go    # 报告数据收集
│       ├── markdown.go  # Markdown 格式化
│       └── format.go    # 格式化工具
├── pkg/                 # 公共包（索引模式）
│   ├── ingest/          # Pcap 文件索引
│   ├── store/           # SQLite 存储后端
│   │   └── sqlite/      # SQLite 实现
│   ├── query/           # 索引数据查询引擎
│   └── model/           # 数据模型 (Flow, ExpertEvent 等)
├── capture/
│   ├── capture.go       # 抓包引擎和协议解析
│   ├── protocols.go     # 扩展协议解析器
│   └── stream.go        # TCP 流重组
├── stream/
│   ├── stream.go        # TCP 流管理
│   ├── reassembly.go    # TCP 重组缓冲区
│   ├── http.go          # HTTP/1.1 解析
│   ├── http2.go         # HTTP/2 帧解析器
│   ├── hpack.go         # HPACK 头部压缩/解压
│   ├── http2_stream.go  # HTTP/2 流管理和连接状态
│   └── websocket.go     # WebSocket 协议解析 (RFC 6455)
├── filter/
│   └── filter.go        # 显示过滤器 (expr-lang/expr)
├── expert/
│   ├── types.go         # 专家信息类型定义 (Severity, Group, ExpertInfo)
│   ├── expert.go        # 专家分析器主程序
│   ├── tcp.go           # TCP 异常检测 (重传、乱序、零窗口等)
│   ├── dns.go           # DNS 异常检测 (NXDOMAIN、超时等)
│   └── http.go          # HTTP 异常检测 (4xx/5xx、慢响应等)
├── fields/
│   └── fields.go        # 协议字段注册表
├── export/
│   └── export.go        # CLI 导出 (text/json/fields)
├── stats/
│   └── stats.go         # 统计分析
├── tls/
│   ├── keylog.go        # SSLKEYLOGFILE 解析
│   ├── parser.go        # TLS 协议解析 (含 ALPN 扩展)
│   ├── prf.go           # 密钥派生函数
│   └── decrypt.go       # TLS 解密引擎
├── agent/
│   ├── agent.go         # AI Agent 协调器
│   ├── tools.go         # AI 工具定义与执行
│   ├── llm/
│   │   ├── types.go     # 统一 LLM 抽象层 (Message, Tool, Client)
│   │   └── factory.go   # Provider 检测与配置
│   ├── providers/
│   │   ├── claude/      # Anthropic Claude 实现
│   │   ├── openai/      # OpenAI 实现 (基础)
│   │   ├── openrouter/  # OpenRouter (复用 OpenAI)
│   │   └── ollama/      # Ollama (OpenAI 兼容)
│   └── react/
│       └── agent.go     # ReAct 推理循环
├── ui/
│   ├── app.go           # TUI 主程序
│   ├── model.go         # 数据模型
│   ├── views.go         # 视图渲染 (含 HTTP/2 显示)
│   ├── styles.go        # 样式定义
│   └── adapter/         # UI 适配器（不同数据源）
│       ├── memory_store.go   # 内存数据包存储（实时抓包）
│       └── indexed_store.go  # SQLite 存储（索引模式）
├── go.mod
└── go.sum
```

## 技术栈

- [cobra](https://github.com/spf13/cobra) - CLI 框架
- [gopacket](https://github.com/google/gopacket) - 数据包捕获和解析
- [bubbletea](https://github.com/charmbracelet/bubbletea) - TUI 框架
- [lipgloss](https://github.com/charmbracelet/lipgloss) - 终端样式
- [expr-lang/expr](https://github.com/expr-lang/expr) - 显示过滤器表达式引擎

## 注意事项

- 实时抓包需要 root 权限
- TLS 解密仅支持有密钥的会话
- 需要捕获完整的 TLS 握手过程才能解密
- 支持的加密套件：AES-128/256-GCM, AES-128/256-CBC
- AI 助手需要设置对应 LLM Provider 的环境变量

## 环境变量

| 变量                 | 说明                                                                |
| -------------------- | ------------------------------------------------------------------- |
| `AI_PROVIDER`        | 显式指定 LLM Provider：`claude`, `openai`, `openrouter`, `ollama`   |
| `AI_MODEL`           | 自定义模型名称（覆盖默认模型）                                      |
| `ANTHROPIC_API_KEY`  | Claude API 密钥                                                     |
| `ANTHROPIC_BASE_URL` | Claude API 地址（默认 `https://api.anthropic.com/v1`）              |
| `OPENAI_API_KEY`     | OpenAI API 密钥                                                     |
| `OPENAI_BASE_URL`    | OpenAI API 地址（默认 `https://api.openai.com/v1`，可用于兼容 API） |
| `OPENROUTER_API_KEY` | OpenRouter API 密钥                                                 |
| `OLLAMA_BASE_URL`    | Ollama API 地址（默认 `http://localhost:11434/v1`）                 |
| `LANGFUSE_PUBLIC_KEY`| Langfuse 公钥（设置后自动开启 AI 追踪）                             |
| `LANGFUSE_SECRET_KEY`| Langfuse 私钥（需与公钥一起设置）                                   |
| `LANGFUSE_HOST`      | Langfuse 主机（默认 `cloud.langfuse.com`，US 区域用 `us.cloud.langfuse.com`） |
| `SSLKEYLOGFILE`      | TLS 密钥日志文件路径                                                |

## License

MIT