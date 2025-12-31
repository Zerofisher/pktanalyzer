package agent

import (
	"encoding/json"
	"fmt"
	"github.com/Zerofisher/pktanalyzer/agent/llm"
	"github.com/Zerofisher/pktanalyzer/capture"
	"sort"
	"strings"
	"sync"
	"time"
)

// ToolExecutor handles tool execution
type ToolExecutor struct {
	capturer    *capture.Capturer
	packets     []capture.PacketInfo
	packetMu    sync.RWMutex
	isCapturing bool
	captureMu   sync.Mutex
	packetChan  <-chan capture.PacketInfo
	stopChan    chan struct{}
}

func NewToolExecutor() *ToolExecutor {
	return &ToolExecutor{
		packets:  make([]capture.PacketInfo, 0),
		stopChan: make(chan struct{}),
	}
}

// SetCapturer sets the packet capturer
func (t *ToolExecutor) SetCapturer(c *capture.Capturer) {
	t.capturer = c
}

// SetPacketChannel sets the packet channel for receiving packets
func (t *ToolExecutor) SetPacketChannel(ch <-chan capture.PacketInfo) {
	t.packetChan = ch
}

// AddPacket adds a packet to the executor's packet list
func (t *ToolExecutor) AddPacket(p capture.PacketInfo) {
	t.packetMu.Lock()
	defer t.packetMu.Unlock()
	t.packets = append(t.packets, p)
}

// GetPackets returns all captured packets
func (t *ToolExecutor) GetPackets() []capture.PacketInfo {
	t.packetMu.RLock()
	defer t.packetMu.RUnlock()
	result := make([]capture.PacketInfo, len(t.packets))
	copy(result, t.packets)
	return result
}

// GetTools returns all available tools
func GetTools() []llm.Tool {
	return []llm.Tool{
		{
			Name:        "get_packets",
			Description: "获取已捕获的数据包列表。可以指定数量限制和偏移量。",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "返回的最大数据包数量，默认20",
					},
					"offset": map[string]interface{}{
						"type":        "integer",
						"description": "从第几个包开始，默认0（最新的包）",
					},
					"protocol": map[string]interface{}{
						"type":        "string",
						"description": "过滤特定协议，如 TCP, UDP, HTTP, DNS 等",
					},
				},
				"required": []string{},
			},
		},
		{
			Name:        "filter_packets",
			Description: "按条件过滤数据包。支持按IP、端口、协议等过滤。",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"src_ip": map[string]interface{}{
						"type":        "string",
						"description": "源IP地址过滤",
					},
					"dst_ip": map[string]interface{}{
						"type":        "string",
						"description": "目标IP地址过滤",
					},
					"src_port": map[string]interface{}{
						"type":        "string",
						"description": "源端口过滤",
					},
					"dst_port": map[string]interface{}{
						"type":        "string",
						"description": "目标端口过滤",
					},
					"protocol": map[string]interface{}{
						"type":        "string",
						"description": "协议过滤（TCP, UDP, HTTP, DNS, TLS等）",
					},
					"contains": map[string]interface{}{
						"type":        "string",
						"description": "Info字段包含的关键字",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "返回的最大数量，默认20",
					},
				},
				"required": []string{},
			},
		},
		{
			Name:        "analyze_packet",
			Description: "分析特定的数据包，返回详细的协议层信息。",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"packet_number": map[string]interface{}{
						"type":        "integer",
						"description": "要分析的数据包编号",
					},
				},
				"required": []string{"packet_number"},
			},
		},
		{
			Name:        "get_statistics",
			Description: "获取流量统计信息，包括协议分布、流量大小、连接数等。",
			Parameters: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
				"required":   []string{},
			},
		},
		{
			Name:        "explain_protocol",
			Description: "解释网络协议的工作原理和用途。",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"protocol": map[string]interface{}{
						"type":        "string",
						"description": "要解释的协议名称，如 TCP, UDP, HTTP, DNS, TLS, ARP 等",
					},
					"topic": map[string]interface{}{
						"type":        "string",
						"description": "具体话题，如 'three-way handshake', 'TLS handshake' 等",
					},
				},
				"required": []string{"protocol"},
			},
		},
		{
			Name:        "find_connections",
			Description: "查找并列出所有TCP连接或特定主机的连接。",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"ip": map[string]interface{}{
						"type":        "string",
						"description": "过滤特定IP的连接",
					},
					"port": map[string]interface{}{
						"type":        "string",
						"description": "过滤特定端口的连接",
					},
				},
				"required": []string{},
			},
		},
		{
			Name:        "find_dns_queries",
			Description: "查找DNS查询记录，可以搜索特定域名。",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]interface{}{
						"type":        "string",
						"description": "要搜索的域名（支持部分匹配）",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "返回的最大数量，默认20",
					},
				},
				"required": []string{},
			},
		},
		{
			Name:        "find_http_requests",
			Description: "查找HTTP请求，可以按URL、方法等过滤。",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "URL包含的关键字",
					},
					"method": map[string]interface{}{
						"type":        "string",
						"description": "HTTP方法（GET, POST等）",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "返回的最大数量，默认20",
					},
				},
				"required": []string{},
			},
		},
		{
			Name:        "detect_anomalies",
			Description: "检测流量中的异常模式，如端口扫描、大量重传、异常连接等。",
			Parameters: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
				"required":   []string{},
			},
		},
	}
}

// ExecuteTool executes a tool and returns the result
func (t *ToolExecutor) ExecuteTool(name string, input map[string]interface{}) (string, error) {
	switch name {
	case "get_packets":
		return t.getPackets(input)
	case "filter_packets":
		return t.filterPackets(input)
	case "analyze_packet":
		return t.analyzePacket(input)
	case "get_statistics":
		return t.getStatistics(input)
	case "explain_protocol":
		return t.explainProtocol(input)
	case "find_connections":
		return t.findConnections(input)
	case "find_dns_queries":
		return t.findDNSQueries(input)
	case "find_http_requests":
		return t.findHTTPRequests(input)
	case "detect_anomalies":
		return t.detectAnomalies(input)
	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

func (t *ToolExecutor) getPackets(input map[string]interface{}) (string, error) {
	limit := 20
	offset := 0
	protocol := ""

	if v, ok := input["limit"].(float64); ok {
		limit = int(v)
	}
	if v, ok := input["offset"].(float64); ok {
		offset = int(v)
	}
	if v, ok := input["protocol"].(string); ok {
		protocol = strings.ToUpper(v)
	}

	packets := t.GetPackets()

	// Filter by protocol if specified
	if protocol != "" {
		filtered := make([]capture.PacketInfo, 0)
		for _, p := range packets {
			if strings.ToUpper(p.Protocol) == protocol {
				filtered = append(filtered, p)
			}
		}
		packets = filtered
	}

	// Get the latest packets (reverse order)
	total := len(packets)
	if offset >= total {
		return fmt.Sprintf("没有数据包（当前共 %d 个包）", total), nil
	}

	start := total - offset - limit
	if start < 0 {
		start = 0
	}
	end := total - offset

	result := packets[start:end]

	// Reverse to show newest first
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("共 %d 个数据包，显示 %d-%d:\n\n", total, start+1, end))
	sb.WriteString(fmt.Sprintf("%-6s %-15s %-22s %-22s %-8s %s\n", "No.", "Time", "Source", "Destination", "Proto", "Info"))
	sb.WriteString(strings.Repeat("-", 100) + "\n")

	for _, p := range result {
		timeStr := p.Timestamp.Format("15:04:05.000")
		src := p.SrcIP
		if p.SrcPort != "" {
			src += ":" + p.SrcPort
		}
		dst := p.DstIP
		if p.DstPort != "" {
			dst += ":" + p.DstPort
		}
		info := p.Info
		if len(info) > 50 {
			info = info[:50] + "..."
		}
		sb.WriteString(fmt.Sprintf("%-6d %-15s %-22s %-22s %-8s %s\n",
			p.Number, timeStr, src, dst, p.Protocol, info))
	}

	return sb.String(), nil
}

func (t *ToolExecutor) filterPackets(input map[string]interface{}) (string, error) {
	packets := t.GetPackets()
	filtered := make([]capture.PacketInfo, 0)

	srcIP, _ := input["src_ip"].(string)
	dstIP, _ := input["dst_ip"].(string)
	srcPort, _ := input["src_port"].(string)
	dstPort, _ := input["dst_port"].(string)
	protocol, _ := input["protocol"].(string)
	contains, _ := input["contains"].(string)
	limit := 20
	if v, ok := input["limit"].(float64); ok {
		limit = int(v)
	}

	for _, p := range packets {
		match := true

		if srcIP != "" && !strings.Contains(p.SrcIP, srcIP) {
			match = false
		}
		if dstIP != "" && !strings.Contains(p.DstIP, dstIP) {
			match = false
		}
		if srcPort != "" && p.SrcPort != srcPort {
			match = false
		}
		if dstPort != "" && p.DstPort != dstPort {
			match = false
		}
		if protocol != "" && !strings.EqualFold(p.Protocol, protocol) {
			match = false
		}
		if contains != "" && !strings.Contains(strings.ToLower(p.Info), strings.ToLower(contains)) {
			match = false
		}

		if match {
			filtered = append(filtered, p)
		}
	}

	if len(filtered) == 0 {
		return "没有找到匹配的数据包", nil
	}

	// Limit results
	if len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("找到 %d 个匹配的数据包:\n\n", len(filtered)))
	sb.WriteString(fmt.Sprintf("%-6s %-15s %-22s %-22s %-8s %s\n", "No.", "Time", "Source", "Destination", "Proto", "Info"))
	sb.WriteString(strings.Repeat("-", 100) + "\n")

	for _, p := range filtered {
		timeStr := p.Timestamp.Format("15:04:05.000")
		src := p.SrcIP
		if p.SrcPort != "" {
			src += ":" + p.SrcPort
		}
		dst := p.DstIP
		if p.DstPort != "" {
			dst += ":" + p.DstPort
		}
		info := p.Info
		if len(info) > 50 {
			info = info[:50] + "..."
		}
		sb.WriteString(fmt.Sprintf("%-6d %-15s %-22s %-22s %-8s %s\n",
			p.Number, timeStr, src, dst, p.Protocol, info))
	}

	return sb.String(), nil
}

func (t *ToolExecutor) analyzePacket(input map[string]interface{}) (string, error) {
	packetNum, ok := input["packet_number"].(float64)
	if !ok {
		return "", fmt.Errorf("packet_number is required")
	}

	packets := t.GetPackets()
	num := int(packetNum)

	var target *capture.PacketInfo
	for i := range packets {
		if packets[i].Number == num {
			target = &packets[i]
			break
		}
	}

	if target == nil {
		return fmt.Sprintf("未找到编号为 %d 的数据包", num), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== 数据包 #%d 详细分析 ===\n\n", num))
	sb.WriteString(fmt.Sprintf("时间: %s\n", target.Timestamp.Format("2006-01-02 15:04:05.000000")))
	sb.WriteString(fmt.Sprintf("长度: %d 字节\n", target.Length))
	sb.WriteString(fmt.Sprintf("协议: %s\n", target.Protocol))
	sb.WriteString(fmt.Sprintf("信息: %s\n\n", target.Info))

	// Layer details
	for _, layer := range target.Layers {
		sb.WriteString(fmt.Sprintf("--- %s ---\n", layer.Name))
		for _, detail := range layer.Details {
			sb.WriteString(fmt.Sprintf("  %s\n", detail))
		}
		sb.WriteString("\n")
	}

	// Hex dump (first 128 bytes)
	if len(target.RawData) > 0 {
		sb.WriteString("--- Hex Dump (前128字节) ---\n")
		maxLen := 128
		if len(target.RawData) < maxLen {
			maxLen = len(target.RawData)
		}
		for i := 0; i < maxLen; i += 16 {
			sb.WriteString(fmt.Sprintf("%04x  ", i))
			// Hex
			for j := 0; j < 16; j++ {
				if i+j < maxLen {
					sb.WriteString(fmt.Sprintf("%02x ", target.RawData[i+j]))
				} else {
					sb.WriteString("   ")
				}
				if j == 7 {
					sb.WriteString(" ")
				}
			}
			sb.WriteString(" |")
			// ASCII
			for j := 0; j < 16 && i+j < maxLen; j++ {
				b := target.RawData[i+j]
				if b >= 32 && b <= 126 {
					sb.WriteByte(b)
				} else {
					sb.WriteByte('.')
				}
			}
			sb.WriteString("|\n")
		}
	}

	return sb.String(), nil
}

func (t *ToolExecutor) getStatistics(input map[string]interface{}) (string, error) {
	packets := t.GetPackets()

	if len(packets) == 0 {
		return "没有捕获到数据包", nil
	}

	// Protocol distribution
	protocols := make(map[string]int)
	// IP statistics
	srcIPs := make(map[string]int)
	dstIPs := make(map[string]int)
	// Port statistics
	dstPorts := make(map[string]int)
	// Total bytes
	totalBytes := 0

	for _, p := range packets {
		protocols[p.Protocol]++
		if p.SrcIP != "" {
			srcIPs[p.SrcIP]++
		}
		if p.DstIP != "" {
			dstIPs[p.DstIP]++
		}
		if p.DstPort != "" {
			dstPorts[p.DstPort]++
		}
		totalBytes += p.Length
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== 流量统计 ===\n\n"))
	sb.WriteString(fmt.Sprintf("总数据包: %d\n", len(packets)))
	sb.WriteString(fmt.Sprintf("总数据量: %s\n", formatBytes(totalBytes)))

	if len(packets) > 1 {
		duration := packets[len(packets)-1].Timestamp.Sub(packets[0].Timestamp)
		sb.WriteString(fmt.Sprintf("时间跨度: %s\n", duration.Round(time.Millisecond)))
		if duration > 0 {
			pps := float64(len(packets)) / duration.Seconds()
			bps := float64(totalBytes*8) / duration.Seconds()
			sb.WriteString(fmt.Sprintf("平均速率: %.1f pps, %s/s\n", pps, formatBits(int(bps))))
		}
	}

	// Top protocols
	sb.WriteString("\n--- 协议分布 ---\n")
	protocolList := sortMapByValue(protocols)
	for i, kv := range protocolList {
		if i >= 10 {
			break
		}
		pct := float64(kv.Value) * 100 / float64(len(packets))
		sb.WriteString(fmt.Sprintf("  %-12s %6d (%5.1f%%)\n", kv.Key, kv.Value, pct))
	}

	// Top source IPs
	sb.WriteString("\n--- Top 源IP ---\n")
	srcList := sortMapByValue(srcIPs)
	for i, kv := range srcList {
		if i >= 5 {
			break
		}
		sb.WriteString(fmt.Sprintf("  %-18s %6d\n", kv.Key, kv.Value))
	}

	// Top destination IPs
	sb.WriteString("\n--- Top 目标IP ---\n")
	dstList := sortMapByValue(dstIPs)
	for i, kv := range dstList {
		if i >= 5 {
			break
		}
		sb.WriteString(fmt.Sprintf("  %-18s %6d\n", kv.Key, kv.Value))
	}

	// Top destination ports
	sb.WriteString("\n--- Top 目标端口 ---\n")
	portList := sortMapByValue(dstPorts)
	for i, kv := range portList {
		if i >= 5 {
			break
		}
		portName := capture.GetPortName(parsePort(kv.Key))
		if portName != "" {
			sb.WriteString(fmt.Sprintf("  %-6s (%s) %6d\n", kv.Key, portName, kv.Value))
		} else {
			sb.WriteString(fmt.Sprintf("  %-18s %6d\n", kv.Key, kv.Value))
		}
	}

	return sb.String(), nil
}

func (t *ToolExecutor) explainProtocol(input map[string]interface{}) (string, error) {
	protocol, _ := input["protocol"].(string)
	topic, _ := input["topic"].(string)

	protocol = strings.ToUpper(protocol)

	explanations := map[string]string{
		"TCP": `TCP (传输控制协议) - 面向连接的可靠传输协议

主要特点:
- 三次握手建立连接 (SYN → SYN-ACK → ACK)
- 四次挥手断开连接 (FIN → ACK → FIN → ACK)
- 序列号和确认号保证数据顺序和可靠传输
- 滑动窗口进行流量控制
- 拥塞控制避免网络过载

常见标志位:
- SYN: 同步，发起连接
- ACK: 确认
- FIN: 结束，断开连接
- RST: 重置，强制断开
- PSH: 推送，立即传递给应用层

常见问题:
- 重传 (Retransmission): 数据包丢失需要重发
- 乱序 (Out-of-Order): 数据包到达顺序与发送顺序不同
- 零窗口 (Zero Window): 接收方缓冲区满`,

		"UDP": `UDP (用户数据报协议) - 无连接的快速传输协议

主要特点:
- 无连接：不需要建立连接，直接发送
- 不可靠：不保证数据到达，不重传
- 无序：不保证数据包顺序
- 轻量：头部只有8字节

适用场景:
- DNS 查询
- 视频/音频流
- 在线游戏
- VoIP

与TCP比较:
- 速度更快，延迟更低
- 没有拥塞控制
- 适合实时应用`,

		"HTTP": `HTTP (超文本传输协议) - Web通信协议

请求方法:
- GET: 获取资源
- POST: 提交数据
- PUT: 更新资源
- DELETE: 删除资源
- HEAD: 获取头部信息

状态码:
- 2xx: 成功 (200 OK, 201 Created)
- 3xx: 重定向 (301 永久, 302 临时, 304 未修改)
- 4xx: 客户端错误 (400 错误请求, 401 未授权, 403 禁止, 404 未找到)
- 5xx: 服务器错误 (500 内部错误, 502 网关错误, 503 服务不可用)

HTTP/1.1 vs HTTP/2:
- HTTP/2 支持多路复用
- HTTP/2 头部压缩
- HTTP/2 服务器推送`,

		"DNS": `DNS (域名系统) - 域名解析协议

查询类型:
- A: IPv4 地址
- AAAA: IPv6 地址
- CNAME: 别名记录
- MX: 邮件服务器
- NS: 域名服务器
- TXT: 文本记录
- PTR: 反向解析

解析过程:
1. 本地缓存查询
2. 递归查询 DNS 服务器
3. 根域名服务器 → 顶级域名服务器 → 权威域名服务器

安全问题:
- DNS 欺骗/投毒
- DNS 放大攻击
- DNSSEC 提供验证`,

		"TLS": `TLS (传输层安全) - 加密通信协议

握手过程 (TLS 1.2):
1. Client Hello: 客户端支持的密码套件
2. Server Hello: 选择密码套件
3. Certificate: 服务器证书
4. Key Exchange: 密钥交换
5. Finished: 握手完成

TLS 1.3 改进:
- 握手只需 1-RTT
- 移除不安全的密码套件
- 加密更多握手数据

密码套件示例:
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- ECDHE: 密钥交换算法
- RSA: 身份验证
- AES_256_GCM: 加密算法
- SHA384: 哈希算法`,

		"ARP": `ARP (地址解析协议) - IP到MAC地址映射

工作原理:
1. 发送 ARP 请求广播："谁有 IP x.x.x.x？"
2. 目标主机响应："我有，MAC 是 xx:xx:xx:xx:xx:xx"
3. 发送方缓存映射关系

ARP 缓存:
- 动态条目：有超时时间
- 静态条目：手动配置

安全问题:
- ARP 欺骗/投毒攻击
- 中间人攻击
- 防护：静态ARP、VLAN、交换机端口安全`,

		"ICMP": `ICMP (互联网控制消息协议) - 网络诊断协议

常见类型:
- Type 0: Echo Reply (ping响应)
- Type 3: Destination Unreachable
- Type 8: Echo Request (ping请求)
- Type 11: Time Exceeded (TTL超时)

用途:
- ping: 检测主机可达性
- traceroute: 追踪路由路径
- 错误报告

安全考虑:
- ICMP 泛洪攻击
- Smurf 攻击
- 许多防火墙限制 ICMP`,
	}

	if explanation, ok := explanations[protocol]; ok {
		if topic != "" {
			return fmt.Sprintf("协议: %s\n话题: %s\n\n%s\n\n(可以问我更具体的问题)", protocol, topic, explanation), nil
		}
		return explanation, nil
	}

	return fmt.Sprintf("暂无 %s 协议的详细解释。支持的协议: TCP, UDP, HTTP, DNS, TLS, ARP, ICMP", protocol), nil
}

func (t *ToolExecutor) findConnections(input map[string]interface{}) (string, error) {
	packets := t.GetPackets()
	filterIP, _ := input["ip"].(string)
	filterPort, _ := input["port"].(string)

	// Track connections
	type connKey struct {
		srcIP, dstIP, srcPort, dstPort string
	}
	type connInfo struct {
		key       connKey
		packets   int
		bytes     int
		startTime time.Time
		endTime   time.Time
		synSeen   bool
		finSeen   bool
	}

	connections := make(map[string]*connInfo)

	for _, p := range packets {
		if p.Protocol != "TCP" {
			continue
		}

		// Apply filters
		if filterIP != "" && p.SrcIP != filterIP && p.DstIP != filterIP {
			continue
		}
		if filterPort != "" && p.SrcPort != filterPort && p.DstPort != filterPort {
			continue
		}

		// Normalize connection key (lower IP:port first)
		var key string
		if p.SrcIP < p.DstIP || (p.SrcIP == p.DstIP && p.SrcPort < p.DstPort) {
			key = fmt.Sprintf("%s:%s-%s:%s", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
		} else {
			key = fmt.Sprintf("%s:%s-%s:%s", p.DstIP, p.DstPort, p.SrcIP, p.SrcPort)
		}

		if conn, ok := connections[key]; ok {
			conn.packets++
			conn.bytes += p.Length
			conn.endTime = p.Timestamp
			if strings.Contains(p.Info, "SYN") && !strings.Contains(p.Info, "ACK") {
				conn.synSeen = true
			}
			if strings.Contains(p.Info, "FIN") {
				conn.finSeen = true
			}
		} else {
			connections[key] = &connInfo{
				packets:   1,
				bytes:     p.Length,
				startTime: p.Timestamp,
				endTime:   p.Timestamp,
				synSeen:   strings.Contains(p.Info, "SYN") && !strings.Contains(p.Info, "ACK"),
				finSeen:   strings.Contains(p.Info, "FIN"),
			}
		}
	}

	if len(connections) == 0 {
		return "没有找到TCP连接", nil
	}

	// Sort by packet count
	type kv struct {
		Key   string
		Value *connInfo
	}
	var sorted []kv
	for k, v := range connections {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value.packets > sorted[j].Value.packets
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("找到 %d 个TCP连接:\n\n", len(connections)))
	sb.WriteString(fmt.Sprintf("%-45s %8s %10s %s\n", "Connection", "Packets", "Bytes", "State"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for i, kv := range sorted {
		if i >= 20 {
			sb.WriteString(fmt.Sprintf("... 还有 %d 个连接\n", len(sorted)-20))
			break
		}
		state := "Active"
		if kv.Value.synSeen && kv.Value.finSeen {
			state = "Closed"
		} else if kv.Value.synSeen {
			state = "Established"
		}
		sb.WriteString(fmt.Sprintf("%-45s %8d %10s %s\n",
			kv.Key, kv.Value.packets, formatBytes(kv.Value.bytes), state))
	}

	return sb.String(), nil
}

func (t *ToolExecutor) findDNSQueries(input map[string]interface{}) (string, error) {
	packets := t.GetPackets()
	domain, _ := input["domain"].(string)
	limit := 20
	if v, ok := input["limit"].(float64); ok {
		limit = int(v)
	}

	var results []capture.PacketInfo
	for _, p := range packets {
		if p.Protocol != "DNS" {
			continue
		}
		if domain != "" && !strings.Contains(strings.ToLower(p.Info), strings.ToLower(domain)) {
			continue
		}
		results = append(results, p)
	}

	if len(results) == 0 {
		return "没有找到DNS查询", nil
	}

	if len(results) > limit {
		results = results[len(results)-limit:]
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("找到 %d 个DNS查询:\n\n", len(results)))
	sb.WriteString(fmt.Sprintf("%-6s %-15s %-18s %s\n", "No.", "Time", "Source", "Info"))
	sb.WriteString(strings.Repeat("-", 90) + "\n")

	for _, p := range results {
		timeStr := p.Timestamp.Format("15:04:05.000")
		sb.WriteString(fmt.Sprintf("%-6d %-15s %-18s %s\n",
			p.Number, timeStr, p.SrcIP, p.Info))
	}

	return sb.String(), nil
}

func (t *ToolExecutor) findHTTPRequests(input map[string]interface{}) (string, error) {
	packets := t.GetPackets()
	url, _ := input["url"].(string)
	method, _ := input["method"].(string)
	limit := 20
	if v, ok := input["limit"].(float64); ok {
		limit = int(v)
	}

	var results []capture.PacketInfo
	for _, p := range packets {
		if p.Protocol != "HTTP" && p.Protocol != "HTTPS" {
			continue
		}
		if url != "" && !strings.Contains(strings.ToLower(p.Info), strings.ToLower(url)) {
			continue
		}
		if method != "" && !strings.HasPrefix(strings.ToUpper(p.Info), strings.ToUpper(method)) {
			continue
		}
		results = append(results, p)
	}

	if len(results) == 0 {
		return "没有找到HTTP请求", nil
	}

	if len(results) > limit {
		results = results[len(results)-limit:]
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("找到 %d 个HTTP请求:\n\n", len(results)))
	sb.WriteString(fmt.Sprintf("%-6s %-15s %-22s %s\n", "No.", "Time", "Destination", "Request"))
	sb.WriteString(strings.Repeat("-", 100) + "\n")

	for _, p := range results {
		timeStr := p.Timestamp.Format("15:04:05.000")
		dst := p.DstIP
		if p.DstPort != "" {
			dst += ":" + p.DstPort
		}
		info := p.Info
		if len(info) > 60 {
			info = info[:60] + "..."
		}
		sb.WriteString(fmt.Sprintf("%-6d %-15s %-22s %s\n",
			p.Number, timeStr, dst, info))
	}

	return sb.String(), nil
}

func (t *ToolExecutor) detectAnomalies(input map[string]interface{}) (string, error) {
	packets := t.GetPackets()

	if len(packets) == 0 {
		return "没有数据包可分析", nil
	}

	var anomalies []string

	// 1. Detect port scanning (many SYN to different ports from same IP)
	synByIP := make(map[string]map[string]bool)
	for _, p := range packets {
		if p.Protocol == "TCP" && strings.Contains(p.Info, "SYN") && !strings.Contains(p.Info, "ACK") {
			if synByIP[p.SrcIP] == nil {
				synByIP[p.SrcIP] = make(map[string]bool)
			}
			synByIP[p.SrcIP][p.DstPort] = true
		}
	}
	for ip, ports := range synByIP {
		if len(ports) > 10 {
			anomalies = append(anomalies, fmt.Sprintf("⚠️  可能的端口扫描: %s 向 %d 个不同端口发送了 SYN", ip, len(ports)))
		}
	}

	// 2. Detect TCP RST flood
	rstCount := make(map[string]int)
	for _, p := range packets {
		if p.Protocol == "TCP" && strings.Contains(p.Info, "RST") {
			rstCount[p.SrcIP]++
		}
	}
	for ip, count := range rstCount {
		if count > 50 {
			anomalies = append(anomalies, fmt.Sprintf("⚠️  大量 RST 包: %s 发送了 %d 个 RST 包", ip, count))
		}
	}

	// 3. Detect potential DNS tunneling (large DNS responses)
	for _, p := range packets {
		if p.Protocol == "DNS" && p.Length > 512 {
			anomalies = append(anomalies, fmt.Sprintf("⚠️  异常大的 DNS 包 (#%d): %d 字节，可能是 DNS 隧道", p.Number, p.Length))
		}
	}

	// 4. Detect ARP spoofing (multiple MACs for same IP)
	arpMACs := make(map[string]map[string]bool)
	for _, p := range packets {
		if p.Protocol == "ARP" {
			if arpMACs[p.SrcIP] == nil {
				arpMACs[p.SrcIP] = make(map[string]bool)
			}
			arpMACs[p.SrcIP][p.SrcMAC] = true
		}
	}
	for ip, macs := range arpMACs {
		if len(macs) > 1 {
			macList := make([]string, 0, len(macs))
			for mac := range macs {
				macList = append(macList, mac)
			}
			anomalies = append(anomalies, fmt.Sprintf("⚠️  可能的 ARP 欺骗: IP %s 对应多个 MAC: %v", ip, macList))
		}
	}

	// 5. Detect retransmissions
	retransCount := 0
	for _, p := range packets {
		if strings.Contains(p.Info, "Retransmission") || strings.Contains(p.Info, "retrans") {
			retransCount++
		}
	}
	if retransCount > 0 {
		pct := float64(retransCount) * 100 / float64(len(packets))
		if pct > 5 {
			anomalies = append(anomalies, fmt.Sprintf("⚠️  高重传率: %d 次重传 (%.1f%%)，可能存在网络问题", retransCount, pct))
		}
	}

	if len(anomalies) == 0 {
		return "✅ 未检测到明显异常", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("检测到 %d 个潜在异常:\n\n", len(anomalies)))
	for _, a := range anomalies {
		sb.WriteString(a + "\n")
	}

	return sb.String(), nil
}

// Helper functions
type keyValue struct {
	Key   string
	Value int
}

func sortMapByValue(m map[string]int) []keyValue {
	var sorted []keyValue
	for k, v := range m {
		sorted = append(sorted, keyValue{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})
	return sorted
}

func formatBytes(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}

func formatBits(bits int) string {
	if bits < 1000 {
		return fmt.Sprintf("%d bps", bits)
	} else if bits < 1000*1000 {
		return fmt.Sprintf("%.1f Kbps", float64(bits)/1000)
	} else if bits < 1000*1000*1000 {
		return fmt.Sprintf("%.1f Mbps", float64(bits)/(1000*1000))
	}
	return fmt.Sprintf("%.1f Gbps", float64(bits)/(1000*1000*1000))
}

func parsePort(s string) uint16 {
	var port uint16
	fmt.Sscanf(s, "%d", &port)
	return port
}

// MarshalJSON for proper JSON serialization
func (t *ToolExecutor) MarshalPackets() ([]byte, error) {
	t.packetMu.RLock()
	defer t.packetMu.RUnlock()
	return json.Marshal(t.packets)
}
