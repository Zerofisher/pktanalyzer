package agent

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Zerofisher/pktanalyzer/agent/llm"
	"github.com/Zerofisher/pktanalyzer/capture"
)

// ToolExecutor handles tool execution with security constraints
type ToolExecutor struct {
	capturer   *capture.Capturer
	packets    []capture.PacketInfo
	packetMu   sync.RWMutex
	packetChan <-chan capture.PacketInfo
	stopChan   chan struct{}

	// Security configuration
	redactConfig  *RedactConfig
	rawDataPolicy *RawDataPolicy
	lastUserInput string // For authorization checks

	// Authorization system
	authStore *AuthorizationStore
}

func NewToolExecutor() *ToolExecutor {
	return &ToolExecutor{
		packets:       make([]capture.PacketInfo, 0),
		stopChan:      make(chan struct{}),
		redactConfig:  DefaultRedactConfig(),
		rawDataPolicy: DefaultRawDataPolicy(),
		authStore:     NewAuthorizationStore(),
	}
}

// SetRedactConfig sets the redaction configuration
func (t *ToolExecutor) SetRedactConfig(cfg *RedactConfig) {
	t.redactConfig = cfg
}

// SetRawDataPolicy sets the raw data policy
func (t *ToolExecutor) SetRawDataPolicy(policy *RawDataPolicy) {
	t.rawDataPolicy = policy
}

// SetLastUserInput stores the last user input for authorization checks
func (t *ToolExecutor) SetLastUserInput(input string) {
	t.lastUserInput = input
}

// GetAuthorizationStore returns the authorization store for external access
func (t *ToolExecutor) GetAuthorizationStore() *AuthorizationStore {
	return t.authStore
}

// GrantRawDataAuthorization grants raw data authorization
// If forSession is true, grants session-wide authorization (even without pending request)
func (t *ToolExecutor) GrantRawDataAuthorization(forSession bool) {
	if forSession {
		// Direct session grant - works even without pending request
		t.authStore.GrantSessionAuthorization(AuthTypeRawData)
	}
	// Also grant pending request if exists
	t.authStore.GrantAuthorization(forSession)
}

// DenyRawDataAuthorization denies the pending raw data authorization
func (t *ToolExecutor) DenyRawDataAuthorization() {
	t.authStore.DenyAuthorization()
}

// ClearPendingAuthorization clears the pending authorization request
func (t *ToolExecutor) ClearPendingAuthorization() {
	t.authStore.ClearPendingRequest()
}

// GetPendingConfirmation returns the current pending confirmation request
func (t *ToolExecutor) GetPendingConfirmation() *ConfirmationRequest {
	return t.authStore.GetPendingRequest()
}

// HasPendingConfirmation returns true if there's a pending confirmation
func (t *ToolExecutor) HasPendingConfirmation() bool {
	req := t.authStore.GetPendingRequest()
	return req != nil && !req.Responded
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

// GetTools returns all available tools with updated descriptions
func GetTools() []llm.Tool {
	return []llm.Tool{
		{
			Name:        "get_packets",
			Description: fmt.Sprintf("获取已捕获的数据包列表。limit最大%d，offset最大%d。", MaxLimit, MaxOffset),
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": fmt.Sprintf("返回的最大数据包数量，默认20，最大%d", MaxLimit),
					},
					"offset": map[string]interface{}{
						"type":        "integer",
						"description": fmt.Sprintf("从第几个包开始，默认0，最大%d", MaxOffset),
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
			Description: fmt.Sprintf("按条件过滤数据包。字符串参数最长%d字符，limit最大%d。", MaxStringLen, MaxLimit),
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
						"description": fmt.Sprintf("Info字段包含的关键字（最长%d字符）", MaxStringLen),
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": fmt.Sprintf("返回的最大数量，默认20，最大%d", MaxLimit),
					},
				},
				"required": []string{},
			},
		},
		{
			Name:        "analyze_packet",
			Description: "分析特定的数据包。默认不返回原始数据(hex dump)。如需查看原始数据，需设置 include_raw=true 且用户明确授权。",
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"packet_number": map[string]interface{}{
						"type":        "integer",
						"description": "要分析的数据包编号（必须为正数且存在）",
					},
					"include_raw": map[string]interface{}{
						"type":        "boolean",
						"description": fmt.Sprintf("是否包含原始数据(hex dump)，默认false。设为true时最多返回%d字节，且需要用户明确授权", MaxRawBytes),
					},
				},
				"required": []string{"packet_number"},
			},
		},
		{
			Name:        "get_statistics",
			Description: "获取流量统计信息，包括协议分布、流量大小、连接数等。建议优先使用此工具了解整体情况后再下钻。",
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
			Description: fmt.Sprintf("查找并列出所有TCP连接。结果包含证据引用(Evidence)以便定位相关包。最多返回%d条连接。", MaxLimit),
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
			Description: fmt.Sprintf("查找DNS查询记录。结果包含证据引用(Evidence)，limit最大%d。", MaxLimit),
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]interface{}{
						"type":        "string",
						"description": fmt.Sprintf("要搜索的域名（支持部分匹配，最长%d字符）", MaxStringLen),
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": fmt.Sprintf("返回的最大数量，默认20，最大%d", MaxLimit),
					},
				},
				"required": []string{},
			},
		},
		{
			Name:        "find_http_requests",
			Description: fmt.Sprintf("查找HTTP请求。结果包含证据引用(Evidence)，limit最大%d。", MaxLimit),
			Parameters: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": fmt.Sprintf("URL包含的关键字（最长%d字符）", MaxStringLen),
					},
					"method": map[string]interface{}{
						"type":        "string",
						"description": "HTTP方法（GET, POST等）",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": fmt.Sprintf("返回的最大数量，默认20，最大%d", MaxLimit),
					},
				},
				"required": []string{},
			},
		},
		{
			Name:        "detect_anomalies",
			Description: "检测流量中的异常模式。结果包含证据引用(Evidence)，列出关键包编号以便快速定位。",
			Parameters: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
				"required":   []string{},
			},
		},
	}
}

// GetToolNames returns a set of valid tool names for allowlist checking
func GetToolNames() map[string]bool {
	tools := GetTools()
	names := make(map[string]bool, len(tools))
	for _, t := range tools {
		names[t.Name] = true
	}
	return names
}

// ExecuteTool executes a tool and returns the result with security constraints
func (t *ToolExecutor) ExecuteTool(name string, input map[string]interface{}) (string, error) {
	// Allowlist check
	validTools := GetToolNames()
	if !validTools[name] {
		return "", fmt.Errorf("未知工具: %s (允许的工具: %v)", name, getToolNameList())
	}

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

func getToolNameList() []string {
	tools := GetTools()
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.Name
	}
	return names
}

func (t *ToolExecutor) getPackets(input map[string]interface{}) (string, error) {
	// Use validated/clamped parameters
	limit := ValidateLimit(input)
	offset := ValidateOffset(input)
	protocol := ValidateStringParam(input, "protocol")
	if protocol != "" {
		protocol = strings.ToUpper(protocol)
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

	// Collect evidence
	evidence := &Evidence{
		PacketIDs:    make([]int, 0, len(result)),
		EvidenceType: "packets",
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("共 %d 个数据包，显示 %d-%d:\n\n", total, start+1, end))
	sb.WriteString(fmt.Sprintf("%-6s %-15s %-22s %-22s %-8s %s\n", "No.", "Time", "Source", "Destination", "Proto", "Info"))
	sb.WriteString(strings.Repeat("-", 100) + "\n")

	for _, p := range result {
		evidence.PacketIDs = append(evidence.PacketIDs, p.Number)

		timeStr := p.Timestamp.Format("15:04:05.000")
		src := t.formatAddress(p.SrcIP, p.SrcPort)
		dst := t.formatAddress(p.DstIP, p.DstPort)
		info := TruncateInfo(p.Info)

		sb.WriteString(fmt.Sprintf("%-6d %-15s %-22s %-22s %-8s %s\n",
			p.Number, timeStr, src, dst, p.Protocol, info))
	}

	// Add evidence reference
	sb.WriteString(evidence.Format())

	return t.sanitizeOutput(sb.String()), nil
}

func (t *ToolExecutor) filterPackets(input map[string]interface{}) (string, error) {
	packets := t.GetPackets()
	filtered := make([]capture.PacketInfo, 0)

	// Validate and clamp all string parameters
	srcIP := ValidateStringParam(input, "src_ip")
	dstIP := ValidateStringParam(input, "dst_ip")
	srcPort, _ := input["src_port"].(string)
	dstPort, _ := input["dst_port"].(string)
	protocol := ValidateStringParam(input, "protocol")
	contains := ValidateStringParam(input, "contains")
	limit := ValidateLimit(input)

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

	// Collect evidence
	evidence := &Evidence{
		PacketIDs:    make([]int, 0, len(filtered)),
		EvidenceType: "filter",
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("找到 %d 个匹配的数据包:\n\n", len(filtered)))
	sb.WriteString(fmt.Sprintf("%-6s %-15s %-22s %-22s %-8s %s\n", "No.", "Time", "Source", "Destination", "Proto", "Info"))
	sb.WriteString(strings.Repeat("-", 100) + "\n")

	for _, p := range filtered {
		evidence.PacketIDs = append(evidence.PacketIDs, p.Number)

		timeStr := p.Timestamp.Format("15:04:05.000")
		src := t.formatAddress(p.SrcIP, p.SrcPort)
		dst := t.formatAddress(p.DstIP, p.DstPort)
		info := TruncateInfo(p.Info)

		sb.WriteString(fmt.Sprintf("%-6d %-15s %-22s %-22s %-8s %s\n",
			p.Number, timeStr, src, dst, p.Protocol, info))
	}

	sb.WriteString(evidence.Format())

	return t.sanitizeOutput(sb.String()), nil
}

func (t *ToolExecutor) analyzePacket(input map[string]interface{}) (string, error) {
	packetNum, ok := input["packet_number"].(float64)
	if !ok {
		return "", fmt.Errorf("packet_number 参数必须提供且为正整数")
	}

	num := int(packetNum)
	if num <= 0 {
		return "", fmt.Errorf("packet_number 必须为正整数，收到: %d", num)
	}

	packets := t.GetPackets()
	var target *capture.PacketInfo
	for i := range packets {
		if packets[i].Number == num {
			target = &packets[i]
			break
		}
	}

	if target == nil {
		return "", fmt.Errorf("未找到编号为 %d 的数据包（当前共 %d 个包）", num, len(packets))
	}

	// Check include_raw parameter with authorization
	includeRawRequested := false
	if v, ok := input["include_raw"]; ok {
		switch val := v.(type) {
		case bool:
			includeRawRequested = val
		case string:
			includeRawRequested = strings.ToLower(val) == "true"
		}
	}

	var rawAllowed bool
	var maxBytes int
	var authError string
	var needsConfirmation bool

	if includeRawRequested {
		rawAllowed, maxBytes, authError, needsConfirmation = CheckRawDataAuthorization(t.lastUserInput, includeRawRequested, t.authStore)

		// If needs confirmation, create a pending request and return a special message
		if needsConfirmation && !rawAllowed {
			// Create pending confirmation request
			ctx := map[string]interface{}{
				"packet_number": num,
				"tool_input":    input,
			}
			t.authStore.RequestAuthorization(AuthTypeRawData, "analyze_packet", ctx)

			// Return a message indicating confirmation is needed
			return fmt.Sprintf("[CONFIRMATION_REQUIRED]\n授权请求: 显示数据包 #%d 的原始数据\n\n"+
				"原始数据可能包含敏感信息（密码、Token、Cookie等）。\n"+
				"请在 TUI 中按 Y 确认或 N 拒绝。", num), nil
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== 数据包 #%d 详细分析 ===\n\n", num))
	sb.WriteString(fmt.Sprintf("时间: %s\n", target.Timestamp.Format("2006-01-02 15:04:05.000000")))
	sb.WriteString(fmt.Sprintf("长度: %d 字节\n", target.Length))
	sb.WriteString(fmt.Sprintf("协议: %s\n", target.Protocol))
	sb.WriteString(fmt.Sprintf("信息: %s\n\n", TruncateInfo(target.Info)))

	// Layer details
	for _, layer := range target.Layers {
		sb.WriteString(fmt.Sprintf("--- %s ---\n", layer.Name))
		for _, detail := range layer.Details {
			// Sanitize each detail line
			sb.WriteString(fmt.Sprintf("  %s\n", t.sanitizeOutput(detail)))
		}
		sb.WriteString("\n")
	}

	// Raw data handling with security constraints
	if includeRawRequested && rawAllowed && len(target.RawData) > 0 {
		sb.WriteString(fmt.Sprintf("--- Hex Dump (最多%d字节，已标记为敏感输出) ---\n", maxBytes))
		sb.WriteString("⚠️  [敏感数据] 以下为原始数据，可能包含凭据信息\n")

		maxLen := maxBytes
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
		if len(target.RawData) > maxLen {
			sb.WriteString(fmt.Sprintf("... 省略 %d 字节\n", len(target.RawData)-maxLen))
		}
	} else if includeRawRequested && !rawAllowed && authError != "" {
		sb.WriteString(fmt.Sprintf("\n⚠️  原始数据未显示: %s\n", authError))
		sb.WriteString("提示: 如需查看原始数据，请在问题中包含关键词（raw/hex/dump/原始/十六进制）\n")
	}

	// Add evidence
	evidence := &Evidence{
		PacketIDs:    []int{num},
		EvidenceType: "analyze",
	}
	sb.WriteString(evidence.Format())

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

	// Top protocols (limited to top 10)
	sb.WriteString("\n--- 协议分布 ---\n")
	protocolList := sortMapByValue(protocols)
	for i, kv := range protocolList {
		if i >= 10 {
			break
		}
		pct := float64(kv.Value) * 100 / float64(len(packets))
		sb.WriteString(fmt.Sprintf("  %-12s %6d (%5.1f%%)\n", kv.Key, kv.Value, pct))
	}

	// Top source IPs (limited, with redaction note)
	sb.WriteString("\n--- Top 源IP (前5) ---\n")
	srcList := sortMapByValue(srcIPs)
	for i, kv := range srcList {
		if i >= 5 {
			break
		}
		sb.WriteString(fmt.Sprintf("  %-18s %6d\n", t.formatIP(kv.Key), kv.Value))
	}

	// Top destination IPs
	sb.WriteString("\n--- Top 目标IP (前5) ---\n")
	dstList := sortMapByValue(dstIPs)
	for i, kv := range dstList {
		if i >= 5 {
			break
		}
		sb.WriteString(fmt.Sprintf("  %-18s %6d\n", t.formatIP(kv.Key), kv.Value))
	}

	// Top destination ports
	sb.WriteString("\n--- Top 目标端口 (前5) ---\n")
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
	filterIP := ValidateStringParam(input, "ip")
	filterPort, _ := input["port"].(string)

	// Track connections
	type connInfo struct {
		packets   int
		bytes     int
		startTime time.Time
		endTime   time.Time
		synSeen   bool
		finSeen   bool
		pktIDs    []int // Track packet IDs for evidence
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
			conn.pktIDs = append(conn.pktIDs, p.Number)
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
				pktIDs:    []int{p.Number},
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

	// Collect evidence
	evidence := &Evidence{
		PacketIDs:    make([]int, 0),
		Connections:  make([]string, 0),
		EvidenceType: "connections",
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("找到 %d 个TCP连接:\n\n", len(connections)))
	sb.WriteString(fmt.Sprintf("%-45s %8s %10s %s\n", "Connection", "Packets", "Bytes", "State"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	limit := ClampInt(len(sorted), 0, MaxLimit)
	for i, kv := range sorted {
		if i >= limit {
			sb.WriteString(fmt.Sprintf("... 还有 %d 个连接\n", len(sorted)-limit))
			break
		}
		state := "Active"
		if kv.Value.synSeen && kv.Value.finSeen {
			state = "Closed"
		} else if kv.Value.synSeen {
			state = "Established"
		}

		// Format connection key with redaction if enabled
		connDisplay := t.formatConnectionKey(kv.Key)
		sb.WriteString(fmt.Sprintf("%-45s %8d %10s %s\n",
			connDisplay, kv.Value.packets, formatBytes(kv.Value.bytes), state))

		// Add to evidence
		evidence.Connections = append(evidence.Connections, kv.Key)
		// Add first few packet IDs per connection
		for j, pktID := range kv.Value.pktIDs {
			if j >= 3 { // Limit per connection
				break
			}
			evidence.PacketIDs = append(evidence.PacketIDs, pktID)
		}
	}

	sb.WriteString(evidence.Format())

	return sb.String(), nil
}

func (t *ToolExecutor) findDNSQueries(input map[string]interface{}) (string, error) {
	packets := t.GetPackets()
	domain := ValidateStringParam(input, "domain")
	limit := ValidateLimit(input)

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

	// Collect evidence
	evidence := &Evidence{
		PacketIDs:    make([]int, 0, len(results)),
		EvidenceType: "dns",
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("找到 %d 个DNS查询:\n\n", len(results)))
	sb.WriteString(fmt.Sprintf("%-6s %-15s %-18s %s\n", "No.", "Time", "Source", "Info"))
	sb.WriteString(strings.Repeat("-", 90) + "\n")

	for _, p := range results {
		evidence.PacketIDs = append(evidence.PacketIDs, p.Number)

		timeStr := p.Timestamp.Format("15:04:05.000")
		sb.WriteString(fmt.Sprintf("%-6d %-15s %-18s %s\n",
			p.Number, timeStr, t.formatIP(p.SrcIP), TruncateInfo(p.Info)))
	}

	sb.WriteString(evidence.Format())

	return t.sanitizeOutput(sb.String()), nil
}

func (t *ToolExecutor) findHTTPRequests(input map[string]interface{}) (string, error) {
	packets := t.GetPackets()
	url := ValidateStringParam(input, "url")
	method, _ := input["method"].(string)
	limit := ValidateLimit(input)

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

	// Collect evidence
	evidence := &Evidence{
		PacketIDs:    make([]int, 0, len(results)),
		EvidenceType: "http",
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("找到 %d 个HTTP请求:\n\n", len(results)))
	sb.WriteString(fmt.Sprintf("%-6s %-15s %-22s %s\n", "No.", "Time", "Destination", "Request"))
	sb.WriteString(strings.Repeat("-", 100) + "\n")

	for _, p := range results {
		evidence.PacketIDs = append(evidence.PacketIDs, p.Number)

		timeStr := p.Timestamp.Format("15:04:05.000")
		dst := t.formatAddress(p.DstIP, p.DstPort)
		info := TruncateInfo(p.Info)

		sb.WriteString(fmt.Sprintf("%-6d %-15s %-22s %s\n",
			p.Number, timeStr, dst, info))
	}

	sb.WriteString(evidence.Format())

	return t.sanitizeOutput(sb.String()), nil
}

func (t *ToolExecutor) detectAnomalies(input map[string]interface{}) (string, error) {
	packets := t.GetPackets()

	if len(packets) == 0 {
		return "没有数据包可分析", nil
	}

	type anomaly struct {
		description string
		evidence    *Evidence
	}
	var anomalies []anomaly

	// 1. Detect port scanning (many SYN to different ports from same IP)
	synByIP := make(map[string]map[string]bool)
	synPackets := make(map[string][]int) // Track packet IDs
	for _, p := range packets {
		if p.Protocol == "TCP" && strings.Contains(p.Info, "SYN") && !strings.Contains(p.Info, "ACK") {
			if synByIP[p.SrcIP] == nil {
				synByIP[p.SrcIP] = make(map[string]bool)
				synPackets[p.SrcIP] = make([]int, 0)
			}
			synByIP[p.SrcIP][p.DstPort] = true
			synPackets[p.SrcIP] = append(synPackets[p.SrcIP], p.Number)
		}
	}
	for ip, ports := range synByIP {
		if len(ports) > 10 {
			pktIDs := synPackets[ip]
			if len(pktIDs) > 10 {
				pktIDs = pktIDs[:10]
			}
			anomalies = append(anomalies, anomaly{
				description: fmt.Sprintf("⚠️  可能的端口扫描: %s 向 %d 个不同端口发送了 SYN", t.formatIP(ip), len(ports)),
				evidence: &Evidence{
					PacketIDs:    pktIDs,
					EvidenceType: "port_scan",
				},
			})
		}
	}

	// 2. Detect TCP RST flood
	rstCount := make(map[string]int)
	rstPackets := make(map[string][]int)
	for _, p := range packets {
		if p.Protocol == "TCP" && strings.Contains(p.Info, "RST") {
			rstCount[p.SrcIP]++
			if rstPackets[p.SrcIP] == nil {
				rstPackets[p.SrcIP] = make([]int, 0)
			}
			rstPackets[p.SrcIP] = append(rstPackets[p.SrcIP], p.Number)
		}
	}
	for ip, count := range rstCount {
		if count > 50 {
			pktIDs := rstPackets[ip]
			if len(pktIDs) > 10 {
				pktIDs = pktIDs[:10]
			}
			anomalies = append(anomalies, anomaly{
				description: fmt.Sprintf("⚠️  大量 RST 包: %s 发送了 %d 个 RST 包", t.formatIP(ip), count),
				evidence: &Evidence{
					PacketIDs:    pktIDs,
					EvidenceType: "rst_flood",
				},
			})
		}
	}

	// 3. Detect potential DNS tunneling (large DNS responses)
	var dnsTunnelPackets []int
	for _, p := range packets {
		if p.Protocol == "DNS" && p.Length > 512 {
			dnsTunnelPackets = append(dnsTunnelPackets, p.Number)
			if len(dnsTunnelPackets) >= 10 {
				break
			}
		}
	}
	if len(dnsTunnelPackets) > 0 {
		anomalies = append(anomalies, anomaly{
			description: fmt.Sprintf("⚠️  发现 %d 个异常大的 DNS 包 (>512字节)，可能是 DNS 隧道", len(dnsTunnelPackets)),
			evidence: &Evidence{
				PacketIDs:    dnsTunnelPackets,
				EvidenceType: "dns_tunnel",
			},
		})
	}

	// 4. Detect ARP spoofing (multiple MACs for same IP)
	arpMACs := make(map[string]map[string]bool)
	arpPackets := make(map[string][]int)
	for _, p := range packets {
		if p.Protocol == "ARP" {
			if arpMACs[p.SrcIP] == nil {
				arpMACs[p.SrcIP] = make(map[string]bool)
				arpPackets[p.SrcIP] = make([]int, 0)
			}
			arpMACs[p.SrcIP][p.SrcMAC] = true
			arpPackets[p.SrcIP] = append(arpPackets[p.SrcIP], p.Number)
		}
	}
	for ip, macs := range arpMACs {
		if len(macs) > 1 {
			macList := make([]string, 0, len(macs))
			for mac := range macs {
				macList = append(macList, t.formatMAC(mac))
			}
			pktIDs := arpPackets[ip]
			if len(pktIDs) > 10 {
				pktIDs = pktIDs[:10]
			}
			anomalies = append(anomalies, anomaly{
				description: fmt.Sprintf("⚠️  可能的 ARP 欺骗: IP %s 对应多个 MAC: %v", t.formatIP(ip), macList),
				evidence: &Evidence{
					PacketIDs:    pktIDs,
					EvidenceType: "arp_spoof",
				},
			})
		}
	}

	// 5. Detect retransmissions
	var retransPackets []int
	for _, p := range packets {
		if strings.Contains(p.Info, "Retransmission") || strings.Contains(p.Info, "retrans") {
			retransPackets = append(retransPackets, p.Number)
		}
	}
	if len(retransPackets) > 0 {
		pct := float64(len(retransPackets)) * 100 / float64(len(packets))
		if pct > 5 {
			pktIDs := retransPackets
			if len(pktIDs) > 10 {
				pktIDs = pktIDs[:10]
			}
			anomalies = append(anomalies, anomaly{
				description: fmt.Sprintf("⚠️  高重传率: %d 次重传 (%.1f%%)，可能存在网络问题", len(retransPackets), pct),
				evidence: &Evidence{
					PacketIDs:    pktIDs,
					EvidenceType: "retransmission",
				},
			})
		}
	}

	if len(anomalies) == 0 {
		return "✅ 未检测到明显异常", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("检测到 %d 个潜在异常:\n\n", len(anomalies)))
	for _, a := range anomalies {
		sb.WriteString(a.description + "\n")
		if a.evidence != nil {
			sb.WriteString(fmt.Sprintf("  → 证据包: %v\n", a.evidence.PacketIDs))
		}
	}

	return sb.String(), nil
}

// --- Helper methods ---

// formatAddress formats IP:port with optional redaction
func (t *ToolExecutor) formatAddress(ip, port string) string {
	addr := t.formatIP(ip)
	if port != "" {
		addr += ":" + port
	}
	return addr
}

// formatIP applies redaction to IP if configured
func (t *ToolExecutor) formatIP(ip string) string {
	if t.redactConfig != nil && t.redactConfig.Enabled && t.redactConfig.RedactIPs {
		return RedactIP(ip)
	}
	return ip
}

// formatMAC applies redaction to MAC if configured
func (t *ToolExecutor) formatMAC(mac string) string {
	if t.redactConfig != nil && t.redactConfig.Enabled && t.redactConfig.RedactMACs {
		return RedactMAC(mac)
	}
	return mac
}

// formatConnectionKey formats a connection key with redaction
func (t *ToolExecutor) formatConnectionKey(key string) string {
	if t.redactConfig == nil || !t.redactConfig.Enabled || !t.redactConfig.RedactIPs {
		return key
	}
	// key format: "ip:port-ip:port"
	parts := strings.Split(key, "-")
	if len(parts) != 2 {
		return key
	}
	return t.formatEndpoint(parts[0]) + "-" + t.formatEndpoint(parts[1])
}

func (t *ToolExecutor) formatEndpoint(endpoint string) string {
	// endpoint format: "ip:port"
	lastColon := strings.LastIndex(endpoint, ":")
	if lastColon == -1 {
		return t.formatIP(endpoint)
	}
	ip := endpoint[:lastColon]
	port := endpoint[lastColon+1:]
	return t.formatIP(ip) + ":" + port
}

// sanitizeOutput applies all configured sanitization to output
func (t *ToolExecutor) sanitizeOutput(output string) string {
	return SanitizeToolOutput(output, t.redactConfig)
}

// --- Utility functions ---

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

// MarshalPackets for proper JSON serialization
func (t *ToolExecutor) MarshalPackets() ([]byte, error) {
	t.packetMu.RLock()
	defer t.packetMu.RUnlock()
	return json.Marshal(t.packets)
}
