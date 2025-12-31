package agent

import (
	"context"
	"fmt"
	"github.com/Zerofisher/pktanalyzer/agent/llm"
	"github.com/Zerofisher/pktanalyzer/agent/providers/claude"
	"github.com/Zerofisher/pktanalyzer/agent/providers/ollama"
	"github.com/Zerofisher/pktanalyzer/agent/providers/openai"
	"github.com/Zerofisher/pktanalyzer/agent/providers/openrouter"
	"github.com/Zerofisher/pktanalyzer/agent/react"
	"github.com/Zerofisher/pktanalyzer/capture"
	"sync"
)

// Agent is the AI agent that can interact with users and execute tools
type Agent struct {
	reactAgent   *react.Agent
	llmClient    llm.Client
	toolExecutor *ToolExecutor
	isProcessing bool
	processingMu sync.Mutex
}

// NewAgent creates a new AI agent
func NewAgent(provider llm.Provider) (*Agent, error) {
	client, err := NewLLMClient(provider)
	if err != nil {
		return nil, err
	}

	toolExecutor := NewToolExecutor()

	// Convert tools to llm.Tool format
	tools := GetTools()

	// Create ReAct agent
	policy := react.DefaultPolicy()
	reactAgent := react.NewAgent(client, tools, &toolExecutorAdapter{toolExecutor}, policy)

	// Set system prompt
	reactAgent.SetSystemPrompt(getSystemPrompt())

	return &Agent{
		reactAgent:   reactAgent,
		llmClient:    client,
		toolExecutor: toolExecutor,
	}, nil
}

// SetCapturer sets the packet capturer for the agent
func (a *Agent) SetCapturer(c *capture.Capturer) {
	a.toolExecutor.SetCapturer(c)
}

// AddPacket adds a packet to the agent's context
func (a *Agent) AddPacket(p capture.PacketInfo) {
	a.toolExecutor.AddPacket(p)
}

// GetPacketCount returns the number of packets captured
func (a *Agent) GetPacketCount() int {
	return len(a.toolExecutor.GetPackets())
}

// Chat sends a message to the AI and returns the response
func (a *Agent) Chat(userMessage string) (string, error) {
	a.processingMu.Lock()
	a.isProcessing = true
	a.processingMu.Unlock()

	defer func() {
		a.processingMu.Lock()
		a.isProcessing = false
		a.processingMu.Unlock()
	}()

	// P0-2: Store user input for raw data authorization checks
	a.toolExecutor.SetLastUserInput(userMessage)

	ctx := context.Background()
	return a.reactAgent.Chat(ctx, userMessage)
}

// StreamEvent re-exports react.StreamEvent for external use
type StreamEvent = react.StreamEvent

// ChatStream sends a message and returns a stream of response events
func (a *Agent) ChatStream(userMessage string) (<-chan StreamEvent, error) {
	a.processingMu.Lock()
	a.isProcessing = true
	a.processingMu.Unlock()

	// P0-2: Store user input for raw data authorization checks
	a.toolExecutor.SetLastUserInput(userMessage)

	ctx := context.Background()
	eventChan, err := a.reactAgent.ChatStream(ctx, userMessage)
	if err != nil {
		a.processingMu.Lock()
		a.isProcessing = false
		a.processingMu.Unlock()
		return nil, err
	}

	// Wrap channel to handle completion
	wrappedChan := make(chan StreamEvent, 100)
	go func() {
		defer close(wrappedChan)
		defer func() {
			a.processingMu.Lock()
			a.isProcessing = false
			a.processingMu.Unlock()
		}()

		for event := range eventChan {
			wrappedChan <- event
		}
	}()

	return wrappedChan, nil
}

// IsProcessing returns whether the agent is currently processing
func (a *Agent) IsProcessing() bool {
	a.processingMu.Lock()
	defer a.processingMu.Unlock()
	return a.isProcessing
}

// GetMessages returns the conversation history
func (a *Agent) GetMessages() []llm.Message {
	return a.reactAgent.GetMessages()
}

// ClearHistory clears the conversation history
func (a *Agent) ClearHistory() {
	a.reactAgent.ClearHistory()
}

// GetProvider returns the LLM provider being used
func (a *Agent) GetProvider() llm.Provider {
	return a.reactAgent.Provider()
}

// --- Authorization methods for TUI interaction ---

// HasPendingConfirmation returns true if there's a pending confirmation request
func (a *Agent) HasPendingConfirmation() bool {
	return a.toolExecutor.HasPendingConfirmation()
}

// GetPendingConfirmation returns the current pending confirmation request
func (a *Agent) GetPendingConfirmation() *ConfirmationRequest {
	return a.toolExecutor.GetPendingConfirmation()
}

// GrantAuthorization grants the pending authorization
// forSession: if true, remember this grant for the entire session
func (a *Agent) GrantAuthorization(forSession bool) {
	a.toolExecutor.GrantRawDataAuthorization(forSession)
}

// DenyAuthorization denies the pending authorization
func (a *Agent) DenyAuthorization() {
	a.toolExecutor.DenyRawDataAuthorization()
}

// ClearPendingAuthorization clears the pending authorization without responding
func (a *Agent) ClearPendingAuthorization() {
	a.toolExecutor.ClearPendingAuthorization()
}

// RetryLastToolCall retries the last tool call that required confirmation
// Returns the result of the retried tool call
func (a *Agent) RetryLastToolCall() (string, error) {
	req := a.toolExecutor.GetPendingConfirmation()
	if req == nil || !req.Responded || !req.Granted {
		return "", fmt.Errorf("no granted authorization to retry")
	}

	// Get the original tool input from context
	toolInput, ok := req.Context["tool_input"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid tool input in authorization context")
	}

	// Clear the pending request before retrying
	a.toolExecutor.ClearPendingAuthorization()

	// Execute the tool again
	return a.toolExecutor.ExecuteTool(req.ToolName, toolInput)
}

// NewLLMClient creates a new LLM client for the specified provider
func NewLLMClient(provider llm.Provider) (llm.Client, error) {
	cfg := llm.ConfigFromEnv(provider)

	switch provider {
	case llm.ProviderClaude:
		return claude.New(cfg)
	case llm.ProviderOpenAI:
		return openai.New(cfg)
	case llm.ProviderOpenRouter:
		return openrouter.New(cfg)
	case llm.ProviderOllama:
		return ollama.New(cfg)
	default:
		// Auto-detect
		detected := llm.DetectProvider()
		if detected == "" {
			return nil, fmt.Errorf("no LLM provider configured. Set one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, or OLLAMA_BASE_URL")
		}
		return NewLLMClient(detected)
	}
}

// DetectProvider detects available LLM provider from environment
func DetectProvider() llm.Provider {
	return llm.DetectProvider()
}

// toolExecutorAdapter adapts ToolExecutor to react.ToolExecutor interface
type toolExecutorAdapter struct {
	executor *ToolExecutor
}

func (a *toolExecutorAdapter) Execute(ctx context.Context, name string, args map[string]any) (string, error) {
	return a.executor.ExecuteTool(name, args)
}

// getSystemPrompt returns the system prompt for the agent with P0-4 rules
func getSystemPrompt() string {
	return `你是一个网络数据包分析专家 AI 助手，集成在 pktanalyzer 工具中。

## 你的能力
1. 帮助用户抓取和分析网络数据包
2. 解释各种网络协议（TCP、UDP、HTTP、DNS、TLS等）
3. 识别网络问题和潜在安全威胁
4. 提供流量统计和摘要
5. 回答网络相关的技术问题

## 可用工具
- get_packets: 获取已捕获的数据包
- filter_packets: 按条件过滤数据包
- analyze_packet: 分析特定数据包（默认不含原始数据）
- get_statistics: 获取流量统计（优先使用）
- explain_protocol: 解释协议概念
- find_connections: 查找TCP连接
- find_dns_queries: 查找DNS查询
- find_http_requests: 查找HTTP请求
- detect_anomalies: 检测异常模式

## 工作规则（必须遵守）

### 1. 先统计后下钻
- 收到分析请求时，**必须先调用 get_statistics** 了解整体流量情况
- 根据统计结果决定是否需要进一步使用 filter_packets 或 find_* 工具
- 避免一开始就获取大量原始数据

### 2. 默认不查看原始数据
- **除非用户明确要求**（使用"原始"、"hex"、"raw"、"十六进制"等关键词），否则不得请求 analyze_packet 的 include_raw=true
- 原始数据可能包含敏感信息（密码、Token、Cookie等）

### 3. 每条结论必须带证据
- 所有分析结论**必须引用具体的包编号**或连接信息
- 格式示例：「检测到 TCP 重传（见包 #12, #18, #33）」
- 工具返回中包含 Evidence 字段，请在回答中引用

### 4. 高效使用工具
- 不要在单轮对话中调用过多工具
- 每次工具调用都有限额限制（limit 最大 50）
- 如果需要更多数据，提示用户缩小范围或添加过滤条件

### 5. 回答风格
- 分析数据包时，提供清晰易懂的解释
- 发现异常时主动提醒用户
- 用中文回复用户（除非用户使用英文）
- 回答要简洁专业

当前环境：macOS，使用 libpcap 进行数据包捕获。抓包需要 root 权限。`
}
