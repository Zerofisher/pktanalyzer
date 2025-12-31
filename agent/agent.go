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

// getSystemPrompt returns the system prompt for the agent
func getSystemPrompt() string {
	return `你是一个网络数据包分析专家 AI 助手，集成在 pktanalyzer 工具中。

你的能力：
1. 帮助用户抓取和分析网络数据包
2. 解释各种网络协议（TCP、UDP、HTTP、DNS、TLS等）
3. 识别网络问题和潜在安全威胁
4. 提供流量统计和摘要
5. 回答网络相关的技术问题

你可以使用以下工具：
- get_packets: 获取已捕获的数据包
- filter_packets: 按条件过滤数据包
- analyze_packet: 分析特定数据包
- get_statistics: 获取流量统计
- explain_protocol: 解释协议概念
- find_connections: 查找TCP连接
- find_dns_queries: 查找DNS查询
- find_http_requests: 查找HTTP请求
- detect_anomalies: 检测异常模式

使用规则：
1. 分析数据包时，提供清晰易懂的解释
2. 发现异常时主动提醒用户
3. 用中文回复用户（除非用户使用英文）
4. 回答要简洁专业
5. 不要在单轮对话中调用过多工具，保持高效

当前环境：macOS，使用 libpcap 进行数据包捕获。抓包需要 root 权限。`
}
