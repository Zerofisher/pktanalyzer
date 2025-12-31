package ui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	primaryColor   = lipgloss.Color("#7D56F4")
	secondaryColor = lipgloss.Color("#3C3C3C")
	accentColor    = lipgloss.Color("#04B575")
	warningColor   = lipgloss.Color("#FFCC00")
	errorColorVal  = lipgloss.Color("#FF6B6B")
	textColor      = lipgloss.Color("#FAFAFA")
	dimColor       = lipgloss.Color("#626262")

	// Chat colors
	userMsgColor      = lipgloss.Color("#87CEEB") // Light blue
	assistantMsgColor = lipgloss.Color("#98FB98") // Light green
	systemMsgColor    = lipgloss.Color("#FFD700") // Gold

	// Protocol colors
	tcpColor       = lipgloss.Color("#7CB9E8")
	udpColor       = lipgloss.Color("#72BF6A")
	icmpColor      = lipgloss.Color("#FFB347")
	arpColor       = lipgloss.Color("#DDA0DD")
	dnsColor       = lipgloss.Color("#87CEEB")
	httpColor      = lipgloss.Color("#98FB98")
	tlsColor       = lipgloss.Color("#FFD700") // Gold
	httpsColor     = lipgloss.Color("#00FF7F") // Spring Green
	http2Color     = lipgloss.Color("#FF69B4") // Hot Pink for HTTP/2
	websocketColor = lipgloss.Color("#9370DB") // Medium Purple for WebSocket

	// Styles
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(textColor).
			Background(primaryColor).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(textColor).
			Background(secondaryColor).
			Padding(0, 1)

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(textColor).
			Background(primaryColor)

	normalStyle = lipgloss.NewStyle().
			Foreground(textColor)

	dimStyle = lipgloss.NewStyle().
			Foreground(dimColor)

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor)

	helpStyle = lipgloss.NewStyle().
			Foreground(dimColor).
			Padding(0, 1)

	statusStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Background(secondaryColor).
			Padding(0, 1)

	layerHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(accentColor)

	layerDetailStyle = lipgloss.NewStyle().
				Foreground(textColor).
				PaddingLeft(2)

	hexOffsetStyle = lipgloss.NewStyle().
			Foreground(dimColor)

	hexByteStyle = lipgloss.NewStyle().
			Foreground(textColor)

	hexAsciiStyle = lipgloss.NewStyle().
			Foreground(accentColor)

	// Chat styles
	userMsgStyle = lipgloss.NewStyle().
			Foreground(userMsgColor)

	assistantMsgStyle = lipgloss.NewStyle().
				Foreground(assistantMsgColor)

	systemMsgStyle = lipgloss.NewStyle().
			Foreground(systemMsgColor)

	errorStyle = lipgloss.NewStyle().
			Foreground(errorColorVal).
			Bold(true)

	warningStyle = lipgloss.NewStyle().
			Foreground(warningColor).
			Bold(true)

	noteStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#87CEEB")) // Light blue

	successStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true)

	inputStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Background(secondaryColor).
			Padding(0, 1)

	http2Style = lipgloss.NewStyle().
			Foreground(http2Color)

	websocketStyle = lipgloss.NewStyle().
			Foreground(websocketColor)
)

func getProtocolStyle(protocol string) lipgloss.Style {
	switch protocol {
	case "TCP":
		return lipgloss.NewStyle().Foreground(tcpColor)
	case "UDP":
		return lipgloss.NewStyle().Foreground(udpColor)
	case "ICMP", "ICMPv6":
		return lipgloss.NewStyle().Foreground(icmpColor)
	case "ARP":
		return lipgloss.NewStyle().Foreground(arpColor)
	case "DNS":
		return lipgloss.NewStyle().Foreground(dnsColor)
	case "HTTP":
		return lipgloss.NewStyle().Foreground(httpColor)
	case "TLS":
		return lipgloss.NewStyle().Foreground(tlsColor)
	case "HTTPS":
		return lipgloss.NewStyle().Foreground(httpsColor)
	case "WebSocket":
		return lipgloss.NewStyle().Foreground(websocketColor)
	default:
		return normalStyle
	}
}
