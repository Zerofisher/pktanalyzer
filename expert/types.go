// Package expert provides network traffic analysis and anomaly detection
package expert

import (
	"fmt"
	"time"
)

// Severity represents the severity level of an expert info
type Severity int

const (
	SeverityChat    Severity = iota // Informational, normal behavior
	SeverityNote                    // Notable but not necessarily problematic
	SeverityWarning                 // Potential issue
	SeverityError                   // Definite problem
)

// String returns a human-readable string for the severity
func (s Severity) String() string {
	switch s {
	case SeverityChat:
		return "Chat"
	case SeverityNote:
		return "Note"
	case SeverityWarning:
		return "Warning"
	case SeverityError:
		return "Error"
	default:
		return "Unknown"
	}
}

// Symbol returns a single character symbol for the severity
func (s Severity) Symbol() string {
	switch s {
	case SeverityChat:
		return "."
	case SeverityNote:
		return "i"
	case SeverityWarning:
		return "!"
	case SeverityError:
		return "X"
	default:
		return "?"
	}
}

// Group represents the category of expert info
type Group string

const (
	GroupSequence   Group = "Sequence"   // TCP sequence analysis
	GroupResponse   Group = "Response"   // Request/Response analysis
	GroupProtocol   Group = "Protocol"   // Protocol-level issues
	GroupSecurity   Group = "Security"   // Security concerns
	GroupMalformed  Group = "Malformed"  // Malformed packets
	GroupReassembly Group = "Reassembly" // Reassembly issues
)

// ExpertInfo represents a single expert information entry
type ExpertInfo struct {
	PacketNum   int       // Packet number where issue was detected
	Timestamp   time.Time // Time of the packet
	Severity    Severity  // Severity level
	Group       Group     // Category group
	Protocol    string    // Protocol involved (TCP, DNS, HTTP, etc.)
	Summary     string    // Short summary (e.g., "TCP Retransmission")
	Details     string    // Detailed description
	RelatedPkts []int     // Related packet numbers (for context)
	StreamKey   string    // Stream identifier if applicable
}

// String returns a formatted string representation
func (e *ExpertInfo) String() string {
	return fmt.Sprintf("[%s] #%d %s: %s - %s",
		e.Severity.Symbol(),
		e.PacketNum,
		e.Protocol,
		e.Summary,
		e.Details,
	)
}

// TCPExpertType represents specific TCP expert info types
type TCPExpertType int

const (
	TCPRetransmission TCPExpertType = iota
	TCPFastRetransmission
	TCPSpuriousRetransmission
	TCPDuplicateACK
	TCPTripleDuplicateACK
	TCPOutOfOrder
	TCPPreviousSegmentNotCaptured
	TCPACKedUnseenSegment
	TCPZeroWindow
	TCPZeroWindowProbe
	TCPZeroWindowProbeACK
	TCPWindowUpdate
	TCPWindowFull
	TCPKeepAlive
	TCPKeepAliveACK
	TCPRSTFlag
	TCPConnectionReset
	TCPConnectionRefused
	TCPSYNFlood // Potential SYN flood detected
)

// String returns a human-readable description
func (t TCPExpertType) String() string {
	switch t {
	case TCPRetransmission:
		return "TCP Retransmission"
	case TCPFastRetransmission:
		return "TCP Fast Retransmission"
	case TCPSpuriousRetransmission:
		return "TCP Spurious Retransmission"
	case TCPDuplicateACK:
		return "TCP Duplicate ACK"
	case TCPTripleDuplicateACK:
		return "TCP Triple Duplicate ACK"
	case TCPOutOfOrder:
		return "TCP Out-Of-Order"
	case TCPPreviousSegmentNotCaptured:
		return "TCP Previous Segment Not Captured"
	case TCPACKedUnseenSegment:
		return "TCP ACKed Unseen Segment"
	case TCPZeroWindow:
		return "TCP Zero Window"
	case TCPZeroWindowProbe:
		return "TCP Zero Window Probe"
	case TCPZeroWindowProbeACK:
		return "TCP Zero Window Probe ACK"
	case TCPWindowUpdate:
		return "TCP Window Update"
	case TCPWindowFull:
		return "TCP Window Full"
	case TCPKeepAlive:
		return "TCP Keep-Alive"
	case TCPKeepAliveACK:
		return "TCP Keep-Alive ACK"
	case TCPRSTFlag:
		return "TCP RST Flag Set"
	case TCPConnectionReset:
		return "TCP Connection Reset"
	case TCPConnectionRefused:
		return "TCP Connection Refused"
	case TCPSYNFlood:
		return "Potential SYN Flood"
	default:
		return "Unknown TCP Issue"
	}
}

// Severity returns the default severity for this TCP expert type
func (t TCPExpertType) Severity() Severity {
	switch t {
	case TCPKeepAlive, TCPKeepAliveACK, TCPWindowUpdate:
		return SeverityChat
	case TCPDuplicateACK, TCPOutOfOrder, TCPZeroWindowProbe, TCPZeroWindowProbeACK:
		return SeverityNote
	case TCPRetransmission, TCPFastRetransmission, TCPTripleDuplicateACK,
		TCPZeroWindow, TCPWindowFull, TCPPreviousSegmentNotCaptured, TCPACKedUnseenSegment:
		return SeverityWarning
	case TCPSpuriousRetransmission, TCPRSTFlag, TCPConnectionReset, TCPConnectionRefused, TCPSYNFlood:
		return SeverityError
	default:
		return SeverityNote
	}
}
