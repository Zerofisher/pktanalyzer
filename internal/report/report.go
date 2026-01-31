// Package report provides report generation for pcap analysis.
package report

import (
	"context"
	"fmt"
	"time"

	"github.com/Zerofisher/pktanalyzer/pkg/query"
)

// Data holds all data for report generation.
type Data struct {
	// Meta
	GeneratedAt time.Time
	PcapPath    string
	PcapSize    int64

	// Overview
	Overview *query.Overview

	// Top flows
	TopFlowsByBytes   []*FlowSummary
	TopFlowsByPackets []*FlowSummary

	// Protocol distribution
	ProtocolStats []*query.ProtocolStat

	// Top talkers
	TopTalkers []*query.TopTalker

	// Expert events
	EventSummary *query.EventSummary
	TopEvents    []*EventSummary
}

// FlowSummary is a simplified flow for display.
type FlowSummary struct {
	ID        string
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Protocol  string
	Packets   int
	Bytes     int64
	BytesStr  string
	Duration  string
	SNI       string
}

// EventSummary is a simplified event for display.
type EventSummary struct {
	Severity string
	Group    string
	Type     string
	Message  string
	Packets  string
}

// Generate creates a report from the query engine.
func Generate(ctx context.Context, engine *query.SQLiteEngine) (*Data, error) {
	report := &Data{
		GeneratedAt: time.Now(),
	}

	// Get overview
	overview, err := engine.GetOverview(ctx)
	if err != nil {
		return nil, fmt.Errorf("get overview: %w", err)
	}
	report.Overview = overview
	report.PcapPath = overview.PcapPath
	report.PcapSize = overview.PcapSize

	// Get top flows by bytes
	flows, err := engine.GetFlows(ctx, query.FlowFilter{
		Limit:     10,
		SortBy:    "bytes",
		SortOrder: "desc",
	})
	if err != nil {
		return nil, fmt.Errorf("get top flows: %w", err)
	}
	for _, f := range flows {
		report.TopFlowsByBytes = append(report.TopFlowsByBytes, &FlowSummary{
			ID:       f.ID[:8],
			SrcIP:    f.SrcIP,
			DstIP:    f.DstIP,
			SrcPort:  f.SrcPort,
			DstPort:  f.DstPort,
			Protocol: f.Protocol,
			Packets:  f.Packets,
			Bytes:    f.Bytes,
			BytesStr: FormatBytes(f.Bytes),
			Duration: time.Duration(f.EndNS - f.StartNS).String(),
			SNI:      f.TLSServerName,
		})
	}

	// Get protocol stats
	report.ProtocolStats, err = engine.GetProtocolStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("get protocol stats: %w", err)
	}

	// Get top talkers
	report.TopTalkers, err = engine.GetTopTalkers(ctx, 10)
	if err != nil {
		return nil, fmt.Errorf("get top talkers: %w", err)
	}

	// Get event summary
	report.EventSummary, err = engine.GetEventSummary(ctx)
	if err != nil {
		return nil, fmt.Errorf("get event summary: %w", err)
	}

	// Format top events
	if report.EventSummary != nil {
		for _, e := range report.EventSummary.TopEvents {
			report.TopEvents = append(report.TopEvents, &EventSummary{
				Severity: string(e.Severity),
				Group:    string(e.Group),
				Type:     e.Type,
				Message:  e.Message,
				Packets:  fmt.Sprintf("%d-%d", e.PacketStart, e.PacketEnd),
			})
		}
	}

	return report, nil
}
