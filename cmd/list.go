package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Zerofisher/pktanalyzer/capture"
	"github.com/Zerofisher/pktanalyzer/fields"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List available resources",
	Long:    `List available network interfaces, fields, and other resources.`,
	GroupID: "info",
}

var listInterfacesCmd = &cobra.Command{
	Use:     "interfaces",
	Short:   "List available network interfaces",
	Long:    `Display a list of network interfaces available for packet capture.`,
	Example: `  pktanalyzer list interfaces`,
	Aliases: []string{"ifaces", "if"},
	RunE:    runListInterfaces,
}

// fields subcommand flags
var listFieldsFilter string

var listFieldsCmd = &cobra.Command{
	Use:   "fields",
	Short: "List available packet fields",
	Long:  `Display a list of fields that can be extracted or filtered.`,
	Example: `  pktanalyzer list fields
  pktanalyzer list fields --filter tcp`,
	RunE: runListFields,
}

func init() {
	// fields flags
	listFieldsCmd.Flags().StringVar(&listFieldsFilter, "filter", "",
		"Filter fields by name pattern")

	listCmd.AddCommand(listInterfacesCmd)
	listCmd.AddCommand(listFieldsCmd)
}

// runListInterfaces lists available network interfaces
func runListInterfaces(cmd *cobra.Command, args []string) error {
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		return fmt.Errorf("error listing interfaces: %w", err)
	}

	fmt.Println("Available network interfaces:")
	fmt.Println(strings.Repeat("-", 60))

	for i, iface := range ifaces {
		fmt.Printf("%d. %s\n", i+1, iface.Name)
		if iface.Description != "" {
			fmt.Printf("   Description: %s\n", iface.Description)
		}
		for _, addr := range iface.Addresses {
			fmt.Printf("   Address: %s\n", addr.IP)
		}
		fmt.Println()
	}

	return nil
}

// runListFields lists available packet fields
func runListFields(cmd *cobra.Command, args []string) error {
	registry := fields.NewRegistry()
	fieldList := registry.List()

	// Sort fields
	sort.Strings(fieldList)

	// Filter if pattern specified
	if listFieldsFilter != "" {
		filtered := make([]string, 0)
		for _, name := range fieldList {
			if strings.Contains(strings.ToLower(name), strings.ToLower(listFieldsFilter)) {
				filtered = append(filtered, name)
			}
		}
		fieldList = filtered
	}

	fmt.Println("Available fields:")
	fmt.Println("Name\t\t\tType\tDescription")
	fmt.Println(strings.Repeat("-", 70))

	for _, name := range fieldList {
		info := registry.GetFieldInfo(name)
		if info != "" {
			fmt.Println(info)
		}
	}

	if len(fieldList) == 0 && listFieldsFilter != "" {
		fmt.Printf("No fields matching '%s' found.\n", listFieldsFilter)
	}

	return nil
}
