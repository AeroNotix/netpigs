/*
Copyright © 2019 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/6RiverSystems/netpigs/pkg/monitor"
	"github.com/spf13/cobra"
)

type MonitorOpts struct {
	iface string
}

func init() {
	// monitorCmd represents the monitor command
	var monitorCmd = &cobra.Command{
		Use: "monitor",
		Run: func(cmd *cobra.Command, args []string) {
			monitor.Monitor("wlp0s20f3")
		},
	}
	rootCmd.AddCommand(monitorCmd)
}
