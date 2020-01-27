/*
Copyright © 2019 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/AeroNotix/netpigs/pkg/monitor"
	"github.com/spf13/cobra"
)

type MonitorOpts struct {
	iface string
}

func init() {
	mo := MonitorOpts{}
	// monitorCmd represents the monitor command
	var monitorCmd = &cobra.Command{
		Use: "monitor",
		Run: func(cmd *cobra.Command, args []string) {
			monitor.Monitor(mo.iface)
		},
	}
	monitorCmd.Flags().StringVarP(&mo.iface, "iface", "i", "", "interface to monitor")
	rootCmd.AddCommand(monitorCmd)
}
