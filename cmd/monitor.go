package cmd

import (
	"github.com/AeroNotix/netpigs/pkg/bpf"
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
			bpf.NewTCPTracer()
		},
	}
	monitorCmd.Flags().StringVarP(&mo.iface, "iface", "i", "", "interface to monitor")
	rootCmd.AddCommand(monitorCmd)
}
