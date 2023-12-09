package cmd

import (
	"fmt"
	"net/http"

	"github.com/AeroNotix/netpigs/pkg/bpf"
	"github.com/spf13/cobra"
)

type MonitorOpts struct {
	groupPids bool
}

func init() {
	mo := MonitorOpts{}
	// monitorCmd represents the monitor command
	var monitorCmd = &cobra.Command{
		Use: "monitor",
		RunE: func(cmd *cobra.Command, args []string) error {
			trackingMap, err := bpf.NewTCPTracer()
			if err != nil {
				return err
			}

			http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
				var key struct {
					Comm [16]byte
					Pid  uint32
				}
				var value uint64
				i := trackingMap.Iterate()
				if mo.groupPids {
					commCounter := make(map[string]uint64)
					for i.Next(&key, &value) {
						commCounter[string(key.Comm[:])] += value
					}
					for comm, value := range commCounter {
						fmt.Fprintf(w, `bpf_network_stats_send{comm="%s"} %d%s`, comm, value, "\n")
					}
				} else {
					for i.Next(&key, &value) {
						fmt.Fprintf(w, `bpf_network_stats_send{comm="%s", pid="%d"} %d%s`, string(key.Comm[:]), key.Pid, value, "\n")
					}
				}

				if err := i.Err(); err != nil {
					fmt.Println(err)
				}
			})
			panic(http.ListenAndServe(":9124", nil))

		},
	}
	monitorCmd.Flags().BoolVarP(&mo.groupPids, "group-pids", "g", true, "Group pids together?")
	rootCmd.AddCommand(monitorCmd)
}
