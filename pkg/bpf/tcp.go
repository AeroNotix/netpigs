package bpf

import (
	"fmt"
	"net/http"

	"github.com/cilium/ebpf/link"
)

func NewTCPTracer() {
	kprobes := kprobesObjects{}
	if err := loadKprobesObjects(&kprobes, nil); err != nil {
		panic(err)
	}

	kp, err := link.Kprobe("tcp_cleanup_rbuf", kprobes.TcpCleanupRbuf, nil)
	if err != nil {
		panic(err)
	}
	defer kp.Close()

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var key [16]byte
		var value uint64
		i := kprobes.kprobesMaps.TrackingMap.Iterate()
		for i.Next(&key, &value) {
			fmt.Fprintf(w, "bpf_network_stats_send{comm=\"%s\"} %d \n", string(key[:]), value)
		}

		if err := i.Err(); err != nil {
			fmt.Println(err)
		}
	})
	panic(http.ListenAndServe(":9124", nil))
}
