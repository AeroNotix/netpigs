package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func NewTCPTracer() (*ebpf.Map, error) {
	kprobes := kprobesObjects{}
	if err := loadKprobesObjects(&kprobes, nil); err != nil {
		return nil, err
	}

	_, err := link.Kprobe("tcp_cleanup_rbuf", kprobes.TcpCleanupRbuf, nil)
	if err != nil {
		return nil, err
	}
	return kprobes.TrackingMap, nil
}
