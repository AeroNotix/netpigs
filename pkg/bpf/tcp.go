package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

const BPFProgram = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>

BPF_HASH(send, u32);
BPF_HASH(recv, u32);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u16 dport = 0, family = sk->__sk_common.skc_family;
    if (family == AF_INET) {
        u32 ipv4_key = pid;
        send.increment(ipv4_key, size);
    }
    return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u16 dport = 0, family = sk->__sk_common.skc_family;
    u64 *val, zero = 0;
    if (copied <= 0)
        return 0;
    if (family == AF_INET) {
        u32 ipv4_key = pid;
        recv.increment(ipv4_key, copied);
    }
    return 0;
}
`

func pidToComm(pid uint32) (string, error) {
	comm, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "", err
	}
	s := strings.Split(strings.Split(string(comm), " ")[0], "/")
	return s[len(s)-1], nil
}

func tallyProcessThroughput(table *bpf.Table) map[string]uint64 {
	var key uint32
	var value uint64
	metrics := make(map[string]uint64)
	var toDelete [][]byte
	for it := table.Iter(); it.Next(); {
		if err := binary.Read(bytes.NewBuffer(it.Key()), binary.LittleEndian, &key); err != nil {
			fmt.Println(err)
		}
		if err := binary.Read(bytes.NewBuffer(it.Leaf()), binary.LittleEndian, &value); err != nil {
			fmt.Println(err)
		}
		if comm, err := pidToComm(key); err == nil {
			if _, ok := metrics[comm]; ok {
				metrics[comm] += value
			} else {
				metrics[comm] = value
			}
		} else {
			toDelete = append(toDelete, it.Key())
		}
	}
	for _, deleteKey := range toDelete {
		if err := table.Delete(deleteKey); err != nil {
			fmt.Println(err)
		}
	}
	return metrics
}

func NewTCPTracer() {
	m := bpf.NewModule(BPFProgram, []string{})
	sendBytes := bpf.NewTable(m.TableId("send"), m)
	recvBytes := bpf.NewTable(m.TableId("recv"), m)
	fd0, err := m.LoadKprobe("kprobe__tcp_sendmsg")
	if err != nil {
		panic(err)
	}
	fd1, err := m.LoadKprobe("kprobe__tcp_cleanup_rbuf")
	if err != nil {
		panic(err)
	}
	if err := m.AttachKprobe("tcp_sendmsg", fd0, -1); err != nil {
		panic(err)
	}
	if err := m.AttachKretprobe("tcp_cleanup_rbuf", fd1, -1); err != nil {
		panic(err)
	}
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		sendMetrics := tallyProcessThroughput(sendBytes)
		recvMetrics := tallyProcessThroughput(recvBytes)

		for comm, sendBytes := range sendMetrics {
			fmt.Fprintf(w, "bpf_network_stats_send{comm=\"%s\"} %d \n", comm, sendBytes)
		}
		for comm, recvBytes := range recvMetrics {
			fmt.Fprintf(w, "bpf_network_stats_recv{comm=\"%s\"} %d \n", comm, recvBytes)
		}
	})
	panic(http.ListenAndServe(":9124", nil))
}
