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

type BPFMetricsKey uint32

type metrics struct {
	Send uint64
	Recv uint64
}

const BPFProgram = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>

struct tracepoint__sock__inet__sock_set_state {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    const void *skaddr;
    int oldstate;
    int newstate;
    u16 sport;
    u16 dport;
    u8 family;
    u8 protocol;
    u8 saddr[4];
    u8 daddr[4];
    u8 saddr_v6[16];
    u8 daddr_v6[16];
};

struct metrics {
    u64 sent;
    u64 recv;
};
struct key_t {
    u32 pid;
};
BPF_HASH(netmetrics, struct key_t, struct metrics);
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct metrics *val;
    struct key_t key = {.pid = pid};
    val = netmetrics.lookup_or_try_init(&key, &(struct metrics){0,0});
    if (val) {
        (*val).sent += size;
    }
    return 0;
}
/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct metrics *val;
    if (copied <= 0)
        return 0;
    struct key_t key = {.pid = pid};
    val = netmetrics.lookup_or_try_init(&key, &(struct metrics){0,0});
    if (val) {
        (*val).recv += copied;
    }
    return 0;
}
// todo: this isn't working right now.
int trace_sock_set_state(struct tracepoint__sock__inet__sock_set_state *args)
{
    if (args->protocol != IPPROTO_TCP)
        return 0;

    u32 pid = bpf_get_current_pid_tgid();

    if (args->newstate != TCP_CLOSE) {
        return 0;
    }
    struct key_t key = {.pid = pid};
    netmetrics.delete(&key);
    return 0;
}
`

func pidToComm(pid BPFMetricsKey) string {
	// TODO: don't need to do this - the kprobe can do it but I had
	// issues with buffer sizes and reading garbage. Figure out what's
	// the fix.
	comm, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "<unknown>"
	}
	s := strings.Split(strings.Split(string(comm), " ")[0], "/")
	return s[len(s)-1]
}

func NewTCPTracer() {
	m := bpf.NewModule(BPFProgram, []string{})
	sendBytes := bpf.NewTable(m.TableId("netmetrics"), m)
	fd0, err := m.LoadKprobe("kprobe__tcp_sendmsg")
	if err != nil {
		panic(err)
	}
	fd1, err := m.LoadKprobe("kprobe__tcp_cleanup_rbuf")
	if err != nil {
		panic(err)
	}
	fd2, err := m.LoadTracepoint("trace_sock_set_state")
	if err != nil {
		panic(err)
	}
	if err := m.AttachKprobe("tcp_sendmsg", fd0, -1); err != nil {
		panic(err)
	}
	if err := m.AttachKretprobe("tcp_cleanup_rbuf", fd1, -1); err != nil {
		panic(err)
	}
	if err := m.AttachTracepoint("sock:inet_sock_set_state", fd2); err != nil {
		panic(err)
	}
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var key BPFMetricsKey
		var value metrics
		for it := sendBytes.Iter(); it.Next(); {
			if err := binary.Read(bytes.NewBuffer(it.Key()), binary.LittleEndian, &key); err != nil {
				fmt.Println(err)
			}
			if err := binary.Read(bytes.NewBuffer(it.Leaf()), binary.LittleEndian, &value); err != nil {
				fmt.Println(err)
			}
			fmt.Fprintf(w, "bpf_network_stats_send{ipv=4, comm=\"%s\"} %d \n", pidToComm(key), value.Send)
			fmt.Fprintf(w, "bpf_network_stats_recv{ipv=4, comm=\"%s\"} %d \n", pidToComm(key), value.Recv)
		}
	})
	panic(http.ListenAndServe(":9124", nil))
}
