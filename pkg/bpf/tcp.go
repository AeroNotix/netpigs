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

// #include <linux/sched.h>
import "C"

type key_t struct {
	Pid uint32
}

type metrics struct {
	Send uint64
	Recv uint64
}

type PrometheusMetric struct {
	Name      string
	Comm      string
	Value     uint64
	IPVersion string
}

func (pm PrometheusMetric) String() string {
	return fmt.Sprintf("%s{ip=\"%s\", comm=\"%s\"} %d", pm.Name, pm.IPVersion, pm.Comm, pm.Value)
}

const BPFProgram = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
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
int kprobe__tcp_set_state(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
    int state = (int) PT_REGS_PARM2(ctx);
    if (state != TCP_CLOSE) {
        return 0;
    }
    struct key_t key = {.pid = pid};
    netmetrics.delete(&key);
    return 0;
}
`

func pidToComm(pid uint32) string {
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
	fd2, err := m.LoadKprobe("kprobe__tcp_set_state")
	if err != nil {
		panic(err)
	}
	if err := m.AttachKprobe("tcp_sendmsg", fd0, -1); err != nil {
		panic(err)
	}
	if err := m.AttachKretprobe("tcp_cleanup_rbuf", fd1, -1); err != nil {
		panic(err)
	}
	if err := m.AttachKretprobe("tcp_set_state", fd2, -1); err != nil {
		panic(err)
	}
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var key key_t
		var value metrics
		for it := sendBytes.Iter(); it.Next(); {
			if err := binary.Read(bytes.NewBuffer(it.Key()), binary.LittleEndian, &key); err != nil {
				fmt.Println(err)
			}
			if err := binary.Read(bytes.NewBuffer(it.Leaf()), binary.LittleEndian, &value); err != nil {
				fmt.Println(err)
			}
			fmt.Fprintf(w, "bpf_network_stats_send{ipv=4, comm=\"%s\"} %d \n", pidToComm(key.Pid), value.Send)
			fmt.Fprintf(w, "bpf_network_stats_recv{ipv=4, comm=\"%s\"} %d \n", pidToComm(key.Pid), value.Recv)
		}
	})
	panic(http.ListenAndServe(":9124", nil))
}
