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

type ipv4_key_t struct {
	Pid   uint32
	Saddr uint32
	Daddr uint32
	Lport uint16
	Dport uint16
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
struct ipv4_key_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv4_metrics, struct ipv4_key_t, struct metrics);
struct ipv6_key_t {
    u32 pid;
    // workaround until unsigned __int128 support:
    u64 saddr0;
    u64 saddr1;
    u64 daddr0;
    u64 daddr1;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv6_metrics, struct ipv6_key_t, struct metrics);
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u32 pid = bpf_get_current_pid_tgid();
    u16 dport = 0, family = sk->__sk_common.skc_family;
    struct metrics *val;
    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        val = ipv4_metrics.lookup_or_try_init(&ipv4_key, &(struct metrics){0,0});
        if (val) {
            (*val).sent += size;
        }
    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        ipv6_key.saddr0 = *(u64 *)&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0];
        ipv6_key.saddr1 = *(u64 *)&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2];
        ipv6_key.daddr0 = *(u64 *)&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0];
        ipv6_key.daddr1 = *(u64 *)&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2];
        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        val = ipv6_metrics.lookup_or_try_init(&ipv6_key, &(struct metrics){0,0});
        if (val) {
            (*val).sent += size;
        }
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
    u16 dport = 0, family = sk->__sk_common.skc_family;
    struct metrics *val;
    if (copied <= 0)
        return 0;
    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        val = ipv4_metrics.lookup_or_try_init(&ipv4_key, &(struct metrics){0,0});
        if (val) {
            (*val).recv += copied;
        }
    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        ipv6_key.saddr0 = *(u64 *)&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0];
        ipv6_key.saddr1 = *(u64 *)&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2];
        ipv6_key.daddr0 = *(u64 *)&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0];
        ipv6_key.daddr1 = *(u64 *)&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2];
        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        val = ipv6_metrics.lookup_or_try_init(&ipv6_key, &(struct metrics){0,0});
        if (val) {
            (*val).recv += copied;
        }
    }
    return 0;
}
`

func pidToComm(pid uint32) string {
	comm, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "<unknown>"
	}
	s := strings.Split(strings.Split(string(comm), " ")[0], "/")
	return s[len(s)-1]
}

func NewTCPTracer() {
	m := bpf.NewModule(BPFProgram, []string{})
	sendBytes := bpf.NewTable(m.TableId("ipv4_metrics"), m)
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
		var key ipv4_key_t
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
