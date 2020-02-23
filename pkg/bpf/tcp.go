package bpf

import (
	"fmt"

	"bytes"
	"encoding/binary"

	bpf "github.com/iovisor/gobpf/bcc"
)

// #include <linux/sched.h>
import "C"

type ipv4_key_t struct {
	char  [16]byte
	saddr uint32
	daddr uint32
	lport uint16
	dport uint16
}

const BPFProgram = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
struct ipv4_key_t {
    char *comm;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);
BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t);
struct ipv6_key_t {
    char *comm;
    // workaround until unsigned __int128 support:
    u64 saddr0;
    u64 saddr1;
    u64 daddr0;
    u64 daddr1;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv6_send_bytes, struct ipv6_key_t);
BPF_HASH(ipv6_recv_bytes, struct ipv6_key_t);
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u32 pid = bpf_get_current_pid_tgid();
    u16 dport = 0, family = sk->__sk_common.skc_family;
    u64 *val, zero = 0;
    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {};
        bpf_get_current_comm(&ipv4_key.comm, sizeof(ipv4_key.comm));
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        val = ipv4_send_bytes.lookup_or_init(&ipv4_key, &zero);
        (*val) += size;
    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {};
        bpf_get_current_comm(&ipv6_key.comm, sizeof(ipv6_key.comm));
        ipv6_key.saddr0 = *(u64 *)&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0];
        ipv6_key.saddr1 = *(u64 *)&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2];
        ipv6_key.daddr0 = *(u64 *)&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0];
        ipv6_key.daddr1 = *(u64 *)&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2];
        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        val = ipv6_send_bytes.lookup_or_init(&ipv6_key, &zero);
        (*val) += size;
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
    u64 *val, zero = 0;
    if (copied <= 0)
        return 0;
    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {};
        bpf_get_current_comm(&ipv4_key.comm, sizeof(ipv4_key.comm));
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        val = ipv4_recv_bytes.lookup_or_init(&ipv4_key, &zero);
        (*val) += copied;
    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {};
        bpf_get_current_comm(&ipv6_key.comm, sizeof(ipv6_key.comm));
        ipv6_key.saddr0 = *(u64 *)&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0];
        ipv6_key.saddr1 = *(u64 *)&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2];
        ipv6_key.daddr0 = *(u64 *)&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0];
        ipv6_key.daddr1 = *(u64 *)&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2];
        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        val = ipv6_recv_bytes.lookup_or_init(&ipv6_key, &zero);
        (*val) += copied;
    }
    return 0;
}
`

func NewTCPTracer() {
	m := bpf.NewModule(BPFProgram, []string{})
	table := bpf.NewTable(m.TableId("ipv4_send_bytes"), m)
	fd0, err := m.LoadKprobe("kprobe__tcp_sendmsg")
	if err != nil {
		panic(err)
	}
	fd1, err := m.LoadKprobe("kprobe__tcp_cleanup_rbuf")
	if err != nil {
		panic(err)
	}
	fmt.Println(m.AttachKprobe("tcp_sendmsg", fd0, -1))
	fmt.Println(m.AttachKretprobe("tcp_cleanup_rbuf", fd1, -1))
	var key ipv4_key_t
	for it := table.Iter(); it.Next(); {
		if err := binary.Read(bytes.NewBuffer(it.Key()), binary.LittleEndian, &key); err != nil {
			panic(err)
		}
		fmt.Println(key)
	}
}
