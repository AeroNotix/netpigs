// go:build ignore
#include <linux/sched.h>
#include <asm/ptrace.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct bpf_map_def SEC("maps") tracking_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(char[TASK_COMM_LEN]),
    .value_size = sizeof(__u64),
    .max_entries = 256,
};

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf)
{
    __u64 *val;
    __u64 sum = 0;

    int copied = (int) PT_REGS_PARM2(ctx);

    if (copied <= 0) {
        return 0;
    }

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    val = bpf_map_lookup_elem(&tracking_map, comm);
    if (val) {
        sum = *val + copied;
        bpf_map_update_elem(&tracking_map, comm, &sum, BPF_ANY);
    } else {
        sum = copied;
    }

    bpf_map_update_elem(&tracking_map, comm, &sum, BPF_ANY);
    return 0;
}
