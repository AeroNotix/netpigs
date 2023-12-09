package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang kprobes c_src/kprobes.c -- -D __TARGET_ARCH_arm64
