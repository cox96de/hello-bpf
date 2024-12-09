package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc ${BPF_CC} -cflags "-O2 -g -Wall -Werror" -type event_t -target arm64 bpf c/main.bpf.c -- -I../headers/aarch64 -I../headers
