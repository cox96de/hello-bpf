package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc ${BPF_CC} -cflags "-O2 -g -Wall -Werror" -type event -target amd64 bpf c/main.bpf.c -- -I../headers/x86_64 -I../headers
