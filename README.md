# hello-bpf

This project aims to provide a series of simple examples of eBPF programs using github.com/cilium/ebpf, making it a
great starting point for anyone interested in learning eBPF.

**Notice**: This project was inspired by [mozillazg/hello-libbpfgo](https://github.com/mozillazg/hello-libbpfgo.git),
which uses a different Go eBPF library.

## How to read this project

For each example, there are C and Go source files. The C source file contains the original eBPF kernel program, while
the Go source file contains the user space program version of eBPF.

To help you understand the meaning of each function, I have added detailed comments in the source code.

But I am a new ebpf leaner, so there may be some mistakes in the comments. If you find any mistakes, please let me know.