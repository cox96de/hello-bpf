CC=clang-13
.PHONY: generate
generate:
	BPF_CC=${CC} go generate
.PHONY: build
build:
	go build
.PHONY: tail
tail:
	tail -f /sys/kernel/debug/tracing/trace_pipe
test:
	sudo timeout -s SIGINT --preserve-status 10 ./03-ring-buf