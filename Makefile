export SHELL := /bin/bash

.PHONY: format
format:
	gofmt -w .
	go mod tidy
	find . -name '*.c' -type f ! -path "*/libbpf/*" | xargs -I {} clang-format {} -i
#gofumpt is more strict than gofmt
	go run mvdan.cc/gofumpt@latest -l -w .

.PHONY: lint
lint:
	golangci-lint run --new-from-rev=origin/master --timeout=10m --go=1.20
