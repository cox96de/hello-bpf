FROM golang:1.19
RUN apt-get update && apt-get install -y clang-13 llvm-13 bpftool
RUN go env -w GOPROXY=https://goproxy.cn,direct