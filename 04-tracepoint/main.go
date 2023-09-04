package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/cilium/ebpf/perf"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Panic(err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Panicf("loading objects: %v", err)
	}
	defer objs.Close()
	kp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TracepointOpenat, nil)
	if err != nil {
		log.Panicf("opening tracepoint: %s", err)
	}
	defer kp.Close()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	log.Println("Waiting for events..")
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	rb, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Panicf("creating ring buffer reader: %s", err)
	}
	go func() {
		defer rb.Close()
		var e bpfEvent
		for {
			record, err := rb.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					break
				}
				log.Printf("failed to read from perf buffer: %s", err)
				continue
			}
			// Parse the perf event entry into an event structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("parsing perf event: %s", err)
				continue
			}
			log.Printf("pid: %d, filepath: %s", &e, str(e.Filename))
		}
		signals <- syscall.SIGTERM
	}()
	<-signals
}

func str(b [256]int8) string {
	builder := strings.Builder{}
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			break
		}
		builder.WriteByte(byte(b[i]))
	}
	return builder.String()
}
