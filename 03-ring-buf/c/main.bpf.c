#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>

struct event {
  u32 pid;
  char filename[256];
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int kprobe__do_sys_openat2(struct pt_regs *ctx) {
  struct event *e;
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 0;
  }
  e->pid = bpf_get_current_pid_tgid() >> 32;
  bpf_probe_read(e->filename, sizeof(e->filename), (void *)PT_REGS_PARM2(ctx));

  bpf_ringbuf_submit(e, 0);
  return 0;
}

char _license[] SEC("license") = "GPL";
