#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>

// Define a struct to hold the data we want to pass to userspace.
// In user space, we'll define a struct with the same structure.
struct event {
  u32 pid;
  // In most filesystem, the filename is limited to 255 characters.
  char filename[256];
};

// The structure of the map can be found in
// "https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/include/bpf_elf.h?h=v4.14.1".
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 1024);
} events SEC(".maps"); /*event map must be defined in .maps section */

SEC("kprobe/do_sys_openat2")
int kprobe__do_sys_openat2(struct pt_regs *ctx) {
  struct event e = {};
  e.pid = bpf_get_current_pid_tgid() >> 32;
  bpf_probe_read(&e.filename, sizeof(e.filename), (void *)PT_REGS_PARM2(ctx));

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

  return 0;
}

char _license[] SEC("license") = "GPL";
