// More information about vmlinux.h can be found at docs/vmlinux.md
#include "vmlinux.h"

#include <bpf_helpers.h>
#include <bpf_tracing.h>

// License is required. It is a requirement from the kernel to be able to load.
// If empty, the kernel will reject the load.
// The license can be any string, but GPL is recommended.
// The license is not checked by the kernel, but it is checked by the verifier.
// Different licenses have different restrictions on what can be done with the
// code by restricting helper functions.
char _license[] SEC("license") = "GPL";

// SEC is a macro which tell compiler place the code into a specific section.
// ebpf programs are loaded into the kernel as a module, and the kernel will
// look for the programs in a specific section.
SEC("kprobe/do_sys_openat2")
// The name of the function does not matter.
int kprobe__do_sys_openat2(struct pt_regs *ctx) {
  // use `man openat2` to get more information about traced syscall, and it's
  // signature. In this example, `openat2`'s signature is `long openat2(int
  // dirfd, const char *pathname, struct open_how *how, size_t size);` `pt_regs`
  // is a structure that contains the values of the CPU registers at the time a
  // system call is made.
  char file_name[256];
  // `PT_REGS_PARM2` is a macro defined in the Linux kernel source code.
  // The `PT_REGS_PARM2` macro is used to extract the value of the second
  // argument passed to the system call. As the signature of `openat2`, the
  // second parameter is `pathname`.
  // bpf_probe_read is a helper function that allows the eBPF program to read
  // data from kernel or user space. EBPF program executes in kernel space but
  // can only read data from kernel or user space using helper functions. You
  // get the pointer to the data, but you can't dereference it.
  bpf_probe_read(file_name, sizeof(file_name), (void *)(PT_REGS_PARM2(ctx)));

  char fmt[] = "open file %s\n";
  bpf_trace_printk(fmt, sizeof(fmt), &file_name);

  return 0;
}
