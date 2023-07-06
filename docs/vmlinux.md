I think this blog examples `vmlinux.h` very well.

https://blog.aquasec.com/vmlinux.h-ebpf-programs

So I uses some explanation from this blog.

## `vmlinux.h` in a nutshell

vmlinux.h is generated code. It contains all the type definitions that your running Linux kernel uses in its own source
code. When you build Linux, one of the output artifacts is a file called vmlinux. It's also typically packaged with
major distributions. This is an ELF binary that contains the compiled bootable kernel inside it.

There's a tool, aptly named bpftool, that is maintained within the Linux repository. It has a feature to read the
vmlinux object file and generate a vmlinux.h file. Since it contains every type-definition that the installed kernel
uses, it's a very large header file.

The actual command is:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

Now when you import this header file, your bpf program can read raw memory and know which bytes correspond to which
fields of structs that you want to use!

For example, linux represents the concept of a process with a type called task_struct. If you want to inspect values in
a task_struct from your bpf program, you're going to need to know the definition of it.

## Compile once, run everywhere

Since the vmlinux.h file is generated from your installed kernel, your bpf program could break if you try to run it
without recompiling on another machine that is running a different kernel version. This is because, from version to
version, definitions of internal structs change within the linux source code.

However, using libbpf enables something called "CO:RE" or "Compile once, run everywhere". There are macros defined in
libbpf (such as BPF_CORE_READ) that will analyze what fields you're trying to access in the types that are defined in
your vmlinux.h. If the field you want to access has been moved within the struct definition that the running kernel
uses, the macro/helpers will find it for you. Therefore, it doesn't matter if you compile your bpf program with the
vmlinux.h file you generated from your own kernel and then ran it on a different one.


