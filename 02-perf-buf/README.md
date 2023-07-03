In eBPF, a "map" is a generic term for a key-value data structure that can be used by eBPF programs to store and
retrieve data. A BPF_MAP_TYPE_PERF_EVENT_ARRAY is a specific type of map that is used to send performance events to user
space.

The BPF_MAP_TYPE_PERF_EVENT_ARRAY map is technically an array of perf event file descriptors, where each element in the
array represents a performance event file descriptor for a specific event. When an eBPF program generates a performance
event, it writes the event data to the perf event file descriptor associated with the corresponding event in the array.

So, even though the type of map is an array, it still has key-value semantics because the array elements are accessed
using integer keys, and the associated value is a file descriptor that is used to send performance events to user space.