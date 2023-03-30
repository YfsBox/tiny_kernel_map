#include "vmlinux/vmlinux.h"
#include "libbpf/src/bpf_helpers.h"
#include "libbpf/src/bpf_tracing.h"
#include "libbpf/src/bpf_core_read.h"

extern char __start___ex_table[];
extern char __stop___ex_table[];

typedef unsigned long long base_offset_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, uint8_t);
    __type(value, u64);
} kstatic_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} mrb SEC(".maps");  // 这个buf往往是作为内核太到用户态的桥梁的.*/


const volatile unsigned long long min_duration_ns = 0;

SEC("raw_tracepoint/sys_enter")
int hello_bpftrace(void *ctx) {
    char data[100];
    bpf_get_current_comm(&data, 100);
    // void *syscall_table = (void *) bpf_probe_read(&syscall_table, sizeof(syscall_table), (void *) kallsyms_lookup_name("sys_call_table"));
    return 0;
}

