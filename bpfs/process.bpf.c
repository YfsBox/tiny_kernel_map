//
// Created by 杨丰硕 on 2023/4/22.
//
#include "vmlinux/vmlinux.h"
#include "libbpf/src/bpf_helpers.h"
#include "libbpf/src/bpf_tracing.h"
#include "libbpf/src/bpf_core_read.h"
#include "common.h"
#include "crc.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_PROCESS_SIZE 8096
#define MAX_PARENTS_DEPTH 2048

struct process_info {
    bool available_;
    crc_uint64_t dynamic_link_crc_;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESS_SIZE);
    __type(key, pid_t);
    __type(value, struct process_info);
} process_map SEC(".maps");

SEC("kprobe/mmap_region")
int measure_on_mmap_region(struct pt_regs *ctx) {
    pid_t curr_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("mmap region %d", curr_pid);
    return 0;
}

SEC("kprobe/mprotect_fixup")
int measure_on_mprotect_fixup(struct pt_regs *ctx) {
    pid_t curr_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("mprotect fixup %d", curr_pid);
    return 0;
}

SEC("kprobe/__do_sys_fork")
int register_process(struct pt_regs *ctx) {
    // bpf_printk("")
    return 0;
}



