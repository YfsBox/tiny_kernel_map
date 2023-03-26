#include <linux/kernel.h>
#include "vmlinux/vmlinux.h"
#include "libbpf/src/bpf_helpers.h"
#include "libbpf/src/bpf_core_read.h"
#include "kernel_info.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

extern char __start___ex_table[];
extern char __stop___ex_table[];

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} msg_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} exec_start SEC(".maps");

struct kernel_static_info ksinfo;

volatile pid_t user_process_id = 0;
volatile bool debug_on = false;
volatile bool is_inited = false;

static base_offset_t load_gdt_base() {
    base_offset_t gdt_base;
    asm ("mov %%gs:0, %0" : "=r" (gdt_base));
    return gdt_base;
}

static base_offset_t load_idt_base() {
    base_offset_t idt_base;
    asm("sidt %0" : "=m" (idt_base));
    return idt_base;
}

static base_offset_t load_systbl_base() {
    return 0;
}

static void load_kdata_base(char *start_base, char *end_base) {
    bpf_probe_read_kernel(start_base, sizeof(char *), &__start___ex_table);
    bpf_probe_read_kernel(end_base, sizeof(char *), &__stop___ex_table);
}

static bool check_and_load_init() {
    if (is_inited) {
        return false;
    }
    u32 curr_pid = bpf_get_current_pid_tgid() >> 32;
    if (curr_pid == user_process_id) {
        set_static_info_base(&ksinfo,load_gdt_base(), GDT_BASE_IDX);
        set_static_info_base(&ksinfo, load_idt_base(), IDT_BASE_IDX);
        load_kdata_base(ksinfo.kernel_data_start_, ksinfo.kernel_data_end_);
        if (debug_on) {
            struct kernel_static_info *submit_info = bpf_ringbuf_reserve(&msg_buffer, sizeof(struct kernel_static_info), 0);
            *submit_info = ksinfo;
            bpf_ringbuf_submit(submit_info, 0);
        }
        is_inited = true;
    }
    return true;
}

SEC("kprobe/do_sys_open")
int open_for_init(struct pt_regs *ctx) {
    check_and_load_init();
}



