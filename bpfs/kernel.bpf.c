#include "vmlinux/vmlinux.h"
#include "libbpf/src/bpf_helpers.h"
#include "libbpf/src/bpf_tracing.h"
#include "libbpf/src/bpf_core_read.h"
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 有关于init load相关的
volatile int curr_load_symbol = -1;
volatile unsigned long curr_load_size = 0;
const volatile int init_handle_fd = 0;
const volatile int user_pid = 0;

struct init_context *load_init_context = NULL;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, uint32_t);
    __type(value, base_offset_t);
} kstatic_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, uint32_t);
    __type(value, uint64_t);
} kstatic_size_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} mrb SEC(".maps");  // 这个buf往往是作为内核太到用户态的桥梁的.*/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct read_buffer);
} read_buffer_map SEC(".maps");

struct read_buffer *rbuffer = NULL;

const volatile unsigned long long min_duration_ns = 0;

SEC("tracepoint/syscalls/sys_enter_init_module")
int register_modules(struct trace_event_raw_sys_enter *ctx) {
    char tmpbuf[256];
    struct module *mod = (struct module *) ctx->args[2];
    char *filename = (char *) ctx->args[0];
    if (!mod) {
        return 0;
    }
    bpf_probe_read_str(tmpbuf, sizeof(tmpbuf), filename);
    bpf_printk("init_module: %s and %s", filename, mod->name);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int test_ringbuf(struct trace_event_raw_sys_enter *ctx) {
    __u64 *val;
    __u32 idx = START_EXTBL_MAP_IDX;
    /*
    __u64 *sysaddr = bpf_map_lookup_elem(&kstatic_map, &idx);
    char *sysaddr_ptr = (char *) sysaddr;

    struct ring_buffer_msg msg;
    bpf_probe_read_str(msg.msg_, MAX_KSYM_NAME_SIZE, sysaddr_ptr);

    struct ring_buffer_msg *rb_msg = bpf_ringbuf_reserve(&mrb, sizeof(struct ring_buffer_msg), 0);
    if (!rb_msg) {
        return 0;
    }
    bpf_probe_read_str(rb_msg->msg_, MAX_KSYM_NAME_SIZE, sysaddr_ptr);
    bpf_ringbuf_submit(rb_msg, 0);
    */
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int load_kernel_mem(struct trace_event_raw_sys_enter *ctx) {
    /*if (curr_load_symbol >= END_SYMBOL_MAP_IDX) {
        return 0;
    }

    pid_t curr_pid = bpf_get_current_pid_tgid() >> 32;
    if (curr_pid != user_pid) {
        return 0;
    }

    int write_fd = ctx->args[0];
    if (write_fd != init_handle_fd) {
        return 0;
    }

    ++curr_load_symbol;
    int idx = curr_load_symbol;
    base_offset_t *base_offset = bpf_map_lookup_elem(&kstatic_map, &idx);
    uint32_t *load_size = bpf_map_lookup_elem(&kstatic_size_map, &idx);
    if (!base_offset || !load_size) {
        return 0;
    }

    if (!rbuffer) {
        int idx = 0;
        rbuffer = bpf_map_lookup_elem(&read_buffer_map, &idx);
    }

    bpf_probe_read_kernel(rbuffer->buffer_, *load_size, (void *) *base_offset);
    // do hash

    // submit for debug
    struct ring_buffer_msg *msg = bpf_ringbuf_reserve(&mrb, sizeof(struct ring_buffer_msg), 0);
    if (!msg) {
        return 0;
    }
    bpf_probe_read_str(msg->msg_, MAX_MSG_STR_SIZE, rbuffer->buffer_);
    bpf_ringbuf_submit(msg, 0);*/
    return 0;
}
