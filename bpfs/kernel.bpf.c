#include "vmlinux/vmlinux.h"
#include "libbpf/src/bpf_helpers.h"
#include "libbpf/src/bpf_tracing.h"
#include "libbpf/src/bpf_core_read.h"

#define MAX_KSYM_NAME_SIZE 64
#define MAX_MSG_STR_SIZE 128

extern char __start___ex_table[];
extern char __stop___ex_table[];

typedef unsigned long long base_offset_t;

typedef struct ksym_name {
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

struct ring_buffer_msg {
    char msg_[MAX_MSG_STR_SIZE];
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} kstatic_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} mrb SEC(".maps");  // 这个buf往往是作为内核太到用户态的桥梁的.*/

const volatile unsigned long long min_duration_ns = 0;

inline __u64 get_ksymbol_addr(__u32 idx) {
    __u64 *sysaddr = bpf_map_lookup_elem(&kstatic_map, &idx);
    return *sysaddr;
}

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
    const char key[] = "sys_call_table";
    struct ksym_name keyname;
    bpf_probe_read_str(keyname.str, MAX_KSYM_NAME_SIZE, key);

    bpf_printk("%s", keyname.str);

    __u64 *sysaddr = bpf_map_lookup_elem(&kstatic_map, &keyname);;
    char *sysaddrp = (char *) sysaddr;

    struct ring_buffer_msg msg;
    bpf_probe_read_str(msg.msg_, MAX_KSYM_NAME_SIZE, sysaddrp);

    struct ring_buffer_msg *rb_msg = bpf_ringbuf_reserve(&mrb, sizeof(struct ring_buffer_msg), 0);
    if (!rb_msg) {
        return 0;
    }
    bpf_probe_read_str(rb_msg->msg_, MAX_KSYM_NAME_SIZE, sysaddrp);
    bpf_ringbuf_submit(rb_msg, 0);

    return 0;
}

