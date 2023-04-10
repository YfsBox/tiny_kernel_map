#include "vmlinux/vmlinux.h"
#include "libbpf/src/bpf_helpers.h"
#include "libbpf/src/bpf_tracing.h"
#include "libbpf/src/bpf_core_read.h"
#include "common.h"
#include "hash.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 有关于init load相关的
volatile int curr_load_symbol = 0;
volatile unsigned long curr_load_size = 0;
const volatile int init_handle_fd = 0;
const volatile int user_pid = 0;
const char load_mem_msg[] = "LOAD OK";

struct init_context *load_init_context = NULL;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, uint32_t);
    __type(value, uint64_t);
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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, uint32_t);
    __type(value, uint64_t);
} kernel_crc_map SEC(".maps");

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
int test_ringbuf(struct trace_event_raw_sys_enter *ctx) {   // some code for test
    if (curr_load_symbol < 4) {
        ++curr_load_symbol;
    } else {
        curr_load_symbol = 0;
    }
    int idx = curr_load_symbol;
    uint64_t *base_offset = bpf_map_lookup_elem(&kstatic_map, &idx);
    uint64_t *load_size = bpf_map_lookup_elem(&kstatic_size_map, &idx);
    if (!base_offset || !load_size) {
        bpf_printk("the base and load is null");
    }
    uint64_t offset;
    uint64_t size;
    bpf_probe_read(&offset, sizeof(uint64_t), base_offset);
    bpf_probe_read(&size, sizeof(uint64_t), load_size);
    bpf_printk("the load size is %llu, the idx %d, the offset is %llx", size, idx, offset);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int load_kernel_mem(struct trace_event_raw_sys_enter *ctx) {
    if (curr_load_symbol >= END_SYMBOL_MAP_IDX) {
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

    int idx = curr_load_symbol++;
    uint64_t *base_offset = bpf_map_lookup_elem(&kstatic_map, &idx);
    uint64_t *load_size = bpf_map_lookup_elem(&kstatic_size_map, &idx);
    if (!base_offset || !load_size) {
        return 0;
    }

    uint64_t size, base;
    bpf_probe_read(&size, sizeof(uint64_t), load_size);
    bpf_probe_read(&base, sizeof(uint64_t), base_offset);
    bpf_printk("the load size is %d, the base is %llx, the idx is %d", size, base, idx);

    int rbidx = 0;
    struct read_buffer *rbuffer = bpf_map_lookup_elem(&read_buffer_map, &rbidx);
    if (!rbuffer) {
        return 0;
    }
    if (size >= MAX_BUFFER_SIZE) {
        return 0;
    }

    bpf_probe_read_kernel(rbuffer->buffer_, size, (char *) base);
    // do hash
    struct hash_msg_buffer *hash_msg = bpf_ringbuf_reserve(&mrb, sizeof(struct hash_msg_buffer), 0);
    if (!hash_msg) {
        return 0;
    }
    hash_uint8_t hash_value[SHA256_SIZE_BYTES];
    // sha256(rbuffer->buffer_, size, hash_value);
    // bpf_probe_read(hash_msg->buffer_, MAX_MSG_STR_SIZE, (const char *) rbuffer->buffer_);
    bpf_probe_read(hash_msg->buffer_, SHA256_SIZE_BYTES, (const void *) hash_value);
    bpf_ringbuf_submit(hash_msg->buffer_, 0);

    return 0;
}

// 1. 尽量不使用*操作取指针中的值
// 2. const volatile或者volatile表示可以在执行时可被修改,因此这是被用户态初始化全局变量的前提
// 3. 读取内存内容时尽量别用bpf_probe_read_str，这样会因为0截断