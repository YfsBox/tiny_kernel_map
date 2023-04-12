#include "vmlinux/vmlinux.h"
#include "libbpf/src/bpf_helpers.h"
#include "libbpf/src/bpf_tracing.h"
#include "libbpf/src/bpf_core_read.h"
#include "common.h"
#include "crc.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 6);
    __type(key, uint32_t);
    __type(value, int);
} global_val_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} mrb SEC(".maps");  // 这个buf往往是作为内核太到用户态的桥梁的.*/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, uint32_t);
    __type(value, struct read_buffer);
} read_buffer_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, uint32_t);
    __type(value, crc_uint64_t);
} kernel_crc_map SEC(".maps");

__always_inline int *read_global_value(int index, int *value) {
    if (index < 0 || index > USER_PID_IDX) {
        return NULL;
    }
    int *value_ptr = bpf_map_lookup_elem(&global_val_map, &index);
    if (!value_ptr) {
        return NULL;
    }
    bpf_probe_read_kernel(value, sizeof(int), value_ptr);
    return value_ptr;
}


SEC("tracepoint/module/module_load")
int register_modules(void *ctx) {
    bpf_printk("begin register modules");
    /*struct module *mod = (struct module *) ctx->args[2];
    char *filename = (char *) ctx->args[0];
    if (!mod) {
        return 0;
    }

    struct ring_buffer_msg *ring_buffer = bpf_ringbuf_reserve(&mrb, sizeof(struct ring_buffer_msg), 0);
    if (!ring_buffer) {
        return 0;
    }
    bpf_probe_read_str(ring_buffer->msg_, sizeof(filename), filename);
    // bpf_printk("init_module: %s and %s", filename, mod->name);
    bpf_ringbuf_submit(ring_buffer, 0);
    bpf_printk("the init_module happened");*/
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int test_ringbuf(struct trace_event_raw_sys_enter *ctx) {   // some code for test
    int curr_load = 0, curr_load_idx = CURR_LOAD_SYMBOL_IDX;
    int *curr_load_ptr = read_global_value(curr_load_idx, &curr_load);
    if (curr_load < 4) {
        curr_load++;
    } else {
        curr_load = 0;
    }
    bpf_map_update_elem(&global_val_map, &curr_load_idx, &curr_load, BPF_ANY);
    uint64_t *base_offset = bpf_map_lookup_elem(&kstatic_map, &curr_load);
    uint64_t *load_size = bpf_map_lookup_elem(&kstatic_size_map, &curr_load);
    if (!base_offset || !load_size) {
        bpf_printk("the base and load is null");
    }
    uint64_t offset;
    uint64_t size;
    bpf_probe_read(&offset, sizeof(uint64_t), base_offset);
    bpf_probe_read(&size, sizeof(uint64_t), load_size);
    // bpf_printk("the load size is %llu, the idx %d, the offset is %llx", size, curr_load, offset);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int load_kernel_mem(struct trace_event_raw_sys_enter *ctx) {
    int curr_load;
    int *curr_load_ptr = read_global_value(CURR_LOAD_SYMBOL_IDX, &curr_load);
    if (!curr_load_ptr || curr_load < 0 || curr_load > 4) {
        return 0;
    }

    pid_t curr_pid = bpf_get_current_pid_tgid() >> 32;
    int user_pid;
    int *user_pid_ptr = read_global_value(USER_PID_IDX, &user_pid);
    if (!user_pid_ptr || user_pid != curr_pid) {
        return 0;
    }

    int write_fd = ctx->args[0];
    int init_handle_fd;
    int *init_handle_fd_ptr = read_global_value(INIT_HANDLE_FD_IDX, &init_handle_fd);
    if (!init_handle_fd_ptr || init_handle_fd != write_fd) {
        return 0;
    }

    uint64_t *base_offset = bpf_map_lookup_elem(&kstatic_map, &curr_load);
    uint64_t *load_size = bpf_map_lookup_elem(&kstatic_size_map, &curr_load);
    if (!base_offset || !load_size) {
        return 0;
    }

    uint64_t size, base;
    bpf_probe_read(&size, sizeof(uint64_t), load_size);
    bpf_probe_read(&base, sizeof(uint64_t), base_offset);

    int rbidx = 0;
    struct read_buffer *rbuffer = bpf_map_lookup_elem(&read_buffer_map, &rbidx);
    if (!rbuffer) {
        return 0;
    }
    if (size >= MAX_BUFFER_SIZE) {
        return 0;
    }

    bpf_probe_read_kernel(rbuffer->buffer_, size, (char *) base);

    crc_uint64_t crc_code = 0;
    crc64(rbuffer->buffer_, size, &crc_code);
    bpf_map_update_elem(&kernel_crc_map, &curr_load, &crc_code, BPF_ANY);

    curr_load++;
    int key = 0;
    bpf_map_update_elem(&global_val_map, &key, &curr_load, BPF_ANY);

    return 0;
}

// 1. 尽量不使用*操作取指针中的值
// 2. const volatile或者volatile表示可以在执行时可被修改,因此这是被用户态初始化全局变量的前提
// 3. 读取内存内容时尽量别用bpf_probe_read_str，这样会因为0截断
// 4. 已经分配的内存如果不submit也会出错
// 5. bpftool prog load build/bpfs/kernel.bpf.o /sys/fs/bpf/kernel
// 6. cat /sys/kernel/debug/tracing/:trace_pipe