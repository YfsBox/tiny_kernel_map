//
// Created by 杨丰硕 on 2023/3/26.
//

#include <pthread.h>
#include <unistd.h>
#include "common.h"
#include "kstatic_info_collector.h"
#include "../ebpf_utils/kernel_info.h"
#include "ebpf_utils/kernel.skel.h"


static int handle_kstatic_info_init(void *ctx, void *data, size_t data_z) {
    const struct kernel_static_info *kstatic_info = (const struct kernel_static_info *) data;

    char time_buf[TS_BUF_LEN];
    set_now_time(time_buf);

    printf("%-8s %s %s %lld %lld\n", time_buf,  kstatic_info->kernel_data_start_, kstatic_info->kernel_data_end_,
           get_static_info_base(kstatic_info, GDT_BASE_IDX),
           get_static_info_base(kstatic_info, IDT_BASE_IDX));
    return 0;
}

static void *start_collector_func(void *args) {
    struct collector_func_args *collector_args = (struct collector_func_args *) args;
    struct ring_buffer *rb = NULL;
    struct kernel_bpf *skel = NULL;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    libbpf_set_print(libbpf_print_fn);
    skel = kernel_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return NULL;
    }
    err = kernel_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }
    err = kernel_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    int msg_buffer_fd = bpf_object__find_map_fd_by_name((const struct bpf_object*) skel, "msg_buffer");
    rb = ring_buffer__new(msg_buffer_fd, handle_kstatic_info_init, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "PID", "UID", "GID", "CUID", "CGID");
    while (true) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

    cleanup:
    ring_buffer__free(rb);
    kernel_bpf__destroy(skel);
    return NULL;
}

int start_kstatic_info_collector(struct kstatic_info_collector *collector) {
    collector->args_.user_pid_ = getpid();
    int ret = pthread_create(&collector->collector_threadid_, NULL, start_collector_func, &collector->args_);
    if (ret < 0) {
        printf("start kstatic collector thread error\n");
        return 1;
    }
    return 0;
}

void close_kstatic_info_collector(struct kstatic_info_collector *collector) {
    pthread_join(collector->collector_threadid_, NULL);
    free(collector);
}


