//
// Created by 杨丰硕 on 2023/3/26.
//

#include <pthread.h>
#include "common.h"
#include "kstatic_info_collector.h"
#include "../ebpf_utils/kernel_info.h"
#include "../ebpf_utils/kernel.skel.h"


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



    return NULL;
}

int create_kstatic_info_collector(struct kstatic_info_collector *collector , pid_t user_pid) {
    collector->args_.user_pid_ = user_pid;
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
