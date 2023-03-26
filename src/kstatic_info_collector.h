//
// Created by 杨丰硕 on 2023/3/26.
//

#ifndef KERNEL_MAP_KSTATIC_INFO_COLLECTOR_H
#define KERNEL_MAP_KSTATIC_INFO_COLLECTOR_H

#include <stdlib.h>

struct collector_func_args {
    pid_t user_pid_;
};

struct kstatic_info_collector {
    int started_;
    int joined_;
    struct collector_func_args args_;
    pthread_t collector_threadid_;
};

int create_kstatic_info_collector(struct kstatic_info_collector *collector, pid_t user_pid);

void close_kstatic_info_collector(struct kstatic_info_collector *collector);

#endif //KERNEL_MAP_KSTATIC_INFO_COLLECTOR_H
