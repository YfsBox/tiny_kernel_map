//
// Created by 杨丰硕 on 2023/3/26.
//

#ifndef KERNEL_MAP_COMMON_H
#define KERNEL_MAP_COMMON_H

#include <time.h>
#include <bpf/libbpf.h>

#define TS_BUF_LEN 32

void set_now_time(char ts_buf[TS_BUF_LEN]) {
    struct tm *now;
    time_t t;
    time(&t);
    now = localtime(&t);
    strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", now);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

#endif //KERNEL_MAP_COMMON_H
