//
// Created by 杨丰硕 on 2023/3/26.
//

#ifndef KERNEL_MAP_COMMON_H
#define KERNEL_MAP_COMMON_H

#include <time.h>
#include <bpf/libbpf.h>

#define TS_BUF_LEN 32

void set_now_time(char ts_buf[TS_BUF_LEN]);

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);

static volatile bool exiting = false;

void sig_handler(int sig);

#endif //KERNEL_MAP_COMMON_H
