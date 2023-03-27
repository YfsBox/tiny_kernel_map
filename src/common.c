//
// Created by 杨丰硕 on 2023/3/27.
//
#include "common.h"


void set_now_time(char ts_buf[TS_BUF_LEN]) {
    struct tm *now;
    time_t t;
    time(&t);
    now = localtime(&t);
    strftime(ts_buf, TS_BUF_LEN, "%H:%M:%S", now);
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

void sig_handler(int sig) {
    exiting = true;
}