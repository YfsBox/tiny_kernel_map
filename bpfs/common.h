//
// Created by 杨丰硕 on 2023/3/26.
//

#ifndef KERNEL_MAP_COMMON_H
#define KERNEL_MAP_COMMON_H

#include <time.h>
#include <bpf/libbpf.h>

#define TS_BUF_LEN 32

const __u32 START_EXTBL_MAP_IDX = 1;
const __u32 STOP_EXTBL_MAP_IDX = 2;
const __u32 INIT_TASK_MAP_IDX = 3;
const __u32 SYSTBL_MAP_IDX = 4;
const __u32 IDT_MAP_IDX = 5;

void set_now_time(char ts_buf[TS_BUF_LEN]);

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);

static volatile bool exiting = false;

void sig_handler(int sig);

#endif //KERNEL_MAP_COMMON_H
