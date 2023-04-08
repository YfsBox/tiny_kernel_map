//
// Created by 杨丰硕 on 2023/3/26.
//

#ifndef KERNEL_MAP_COMMON_H
#define KERNEL_MAP_COMMON_H

#define TS_BUF_LEN 32
#define MAX_KSYM_NAME_SIZE 64
#define MAX_MSG_STR_SIZE 128
#define MAX_BUFFER_SIZE 8192

typedef unsigned long uint32;

typedef unsigned long long base_offset_t;

const uint32 START_EXTBL_MAP_IDX = 1;
const uint32 STOP_EXTBL_MAP_IDX = 2;
const uint32 INIT_TASK_MAP_IDX = 3;
const uint32 SYSTBL_MAP_IDX = 4;
const uint32 IDT_MAP_IDX = 5;
const uint32 END_SYMBOL_MAP_IDX = 6;
const uint32 SYSCALL_TABLE_SIZE = 313 * 8;

typedef struct ksym_name {
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

struct ring_buffer_msg {
    char msg_[MAX_MSG_STR_SIZE];
};

struct read_buffer {
    char buffer_[MAX_BUFFER_SIZE];
};


#endif //KERNEL_MAP_COMMON_H
