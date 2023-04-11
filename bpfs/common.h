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

#define START_EXTBL_MAP_IDX 1
#define STOP_EXTBL_MAP_IDX 2
#define INIT_TASK_MAP_IDX 3
#define SYSTBL_MAP_IDX 4
#define IDT_MAP_IDX 5
#define END_SYMBOL_MAP_IDX 6
#define SYSCALL_TABLE_SIZE 313 * 8

// #define GLOBAL_VALUES_IDX 0
#define CURR_LOAD_SYMBOL_IDX 0
#define INIT_HANDLE_FD_IDX 1
#define USER_PID_IDX 2

typedef struct ksym_name {
    char str[MAX_KSYM_NAME_SIZE];
} ksym_name_t;

struct ring_buffer_msg {
    char msg_[MAX_MSG_STR_SIZE];
};

struct read_buffer {
    unsigned char buffer_[MAX_BUFFER_SIZE];
};

struct global_values {
    int curr_load_sysmbol_;
    int init_handle_fd_;
    int user_pid_;
};


#endif //KERNEL_MAP_COMMON_H
