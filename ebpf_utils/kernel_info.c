//
// Created by 杨丰硕 on 2023/3/26.
//
#include "kernel_info.h"

void set_static_info_base(struct kernel_static_info *info, base_offset_t base, int idx) {
    info->bases_[idx] = base;
}

base_offset_t get_static_info_base(const struct kernel_static_info *info, int idx) {
    return info->bases_[idx];
}

