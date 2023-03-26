//
// Created by 杨丰硕 on 2023/3/18.
//

#ifndef KERNEL_MAP_KERNEL_H
#define KERNEL_MAP_KERNEL_H

#define BASES_MAXN 6
#define GDT_BASE_IDX 0
#define IDT_BASE_IDX 1

typedef unsigned long long base_offset_t;

struct kernel_static_info {
    char *kernel_data_start_;
    char *kernel_data_end_;
    base_offset_t bases_[BASES_MAXN];
};

void set_static_info_base(struct kernel_static_info *info, base_offset_t base, int idx);

base_offset_t get_static_info_base(const struct kernel_static_info *info, int idx);









#endif //KERNEL_MAP_KERNEL_H
