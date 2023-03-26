//
// Created by 杨丰硕 on 2023/3/25.
//
#include <signal.h>
#include "common.h"
#include "kstatic_info_collector.h"

int main(int argc, char **argv) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct kstatic_info_collector *collector = (struct kstatic_info_collector *) calloc(0, sizeof(struct kstatic_info_collector));
    start_kstatic_info_collector(collector);

}

