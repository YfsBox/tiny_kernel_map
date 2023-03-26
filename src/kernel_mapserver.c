//
// Created by 杨丰硕 on 2023/3/25.
//
#include <signal.h>
#include "kstatic_info_collector.h"

int main(int argc, char **argv) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

}

