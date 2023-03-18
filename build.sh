#!/bin/bash

chmod +x ebpf_utils/tools/bpftool
rm -r build
mkdir build
cd build
cmake ..
