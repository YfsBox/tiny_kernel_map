#!/bin/bash

chmod +x bpfs/tools/bpftool
rm -r build
mkdir build
cd build
cmake ..
