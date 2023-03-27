cmake_minimum_required(VERSION 3.16)
project(kernel_map C)

set(CMAKE_C_STANDARD 99)

set(C_FLAGS
        -g
        -Wall
        -std=c99
        -D_PTHREADS
        )

set(CMAKE_C_COMPILER "clang")
set(CMAKE_C_FLAGS_DEBUG "-O3")
set(CMAKE_C_FLAGS_RELEASE "-O3")

string(REPLACE ";" " " CMAKE_C_FLAGS "${C_FLAGS}")

# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/ebpf_utils//tools/cmake)

# Build vendored libbpf
include(ExternalProject)
ExternalProject_Add(libbpf
        PREFIX libbpf
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ebpf_utils/libbpf/src
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make
        BUILD_STATIC_ONLY=1
        OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/ebpf_utils/libbpf/libbpf
        DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/ebpf_utils/libbpf
        INCLUDEDIR=
        LIBDIR=
        UAPIDIR=
        install
        BUILD_IN_SOURCE TRUE
        INSTALL_COMMAND ""
        STEP_TARGETS build
        )

# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment (like libbpf-bootstrap)
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_SOURCE_DIR}/ebpf_utils/tools/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/ebpf_utils/vmlinux/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/ebpf_utils/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/ebpf_utils/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

# Create an executable for each application
SET(skel_list)


#foreach(app ${apps})
#    get_filename_component(app_stem ${app} NAME_WE)
#    bpf_object(${app_stem} ${app_stem}.bpf.c)
#    add_dependencies(${app_stem}_skel libbpf-build)
#    list(APPEND skel_list ${app_stem}_skel)
# endforeach()

bpf_object(kernel ebpf_utils/kernel_info.c ebpf_utils/kernel.bpf.c)
add_dependencies(kernel_skel libbpf-build)
list(APPEND skel_list kernel_skel)

string(REPLACE ";" " " SKEL_LIST "${skel_list}")

set(BPF_SRC
        ebpf_utils/kernel_info.c
        src/kernel_mapserver.c
        src/kstatic_info_collector.c
        src/common.c)

add_executable(mapserver ${BPF_SRC})
target_link_libraries(mapserver ${skel_list} pthread rt)
