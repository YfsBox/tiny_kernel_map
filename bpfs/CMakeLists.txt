set(C_FLAGS
        -g
        -Wall
        -O2
        -std=c99
        -D_PTHREADS
        )

set(CMAKE_C_COMPILER "clang")

string(REPLACE ";" " " CMAKE_C_FLAGS "${C_FLAGS}")

# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake)

# Build vendored libbpf
include(ExternalProject)
ExternalProject_Add(libbpf
        PREFIX libbpf
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make
        BUILD_STATIC_ONLY=1
        OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
        DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
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
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_SOURCE_DIR}/tools/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

# Create an executable for each application
file(GLOB apps *.bpf.c)
SET(skel_list)
foreach(app ${apps})
    get_filename_component(app_stem ${app} NAME_WE)
    # Build object skeleton and depend skeleton on libbpf build
    bpf_object(${app_stem} ${app_stem}.bpf.c)
    add_dependencies(${app_stem}_skel libbpf-build)
    list(APPEND skel_list ${app_stem}_skel)
endforeach()

string(REPLACE ";" " " SKEL_LIST "${skel_list}")

SET(BPF_SRC
        common.c
        )

add_library(ebpfs ${BPF_SRC})
target_link_libraries(ebpfs ${skel_list} pthread rt)

