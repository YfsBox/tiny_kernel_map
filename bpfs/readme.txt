# bpfs
    该文件夹下面,主要是内核态中ebpf程序相关的实现。
    libbpf文件夹之下存放了有关于libbpf库的相关内容。tools则是与ebpf相关的构建工具。vmlinux中包含了一些内核信息的头文件。
    CMakeLists.txt是该目录下的CMake构建文件，将会得出kernel.bpf.o目标文件,从而可被加载到内核.
    common.h/c中涉及到对于内核中一些基本数据结构的定义与实现,crc.h中包含了对于crc64算法的定义与实现.kernel.bpf.c中包含了
对于ebpf内核态程序的核心部分,其中包含感知层所用的内核hook函数,以及度量所用的hook,以及相关的map数据结构.
