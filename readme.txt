# kernnelmap
    整个工程的总目录,其中bpfs中包含了关于内核态ebpf的相关实现,common用于用户态对于ebpf对象及其方法的基本封装,kstatic中则是
对于内核度量工作单元的用户态抽象.tests文件夹下定义了一些用于测试系统有效性的程序,主要是rootkit程序.
    build.sh是一个用于生成CMake构建文件夹及其相应的构建文件的脚本,CMakeList.txt用来驱动bpfs中的CMake进而构建ebpf内核态的部分.
Makefile用于内核态部分的编译与构建.
    main.go是用户态的运行主程序,kernelmap_test.go包含了对于用户态部分程序的单元测试与系统测试.go.mod是该项目的go包管理文件.