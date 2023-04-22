# kstatic
    该文件夹对应的是用户态程序中的kstatic package,这个package中包括对KstaticWorker的核心实现，同时这个对象也是
基于common中对于ebpf相关的基础封装所实现的.
    该目录下只包含一个kstatic.go代码文件，其中具体定义了KstaticWorker类，及其相关的方法，比如InitKstaticWorker、
LoadGlobalValues、LoadKallsymsValues等.