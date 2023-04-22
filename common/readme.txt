# common
    common文件夹下的代码用于在用户态对于可操作的ebpf对象或接口进行基本的封装,从而便于在KstaticWorker中调用.
    bpfworker.go是对于一个ebpf工作单元所进行的基本的封装.maps.go对于不同类型的ebpf map进行了封装,包括ring buffer、
perf buffer等类型.point.go用于对于ebpf hook point的封装,支持kprobe、tracepoint等类型.utils.go中则定义了一些辅助方法.


