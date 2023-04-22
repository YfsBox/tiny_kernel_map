/*  hello-5.c  */
#include <linux/module.h>      //Needed by all modules
#include <linux/kernel.h>      //Needed for KERN_INFO
#include <linux/moduleparam.h> //参数处理相关头文件
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/stat.h>

MODULE_LICENSE("GPL");         //声明Licesne
MODULE_AUTHOR("Hunk He");      //声明模块作者

static int __init hello_5_init(void) {
    printk(KERN_INFO "Hello world 5.\n"); //printk是内核的打印函数，可以向系统日志打印log
    return 0;
}

static void __exit hello_5_exit(void) {
    printk(KERN_INFO "Goodbye world 5.\n");
}

//实际上，模块安装卸载函数的用法还有好几种，可以参考References中的guide
module_init(hello_5_init); //模块加载函数，用modprobe或者insmod命令安装模块时被调用
module_exit(hello_5_exit); //模块卸载函数，用rmmod命令卸载模块时被调用，可以执行一些清理还原操作