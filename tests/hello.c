/*  hello-5.c  */
#include <linux/module.h>      //Needed by all modules
#include <linux/kernel.h>      //Needed for KERN_INFO
#include <linux/moduleparam.h> //参数处理相关头文件
#include <linux/init.h>
#include <linux/stat.h>

MODULE_LICENSE("GPL");         //声明Licesne
MODULE_AUTHOR("Hunk He");      //声明模块作者

static int param_cnt = 0;
static char *param_arr[3] = {"", "", ""};

module_param_array(param_arr, charp, &param_cnt, 0644);     //接收模块参数，参数名为param_arr，类型是字符串数组
//MODULE_PARAM_DESC(param_arr, "My param array[up to 3]."); //参数描述信息，这里有奇怪编译错误

static int __init hello_5_init(void)
{
    printk(KERN_INFO "Hello world 5.\n"); //printk是内核的打印函数，可以向系统日志打印log
    int i;
    for( i = 0; i < 3; ++i) {
        printk(KERN_INFO "param_arr[%d] = %s.\n", i, param_arr[i]);
    }

    return 0;
}

static void __exit hello_5_exit(void)
{
    printk(KERN_INFO "Goodbye world 5.\n");
}

//实际上，模块安装卸载函数的用法还有好几种，可以参考References中的guide
module_init(hello_5_init); //模块加载函数，用modprobe或者insmod命令安装模块时被调用
module_exit(hello_5_exit); //模块卸载函数，用rmmod命令卸载模块时被调用，可以执行一些清理还原操作