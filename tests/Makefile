CC := gcc
ENTRY := hello
obj-m := $(ENTRY).o
KERNEL_VER = $(shell uname -r)
default: notfound_build

force_build: hello.c
	make -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) modules
	#make -C linux-5.15 M=$(PWD) modules
	ls -alh *.ko

notfound_build: hello.c
	[ -f *.ko ] || make -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) modules
	#[ -f *.ko ] || make -C linux-5.15 M=$(PWD) modules

build: force_build

clean:
	make -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) clean

insmod: info notfound_build
	dmesg --clear
	insmod hello.ko || true
	dmesg

rmmod:
	rmmod hello && dmesg

lsmod:
	lsmod |grep hello

status: lsmod

info: notfound_build hello.ko
	modinfo hello.ko
	md5sum hello.ko

modinfo: info