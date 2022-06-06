# level 1

**disclaimer:** 

my rootkit skeleton was taken from this blog:

https://blog.sourcerer.io/writing-a-simple-linux-kernel-module-d9dc3762c234

## A
printing from a kernel module is done using the function printk.
It accept a log level and a format string, and the output can be seen with the dmesg(1) command

## B
compiling an LKM is done using a makefile:
``` makefile
obj-m += rootkit.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

```

## C
- listing currently loaded LKMs is done with the command lsmod(8)
- inserting a module is done with insmod(8)
- removing a loaded module is done with rmmod(8)

