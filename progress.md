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

# level 2

the file I am choosing to hide is /etc/hideme.

my goal here will be to hook and change the relevant syscall output before it reaches ls.

by using strace I figured that the syscall ls(1) is using for listing files is statx(2).

our goal here is probably to hook the call to statx, and strip it of the entry we want to hide. 

after some expirimentation with it, it seems I misunderstood the situation.

the order of the syscalls is

1. statx- get stats of file.

2. openat- open directory and get fd

3. getdents64- actually get the contents of the directory.
   it returns the wanted data as a struct, which can be parsed, + the size of the data in bytes.

   so that is the 2 things we have to change.


## hooking

I chose to hook functions by getting the address of the syscall table and replacing pointers to functions there with my custom functions.

I used [this](https://infosecwriteups.com/linux-kernel-module-rootkit-syscall-table-hijacking-8f1bc0bd099c) article to find out how to get the address of the syscall table from inside the kernel module:

```c
printk("The address of sys_call_table is: %lx\n", kallsyms_lookup_name("sys_call_table"));
```

### oops

compilation error: 

ERROR: modpost: "kallsyms_lookup_name" [/home/royco/rootkit/rootkit.ko] undefined!

it seems the method is outdated and the function is not exported in latest kernels :(

I figured out how to give command line arguments to kernel modules with module_param,
and from [this project](https://github.com/DanielNiv/Process-Hiding-Rootkit/blob/master/captainHook.c) I got the idea of getting the address of kallsyms_lookup_name function from /proc/kallsyms and setting it in the code.



I managed to hook the function getdents, and my function is now called instead while the lkm is loaded.

from reading online I saw that when syscalled are called from userspace, the arguments are stored in %rdi,%rsi,%rdx,%r10,%r8,%r9 respectively.
getdents signature looks like this:


   ```c
   size_t getdents64(int fd, void *dirp, size_t count);
   ```

which means that the dirent structure which I want to change will be in the RSI register.

### crashing

i've run into a situation where the following line caused a system crash:

```c
printk("%d\n",dirent->d_reclen); - this line crashes the kernel
```

where dirent is a userspace address containing the dirent64 struct.

I saw that [this blogpost](https://xcellerator.github.io/posts/linux_rootkits_06/) allocated a kernel buffer and copied the struct to there, then operated on it there. I tried it and it stopped crashing. 
I'm still not sure why dereferencing a userspace addr from kernel caused the crash- **need to learn more about it.**

turns out it also crashes when doing printk on the kernel-buffer copied struct, but it works fine otherwise- just the printk crashes it. No idea why this happens but it wasted me some precious time.

```assembly
mov %rax, 1
ret
lea a, b
```

