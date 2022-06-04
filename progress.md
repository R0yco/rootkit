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

**disclaimer:**  most of the hooked getdents64 is based on [this article](https://xcellerator.github.io/posts/linux_rootkits_06/), but I tried to understand every line that I copied.

**aother disclaimer:** there are still parts I don't understand properly here, most of which are 

- kallsyms
- make_address_rw/ro 

still working on it.





# level 3

from strace'ing netstat, it seems that the data comes from reading and parsing /proc/net/tcp file.

```
cat /proc/net/tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 251662 1 0000000000000000 100 0 0 10 0                    
   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 40139 1 0000000000000000 100 0 0 10 0                     
   2: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 36619 1 0000000000000000 100 0 0 10 5                     
   3: 803AA8C0:D062 95F1BDCE:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 186237 1 0000000000000000 20 4 28 10 -1                   
   4: 803AA8C0:C0E6 B3AF2734:01BB 01 00000000:00000000 02:000051DD 00000000  1000        0 69620 2 0000000000000000 20 4 28 10 -1                    
   5: 803AA8C0:DE52 1121E32C:01BB 08 00000000:0000004E 02:00001147 00000000  1000        0 88197 2 0000000000000000 68 4 0 10 -1                     
   6: 803AA8C0:8EFE EFED7522:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 257294 1 0000000000000000 22 4 30 10 -1

```

this^ is while having a python httpserver on port 8000.

```
openat(AT_FDCWD, "/proc/net/tcp", O_RDONLY) = 3
read(3, "  sl  local_address rem_address "..., 4096) = 1050

```

I can think of 2 options of how to solve this from here.

1) hook the read syscall, and check if the opened file is /proc/net/tcp. if it is, remove the server line from the output.
   - this will be complicated because if we hook the read function we only have an fd, not filename, and we will have to backtrack what the filename is.
   - checking all the read outputs without checking if its relevant to us might have performance issues since read is a very very common syscall in linux
2)  hook openat, and if it opens /proc/net/tcp, open it ourselves, and give out a "proxied" syscall.
