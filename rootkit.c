#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ROYCO");
MODULE_DESCRIPTION("a kernel module rootkit");
MODULE_VERSION("1");
static int __init rootkit_enter(void) {
 printk(KERN_INFO "Hello, World!\n");
 return 0;
}
static void __exit rootkit_exit(void) {
 printk(KERN_INFO "Goodbye, World!\n");
}
module_init(rootkit_enter);
module_exit(rootkit_exit);
