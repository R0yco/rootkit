unsigned long (*kallsyms_lookup_name_)(const char *name);


void populate_kallsyms_lookup_name(unsigned long addr)
{
	kallsyms_lookup_name_ = (void*)addr;
}