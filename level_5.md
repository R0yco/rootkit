# blocking traffic by filter

now I need to block traffic by a certain filter. this seems like a big goal so I don't even know where to start. if I want to block by IP then I can sit on the IP stack and block anything layer 3 and above: ping, tcp udp etc. and if I sit higher- tcp for example- I can filter by port but cannot filter non-tcp protocols.

seems like IP is a better choice for now.

```c
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev)
{
	struct net *net = dev_net(dev);

	skb = ip_rcv_core(skb, net);
	if (skb == NULL)
		return NET_RX_DROP;

	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip_rcv_finish);
}
```

from some poking around, this might be relevant.

https://elixir.bootlin.com/linux/latest/source/net/ipv4/ip_input.c#L547	

I used [this article](https://blog.packagecloud.io/monitoring-tuning-linux-networking-stack-receiving-data/) as reference.

it seems pretty straight forward what I need to do here:

​	return NET_RX_DROP; - this line probably drops the packet.

1. hook this function
2. parse the sk_buff struct
3. extract the source IP
4. if it is our target bad IP, drop with NET_RX_DROP.
5. else, return.

## hooking ip_rcv func

**disclaimer**: I know that this is probably a naive and bad idea, since adding this logic on every IP packet is probably going to slow down the machine, as this is a highly optimized part of the kernel logic.

there are most definetly better ways to do this.



so, like before, I am using the wrapper for ftrace.

```c
static struct ftrace_hook hooks[] = {
 	HOOK("ip_rcv", new_ip_rcv, &old_ip_rcv),
 };
___sniped___
    
asmlinkage int new_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev) {
	printk("hooked ip_rcv! hooray\n");
	return old_ip_rcv(skb, dev, pt, orig_dev);

}
```

wget google.com

sudo dmesg: [ 2574.898953] hooked ip_recv! hooray

now I need to fill it with the above logic.

from [here](https://stackoverflow.com/questions/32585573/how-to-read-actual-destination-address-from-sk-buff) I see how to take this skbuff struct and extract the ip header from it, and there we can find the source ip address.

```c
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	unsigned int src_ip = (unsigned int)ip_header->saddr;
	unsigned int dest_ip = (unsigned int)ip_header->daddr;
	printk(KERN_DEBUG "src IP address = %pI4 dst IP address = %pI4\n", &src_ip, &dest_ip);


```

after looking at dmesg, all I see is those logs:

```
[ 3765.817106] src IP address = 127.0.0.1 dst IP address = 127.0.0.53
[ 3765.817143] src IP address = 127.0.0.1 dst IP address = 127.0.0.53
[ 3765.889335] src IP address = 127.0.0.53 dst IP address = 127.0.0.1
[ 3767.836222] src IP address = 127.0.0.53 dst IP address = 127.0.0.1

```

this is wierd- it seems like I only get local DNS traffic (or whatever this is) and no actual traffic from google.

welp

nevermind, it seems that it did work suddenly.

```
[ 5658.852451] src IP address = 44.227.33.17 dst IP address = 192.168.58.128
[ 5658.906098] src IP address = 192.168.58.2 dst IP address = 192.168.58.128
[ 5658.906359] src IP address = 127.0.0.53 dst IP address = 127.0.0.1
[ 5658.999167] src IP address = 192.168.58.2 dst IP address = 192.168.58.128
[ 5658.999431] src IP address = 127.0.0.53 dst IP address = 127.0.0.1
[ 5659.071494] src IP address = 142.250.185.174 dst IP address = 192.168.58.128
[ 5659.072217] src IP address = 142.250.185.174 dst IP address = 192.168.58.128
[ 5659.291299] src IP address = 142.250.185.174 dst IP address = 192.168.58.128
[ 5659.292469] src IP address = 142.250.185.174 dst IP address = 192.168.58.128
[ 5659.361529] src IP address = 142.250.185.174 dst IP address = 192.168.58.128
```

so it seems to work statistically which is odd. 

I rebooted the machine and it passed completely.

but anyway, my poc worked:

```c

asmlinkage int new_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *ori_dev) {

	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	unsigned int src_ip = (unsigned int)ip_header->saddr;
	unsigned int dest_ip = (unsigned int)ip_header->daddr;

	printk(KERN_INFO "src IP address = %pI4 dst IP address = %pI4 src IP %x\n", &src_ip, &dest_ip, src_ip);
	if (src_ip == 0x01010101)
	{
		printk(KERN_INFO "found traffic from 1.1.1.1\n");
		return NET_RX_DROP;
	}
	//printk("hooked ip_rcv! hooray\n");
	return old_ip_rcv(skb, dev, pt, orig_dev);


}

```

this blocks all IP traffic incomming from 1.1.1.1 .

```bash
ping 1.1.1.1
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
--- 1.1.1.1 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1001ms

sudo rmmod ip_drop_rootkit 
➜  ip_drop_rootkit git:(main) ✗ ping 1.1.1.1              
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=128 time=4.40 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=128 time=3.62 ms 

--- 1.1.1.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 3.623/4.009/4.396/0.386 ms


```

there are still a lot of ways to improve this:

make this work on ARP as well (since arp doesn't have an ip header), make a filter for tcp/udp ports and etc.

but this is but a humble PoC.


