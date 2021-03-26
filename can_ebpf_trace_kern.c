#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <linux/can.h>
#include <linux/can/dev.h>
#include "bpf_helpers.h"

#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

#define MAX_CAN_DEVICES 10

struct TxRx_Pair {
	u32 txCount;
	u32 rxCount;
};

struct netdevxmit_args {
	long nameptr;
	long skbptr;
	long len;
	long rc;
};

struct netif_rx_args {
	long nameptr;
	long skbptr;
	long len;
};

struct bpf_map_def SEC("maps") can_stat_counter = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(u64),
	.max_entries = MAX_CAN_DEVICES,
};

SEC("tracepoint/net/net_dev_xmit")
int bpf_prog_send_canmsg_Count( struct netdevxmit_args  *ctx)
{
	struct sk_buff *skb;
	struct net_device *dev;
	char devname[30] = {0};
	u64 key = 0, *map_element;  
	u64 init_value = 1;
	skb = (struct sk_buff *) ctx->skbptr;
	dev = _(skb->dev);
    bpf_probe_read(devname, sizeof (devname), dev->name); // get can device name
	
	if (devname[0] == 'c' && devname[1] == 'a' && devname[2] == 'n' )
	{
		key = devname[3] - '0'; //key is index number of the can0/can1,...
		map_element = bpf_map_lookup_elem(&can_stat_counter, &key);		
		if(map_element)
		{
			struct TxRx_Pair *ele = map_element;
			ele->txCount +=1;
		}
		else
		{
			bpf_map_update_elem(&can_stat_counter,&key,&init_value,BPF_NOEXIST);
		} 
	}
	return 0;
}


SEC("tracepoint/net/netif_receive_skb")
int bpf_prog_receive_canmsg_Count( struct netif_rx_args  *ctx)
{
	struct sk_buff *skb;
	struct net_device *dev;
	char devname[30] = {0};
	u64 key = 0,init_value =0x0100000000, *map_element;  
	u64 value=0;
	skb = (struct sk_buff *) ctx->skbptr;
	dev = _(skb->dev);
    bpf_probe_read(devname, sizeof (devname), dev->name); // get can device name
	
	if (devname[0] == 'c' && devname[1] == 'a' && devname[2] == 'n' )
	{
		key = devname[3] - '0'; //key is index number of the can0/can1,...
		map_element = bpf_map_lookup_elem(&can_stat_counter, &key);		
		if(map_element)
		{
			struct TxRx_Pair *ele = map_element;
			ele->rxCount +=1;
		}
		else
		{
			bpf_map_update_elem(&can_stat_counter,&key,&init_value,BPF_NOEXIST);
		} 
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
