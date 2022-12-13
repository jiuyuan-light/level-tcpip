#include "syshead.h"
#include "dst.h"
#include "ip.h"
#include "arp.h"

int dst_neigh_output(struct sk_buff *skb)
{
    struct iphdr *iphdr = ip_hdr(skb);
    struct netdev *netdev = skb->dev;
    struct rtentry *rt = skb->rt;
    uint32_t daddr = ntohl(iphdr->daddr);
    uint32_t saddr = ntohl(iphdr->saddr);

    uint8_t *dmac;

    if (rt->flags & RT_GATEWAY) {
        daddr = rt->gateway;
    }
    
    dmac = arp_get_hwaddr(daddr);
    if (dmac) {
        return netdev_transmit(skb, dmac, ETH_P_IP);
    } else {
        arp_request(saddr, daddr, netdev);

        /* Inform upper layer that traffic was not sent, retry later */
        /* TCP应该是在三次握手获取到路由，后续数据报文可以正常发送
            UDP的报文没有邻居地址，要进行处理 */
        lvl_ip_warn("FIRST PKT ERR, CHECK [SOME THREAD] RETRY");
        return NO_ARP_ENTRY;
    }
}
