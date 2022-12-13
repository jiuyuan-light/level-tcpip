#include "syshead.h"
#include "skbuff.h"
#include "arp.h"
#include "ip.h"
#include "icmpv4.h"
#include "tcp.h"
#include "udp.h"
#include "utils.h"

static void ip_init_pkt(struct iphdr *ih)
{
    ih->saddr = ntohl(ih->saddr);
    ih->daddr = ntohl(ih->daddr);
    ih->len = ntohs(ih->len);
    ih->id = ntohs(ih->id);
}

int ip_rcv(struct sk_buff *skb)
{
    struct iphdr *ih = ip_hdr(skb);
    uint16_t csum = -1;

    if (ih->version != IPV4) {
        print_err("Datagram version was not IPv4\n");
        goto drop_pkt;
    }

    if (ih->ihl < 5) {
        print_err("IPv4 header length must be at least 5\n");
        goto drop_pkt;
    }

    if (ih->ttl == 0) {
        //TODO: Send ICMP error
        print_err("Time to live of datagram reached 0\n");
        goto drop_pkt;
    }

    csum = checksum(ih, ih->ihl * 4, 0);

    if (csum != 0) {
        // Invalid checksum, drop packet handling
        goto drop_pkt;
    }

    // TODO: Check fragmentation, possibly reassemble

    ip_init_pkt(ih);

    ip_dbg("in", ih);

    switch (ih->proto) {
    case ICMPV4:
        icmpv4_incoming(skb);
        return 0;
    case IP_TCP:
        lvl_ip_debug("====================== ip->tcp recv ======================");
        tcp_in(skb);
        return 0;
    case IP_UDP:
        udp_in(skb);
        return 0;
    case IP_IGMP:
        lvl_ip_trace("Not sup IGMP");
        goto drop_pkt;
    default:
        lvl_ip_trace("Unknown IP header proto[%d]", ih->proto);
        goto drop_pkt;
    }

drop_pkt:
    free_skb(skb);
    return 0;
}
