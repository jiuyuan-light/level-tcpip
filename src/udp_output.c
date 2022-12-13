#include "syshead.h"
#include "utils.h"
#include "dst.h"
#include "udp.h"
#include "ipc.h"
#include "ip.h"
#include "skbuff.h"
#include "timer.h"

int udp_v4_checksum(struct sk_buff *skb, uint32_t saddr, uint32_t daddr)
{
    return tcp_udp_checksum(saddr, daddr, IP_UDP, skb->data, skb->len);
}

static int udp_transmit_skb(struct sock *sk, struct sk_buff *skb)
{
    struct lvl_udphdr *uhdr = udp_hdr(skb);
    int re;

    skb_push(skb, UDP_HDR_LEN);

    uhdr->sport = htons(sk->sport);
    uhdr->dport = htons(sk->dport);
    // uhdr->length = htons((char *)skb->end - (char *)skb->data);
    uhdr->length = htons(skb->len);
    uhdr->checksum = udp_v4_checksum(skb, htonl(sk->saddr), htonl(sk->daddr));

    re = ip_output(sk, skb);
    if (re < 0) {
        if (re == NO_ARP_ENTRY) { /* 发送失败 */
            /* 添加wait arp的节点 */
            lvl_ip_warn("NO ARP ENTRY, ADD NODE, INSERT SKB");
            skb_queue_tail(&sk->write_queue, skb);
            sock_wait_arp_entry_add(sk->sock);
            if (SOCK_IS_NONBLOCK(sk->sock)) {
                lvl_ip_info("Socket[%d] is nonblock and no arp entry, but immediately return success", sk->sock->connfd);
            }
            return 0;
        }
        return -1;
    }

    return 0;
}

static struct sk_buff *udp_alloc_skb(int optlen, int size)
{
    int reserved = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + optlen + size;
    struct sk_buff *skb = alloc_skb(reserved);
    if (!skb) {
        return NULL;
    }

    skb_reserve(skb, reserved);
    skb->protocol = IP_UDP;
    skb->dlen = size;
    skb->seq = 0;

    return skb;
}

int udp_send(struct udp_sock *usk, const void *buf, int len)
{
    struct sk_buff *skb;
    int slen = len;
    int mss = usk->smss;
    int dlen = 0;

    dlen = slen > mss ? mss : slen;
    slen -= dlen;

    skb = udp_alloc_skb(0, dlen);
    if (!skb) {
        return -1;
    }
    skb_push(skb, dlen); // ����skb���Դ��dlen������
    memcpy(skb->data, buf, dlen);
    buf += dlen;

    if (udp_transmit_skb(&usk->sk, skb)) {
        return -1;
    }

    return udp_data_len(skb);
}
