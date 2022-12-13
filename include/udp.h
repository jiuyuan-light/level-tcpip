#ifndef __M_UDP_H__
#define __M_UDP_H__

#include "ip.h"

struct udp_sock {
    struct sock sk;
    uint16_t smss;  /* Max Segment Size */ /* 鉴于 Internet 上的标准 MTU 值为 576 字节，所以建议在进行 Internet 的 UDP 编程时，最好将 UDP 的数据长度控件在 548 字节(576-20-8)以内 */
};

#define UDP_HDR_LEN     (sizeof(struct lvl_udphdr))
#define udp_sk(sk) ((struct udp_sock *)sk)


struct lvl_udphdr {
    uint16_t sport;             /* 源端口号 */
    uint16_t dport;             /* 目的端口号 */
    uint16_t length;            /* UDP长度 = UDP头部 + UDP数据的长度 */
    uint16_t checksum;          /* UDP校验和 */
    uint8_t data[0];
};

static inline struct lvl_udphdr *udp_hdr(const struct sk_buff *skb)
{
    return (struct lvl_udphdr *)(skb->head + ETH_HDR_LEN + IP_HDR_LEN);
}

struct sock *udp_alloc_sock(int protocol);
int udp_v4_init_sock(struct sock *sk);
int udp_write(struct sock *sk, const void *buf, int len);
int udp_send(struct udp_sock *usk, const void *buf, int len);
int udp_close(struct sock *sk);

void udp_in(struct sk_buff *skb);
int udp_recv_notify(struct sock *sk);
int udp_read(struct sock *sk, void *buf, int len);

#endif /* __M_UDP_H__ */