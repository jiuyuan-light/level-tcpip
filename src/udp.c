#include "syshead.h"
#include <hloop.h>

#include "inet.h"
#include "udp.h"
#include "ip.h"
#include "sock.h"
#include "utils.h"
#include "timer.h"
#include "wait.h"

struct sock *udp_alloc_sock(int protocol);

struct net_ops udp_ops = {
    .alloc_sock = udp_alloc_sock,
    .init = udp_v4_init_sock,
    .connect = NULL,
    .disconnect = NULL,
    .write = udp_write,
    .read = udp_read,
    .recv_notify = udp_recv_notify,
    .close = udp_close,
    // .abort = &tcp_abort,
};

// int ipc_read(int sockfd, struct ipc_msg *msg, int len);
// void block_io_can_read(hevent_t* ev)
// {
//     lvl_ip_warn("BLOCK IO CAN READ");

//     void *b = hloop_userdata(get_ipc_loop());
//     if (!b) {
//         lvl_ip_warn("B ERROR");
//         return;
//     }

//     int sockfd;

//     memcpy(&sockfd, b, sizeof(int));
//     struct ipc_msg *msg = (char*)b + sizeof(int);
//     ipc_read(sockfd, msg, -1);
//     hloop_set_userdata(get_ipc_loop(), NULL);
//     free(b);
// }

int udp_recv_notify(struct sock *sk)
{
    // hevent_t ev;
    // memset(&ev, 0, sizeof(ev));
    // ev.cb = block_io_can_read;

    // lvl_ip_warn("NTF IPC LOOP");
    // // ev.userdata = NULL;
    // hloop_t *loop = get_ipc_loop();
    // if (!loop) {
    //     lvl_ip_warn("LOOP IS NIL???");
    //     return -1;
    // }
    // hloop_post_event(loop, &ev);
    lvl_ip_warn("udp_recv_notify DO NOTHING");

    return 0;
}

struct sock *udp_alloc_sock(int protocol)
{
    struct udp_sock *usk = malloc(sizeof(struct udp_sock));
    if (!usk) {
        /* TODO */
        return NULL;
    }

    memset(usk, 0, sizeof(struct udp_sock));
    usk->smss = 548;
    
    return (struct sock *)usk;
}

int udp_v4_init_sock(struct sock *sk)
{
    sk->sport = generate_port();

    return 0;
}

int udp_read(struct sock *sk, void *buf, int len)
{
    int rlen = 0;
    struct sk_buff *skb;
    struct socket *sock = sk->sock;

    memset(buf, 0, len);
    if (!skb_queue_empty(&sk->receive_queue)) {
        skb = skb_dequeue(&sk->receive_queue);
        if (skb->len <= len) {
            memcpy(buf, skb->payload, skb->len);
            rlen = skb->len;
            skb->refcnt--;
            free_skb(skb); /* TODO, 其他线程? */
        }
    }

    if (SOCK_IS_NONBLOCK(sock)) {
        if (rlen == 0) {
            rlen = -EAGAIN;
        }
    }

    if (skb_queue_empty(&sk->receive_queue)) {
        sk->poll_events &= ~POLLIN;
    }

    return rlen;
}

int udp_write(struct sock *sk, const void *buf, int len)
{
    struct udp_sock *usk = udp_sk(sk);
    int ret = sk->err;

    if (ret != 0) goto out;

    return udp_send(usk, buf, len);

out: 
    return ret;
}

int udp_close(struct sock *sk)
{
    return 0;
}

static void udp_init_pkt(struct lvl_udphdr *uh, struct sk_buff *skb)
{
    uh->sport = ntohs(uh->sport);
    uh->dport = ntohs(uh->dport);
    uh->length = ntohs(uh->length);

    skb->len = uh->length - UDP_HDR_LEN;
    skb->payload = uh->data;
}

int udp_input(struct sock *sk, struct lvl_udphdr *uh, struct sk_buff *skb)
{
    struct udp_sock *usk = udp_sk(sk);

    skb->refcnt++;
    skb_queue_tail(&sk->receive_queue, skb);

    // There is new data for user to read
    sk->poll_events |= (POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND);
    usk->sk.ops->recv_notify(&usk->sk);

    return 0;
}

void udp_in(struct sk_buff *skb)
{
    struct sock *sk;
    struct lvl_udphdr *uh = udp_hdr(skb);

    udp_init_pkt(uh, skb);

    sk = inet_lookup(skb, uh->sport, uh->dport);
    if (!sk) {
        lvl_ip_trace("No UDP socket for sport %d dport %d", uh->sport, uh->dport);
        free_skb(skb);
        return;
    }
    socket_wr_acquire(sk->sock);

    /* check 校验和 */
    /* if (udp_checksum(iph, uh) != 0) { */
    /*     goto discard; */
    /* } */
    udp_input(sk, uh, skb);

    socket_release(sk->sock);
}
