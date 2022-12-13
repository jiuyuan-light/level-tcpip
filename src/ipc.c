#include <hsocket.h>
#include <hloop.h>

#include "syshead.h"
#include "utils.h"
#include "ipc.h"
#include "arp.h"
#include "socket.h"
#include "ipc_nonblock.h"

#define IPC_BUFLEN 8192

int ipc_try_send(int sockfd, const void *buf, size_t len)
{
    return send(sockfd, buf, len, MSG_NOSIGNAL);
}

int ipc_write_rc(int sockfd, pid_t pid, uint16_t type, int rc)
{
    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err);
    struct ipc_msg *response = alloca(resplen);
    if (response == NULL) {
        lvl_ip_warn("Could not allocate memory for IPC write response\n");
        return -1;
    }

    response->type = type;
    response->pid = pid;

    struct ipc_err err;

    if (rc < 0) {
        err.err = -rc;
        err.rc = -1;
    } else {
        err.err = 0;
        err.rc = rc;
    }
    
    memcpy(response->data, &err, sizeof(struct ipc_err));
    if (ipc_try_send(sockfd, (char *)response, resplen) == -1) {
        lvl_ip_warn("Error on writing IPC write response");
    }

    return 0;
}

int ipc_read(int sockfd, struct ipc_msg *msg, int len)
{
    struct ipc_read *requested = (struct ipc_read *) msg->data;
    pid_t pid = msg->pid;
    int rlen = -1;
    char rbuf[requested->len];
    memset(rbuf, 0, requested->len);

    lvl_ip_trace("[IPC] on_recv ipc_read, fd %d pid %d", sockfd, pid);
    rlen = _read(pid, requested->sockfd, rbuf, requested->len);
    struct socket *sock = get_struct_socket_by_pidandfd(pid, requested->sockfd);
    if (sock == NULL) {
        lvl_ip_warn("Read: could not find socket (fd %u) for connection (pid %d)", requested->sockfd, pid);
        return -1;
    }

    socket_wr_acquire(sock);
    if (rlen == WAIT_MORE_DATA) {
        ipc_post_wait(sock, IPC_CONNECT);
        socket_release(sock);
        return 0;
    } else if (rlen >= 0) {
        sock->readbytes = rlen;
        memcpy(sock->readbuf, rbuf, rlen > 0 ? rlen : 0);
        ipc_post_direct_response_with_sock(IPC_READ, rlen, sock);
    }
    socket_release(sock);

    return 0;
}

static int ipc_write(int sockfd, struct ipc_msg *msg)
{
    struct ipc_write *payload = (struct ipc_write *) msg->data;
    pid_t pid = msg->pid;
    int rc = -1;
    int head = IPC_BUFLEN - sizeof(struct ipc_write) - sizeof(struct ipc_msg);
    struct socket *sock;

    lvl_ip_trace("[IPC] on_recv ipc_write, fd %d pid %d", sockfd, pid);
    char buf[payload->len];
    memset(buf, 0, payload->len);
    memcpy(buf, payload->buf, payload->len > head ? head : payload->len);

    // Guard for payload that is longer than initial IPC_BUFLEN
    if (payload->len > head) {
        int tail = payload->len - head;
        int res = read(sockfd, &buf[head], tail);
        if (res == -1) {
            perror("Read on IPC payload guard");
            return -1;
        } else if (res != tail) {
            print_err("Hmm, we did not read exact payload amount in IPC write\n");
        }
    }

    if ((sock = get_struct_socket_by_pidandfd(pid, payload->sockfd)) == NULL) {
        print_err("Write: could not find socket (fd %u) for connection (pid %d)\n", sockfd, pid);
        return -EBADF;
    }

    socket_wr_acquire(sock);
    rc = sock->ops->write(sock, buf, payload->len);

    /* TODO 发送成功? */
    ipc_post_direct_response_with_sock(IPC_WRITE, rc, sock);

    socket_release(sock);

    return 0;
}

static int ipc_connect(int sockfd, struct ipc_msg *msg)
{
    struct ipc_connect *payload = (struct ipc_connect *)msg->data;
    pid_t pid = msg->pid;
    int rc = -1;
    struct socket *sock;

    lvl_ip_trace("[IPC] on_recv ipc_connect, fd %d pid %d", sockfd, pid);
    if ((sock = get_struct_socket_by_pidandfd(pid, payload->sockfd)) == NULL) {
        print_err("Connect: could not find socket (fd %u) for connection (pid %d)\n", sockfd, pid);
        return -EBADF;
    }

    socket_wr_acquire(sock);
    rc = sock->ops->connect(sock, &payload->addr, payload->addrlen, 0);
    if (rc == WAIT_CONNECTED) {
        ipc_post_wait(sock, IPC_CONNECT);
        socket_release(sock);
        return 0;
    }
    ipc_post_direct_response_with_sock(IPC_CONNECT, rc, sock);

    if (SOCK_IS_NONBLOCK(sock)) {
        lvl_ip_info("[CONNECT] APP[%s] expect SOCK [%d][%s]", get_sock_type(sock->type), sock->fd, "NONBLOCK");
    } else {
        lvl_ip_info("[CONNECT] APP[%s] expect SOCK [%d][%s]", get_sock_type(sock->type), sock->fd, "BLOCK");
    }
    socket_release(sock);
    return 0;
}

static int ipc_socket(int sockfd, struct ipc_msg *msg)
{
    struct ipc_socket *sock = (struct ipc_socket *)msg->data;
    pid_t pid = msg->pid;
    int rc = -1;

    lvl_ip_trace("[IPC] on_recv ipc_socket, fd %d pid %d", sockfd, pid);
    rc = _socket(pid, sockfd, sock->domain, sock->type, sock->protocol);

    ipc_nonblock_socket_resp_t resp;
    IPC_NONBLOCK_SOCKET_RESP_INIT(&resp, sockfd, pid, sizeof(ipc_nonblock_socket_resp_t));
    resp.socket = rc;
    ipc_post_direct_response(IPC_SOCKET, rc >= 0 ? 0 : -1, &resp);
    return 0;
}

static int ipc_close(int sockfd, struct ipc_msg *msg)
{
    struct ipc_close *payload = (struct ipc_close *)msg->data;
    pid_t pid = msg->pid;
    int rc = -1;

    lvl_ip_trace("[IPC] on_recv ipc_close, fd %d pid %d", sockfd, pid);
    rc = _close(pid, payload->sockfd);

    ipc_post_direct_response_with_id(IPC_CLOSE, rc, pid, payload->sockfd);

    return rc;
}

static int polled_with_pid(struct pollfd *fds, int nfds, int pid)
{
    int polled = 0;

    for (int i = 0; i < nfds; i++) {
        struct socket *sock;
        struct pollfd *poll = &fds[i];
        if ((sock = get_struct_socket_by_pidandfd(pid, poll->fd)) == NULL) {
            print_err("Poll: could not find socket (fd %u) for connection (pid %d)\n", poll->fd, pid);
            return -EBADF;
        }

        socket_rd_acquire(sock);
        poll->revents = sock->sk->poll_events & (poll->events | POLLHUP | POLLERR | POLLNVAL);
        
        CLEAN_FLAG(sock->ipc_wait_resp_type);
        if (poll->revents > 0) {
            polled++;
        }
        socket_release(sock);
    }

    return polled;
}

static void nonblock_poll_response(int pid, int fd, int polled, int nfds, struct pollfd *fds)
{
    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_pollfd) * nfds;
    struct ipc_msg *response = alloca(resplen);
    if (response == NULL) {
        lvl_ip_warn("Could not allocate memory for IPC write response\n");
        return;
    }

    response->type = IPC_POLL;
    response->pid = pid;

    struct ipc_err err;
    if (polled < 0) {
        err.err = -polled;
        err.rc = -1;
    } else {
        err.err = 0;
        err.rc = polled;
    }
    
    memcpy(response->data, &err, sizeof(struct ipc_err));

    struct ipc_pollfd *poll = (struct ipc_pollfd *) ((struct ipc_err *)response->data)->data;

    for (int i = 0; i < nfds; i++) {
        poll[i].fd = fds[i].fd;
        poll[i].events = fds[i].events;
        poll[i].revents = fds[i].revents;
    }

    if (ipc_try_send(fd, response, resplen) == -1) {
        lvl_ip_warn("Error on writing IPC poll response1");
    }
}

static void ipc_poll_timer_cb(htimer_t* timer)
{
    poll_timer_t *ctx = hevent_userdata(timer);

    int polled = polled_with_pid(ctx->fds, ctx->nfds, ctx->pid);
    if (polled > 0 || !ctx->infinite) {
        nonblock_poll_response(ctx->pid, ctx->connfd, polled, ctx->nfds, ctx->fds);
        free(ctx->fds);
        free(ctx);
        htimer_del(timer);
    }
}

static int ipc_poll(int sockfd, struct ipc_msg *msg)
{
    struct ipc_poll *data = (struct ipc_poll *)msg->data;
    pid_t pid = msg->pid;
    struct pollfd fds[data->nfds]; /* 和ipc_pollfd类型不同 */

    lvl_ip_trace("[IPC] on_recv ipc_poll, fd %d pid %d", sockfd, pid);
    for (int i = 0; i < data->nfds; i++) {
        fds[i].fd = data->fds[i].fd;
        fds[i].events = data->fds[i].events;
        fds[i].revents = data->fds[i].revents;
    }

    int polled = polled_with_pid(fds, data->nfds, pid);
    if (polled > 0 || data->timeout == 0) {
        nonblock_poll_response(pid, sockfd, polled, data->nfds, fds);
        return 0;
    }

    poll_timer_t *timer = malloc(sizeof(poll_timer_t));
    if (!timer) {
        lvl_ip_warn("No enouth memory for timer");
        return -1;
    }
    memset(timer, 0, sizeof(poll_timer_t));

    timer->fds = malloc(sizeof(fds));
    if (!timer->fds) {
        lvl_ip_warn("No enouth memory for timer->fds");
        return -1;
    }
    memcpy(timer->fds, fds, sizeof(fds));
    timer->nfds = data->nfds;
    timer->pid = pid;
    timer->connfd = sockfd;

    if (data->timeout < 0) {
        data->timeout = 1000;
        timer->infinite = 1;
    }
    htimer_t *htimer = htimer_add(get_ipc_loop(), ipc_poll_timer_cb, data->timeout, INFINITE);
    if (!htimer) {
        lvl_ip_warn("htimer error");
        return -1;
    }

    hevent_set_userdata(htimer, timer);
    return 0;
}

static int ipc_fcntl(int sockfd, struct ipc_msg *msg)
{
    struct ipc_fcntl *fc = (struct ipc_fcntl *)msg->data;
    pid_t pid = msg->pid;
    int rc = -1;

    lvl_ip_trace("[IPC] on_recv ipc_fcntl, fd %d pid %d", sockfd, pid);
    switch (fc->cmd) {
    case F_GETFL:
        rc = _fcntl(pid, fc->sockfd, fc->cmd);
        break;
    case F_SETFL:
        rc = _fcntl(pid, fc->sockfd, fc->cmd, *(int *)fc->data);
        break;
    default:
        print_err("IPC Fcntl cmd not supported %d\n", fc->cmd);
        rc = -EINVAL;
    }
    
    return ipc_write_rc(sockfd, pid, IPC_FCNTL, rc);
}

static int ipc_getsockopt(int sockfd, struct ipc_msg *msg)
{
    struct ipc_sockopt *opts = (struct ipc_sockopt *)msg->data;

    pid_t pid = msg->pid;
    int rc = -1;

    rc = _getsockopt(pid, opts->fd, opts->level, opts->optname, opts->optval, &opts->optlen);

    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockopt) + opts->optlen;
    struct ipc_msg *response = alloca(resplen);

    if (response == NULL) {
        print_err("Could not allocate memory for IPC getsockopt response\n");
        return -1;
    }

    response->type = IPC_GETSOCKOPT;
    response->pid = pid;

    struct ipc_err err;

    if (rc < 0) {
        err.err = -rc;
        err.rc = -1;
    } else {
        err.err = 0;
        err.rc = rc;
    }
    
    memcpy(response->data, &err, sizeof(struct ipc_err));

    struct ipc_sockopt *optres = (struct ipc_sockopt *) ((struct ipc_err *)response->data)->data;

    optres->fd = opts->fd;
    optres->level = opts->level;
    optres->optname = opts->optname;
    optres->optlen = opts->optlen;
    memcpy(&optres->optval, opts->optval, opts->optlen);

    if (ipc_try_send(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC getsockopt response");
    }

    return rc;
}

static int ipc_getpeername(int sockfd, struct ipc_msg *msg)
{
    struct ipc_sockname *name = (struct ipc_sockname *)msg->data;

    pid_t pid = msg->pid;
    int rc = -1;

    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockname);
    struct ipc_msg *response = alloca(resplen);

    if (response == NULL) {
        print_err("Could not allocate memory for IPC getpeername response\n");
        return -1;
    }

    response->type = IPC_GETPEERNAME;
    response->pid = pid;

    struct ipc_sockname *nameres = (struct ipc_sockname *) ((struct ipc_err *)response->data)->data;
    rc = _getpeername(pid, name->socket, (struct sockaddr *)nameres->sa_data, &nameres->address_len);
    
    struct ipc_err err;

    if (rc < 0) {
        err.err = -rc;
        err.rc = -1;
    } else {
        err.err = 0;
        err.rc = rc;
    }
    
    memcpy(response->data, &err, sizeof(struct ipc_err));

    nameres->socket = name->socket;
    
    if (ipc_try_send(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC getpeername response");
    }

    return rc;
}

static int ipc_getsockname(int sockfd, struct ipc_msg *msg)
{
    struct ipc_sockname *name = (struct ipc_sockname *)msg->data;

    pid_t pid = msg->pid;
    int rc = -1;

    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockname);
    struct ipc_msg *response = alloca(resplen);

    if (response == NULL) {
        print_err("Could not allocate memory for IPC getsockname response\n");
        return -1;
    }

    response->type = IPC_GETSOCKNAME;
    response->pid = pid;

    struct ipc_sockname *nameres = (struct ipc_sockname *) ((struct ipc_err *)response->data)->data;
    rc = _getsockname(pid, name->socket, (struct sockaddr *)nameres->sa_data, &nameres->address_len);
    
    struct ipc_err err;

    if (rc < 0) {
        err.err = -rc;
        err.rc = -1;
    } else {
        err.err = 0;
        err.rc = rc;
    }
    
    memcpy(response->data, &err, sizeof(struct ipc_err));

    nameres->socket = name->socket;

    if (ipc_try_send(sockfd, (char *)response, resplen) == -1) {
        perror("Error on writing IPC getsockname response");
    }

    return rc;
}

static int demux_ipc_socket_call(int sockfd, char *cmdbuf, int blen)
{
    struct ipc_msg *msg = (struct ipc_msg *)cmdbuf;

    switch (msg->type) {
    case IPC_SOCKET:
        return ipc_socket(sockfd, msg);
        break;
    case IPC_CONNECT:
        return ipc_connect(sockfd, msg);
        break;
    case IPC_WRITE:
        return ipc_write(sockfd, msg);
        break;
    case IPC_READ:
        return ipc_read(sockfd, msg, blen);
        break;
    case IPC_CLOSE:
        return ipc_close(sockfd, msg);
        break;
    case IPC_POLL:
        return ipc_poll(sockfd, msg);
        break;
    case IPC_FCNTL:
        return ipc_fcntl(sockfd, msg);
        break;
    case IPC_GETSOCKOPT:
        return ipc_getsockopt(sockfd, msg);
    case IPC_GETPEERNAME:
        return ipc_getpeername(sockfd, msg);
    case IPC_GETSOCKNAME:
        return ipc_getsockname(sockfd, msg);
    default:
        print_err("No such IPC type %d\n", msg->type);
        break;
    };
    
    return 0;
}

void on_recv(hio_t* io, void* buf, int readbytes) {
    int rc;

    rc = demux_ipc_socket_call(hio_fd(io), buf, readbytes);
    if (rc == -1) {
        lvl_ip_warn("lvl-ip error on demuxing IPC socket call\n");
        hio_close(io);
        return;
    };
}

static void on_accept(hio_t* connio)
{
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};
    int connfd;

    if (!connio) {
        return;
    }

    connfd = hio_fd(connio);
    lvl_ip_info("on_accept: connfd=%d[%s], [%s] <= [%s]", connfd, get_block_attr(connfd) ? "BLOCK" : "NONBLOCK",
            SOCKADDR_STR(hio_localaddr(connio), localaddrstr),
            SOCKADDR_STR(hio_peeraddr(connio), peeraddrstr));

    hio_setcb_read(connio, on_recv);
    hio_read(connio);
}

static hloop_t *lvl_netdev_tx_loop;
static netdev_tx_loop_ctx_t netdev_tx_loop_ctx;
static ipc_loop_ctx_t ipc_loop_ctx;

void *get_netdev_tx_loop()
{
    return lvl_netdev_tx_loop;
}

netdev_tx_loop_ctx_t *get_netdev_tx_loop_ctx()
{
    return hloop_userdata(get_netdev_tx_loop());
}

ipc_loop_ctx_t *get_ipc_loop_ctx()
{
    return hloop_userdata(get_ipc_loop());
}

void sock_wait_arp_entry_add(struct socket *sock)
{
    sock_wait_arp_entry_t *pnode;
    netdev_tx_loop_ctx_t *ctx;

    if (!sock) {
        return;
    }

    pnode = malloc(sizeof(sock_wait_arp_entry_t));
    if (!pnode) {
        return;
    }
    memset(pnode, 0, sizeof(sock_wait_arp_entry_t));

    pnode->fd = sock->fd;
    pnode->connfd = sock->connfd;
    pnode->pid = sock->pid;

    ctx = get_netdev_tx_loop_ctx();
    if (!ctx) {
        return;
    }

    TAILQ_INSERT_TAIL(&ctx->wait_arp_entry, pnode, entries);
}

static void wakeup_netdev_tx_cb(hevent_t* ev)
{
    struct rtentry *rt;
    struct arp_cache_entry *entry = ev->userdata;
    netdev_tx_loop_ctx_t *ctx;
    sock_wait_arp_entry_t *pnode;
    struct socket *sock;
    struct sock *sk;
    int ret;
    
    ctx = get_netdev_tx_loop_ctx();
    if (!ctx) {
        return;
    }

    if (TAILQ_EMPTY(&ctx->wait_arp_entry)) {
        return;
    }

    TAILQ_FOREACH(pnode, &ctx->wait_arp_entry, entries) {
        sock = get_struct_socket_by_pidandfd(pnode->pid, pnode->fd);
        if (!sock) {
            lvl_ip_warn("NO SOCK BY pid[%d] fd[%d]", pnode->pid, pnode->fd);
            continue;
        }

        socket_wr_acquire(sock);
        sk = sock->sk;
        if (skb_queue_empty(&sk->write_queue)) {
            return;
        }

        struct sk_buff *skb = skb_peek(&sk->write_queue);
        rt = skb->rt;
        if (!rt) {
            continue;
        }

        if (entry->sip == rt->gateway) {
            ret = netdev_transmit(skb, entry->smac, ETH_P_IP);
            if (ret < 0) {
                lvl_ip_warn("PKT SEND ERROR [%d]", udp_data_len(skb));
                continue;
            }
            lvl_ip_warn("UDP RE SEND ret[%d]", udp_data_len(skb));
            TAILQ_REMOVE(&ctx->wait_arp_entry, pnode, entries);
        }

        socket_release(sock);
    }

    free(entry);
}

void wake_lvl_netdev_tx_thread(struct arp_cache_entry *entry)
{
    struct arp_cache_entry *entry_cp = malloc(sizeof(struct arp_cache_entry));
    if (!entry_cp) {
        return;
    }

    /* hloop_post_event, Ҳ���Բ���eventfd, socketpair, ��������(����)�� */
    hevent_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.cb = wakeup_netdev_tx_cb;
    memcpy(entry_cp, entry, sizeof(struct arp_cache_entry));
    ev.userdata = entry_cp;
    hloop_post_event(get_netdev_tx_loop(), &ev);
}

static void* netdev_tx_loop(void *arg)
{
    lvl_netdev_tx_loop = hloop_new(0);

    if (!lvl_netdev_tx_loop) {
        lvl_ip_warn("lvl_netdev_tx_loop init fail");
        exit(EXIT_FAILURE);
    }

    TAILQ_INIT(&netdev_tx_loop_ctx.wait_arp_entry);
    hloop_set_userdata(lvl_netdev_tx_loop, &netdev_tx_loop_ctx);

    hloop_run(lvl_netdev_tx_loop);
    lvl_ip_warn("netdev_tx_loop thread quit!");

    return NULL;
}


static hloop_t *ipc_loop;
void *get_ipc_loop()
{
    return ipc_loop;
}

void *start_ipc_listener()
{
    int listenfd;
    ipc_loop = hloop_new(0);

    if (!ipc_loop) {
        lvl_ip_warn("ipc_loop init fail");
        exit(EXIT_FAILURE);
    }

    unlink(IPC_DOMAIN_SOCKET);

    // listenfd的io_type是case SOCK_STREAM:   io->io_type = HIO_TYPE_TCP; => 非阻塞
    // connfd的io_type判断结果如上, getsockopt(io->fd, SOL_SOCKET, SO_TYPE)调用返回SOCK_STREAM
    listenfd = ListenUnix(IPC_DOMAIN_SOCKET);
    if (listenfd < 0) {
        lvl_ip_warn("IPC listener UNIX socket error");
        exit(EXIT_FAILURE);
    }
    lvl_ip_info("ipc_listener bind succ[%s], listen-fd is [%d]", IPC_DOMAIN_SOCKET, listenfd);

    haccept(ipc_loop, listenfd, on_accept);

    if (create_thread(THREAD_NETDEV_XMIT, netdev_tx_loop, "netdev_tx_loop", NULL)) {
        return NULL;
    }

    ipc_loop_ctx.ipc = &ipc_nonblock_cb_func;
    hloop_set_userdata(ipc_loop, &ipc_loop_ctx);

    hloop_run(ipc_loop); // 这个线程，一处异步，处处异步
    lvl_ip_warn("ipc_loop not run this");

    return NULL;
}
