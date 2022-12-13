#include <hloop.h>
#include <unistd.h>
#include <fcntl.h>

#include "syshead.h"
#include "ipc_nonblock.h"
#include "utils.h"
#include "ipc.h"
#include "tcp.h"
#include "tcp_data.h"
#include "socket.h"


void nonblock_socket_cb(int ret, ipc_nonblock_socket_resp_t *resp)
{
    if (!ret) {
        ret = resp->socket;
    }

    ipc_write_rc(resp->req.connect_fd, resp->req.pid, IPC_SOCKET, ret);
}

void nonblock_connect_cb(int ret, ipc_nonblock_general_resp_t *resp)
{
    ipc_write_rc(resp->req.connect_fd, resp->req.pid, IPC_CONNECT, ret);
}

void nonblock_fcntl_cb(int ret, ipc_nonblock_general_resp_t *resp)
{
    ipc_write_rc(resp->req.connect_fd, resp->req.pid, IPC_FCNTL, ret);
}

void nonblock_read_cb(int ret, ipc_nonblock_read_resp_t *resp)
{
    if (ret) {
        ipc_write_rc(resp->req.connect_fd, resp->req.pid, IPC_SOCKET, ret);
        return;
    }

    int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_read) + (resp->readbytes > 0 ? resp->readbytes : 0);
    struct ipc_msg *response = alloca(resplen);
    if (response == NULL) {
        lvl_ip_warn("Could not allocate memory for IPC read response\n");
        return;
    }

    struct ipc_err *error = (struct ipc_err *)response->data;
    struct ipc_read *actual = (struct ipc_read *)error->data;
    
    response->type = IPC_READ;
    response->pid = resp->req.pid;

    error->rc = resp->readbytes < 0 ? -1 : resp->readbytes;
    error->err = resp->readbytes < 0 ? -1 : 0;

    actual->sockfd = -1; /* NOT USE */
    actual->len = resp->readbytes;
    memcpy(actual->buf, resp->buf, resp->readbytes > 0 ? resp->readbytes : 0);

    if (ipc_try_send(resp->req.connect_fd, response, resplen) == -1) {
        lvl_ip_warn("Error on writing IPC read response7");
    }
}

void nonblock_write_cb(int ret, ipc_nonblock_write_resp_t *resp)
{
    if (!ret) {
        ret = resp->writebytes;
    }

    ipc_write_rc(resp->req.connect_fd, resp->req.pid, IPC_WRITE, ret);
}

void nonblock_close_cb(int ret, ipc_nonblock_general_resp_t *resp)
{
    ipc_write_rc(resp->req.connect_fd, resp->req.pid, IPC_CLOSE, ret);
}


g_ipc_nonblock_cb_t ipc_nonblock_cb_func = {
    .nonblock_socket_cb = (nonblock_resp_func_t)nonblock_socket_cb,
    .nonblock_connect_cb = (nonblock_resp_func_t)nonblock_connect_cb,
    .nonblock_fcntl_cb = (nonblock_resp_func_t)nonblock_fcntl_cb,
    .nonblock_read_cb = (nonblock_resp_func_t)nonblock_read_cb,
    .nonblock_write_cb = (nonblock_resp_func_t)nonblock_write_cb,
    .nonblock_close_cb = (nonblock_resp_func_t)nonblock_close_cb
};

static nonblock_resp_func_t get_nonblock_cb_function(int type)
{
    ipc_loop_ctx_t *ctx = get_ipc_loop_ctx();

    switch (type) {
    case IPC_SOCKET:
        return ctx->ipc->nonblock_socket_cb;
    case IPC_CONNECT:
        return ctx->ipc->nonblock_connect_cb;
    case IPC_READ:
        return ctx->ipc->nonblock_read_cb;
    case IPC_WRITE:
        return ctx->ipc->nonblock_write_cb;
    case IPC_CLOSE:
        return ctx->ipc->nonblock_close_cb;
    default:
        break;
    }

    return NULL;
}

int ipc_post_direct_response(int type, int ret, void *arg)
{
    nonblock_resp_func_t func = get_nonblock_cb_function(type);
    if (!func) {
        lvl_ip_warn("FUNC IS NIL??????????? %d", type);
        return -1;
    }

    func(ret, arg);
    return 0;
}

int ipc_post_direct_response_with_sock(int type, int ret, struct socket *sock)
{
    ipc_nonblock_resp_un_t ipc;
    void *resp;

    switch (type) {
    case IPC_SOCKET:
    case IPC_POLL:
        /* IPC_SOCKET、IPC_POLL 比较特殊, 不应该走这里 */
        break;
    case IPC_CONNECT:
    case IPC_CLOSE:
        resp = &ipc.general;
        IPC_NONBLOCK_SOCKET_RESP_INIT((ipc_nonblock_general_resp_t *)resp, sock->connfd, sock->pid, sizeof(ipc_nonblock_general_resp_t));
        break;
    case IPC_READ:
        resp = &ipc.read;
        IPC_NONBLOCK_SOCKET_RESP_INIT((ipc_nonblock_read_resp_t *)resp, sock->connfd, sock->pid, sizeof(ipc_nonblock_read_resp_t));
        ((ipc_nonblock_read_resp_t *)resp)->readbytes = ret;
        ((ipc_nonblock_read_resp_t *)resp)->buf = sock->readbuf;
        ret = ret >= 0 ? 0 : -1;
        break;
    case IPC_WRITE:
        resp = &ipc.write;
        IPC_NONBLOCK_SOCKET_RESP_INIT((ipc_nonblock_write_resp_t *)resp, sock->connfd, sock->pid, sizeof(ipc_nonblock_write_resp_t));
        ((ipc_nonblock_write_resp_t *)resp)->writebytes = ret;
        ret = ret >= 0 ? 0 : -1;
        break;
    default:
        break;
    }

    ipc_post_direct_response(type, ret, resp);
    return 0;
}

int ipc_post_direct_response_with_flag(int type, int ret, struct socket *sock)
{
    if (CHECK_FLAG(sock->ipc_wait_resp_type, type)) {
        ipc_post_direct_response_with_sock(type, ret, sock);
        UNSET_FLAG(sock->ipc_wait_resp_type, type);
    }

    return 0;
}

int ipc_post_direct_response_with_id(int type, int ret, pid_t pid, int fd)
{
    int re;
    struct socket *sock = get_struct_socket_by_pidandfd(pid, fd);
    if (sock == NULL) {
        return -1;
    }

    socket_wr_acquire(sock);
    re = ipc_post_direct_response_with_sock(type, ret, sock);
    socket_release(sock);

    return re;
}

void ipc_post_shift_read_cb(hevent_t* ev)
{
    ipc_post_shift_response_t *resp = ev->privdata;
    struct socket *sock;
    struct sock *sk;

    if (!resp) {
        return;
    }

    if ((sock = get_struct_socket_by_pidandfd(resp->pid, resp->fd)) == NULL) {
        lvl_ip_warn("Could not find socket (fd %u) for connection (pid %d)\n", resp->fd, resp->pid);
        goto FREE;
    }

    socket_wr_acquire(sock);
    sk = sock->sk;
    if (!sk) {
        lvl_ip_warn("NO SK");
        goto RELEASE_SOCK;
    }

    if (!CHECK_FLAG(sock->ipc_wait_resp_type, IPC_READ) || sock->closed || resp->type != IPC_READ) {
        goto FREE;
    }

    int buflen = sizeof(sock->readbuf);
    int rlen = sock->readbytes;
    char *buf = sock->readbuf;
    struct tcp_sock *tsk = tcp_sk(sk);
    lvl_ip_debug("cur read to buf`s len is [%d], buflen is [%d]", rlen, buflen);

    while (rlen < buflen) {
        int curlen = tcp_data_dequeue(tsk, buf + rlen, buflen - rlen);
        rlen += curlen;

        if (tsk->flags & TCP_PSH) {
            lvl_ip_debug("peer set push bit");
            tsk->flags &= ~TCP_PSH;
            break;
        }

        if (tsk->flags & TCP_FIN || rlen == buflen) break;

        sock->readbytes = rlen;
        lvl_ip_debug("tcp need more data, going wait, rlen[%d]", rlen);
        ipc_post_wait(sock, IPC_READ);
        goto RELEASE_SOCK;
    }

    /* 读取完成或者失败 */
    if (rlen >= 0) {
        tcp_rearm_user_timeout(sk);
    }

    sock->readbytes = 0;
    lvl_ip_debug("================= read complete rlen[%d] =================", rlen);
    
    ipc_post_direct_response_with_sock(IPC_READ, rlen, sock);

RELEASE_SOCK:
    socket_release(sock);
FREE:
    free(resp);
}

// #include "tcp.h" 和hloop有些冲突
void tcp_rearm_user_timeout(struct sock *sk);

/* 返回true表示�??? */
bool get_block_attr(int fd)
{
    return !(fcntl(fd, F_GETFL) & O_NONBLOCK);
}

void *alloc_ipc_post_resp()
{
    ipc_post_shift_response_t *p = malloc(sizeof(ipc_post_shift_response_t));
    if (!p) {
        return NULL;
    }
    
    return p;
}

int ipc_post_wait(struct socket *sock, int type)
{
    if (SOCK_IS_NONBLOCK(sock)) {
        return 0;
    }

    SET_FLAG(sock->ipc_wait_resp_type, type);

    return 0;
}

void ipc_post_shift_response_cb(hevent_t* ev)
{
    ipc_post_shift_response_t *resp = ev->privdata;
    struct socket *sock;

    if (!resp) {
        return;
    }

    if ((sock = get_struct_socket_by_pidandfd(resp->pid, resp->fd)) == NULL) {
        lvl_ip_warn("Could not find socket (fd %u) for connection (pid %d)\n", resp->fd, resp->pid);
        return;
    }

    socket_wr_acquire(sock);

    ipc_post_direct_response_with_flag(resp->type, resp->ret, sock);
    
    socket_release(sock);
    free(resp);
}

int ipc_post_shift_response_with_sock(struct socket *sock, int type, int ret, hevent_cb cb)
{
    hevent_t ev;
    ipc_post_shift_response_t *p;

    if (!sock) {
        lvl_ip_warn("CHECK SOCK IS NIL[%d]", type);
        return -1;
    }

    /* no ipc_post_wait */
    if (!CHECK_FLAG(sock->ipc_wait_resp_type, IPC_CONNECT) && !CHECK_FLAG(sock->ipc_wait_resp_type, IPC_READ)) {
        return -1;
    }
    
    p = alloc_ipc_post_resp();
    if (!p) {
        return -1;
    }
    p->pid = sock->pid;
    p->fd = sock->fd;
    p->ret = ret;
    p->type = type;

    memset(&ev, 0, sizeof(ev));
    ev.cb = cb;
    ev.privdata = p;

    hloop_post_event(get_ipc_loop(), &ev);

    return 0;
}
