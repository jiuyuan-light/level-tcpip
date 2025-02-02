#include "syshead.h"
#include <hloop.h>

#include "utils.h"
#include "socket.h"
#include "inet.h"
#include "wait.h"
#include "timer.h"

static int sock_amount = 0;
static LIST_HEAD(sockets);
static pthread_rwlock_t slock = PTHREAD_RWLOCK_INITIALIZER;

extern struct net_family inet;

static struct net_family *families[128] = {
    [AF_INET] = &inet,
};

const char *get_sock_type(int type)
{
    switch (type) {
    case SOCK_STREAM:
        return "TCP";
    case SOCK_DGRAM:
        return "UDP";
    default:
        break;
    }

    return "NONE";
}

static struct socket *alloc_socket(pid_t pid)
{
    // TODO: Figure out a way to not shadow kernel file descriptors.
    // Now, we'll just expect the fds for a process to never exceed this.
    static int fd = 4097;
    struct socket *sock = malloc(sizeof (struct socket));
    if (!sock) {
        return NULL;
    }

    memset(sock, 0, sizeof(struct socket));
    list_init(&sock->list);

    sock->pid = pid;
    sock->refcnt = 1;

    pthread_rwlock_wrlock(&slock);
    sock->fd = fd++;
    pthread_rwlock_unlock(&slock);

    sock->state = SS_UNCONNECTED;
    sock->ops = NULL;
    sock->flags = O_RDWR;
    wait_init(&sock->sleep);
    pthread_rwlock_init(&sock->lock, NULL);
    
    return sock;
}

int socket_rd_acquire(struct socket *sock)
{
    int rc = pthread_rwlock_wrlock(&sock->lock);
    sock->refcnt++;
    return rc;
}

int socket_wr_acquire(struct socket *sock)
{
    int rc = pthread_rwlock_wrlock(&sock->lock);
    sock->refcnt++;
    return rc;
}

int socket_release(struct socket *sock)
{
    int rc = 0;
    sock->refcnt--;

    if (sock->refcnt == 0) {
        rc = pthread_rwlock_unlock(&sock->lock);
        free(sock);
    } else {
        rc = pthread_rwlock_unlock(&sock->lock);
    }

    return rc;
}

int socket_free(struct socket *sock)
{
    pthread_rwlock_wrlock(&slock);
    socket_wr_acquire(sock);
    list_del(&sock->list);
    sock_amount--;
    pthread_rwlock_unlock(&slock);

    if (sock->ops) {
        sock->ops->free(sock);
    }

    wait_free(&sock->sleep);
    socket_release(sock);
    
    return 0;
}

static void *socket_garbage_collect(void *arg)
{
    struct socket *sock = socket_find((struct socket *)arg);

    if (sock == NULL) return NULL;

    lvl_ip_warn("socket_garbage_collect sockke free");
    socket_free(sock);

    return NULL;
}

int socket_delete(struct socket *sock)
{
    int rc = 0;

    if (sock->state == SS_DISCONNECTING) goto out;

    sock->state = SS_DISCONNECTING;
    timer_oneshot(10000, &socket_garbage_collect, sock);

out:
    return rc;
}

void abort_sockets() {
    struct list_head *item, *tmp;
    struct socket *sock;

    list_for_each_safe(item, tmp, &sockets) {
        sock = list_entry(item, struct socket, list);
        sock->ops->abort(sock);
    }
}

struct socket *get_struct_socket_by_pidandfd(pid_t pid, uint32_t fd)
{
    struct list_head *item;
    struct socket *sock = NULL;

    pthread_rwlock_rdlock(&slock);
    list_for_each(item, &sockets) {
        sock = list_entry(item, struct socket, list);
        if (sock->pid == pid && sock->fd == fd) goto out;
    }
    
    sock = NULL;

out:
    pthread_rwlock_unlock(&slock);
    return sock;
}

struct socket *socket_lookup(uint16_t remoteport, uint16_t localport)
{
    struct list_head *item;
    struct socket *sock = NULL;
    struct sock *sk = NULL;

    pthread_rwlock_rdlock(&slock);
    
    list_for_each(item, &sockets) {
        sock = list_entry(item, struct socket, list);

        if (sock == NULL || sock->sk == NULL) continue;
        sk = sock->sk;

        if (sk->sport == localport && sk->dport == remoteport) {
            goto found;
        }
    }

    sock = NULL;
found:
    pthread_rwlock_unlock(&slock);
    return sock;
}

struct socket *socket_find(struct socket *find)
{
    struct list_head *item;
    struct socket *sock = NULL;

    pthread_rwlock_rdlock(&slock);
    list_for_each(item, &sockets) {
        sock = list_entry(item, struct socket, list);
        if (sock == find) goto out;
    }
    
    sock = NULL;

out:
    pthread_rwlock_unlock(&slock);
    return sock;
}

#ifdef DEBUG_SOCKET
void socket_debug()
{
    struct list_head *item;
    struct socket *sock = NULL;

    pthread_rwlock_rdlock(&slock);

    list_for_each(item, &sockets) {
        sock = list_entry(item, struct socket, list);
        socket_rd_acquire(sock);
        socket_trace(sock, "");
        socket_release(sock);
    }

    pthread_rwlock_unlock(&slock);
}
#else
void socket_debug()
{
    return;
}
#endif

int _socket(pid_t pid, int sockfd, int domain, int type, int protocol)
{
    struct socket *sock;
    struct net_family *family;

    if ((sock = alloc_socket(pid)) == NULL) {
        print_err("Could not alloc socket\n");
        return -1;
    }

    sock->type = type;

    family = families[domain];

    if (!family) {
        print_err("Domain not supported: %d\n", domain);
        goto abort_socket;
    }
    
    if (family->create(sock, protocol) != 0) {
        print_err("Creating domain failed\n");
        goto abort_socket;
    }

    pthread_rwlock_wrlock(&slock);
    
    list_add_tail(&sock->list, &sockets);
    sock_amount++;
    sock->connfd = sockfd;
    socket_rd_acquire(sock);
    pthread_rwlock_unlock(&slock);
    int rc = sock->fd;
    socket_release(sock);

    return rc;

abort_socket:
    lvl_ip_warn("abort free socket");
    socket_free(sock);
    return -1;
}

int _write(pid_t pid, int sockfd, const void *buf, const unsigned int count)
{
    struct socket *sock;

    if ((sock = get_struct_socket_by_pidandfd(pid, sockfd)) == NULL) {
        print_err("Write: could not find socket (fd %u) for connection (pid %d)\n", sockfd, pid);
        return -EBADF;
    }

    socket_wr_acquire(sock);
    int rc = sock->ops->write(sock, buf, count);
    socket_release(sock);

    return rc;
}

int _read(pid_t pid, int sockfd, void *buf, const unsigned int count)
{
    struct socket *sock;

    if ((sock = get_struct_socket_by_pidandfd(pid, sockfd)) == NULL) {
        print_err("Read: could not find socket (fd %u) for connection (pid %d)\n", sockfd, pid);
        return -EBADF;
    }

    socket_wr_acquire(sock);
    int rc = sock->ops->read(sock, buf, count);
    socket_release(sock);

    return rc;
}

int _close(pid_t pid, int sockfd)
{
    struct socket *sock;

    if ((sock = get_struct_socket_by_pidandfd(pid, sockfd)) == NULL) {
        print_err("Close: could not find socket (fd %u) for connection (pid %d)\n", sockfd, pid);
        return -EBADF;
    }


    socket_wr_acquire(sock);
    int rc = sock->ops->close(sock);
    sock->closed = 1;
    socket_release(sock);

    return rc;
}

int _fcntl(pid_t pid, int fildes, int cmd, ...)
{
    struct socket *sock;

    if ((sock = get_struct_socket_by_pidandfd(pid, fildes)) == NULL) {
        print_err("Fcntl: could not find socket (fd %u) for connection (pid %d)\n", fildes, pid);
        return -EBADF;
    }

    socket_wr_acquire(sock);
    va_list ap;
    int rc = 0;

    switch (cmd) {
    case F_GETFL:
        rc = sock->flags;
        goto out;
    case F_SETFL:
        va_start(ap, cmd);
        sock->flags = va_arg(ap, int);
        va_end(ap);
        if (SOCK_IS_NONBLOCK(sock)) {
            lvl_ip_info("[F_SETFL] APP[%s] expect SOCK [%d][%s]", get_sock_type(sock->type), sock->fd, "NONBLOCK");
        } else {
            lvl_ip_info("[F_SETFL] APP[%s] expect SOCK [%d][%s]", get_sock_type(sock->type), sock->fd, "BLOCK");
        }

        goto out;
    default:
        rc = -1;
        goto out;
    }

    rc = -1;

out:
    socket_release(sock);
    return rc;
}

int _getsockopt(pid_t pid, int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    struct socket *sock;

    if ((sock = get_struct_socket_by_pidandfd(pid, fd)) == NULL) {
        print_err("Getsockopt: could not find socket (fd %u) for connection (pid %d)\n", fd, pid);
        return -EBADF;
    }

    int rc = 0;

    socket_rd_acquire(sock);
    switch (level) {
    case SOL_SOCKET:
        switch (optname) {
        case SO_ERROR:
            *optlen = 4;
            *(int *)optval = sock->sk->err;
            rc = 0;
            break;
        default:
            print_err("Getsockopt unsupported optname %d\n", optname);
            rc =  -ENOPROTOOPT;
            break;
        }
        
        break;
    default:
        print_err("Getsockopt: Unsupported level %d\n", level);
        rc = -EINVAL;
        break;
    }

    socket_release(sock);

    return rc;
}

int _getpeername(pid_t pid, int socket, struct sockaddr *restrict address,
                 socklen_t *restrict address_len)
{
    struct socket *sock;

    if ((sock = get_struct_socket_by_pidandfd(pid, socket)) == NULL) {
        print_err("Getpeername: could not find socket (fd %u) for connection (pid %d)\n", socket, pid);
        return -EBADF;
    }

    socket_rd_acquire(sock);
    int rc = sock->ops->getpeername(sock, address, address_len);
    socket_release(sock);

    return rc;
}

int _getsockname(pid_t pid, int socket, struct sockaddr *restrict address,
                 socklen_t *restrict address_len)
{
    struct socket *sock;

    if ((sock = get_struct_socket_by_pidandfd(pid, socket)) == NULL) {
        print_err("Getsockname: could not find socket (fd %u) for connection (pid %d)\n", socket, pid);
        return -EBADF;
    }

    socket_rd_acquire(sock);
    int rc = sock->ops->getsockname(sock, address, address_len);
    socket_release(sock);

    return rc;
}
