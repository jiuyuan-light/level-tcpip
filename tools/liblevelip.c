#define _GNU_SOURCE
#include "syshead.h"
#include "liblevelip.h"
#include "ipc.h"
#include "list.h"
#include "utils.h"

zlog_category_t *c = NULL;
#define RCBUF_LEN 512

#define CONNECTED   (0x1)
uint32_t lib_flags = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static int (*_fcntl)(int fildes, int cmd, ...) = NULL;
static int (*_setsockopt)(int fd, int level, int optname,
                         const void *optval, socklen_t optlen) = NULL;
static int (*_getsockopt)(int fd, int level, int optname,
                         const void *optval, socklen_t *optlen) = NULL;
static int (*_read)(int sockfd, void *buf, size_t len) = NULL;
static int (*_write)(int sockfd, const void *buf, size_t len) = NULL;
static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int fildes) = NULL;
static int (*_poll)(struct pollfd fds[], nfds_t nfds, int timeout) = NULL;
static int (*_pollchk)(struct pollfd *__fds, nfds_t __nfds, int __timeout,
                       __SIZE_TYPE__ __fdslen) = NULL;

static int (*_ppoll)(struct pollfd *fds, nfds_t nfds,
                     const struct timespec *tmo_p, const sigset_t *sigmask) = NULL;
static int (*_select)(int nfds, fd_set *restrict readfds,
                      fd_set *restrict writefds, fd_set *restrict errorfds,
                      struct timeval *restrict timeout);
static ssize_t (*_sendto)(int sockfd, const void *message, size_t length,
                          int flags, const struct sockaddr *dest_addr,
                          socklen_t dest_len) = NULL;
static ssize_t (*_recvfrom)(int sockfd, void *buf, size_t len,
                            int flags, struct sockaddr *restrict address,
                            socklen_t *restrict addrlen) = NULL;
static int (*_shutdown)(int sockfd, int how) = NULL;
static int (*_getpeername)(int socket, struct sockaddr *restrict address,
                           socklen_t *restrict address_len) = NULL;
static int (*_getsockname)(int socket, struct sockaddr *restrict address,
                           socklen_t *restrict address_len) = NULL;

static int lvlip_socks_count = 0;
static LIST_HEAD(lvlip_socks);

static inline struct lvlip_sock *lvlip_get_sock(int fd)
{
    struct lvlip_sock *sock;

    pthread_mutex_lock(&mutex);
    list_for_each_entry(sock, &lvlip_socks, list) {
        if (sock->fd == fd) {
            pthread_mutex_unlock(&mutex);
            return sock;
        };
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
};

static int is_socket_supported(int domain, int type, int protocol)
{
    if (domain != AF_INET) {
        lib_lvl_ip_warn("lvlip not support domain[%d]", domain);
        return 0;
    }
    
    if (!(type & (SOCK_STREAM | SOCK_DGRAM))) {
        lib_lvl_ip_warn("lvlip not support type[%d]", type);
        return 0;
    }

    if (protocol != 0 && (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)) {
        lib_lvl_ip_warn("lvlip not support protocol[%d]", protocol);
        return 0;
    }

    return 1;
}

static int init_socket(char *sockname)
{
    struct sockaddr_un addr;
    int ret;
    int data_socket;

    /* Create local socket. */
    data_socket = _socket(AF_UNIX, SOCK_STREAM, 0);
    if (data_socket == -1) {
        lib_lvl_ip_warn("unix domain socket\n");
        return -1;
    }

    /*
     * For portability clear the whole structure, since some
     * implementations have additional (nonstandard) fields in
     * the structure.
     */
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockname, sizeof(addr.sun_path) - 1);

    ret = _connect(data_socket, (const struct sockaddr *) &addr, sizeof(struct sockaddr_un));
    if (ret == -1) {
        lib_lvl_ip_warn("[init_socket][%s] Error connecting to level-ip. Is it up?", strerror(errno));
        return -1;
    }

    return data_socket;
}

static int free_socket(int lvlfd)
{
    return _close(lvlfd);
}

static int transmit_lvlip(int lvlfd, struct ipc_msg *msg, int msglen)
{
    char *buf[RCBUF_LEN];
    int re;

    // Send mocked syscall to lvl-ip
    errno = 0;
    if (_write(lvlfd, (char *)msg, msglen) == -1) {
        lib_lvl_ip_warn("Error on writing IPC[%s]", strerror(errno));
        return -1;
    }

    // Read return value from lvl-ip
    re = _read(lvlfd, buf, RCBUF_LEN);
    if (re < 0) {
        lib_lvl_ip_warn("Could not read IPC response");
        return -1;
    } else if (re == 0) {
        return -1;
    }
    
    struct ipc_msg *response = (struct ipc_msg *) buf;
    if (response->type != msg->type || response->pid != msg->pid) {
        lib_lvl_ip_warn("ERR: IPC msg response expected type %d, pid %d, actual type %d, pid %d", msg->type, msg->pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *err = (struct ipc_err *) response->data;

    if (err->rc == -1) errno = err->err;

    return err->rc;
}

int socket(int domain, int type, int protocol)
{
    if (!is_socket_supported(domain, type, protocol)) {
        return _socket(domain, type, protocol);
    }

    struct lvlip_sock *sock;
    
    int lvlfd = init_socket(IPC_DOMAIN_SOCKET);
    if (lvlfd < 0) {
        return -1;
    }

    sock = lvlip_alloc();
    if (!sock) {
        return -1;
    }
    sock->lvlfd = lvlfd;
    list_add_tail(&sock->list, &lvlip_socks);
    lvlip_socks_count++;

    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_socket);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_SOCKET;
    msg->pid = getpid();

    struct ipc_socket usersock = {
        .domain = domain,
        .type = type,
        .protocol = protocol
    };
    
    memcpy(msg->data, &usersock, sizeof(struct ipc_socket));

    int sockfd = transmit_lvlip(sock->lvlfd, msg, msglen);
    if (sockfd == -1) {
        /* Socket alloc failed */
        /* ????????????lvl-ip????????????? */
        lib_lvl_ip_warn("IPC_SOCKET err from lvl-ip-stack");
        lvlip_free(sock);
        return -1;
    }

    sock->fd = sockfd;

    lib_lvl_ip_debug("Socket called fd[%d]", sock->fd);
    
    return sockfd;
}

int close(int fd)
{
    struct lvlip_sock *sock = lvlip_get_sock(fd);

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        return _close(fd);
    }

    lib_lvl_ip_debug("Close called fd[%d]", sock->fd);
    
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_close);
    int rc = 0;

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_CLOSE;
    msg->pid = pid;

    struct ipc_close *payload = (struct ipc_close *)msg->data;
    payload->sockfd = fd;

    rc = transmit_lvlip(sock->lvlfd, msg, msglen);
    free_socket(sock->lvlfd);
    lib_lvl_ip_debug("Close called complete");
    return rc;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct lvlip_sock *sock = lvlip_get_sock(sockfd);
    int re;

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        return _connect(sockfd, addr, addrlen);
    }

    lib_lvl_ip_debug("Connect called fd[%d]", sock->fd);
    
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_connect);
    int pid = getpid();
    
    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_CONNECT;
    msg->pid = pid;

    struct ipc_connect payload = {
        .sockfd = sockfd,
        .addr = *addr,
        .addrlen = addrlen
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_connect));

    re = transmit_lvlip(sock->lvlfd, msg, msglen);
    if (!re) {
        lib_flags |= CONNECTED;
    }
    lib_lvl_ip_debug("Connect called complete, fd[%d]", sock->fd);
    return re;
}

ssize_t write(int sockfd, const void *buf, size_t len)
{
    int re;
    struct lvlip_sock *sock = lvlip_get_sock(sockfd);

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        return _write(sockfd, buf, len);
    }

    lib_lvl_ip_debug("Write called fd[%d]", sock->fd);
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_write) + len;
    int pid = getpid();

    struct ipc_msg *msg = alloca(msglen);
    if (!msg) {
        return 0;
    }

    msg->type = IPC_WRITE;
    msg->pid = pid;

    struct ipc_write payload = {
        .sockfd = sockfd,
        .len = len
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_write));
    memcpy(((struct ipc_write *)msg->data)->buf, buf, len);

    re = transmit_lvlip(sock->lvlfd, msg, msglen);
    lib_lvl_ip_debug("Write called complete, fd[%d], re %d", sock->fd, re);

    return re;
}

ssize_t read(int sockfd, void *buf, size_t len)
{
    int re;
    struct lvlip_sock *sock = lvlip_get_sock(sockfd);
    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        return _read(sockfd, buf, len);
    }

    lib_lvl_ip_debug("Read called fd[%d]", sock->fd);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_read);
    struct ipc_msg *msg = alloca(msglen);
    if (!msg) {
        return -1;
    }
    msg->type = IPC_READ;
    msg->pid = pid;

    struct ipc_read payload = {
        .sockfd = sockfd,
        .len = len
    };
    memcpy(msg->data, &payload, sizeof(struct ipc_read));

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)msg, msglen) == -1) {
        lib_lvl_ip_warn("Error on writing IPC read");
        return -1;
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_read) + len;
    char rbuf[rlen];
    memset(rbuf, 0, rlen);
    // Read return value from lvl-ip
    re = _read(sock->lvlfd, rbuf, rlen);
    if (re == 0) {
        lib_lvl_ip_debug("ERR: IPC read response, peer close connect, pid %d", pid);
        return 0;
    } else if (re == -1) {
        lib_lvl_ip_warn("Could not read IPC read response");
        return -1;
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;
    if (response->type != IPC_READ || response->pid != pid) {
        lib_lvl_ip_warn("ERR: IPC read response expected: type %d, pid %d, actual: type %d, pid %d",
               IPC_READ, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *)response->data;
    if (error->rc < 0) {
        lib_lvl_ip_warn("STH ERR[%d][%d]", error->err, error->rc);
        errno = error->err;
        return error->rc;
    }

    struct ipc_read *data = (struct ipc_read *)error->data;
    if (len < data->len) {
        lib_lvl_ip_warn("IPC read received len error: %lu\n", data->len);
        return -1;
    }

    memset(buf, 0, len);
    memcpy(buf, data->buf, data->len);

    lib_lvl_ip_debug("Read called complete, rlen[%ld]", data->len);
    // lib_lvl_ip_warn("APP reads buf[%s] rlen[%ld] fd[%d] errno[%d-%s]", (char*)buf, data->len, sockfd, errno, strerror(errno));
    errno = 0;
    return data->len;
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
    return sendto(fd, buf, len, flags, NULL, 0);
}

ssize_t sendto(int fd, const void *buf, size_t len,
               int flags, const struct sockaddr *dest_addr,
               socklen_t dest_len)
{
    if (!lvlip_get_sock(fd)) return _sendto(fd, buf, len,
                                        flags, dest_addr, dest_len);
    /* ??connect??????app???????????????????ip???? */
    if (lib_flags & CONNECTED) {
        return write(fd, buf, len);
    }
    int re = connect(fd, dest_addr, dest_len);
    if (re) {
        lib_lvl_ip_warn("sendto connect error");
        return -1;
    }

    return write(fd, buf, len);
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
    return recvfrom(fd, buf, len, flags, NULL, 0);
}

ssize_t recvfrom(int fd, void *restrict buf, size_t len,
                 int flags, struct sockaddr *restrict address,
                 socklen_t *restrict addrlen)
{
    if (!lvlip_get_sock(fd)) return _recvfrom(fd, buf, len,
                                          flags, address, addrlen);
    lib_lvl_ip_warn("RECVFROM");
    return read(fd, buf, len);
}

int shutdown(int sockfd, int how)
{
    if (!lvlip_get_sock(sockfd)) return _shutdown(sockfd, how);
    lib_lvl_ip_warn("NOT SUP, TODO");

    return -1;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    struct pollfd kernel_fds[nfds];
    struct pollfd *lvlip_fds[nfds];
    int lvlip_nfds = 0;
    int kernel_nfds = 0;
    int lvlip_sock = 0;
    int kfds_fds_map[nfds];
    struct lvlip_sock *sock = NULL;
    int re;

    memset(kfds_fds_map, 0, sizeof(kfds_fds_map));
    for (int i = 0; i < nfds; i++) {
        struct pollfd *pfd = &fds[i];
        if ((sock = lvlip_get_sock(pfd->fd)) != NULL) {
            lvlip_fds[lvlip_nfds++] = pfd;
            lvlip_sock = sock->lvlfd;
        } else {
            memcpy(&kernel_fds[kernel_nfds], pfd, sizeof(struct pollfd));
            kfds_fds_map[kernel_nfds] = i;
            kernel_nfds++;
        }
    }

    int blocking = 0;
    if (kernel_nfds > 0 && lvlip_nfds > 0 && timeout == -1) {
        /* Cannot sleep indefinitely when we demux poll 
           with both kernel and lvlip fds */
        timeout = 100; /* ???? */
        blocking = 1;
    }

    lib_lvl_ip_debug("Poll called with kernel_nfds %d lvlip_nfds %d timeout %d", kernel_nfds, lvlip_nfds, timeout);
    if (timeout != -1) {
        timeout /= 2; /* kernel_nfds??lvlip_nfds??????????? */
    }

    for (;;) {
        int events = 0;
        if (kernel_nfds > 0) {
            events = _poll(kernel_fds, kernel_nfds, timeout);
            if (events == -1) {
                lib_lvl_ip_warn("Poll kernel error");
                errno = EAGAIN;
                return -1;
            }

            for (int i = 0; i < kernel_nfds; i++) {
                memcpy(&fds[kfds_fds_map[i]], &kernel_fds[i], sizeof(struct pollfd));
            }
        }

        if (lvlip_nfds < 1) {
            lib_lvl_ip_debug("Poll not need lvlip_nfds");
            return events;
        }

        int pid = getpid();
        int pollfd_size = sizeof(struct ipc_pollfd);
        int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_poll) + pollfd_size * lvlip_nfds;
        struct ipc_msg *msg = alloca(msglen);

        msg->type = IPC_POLL;
        msg->pid = pid;

        struct ipc_poll *data = (struct ipc_poll *)msg->data;
        data->nfds = lvlip_nfds;
        data->timeout = timeout;

        struct ipc_pollfd *pfd = NULL;
        for (int i = 0; i < lvlip_nfds; i++) {
            pfd = &data->fds[i];
            pfd->fd = lvlip_fds[i]->fd;
            pfd->events = lvlip_fds[i]->events;
            pfd->revents = lvlip_fds[i]->revents;
        }

        errno = 0;
        if (_write(lvlip_sock, (char *)msg, msglen) == -1) {
            lib_lvl_ip_warn("Error on writing IPC poll, [%s]", strerror(errno));
            return -1;
        }

        int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + pollfd_size * lvlip_nfds;
        char rbuf[rlen];
        memset(rbuf, 0, rlen);

        // Read return value from lvl-ip
        re = _read(lvlip_sock, rbuf, rlen);
        if (re == 0) {
            return 0;
        }
        else if (re < 0) {
            lib_lvl_ip_warn("Could not read IPC poll response, ret=[%d]", re);
            errno = EAGAIN;
            return -1;
        }
    
        struct ipc_msg *response = (struct ipc_msg *) rbuf;
        if (response->type != IPC_POLL || response->pid != pid) {
            lib_lvl_ip_warn("ERR: IPC poll response expected: type %d, pid %d, actual: type %d, pid %d\n", IPC_POLL, pid, response->type, response->pid);
            errno = EAGAIN;
            return -1;
        }

        struct ipc_err *error = (struct ipc_err *) response->data;
        if (error->rc < 0) {
            errno = error->err;
            lib_lvl_ip_warn("Error on poll %d %s\n", error->rc, strerror(errno));
            return error->rc;
        }

        struct ipc_pollfd *returned = (struct ipc_pollfd *) error->data;
        
        for (int i = 0; i < lvlip_nfds; i++) {
            lvlip_fds[i]->events = returned[i].events;
            lvlip_fds[i]->revents = returned[i].revents;
        }

        int result = events + error->rc;
        if (result > 0 || !blocking) {
            for (int i = 0; i < nfds; i++) {
                lib_lvl_ip_debug("idx[%d]Returning counts %d fd %d with events %d revents %d timeout %d", i, result, fds[i].fd, fds[i].events, fds[i].revents, timeout);
            }
            lib_lvl_ip_debug("=============================================================================");
            return result;
        } 
    }

    lib_lvl_ip_warn("Poll returning with -1\n");
    return -1;
}

int __poll_chk (struct pollfd *__fds, nfds_t __nfds, int __timeout,
                __SIZE_TYPE__ __fdslen)
{
    return poll(__fds, __nfds, __timeout);
}

int ppoll(struct pollfd *fds, nfds_t nfds,
          const struct timespec *tmo_p, const sigset_t *sigmask)
{
    lib_lvl_ip_warn("Ppoll called but not supported\n");
    return -1;
}

int select(int nfds, fd_set *restrict readfds,
           fd_set *restrict writefds, fd_set *restrict errorfds,
           struct timeval *restrict timeout)
{
    lib_lvl_ip_warn("Select not implemented yet\n");
    return _select(nfds, readfds, writefds, errorfds, timeout);
}


int setsockopt(int fd, int level, int optname,
               const void *optval, socklen_t optlen)
{
    struct lvlip_sock *sock = lvlip_get_sock(fd);
    if (sock == NULL) return _setsockopt(fd, level, optname, optval, optlen);

    lib_lvl_ip_debug("Setsockopt called fd[%d]", sock->fd);

    /* WARN: Setsockopt not supported yet */
    
    return 0;
}

int getsockopt(int fd, int level, int optname,
               void *optval, socklen_t *optlen)
{
    struct lvlip_sock *sock = lvlip_get_sock(fd);
    if (sock == NULL) return _getsockopt(fd, level, optname, optval, optlen);

    lib_lvl_ip_debug("Getsockopt called: level %d optname %d optval %d socklen %d",
                level, optname, *(int *)optval, *(int *)optlen);
    
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_sockopt) + *optlen;

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_GETSOCKOPT;
    msg->pid = pid;

    struct ipc_sockopt opts = {
        .fd = fd,
        .level = level,
        .optname = optname,
        .optlen = *optlen,
    };

    memcpy(&opts.optval, optval, *optlen);
    memcpy(msg->data, &opts, sizeof(struct ipc_sockopt) + *optlen);

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)msg, msglen) == -1) {
        lib_lvl_ip_warn("Error on writing IPC getsockopt");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockopt) + *optlen;
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(sock->lvlfd, rbuf, rlen) == -1) {
        lib_lvl_ip_warn("Could not read IPC getsockopt response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_GETSOCKOPT || response->pid != pid) {
        lib_lvl_ip_warn("ERR: IPC getsockopt response expected: type %d, pid %d, actual: type %d, pid %d\n",
               IPC_GETSOCKOPT, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc != 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_sockopt *optres = (struct ipc_sockopt *) error->data;

    lib_lvl_ip_debug("Got getsockopt level %d optname %d optval %d socklen %d",
                 optres->level, optres->optname, *(int *)optres->optval, optres->optlen);

    int val = *(int *)optres->optval;

    /* lvl-ip probably encoded the error value as negative */
    val *= -1;

    *(int *)optval = val;
    *optlen = optres->optlen;

    return 0;
}

int getpeername(int socket, struct sockaddr *restrict address,
                socklen_t *restrict address_len)
{
    struct lvlip_sock *sock = lvlip_get_sock(socket);
    if (sock == NULL) return _getpeername(socket, address, address_len);

    lib_lvl_ip_debug("Getpeername called fd[%d]", sock->fd);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_sockname);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_GETPEERNAME;
    msg->pid = pid;

    struct ipc_sockname *name = (struct ipc_sockname *)msg->data;
    name->socket = socket;

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)msg, msglen) == -1) {
        lib_lvl_ip_warn("Error on writing IPC getpeername");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockname);
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(sock->lvlfd, rbuf, rlen) == -1) {
        lib_lvl_ip_warn("Could not read IPC getpeername response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_GETPEERNAME || response->pid != pid) {
        lib_lvl_ip_warn("ERR: IPC getpeername response expected: type %d, pid %d, actual: type %d, pid %d\n",
               IPC_GETPEERNAME, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc != 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_sockname *nameres = (struct ipc_sockname *) error->data;

    lib_lvl_ip_debug("Got getpeername fd %d addrlen %d sa_data %p",
                  nameres->socket, nameres->address_len, nameres->sa_data);

    if (nameres->socket != socket) {
        lib_lvl_ip_warn("Got socket %d but requested %d\n", nameres->socket, socket);
    }

    *address_len = nameres->address_len;
    memcpy(address, nameres->sa_data, nameres->address_len);
    
    return 0;
}

int getsockname(int socket, struct sockaddr *restrict address,
                socklen_t *restrict address_len)
{
    struct lvlip_sock *sock = lvlip_get_sock(socket);
    if (sock == NULL) return _getsockname(socket, address, address_len);

    lib_lvl_ip_debug("Getsockname called fd[%d]", sock->fd);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_sockname);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_GETSOCKNAME;
    msg->pid = pid;

    struct ipc_sockname *name = (struct ipc_sockname *)msg->data;
    name->socket = socket;

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)msg, msglen) == -1) {
        lib_lvl_ip_warn("Error on writing IPC getsockname");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockname);
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(sock->lvlfd, rbuf, rlen) == -1) {
        lib_lvl_ip_warn("Could not read IPC getsockname response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_GETSOCKNAME || response->pid != pid) {
        lib_lvl_ip_warn("ERR: IPC getsockname response expected: type %d, pid %d, actual: type %d, pid %d\n",
               IPC_GETSOCKNAME, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc != 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_sockname *nameres = (struct ipc_sockname *) error->data;

    lib_lvl_ip_debug("Got getsockname fd %d addrlen %d sa_data %p",
               nameres->socket, nameres->address_len, nameres->sa_data);

    if (nameres->socket != socket) {
        lib_lvl_ip_warn("Got socket %d but requested %d\n", nameres->socket, socket);
    }

    *address_len = nameres->address_len;
    memcpy(address, nameres->sa_data, nameres->address_len);

    return 0;
}

int fcntl(int fildes, int cmd, ...)
{
    int rc = -1;
    va_list ap;
    void *arg;

    struct lvlip_sock *sock = lvlip_get_sock(fildes);

    if (!sock) {
        va_start(ap, cmd);
        arg = va_arg(ap, void *);
        va_end(ap);

        return _fcntl(fildes, cmd, arg);
    }

    lib_lvl_ip_debug("Fcntl called fd[%d]", sock->fd);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_fcntl) + sizeof(struct flock) + sizeof(int);
    struct ipc_msg *msg = alloca(msglen);

    msg->type = IPC_FCNTL;
    msg->pid = pid;

    struct ipc_fcntl *fc = (struct ipc_fcntl *)msg->data;
    fc->sockfd = fildes;
    fc->cmd = cmd;
    
    switch (cmd) {
    case F_GETFL:
        lib_lvl_ip_debug("Fcntl GETFL fd[%d]", sock->fd);

        rc = transmit_lvlip(sock->lvlfd, msg, msglen);
        break;
    case F_SETFL:
        lib_lvl_ip_debug("Fcntl SETFL fd[%d]", sock->fd);

        va_start(ap, cmd);

        int flags = va_arg(ap, int);
        memcpy(fc->data, &flags, sizeof(int));

        va_end(ap);

        rc = transmit_lvlip(sock->lvlfd, msg, msglen);
        break;
    default:
        rc = -1;
        errno = EINVAL;
        break;
    }
    
    return rc;
}

static int szlog_init(void)
{
    int rc;
    char path[128] = {0};
    char *env = getenv("ROOT_DIR");
    if (!env) {
        printf("zlog env failed\n");
        return -1;
    }
    strncpy(path, env, sizeof(path) - 1);
    strncat(path, "/zlog.conf", sizeof(path) - strlen(env));
    rc = zlog_init(path);
    if (rc) {
        printf("init failed\n");
        return -1;
    }

    c = zlog_get_category("liblvliptools");
    if (!c) {
        printf("get cat fail\n");
        zlog_fini();
        return -2;
    }

    return 0;
}

int __libc_start_main(int (*main) (int, char * *, char * *), int argc,
                      char * * ubp_av, void (*init) (void), void (*fini) (void),
                      void (*rtld_fini) (void), void (* stack_end))
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");

    _sendto = dlsym(RTLD_NEXT, "sendto");
    _recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    _shutdown = dlsym(RTLD_NEXT, "shutdown");
    _poll = dlsym(RTLD_NEXT, "poll");
    _ppoll = dlsym(RTLD_NEXT, "ppoll");
    _pollchk = dlsym(RTLD_NEXT, "__poll_chk");
    _select = dlsym(RTLD_NEXT, "select");
    _fcntl = dlsym(RTLD_NEXT, "fcntl");
    _setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    _getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    _read = dlsym(RTLD_NEXT, "read");
    _write = dlsym(RTLD_NEXT, "write");
    _connect = dlsym(RTLD_NEXT, "connect");
    _socket = dlsym(RTLD_NEXT, "socket");
    _close = dlsym(RTLD_NEXT, "close");
    _getpeername = dlsym(RTLD_NEXT, "getpeername");
    _getsockname = dlsym(RTLD_NEXT, "getsockname");

    list_init(&lvlip_socks);

    if (szlog_init()) {
        return -1;
    }

    return __start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}
