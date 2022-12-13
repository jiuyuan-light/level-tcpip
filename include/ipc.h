#ifndef IPC_H_
#define IPC_H_

#include "list.h"
#include "ipc_nonblock.h"

#define IPC_DOMAIN_SOCKET "/tmp/lvlip.socket"

#ifdef DEBUG_IPC
#define ipc_dbg(msg, th)                                                \
    do {                                                                \
        lvl_ip_debug("IPC sockets count %d, current sock %d, tid %lu: %s", \
                    socket_count, th->sock, th->id, msg);             \
    } while (0)
#else
#define ipc_dbg(msg, th)
#endif

void *start_ipc_listener();

#define IPC_SOCKET      0x0001
#define IPC_CONNECT     0x0002
#define IPC_WRITE       0x0003
#define IPC_READ        0x0004
#define IPC_CLOSE       0x0005
#define IPC_POLL        0x0006
#define IPC_FCNTL       0x0007
#define IPC_GETSOCKOPT  0x0008
#define IPC_SETSOCKOPT  0x0009
#define IPC_GETPEERNAME 0x000A
#define IPC_GETSOCKNAME 0x000B

struct ipc_msg {
    uint16_t type;
    pid_t pid;
    uint8_t data[];
} __attribute__((packed));

struct ipc_err {
    int rc;
    int err;
    uint8_t data[];
} __attribute__((packed));

struct ipc_socket {
    int domain;
    int type;
    int protocol;
} __attribute__((packed));

struct ipc_connect {
    int sockfd;
    struct sockaddr addr;
    socklen_t addrlen;
} __attribute__((packed));

struct ipc_write {
    int sockfd;
    size_t len;
    uint8_t buf[];
} __attribute__((packed));

struct ipc_read {
    int sockfd;
    size_t len;
    uint8_t buf[];
} __attribute__((packed));

struct ipc_close {
    int sockfd;
} __attribute__((packed));

struct ipc_pollfd {
    int fd;
    short int events;
    short int revents;
} __attribute__((packed));

struct ipc_poll {
    nfds_t nfds;
    int timeout;
    struct ipc_pollfd fds[];
} __attribute__((packed));

struct ipc_fcntl {
    int sockfd;
    int cmd;
    uint8_t data[];
} __attribute__((packed));

struct ipc_sockopt {
    int fd;
    int level;
    int optname;
    socklen_t optlen;
    uint8_t optval[];
} __attribute__((packed));

struct ipc_sockname {
    int socket;
    socklen_t address_len;
    uint8_t sa_data[128];
};

typedef struct sock_wait_arp_entry {
  int connfd;   /* IPC通信的 */
  int fd;       /* 分配给app的 */
  int pid;
  TAILQ_ENTRY(sock_wait_arp_entry) entries;
} sock_wait_arp_entry_t;

typedef struct {
    TAILQ_HEAD(, sock_wait_arp_entry) wait_arp_entry;
} netdev_tx_loop_ctx_t;

typedef struct {
    g_ipc_nonblock_cb_t *ipc;
} ipc_loop_ctx_t;

ipc_loop_ctx_t *get_ipc_loop_ctx();
netdev_tx_loop_ctx_t *get_netdev_tx_loop_ctx();

int ipc_try_send(int sockfd, const void *buf, size_t len);
int ipc_write_rc(int sockfd, pid_t pid, uint16_t type, int rc);
struct socket *get_struct_socket_by_pidandfd(pid_t pid, uint32_t fd);
void sock_wait_arp_entry_add(struct socket *sock);

#endif
