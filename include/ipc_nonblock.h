#ifndef __IPC_NONBLOCK_H__
#define __IPC_NONBLOCK_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "syshead.h"
#include <hloop.h>

#define IPC_NONBLOCK_SOCKET_RESP_INIT(presp, _fd, _pid, _len) do {      \
    memset((presp), 0, _len);     \
    (presp)->req.connect_fd = _fd;                           \
    (presp)->req.pid = _pid;                                     \
} while (0)

// 前置声明
struct socket;

typedef void (*nonblock_resp_func_t)(int ret, void *arg);

typedef struct {
    int connect_fd;
    pid_t pid;
} ipc_nonblock_req_t;

typedef struct {
    ipc_nonblock_req_t req;
} ipc_nonblock_general_resp_t;

typedef struct {
    int writebytes;
    ipc_nonblock_req_t req;
} ipc_nonblock_write_resp_t;

typedef struct {
    int socket;
    ipc_nonblock_req_t req;
} ipc_nonblock_socket_resp_t;

typedef struct {
    void *buf;
    int readbytes;
    ipc_nonblock_req_t req;
} ipc_nonblock_read_resp_t;

typedef union {
    ipc_nonblock_general_resp_t general;
    ipc_nonblock_write_resp_t write;
    ipc_nonblock_socket_resp_t socket;
    ipc_nonblock_read_resp_t read;
} ipc_nonblock_resp_un_t;

typedef struct  {
    nonblock_resp_func_t nonblock_socket_cb;
    nonblock_resp_func_t nonblock_connect_cb;
    nonblock_resp_func_t nonblock_fcntl_cb;
    nonblock_resp_func_t nonblock_read_cb;
    nonblock_resp_func_t nonblock_write_cb;
    nonblock_resp_func_t nonblock_close_cb;
} g_ipc_nonblock_cb_t;

typedef struct {
    int infinite;
    int pid;
    int connfd;
    int nfds;
    struct pollfd *fds;
} poll_timer_t;

typedef struct {
    int fd;
    pid_t pid;
    int ret;
    int type;
} ipc_post_shift_response_t;

extern g_ipc_nonblock_cb_t ipc_nonblock_cb_func;

int ipc_post_direct_response(int type, int ret, void *arg);
int ipc_post_direct_response_with_sock(int type, int ret, struct socket *sock);
int ipc_post_direct_response_with_id(int type, int ret, pid_t pid, int fd);
int ipc_post_direct_response_with_flag(int type, int ret, struct socket *sock);
void ipc_post_shift_response_cb(hevent_t* ev);
int ipc_post_shift_response_with_sock(struct socket *sock, int type, int ret, hevent_cb cb);
int ipc_post_wait(struct socket *sock, int type);

void ipc_post_shift_read_cb(hevent_t* ev);
#define ipc_post_shift_connect_with_sock(sock, ret) ipc_post_shift_response_with_sock(sock, IPC_CONNECT, ret, ipc_post_shift_response_cb)
#define ipc_post_shift_read_with_sock(sock, ret) ipc_post_shift_response_with_sock(sock, IPC_READ, ret, ipc_post_shift_read_cb)

#endif /* __IPC_NONBLOCK_H__ */