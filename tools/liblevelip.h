#ifndef LIBLEVELIP_H_
#define LIBLEVELIP_H_

#include <poll.h>
#include <dlfcn.h>
#include <zlog.h>
#include "list.h"
#include "utils.h"

#define lib_lvl_ip_warn(fmt, ...) zlog_warn(c, fmt, ##__VA_ARGS__);
#define lib_lvl_ip_debug(fmt, ...) zlog_debug(c, fmt, ##__VA_ARGS__);

struct lvlip_sock {
    struct list_head list;
    int lvlfd; /* For Level-IP IPC */
    int fd;     /* what? */
};

static inline struct lvlip_sock *lvlip_alloc() {
    struct lvlip_sock *sock = malloc(sizeof(struct lvlip_sock));
    if (!sock) {
        return NULL;
    }
    memset(sock, 0, sizeof(struct lvlip_sock));

    return sock;
};

static inline void lvlip_free(struct lvlip_sock *sock) {
    free(sock);
}

#endif
