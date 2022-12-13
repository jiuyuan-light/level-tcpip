#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <zlog.h>

#include "basic.h"
#include "list.h"
#include "zlog_trace.h"

#define CMDBUFLEN 100

#define ARRAY_NUMS(array) (int)(sizeof(array)/sizeof(array[0]))

#define THREAD_CORE 0
#define THREAD_TIMERS 1
#define THREAD_IPC 2
#define THREAD_SIGNAL 3
#define THREAD_NETDEV_XMIT 4

// THREAD_NUMS个pthread_create的子线程
#define THREAD_NUMS     (5)
#define THREAD_NAME_MAXLEN (16) /* 包含'\0' */

#define lvl_ip_trace(fmt, ...) zlog_trace(c, "Thread[%s] "fmt, thread_getname(pthread_self()), ##__VA_ARGS__);
#define lvl_ip_debug(fmt, ...) zlog_debug(c, "Thread[%s] "fmt, thread_getname(pthread_self()), ##__VA_ARGS__);
#define lvl_ip_info(fmt, ...) zlog_info(c, "Thread[%s] "fmt, thread_getname(pthread_self()), ##__VA_ARGS__);
#define lvl_ip_warn(fmt, ...) zlog_warn(c, "Thread[%s] "fmt, thread_getname(pthread_self()), ##__VA_ARGS__);

#define print_err(str, ...)                     \
    fprintf(stderr, str, ##__VA_ARGS__);

extern zlog_category_t *c;

int run_cmd(char *cmd, ...);
uint32_t sum_every_16bits(void *addr, int count);
uint16_t checksum(void *addr, int count, int start_sum);
int tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto,
                     uint8_t *data, uint16_t len);
int get_address(char *host, char *port, struct sockaddr *addr);
uint32_t parse_ipv4_string(char *addr);
uint32_t min(uint32_t x, uint32_t y);
uint16_t generate_port();
const char *thread_getname(pthread_t id);
int create_thread(int idx, void *(*func) (void *), const char *name, void *arg);

void *get_netdev_tx_loop();
void *get_ipc_loop();

bool get_block_attr(int fd);

#endif
