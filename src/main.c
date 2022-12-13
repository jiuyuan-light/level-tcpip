#define _GNU_SOURCE
#include <pthread.h>

#include <zlog.h>

#include "syshead.h"
#include "basic.h"
#include "cli.h"
#include "tuntap_if.h"
#include "utils.h"
#include "ipc.h"
#include "timer.h"
#include "route.h"
#include "ethernet.h"
#include "arp.h"
#include "tcp.h"
#include "netdev.h"
#include "ip.h"

#define MAX_CMD_LENGTH 6

typedef void (*sighandler_t)(int);

static pthread_t threads[THREAD_NUMS];

int running = 1;
sigset_t mask;
zlog_category_t *c = NULL;

int create_thread(int idx, void *(*func) (void *), const char *name, void *arg)
{
    int re;
    char threadname[THREAD_NAME_MAXLEN] = {0};
    // const pthread_attr_t attr;

    // pthread_attr_init(&attr);
    // pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (idx >= THREAD_NUMS || idx < 0) {
        lvl_ip_warn("Thread idx error");
        return -1;
    }
    
    if (pthread_create(&threads[idx], NULL, func, arg) != 0) {
        lvl_ip_warn("Could not create core thread");
        return -1;
    }

    if (name && strlen(name) >= sizeof(threadname)) {
        lvl_ip_warn("thread set name[%s], len truncation[%ld]", name, sizeof(threadname) - 1);
    }
    strncpy(threadname, name, sizeof(threadname) - 1);

    re = pthread_setname_np(threads[idx], threadname);
    if (re) {
        lvl_ip_warn("Thread set name[%s] fail, re[%d]", name, re);
    } else {
        lvl_ip_info("Thread[%ld] name[%s] create complete", threads[idx], threadname);
    }
    
    return re;
}

static void *stop_stack_handler(void *arg)
{
    int err, signo, i;

    for (;;) {
        err = sigwait(&mask, &signo); // 监听信号集mask中所包含的信号，并将其存在signo中
        if (err != 0) {
            print_err("Sigwait failed: %d\n", err);
        }

        switch (signo) {
        case SIGINT:
        case SIGQUIT:
            running = 0; // 应该有锁保护

            for (i = 0; i < THREAD_NUMS; i++) {
                if (i == THREAD_CORE || i == THREAD_SIGNAL) { /* 防止ASAN报错 */
                    continue;
                }
                lvl_ip_info("thread[%s][%ld] cancled", thread_getname(threads[i]), threads[i]);
                pthread_cancel(threads[i]);
            }
            /* 主线程等待其他线程的结束，不直接exit */
            return NULL;
        default:
            printf("Unexpected signal %d\n", signo);
        }
    }
}

static void init_signals()
{
    int err;
    
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGQUIT);

    // 仅某个sigwait的线程处理这些信号, 利用线程信号屏蔽集的继承关系 （在主线程中对sigmask进行设置后，主线程创建出来的线程将继承主线程的掩码）
    if ((err = pthread_sigmask(SIG_BLOCK, &mask, NULL)) != 0) {
        print_err("SIG_BLOCK error\n");
        exit(1);
    }
}

static void init_stack()
{
    tun_init();
    netdev_init();
    route_init();
    arp_init();
    tcp_init();
}

const char *thread_getname(pthread_t id)
{
    static __thread char thread_name[THREAD_NAME_MAXLEN] = {0};
    pthread_getname_np(id, thread_name, sizeof(thread_name));
    return thread_name;
}

static void create_threads()
{
    int re;

    re = create_thread(THREAD_CORE, netdev_rx_loop, "netdev_rx_loop", NULL);                 // 接收报文处理
    if (re) {
        return;
    }
    re = create_thread(THREAD_TIMERS, timers_start, "timers", NULL);
    if (re) {
        return;
    }
    re = create_thread(THREAD_IPC, start_ipc_listener, "ipc_loop", NULL);              // 本机应用程序发包
    if (re) {
        return;
    }
    re = create_thread(THREAD_SIGNAL, stop_stack_handler, "signal_trap", NULL);           // 线程信号处理
    if (re) {
        return;
    }
}

static void wait_for_threads()
{
    lvl_ip_info("========== main thread init complete ==========\n");
    for (int i = 0; i < THREAD_NUMS; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            lvl_ip_warn("Error when joining threads\n");
        }
    }
}

void free_stack()
{
    abort_sockets();
    free_arp();
    free_routes();
    free_netdev();
    free_tun();
}

void init_security()
{
    if (prctl(PR_CAPBSET_DROP, CAP_NET_ADMIN) == -1) { // 允许执行网络管理任务
        perror("Error on network admin capability drop");
        exit(1);
    }

    if (prctl(PR_CAPBSET_DROP, CAP_SETPCAP) == -1) { // 允许向其他进程转移能力以及删除其他进程的能力
        perror("Error on capability set drop");
        exit(1);
    }
}

static int lvl_ip_zlog_init(void)
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
        printf("path[%s]\n", path);
        return -1;
    }

    c = zlog_get_category("lvlip_log_cfg");
    if (!c) {
        printf("get cat fail\n");
        zlog_fini();
        return -2;
    }

    return 0;
}

int main(int argc, char** argv)
{
    int rc;

    parse_cli(argc, argv);

    rc = lvl_ip_zlog_init();
    if (rc) {
        printf("zlog init failed\n");
        return -1;
    }

    init_signals();
    init_stack();
    init_security();

    create_threads();
    wait_for_threads();

    // TODO, 可以不调用
    free_stack();
}
