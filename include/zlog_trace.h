#ifndef __ZLOG_TRACE_H__
#define __ZLOG_TRACE_H__

#include "zlog.h"

enum {
    ZLOG_LEVEL_TRACE = 10,
    /* must equals conf file setting */
};

#define zlog_trace(cat, format, ...) \
        zlog(cat, __FILE__, sizeof(__FILE__)-1, \
        __func__, sizeof(__func__)-1, __LINE__, \
        ZLOG_LEVEL_TRACE, format, ## __VA_ARGS__)

#endif /* __ZLOG_TRACE_H__ */