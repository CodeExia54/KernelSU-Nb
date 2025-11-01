#ifndef WUWA_COMMON_H
#define WUWA_COMMON_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>
#include "wuwa_utils.h"

#define WUWA_LOG_PREFIX "[wuwa] "

// Log control - enable/disable via Makefile
#ifdef ENABLE_WUWA_LOGS
    // ORIGINAL LOG MACROS - LOGS ENABLED
    #define wuwa_info(fmt, ...) pr_info(WUWA_LOG_PREFIX fmt, ##__VA_ARGS__)
    #define wuwa_warn(fmt, ...) pr_warn(WUWA_LOG_PREFIX fmt, ##__VA_ARGS__)
    #define wuwa_err(fmt, ...) pr_err(WUWA_LOG_PREFIX fmt, ##__VA_ARGS__)
    #define wuwa_debug(fmt, ...) pr_debug(WUWA_LOG_PREFIX fmt, ##__VA_ARGS__)

    #define ovo_info(fmt, ...) pr_info(WUWA_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)
    #define ovo_warn(fmt, ...) pr_warn(WUWA_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)
    #define ovo_err(fmt, ...) pr_err(WUWA_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)
    #define ovo_debug(fmt, ...) pr_debug(WUWA_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)
#else
    // EMPTY LOG MACROS - LOGS DISABLED
    #define wuwa_info(fmt, ...) 
    #define wuwa_warn(fmt, ...) 
    #define wuwa_err(fmt, ...) 
    #define wuwa_debug(fmt, ...) 

    #define ovo_info(fmt, ...) 
    #define ovo_warn(fmt, ...) 
    #define ovo_err(fmt, ...) 
    #define ovo_debug(fmt, ...) 
#endif

#define LUCKY_LUO 0x00000000faceb00c

#define CONFIG_COMPARE_TASK 0
#define CONFIG_COMPARE_PT_REGS 0

#define CONFIG_COPY_PROCESS 0
/*
 * !!!Poor performance!!!
 */
#define CONFIG_REDIRECT_VIA_ABORT 0

/*
 * !!!!Poor performance!!!
 * The LR address redirection is achieved by using the Linux signal processor mechanism.
 *  > is unsafe and has competition risks.
 *  > is only used for learning and verification that
 *     it can be injected into the executable memory and executed normally without any trace.
 */
#define CONFIG_REDIRECT_VIA_SIGNAL 0

#define CMD_MAX_BYTES (50 * 1024 * 1024)
#define CMD_MAX_PAGES (CMD_MAX_BYTES / PAGE_SIZE)

struct wuwa_sock {
    struct sock sk;

    int version;

    pid_t session;

    struct karray_list* used_pages;
};

#endif /* WUWA_COMMON_H */
