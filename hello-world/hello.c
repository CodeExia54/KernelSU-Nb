// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/kallsyms.h>
#include <linux/types.h>
#include <linux/bitops.h>

MODULE_DESCRIPTION("PVM hello + direct kallsyms resolve");
MODULE_AUTHOR("You");
MODULE_LICENSE("GPL");

/* Exact prototype of input_handle_event */
typedef void (*input_handle_event_t)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value);

/* kallsyms_lookup_name isn't always declared in headers */
extern unsigned long kallsyms_lookup_name(const char *name);

/* Use kernel-provided __nocfi if defined (Clang), else empty fallback */
#ifndef __nocfi
#define __nocfi
#endif

static input_handle_event_t g_ihe;

static inline void ihe_emit(struct input_dev *dev,
                            unsigned int type, unsigned int code, int value)
{
    input_handle_event_t fn = g_ihe;

    if (!dev)
        return;

    if (fn) {
        ((input_handle_event_t __nocfi)fn)(dev, type, code, value);
    } else {
        /* Optional fallback to the public API */
        input_event(dev, type, code, value);
    }
}

static int __init pvm_hello_init(void)
{
#if IS_ENABLED(CONFIG_KALLSYMS) && IS_ENABLED(CONFIG_KALLSYMS_ALL)
    unsigned long addr = kallsyms_lookup_name("input_handle_event");
    if (!addr) {
        pr_warn("kallsyms: input_handle_event not found; using input_event() fallback\n");
        g_ihe = NULL;
    } else {
        g_ihe = (input_handle_event_t)(uintptr_t)addr;
        pr_info("kallsyms: input_handle_event @ %px\n", (void *)addr);
    }
#else
    pr_warn("KALLSYMS_ALL not enabled; cannot resolve static symbols\n");
    g_ihe = NULL;
#endif

    pr_info("hello: late init — built-in initialized.\n");
    return 0;
}

late_initcall_sync(pvm_hello_init);

static void __exit pvm_hello_exit(void)
{
    g_ihe = NULL;
    pr_info("hello: exit.\n");
}
module_exit(pvm_hello_exit);
