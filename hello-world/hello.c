// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/kallsyms.h>

MODULE_DESCRIPTION("PVM hello + direct kallsyms resolve of input_handle_event");
MODULE_AUTHOR("You");
MODULE_LICENSE("GPL");

/* Exact prototype of the internal function */
typedef void (*input_handle_event_t)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value);

/* Not always in a public header */
extern unsigned long kallsyms_lookup_name(const char *name);

static input_handle_event_t g_ihe;  /* resolved at init */

static inline void ihe_emit(struct input_dev *dev,
                            unsigned int type, unsigned int code, int value)
{
    if (g_ihe)
        g_ihe(dev, type, code, value);
}

static int __init pvm_hello_init(void)
{
#if IS_ENABLED(CONFIG_KALLSYMS) && IS_ENABLED(CONFIG_KALLSYMS_ALL)
    unsigned long addr = kallsyms_lookup_name("input_handle_event");
    if (addr) {
        g_ihe = (input_handle_event_t)(uintptr_t)addr;
        pr_info("kallsyms: input_handle_event @ %px\n", (void *)addr);
    } else {
        g_ihe = NULL;
        pr_info("kallsyms: input_handle_event not found\n");
    }
#else
    g_ihe = NULL;
    pr_info("kallsyms: CONFIG_KALLSYMS_ALL required for static symbols\n");
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
module_exit(pvm_hello_exit)

/* Usage from your code:
 *
 *   // have a valid struct input_dev *dev
 *   ihe_emit(dev, EV_ABS, ABS_MT_SLOT, slot);
 *   ihe_emit(dev, EV_ABS, ABS_MT_TRACKING_ID, tid);
 *   ihe_emit(dev, EV_KEY, BTN_TOUCH, 1);
 *   ihe_emit(dev, EV_SYN, SYN_REPORT, 0);
 *
 * That’s it: resolve once, call by address.
 */
