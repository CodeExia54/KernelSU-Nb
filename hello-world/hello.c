// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/bitops.h>

MODULE_DESCRIPTION("PVM hello + safe test call to input_handle_event");
MODULE_AUTHOR("You");
MODULE_LICENSE("GPL");

/* Exact prototype of the internal function */
typedef void (*input_handle_event_t)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value);

extern unsigned long kallsyms_lookup_name(const char *name);

static input_handle_event_t g_ihe;   /* resolved function pointer */

/* Try to locate a reasonable input device (touchscreen-like) safely.
 * Returns with a held reference via input_get_device(), caller must input_put_device().
 */
static struct input_dev *pvm_find_touch_dev(void)
{
    struct input_dev *dev, *found = NULL;
    struct list_head *input_dev_list_sym = NULL;
    struct mutex *input_mutex_sym = NULL;

    input_dev_list_sym = (struct list_head *)kallsyms_lookup_name("input_dev_list");
    input_mutex_sym    = (struct mutex *)kallsyms_lookup_name("input_mutex");
    if (!input_dev_list_sym || !input_mutex_sym) {
        pr_warn("could not resolve input_dev_list or input_mutex\n");
        return NULL;
    }

    mutex_lock(input_mutex_sym);
    list_for_each_entry(dev, input_dev_list_sym, node) {
        /* Heuristics: device advertises ABS or MT bits → likely touch */
        if (test_bit(EV_ABS, dev->evbit) &&
            (test_bit(ABS_MT_POSITION_X, dev->absbit) ||
             test_bit(ABS_X, dev->absbit))) {
            input_get_device(dev);   /* take a reference we can use after unlock */
            found = dev;
            break;
        }
    }
    mutex_unlock(input_mutex_sym);

    if (found) {
        pr_info("using input device: \"%s\" bus=%u vendor=%u product=%u ver=%u\n",
                found->name ?: "?", found->id.bustype, found->id.vendor,
                found->id.product, found->id.version);
    } else {
        pr_warn("no suitable input device found\n");
    }
    return found;
}

static int __init pvm_hello_init(void)
{
    unsigned long addr;

    pr_info("hello: init (safe test)\n");

#if IS_ENABLED(CONFIG_KALLSYMS) && IS_ENABLED(CONFIG_KALLSYMS_ALL)
    addr = kallsyms_lookup_name("input_handle_event");
    if (!addr) {
        pr_warn("kallsyms: input_handle_event not found\n");
        g_ihe = NULL;
        pr_info("hello: init done.\n");
        return 0;
    }
    g_ihe = (input_handle_event_t)(uintptr_t)addr;
    pr_info("resolved input_handle_event @ %px\n", (void *)addr);

    /* SAFE TEST CALL: only if we have a real device */
    if (g_ihe) {
        struct input_dev *dev = pvm_find_touch_dev();
        if (dev) {
            /* Benign sync-only event: should be a no-op but valid path */
            g_ihe(dev, EV_SYN, SYN_REPORT, 0);
            input_put_device(dev);
            pr_info("test call OK (SYN_REPORT on \"%s\")\n", dev->name ?: "?");
        } else {
            pr_warn("skipping test call: no device\n");
        }
    }
#else
    pr_warn("CONFIG_KALLSYMS_ALL required to resolve static symbols\n");
    g_ihe = NULL;
#endif

    pr_info("hello: init done.\n");
    return 0;
}

late_initcall_sync(pvm_hello_init);

static void __exit pvm_hello_exit(void)
{
    pr_info("hello: exit.\n");
}
module_exit(pvm_hello_exit);
