// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/kallsyms.h>

MODULE_DESCRIPTION("PVM hello + test input_handle_event call");
MODULE_AUTHOR("You");
MODULE_LICENSE("GPL");

/* Define the correct prototype */
typedef void (*input_handle_event_t)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value);

extern unsigned long kallsyms_lookup_name(const char *name);

static input_handle_event_t g_ihe;  // global pointer

static int __init pvm_hello_init(void)
{
    unsigned long addr;

#if IS_ENABLED(CONFIG_KALLSYMS) && IS_ENABLED(CONFIG_KALLSYMS_ALL)
    addr = kallsyms_lookup_name("input_handle_event");
    if (addr) {
        g_ihe = (input_handle_event_t)(uintptr_t)addr;
        pr_info("Resolved input_handle_event @ %px\n", (void *)addr);

        /* Test call with NULL device and dummy values */
        pr_info("Testing function call...\n");
        g_ihe(NULL, 0, 0, 0);
        pr_info("Function call completed without crash ✅\n");
    } else {
        pr_warn("Failed to resolve input_handle_event ❌\n");
    }
#else
    pr_warn("CONFIG_KALLSYMS_ALL required to resolve static symbols\n");
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
