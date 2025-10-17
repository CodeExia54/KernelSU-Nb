// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/kallsyms.h>
#include <linux/types.h>

MODULE_DESCRIPTION("PVM hello + direct kallsyms resolve");
MODULE_AUTHOR("You");
MODULE_LICENSE("GPL");

/* Exact prototype of input_handle_event */
typedef void (*input_handle_event_t)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value);

extern unsigned long kallsyms_lookup_name(const char *name);

static input_handle_event_t g_ihe;  /* function address we resolve once */

/* Optional: avoid CFI false-positives on indirect call; harmless if unused */
#if defined(__has_attribute)
# if __has_attribute(nocfi)
#  define __nocfi __attribute__((nocfi))
# else
#  define __nocfi
# endif
#else
# define __nocfi
#endif

/* Call helper: exactly what you asked—call by address if resolved */
static inline void ihe_emit(struct input_dev *dev,
                            unsigned int type, unsigned int code, int value)
{
    input_handle_event_t fn = g_ihe;
    if (fn) {
        ((input_handle_event_t __nocfi)fn)(dev, type, code, value);
    } else {
        /* If you truly want no fallback, delete this line and the else block. */
        input_event(dev, type, code, value);
    }
}

static int __init pvm_hello_init(void)
{
#if IS_ENABLED(CONFIG_KALLSYMS) && IS_ENABLED(CONFIG_KALLSYMS_ALL)
    unsigned long addr = kallsyms_lookup_name("input_handle_event");
    if (!addr) {
        pr_warn("kallsyms: input_handle_event not found (keeping fallback)\n");
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

/* Usage elsewhere in your code:
 *
 *   // assuming you have a valid 'struct input_dev *touch_dev'
 *   ihe_emit(touch_dev, EV_ABS, ABS_MT_SLOT, slot);
 *   ihe_emit(touch_dev, EV_ABS, ABS_MT_TRACKING_ID, tid);
 *   ihe_emit(touch_dev, EV_KEY, BTN_TOUCH, 1);
 *   ihe_emit(touch_dev, EV_SYN, SYN_REPORT, 0);
 *
 * If you want *no* fallback at all, remove the input_event() line inside ihe_emit().
 */
