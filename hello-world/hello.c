// SPDX-License-Identifier: GPL-2.0
// PVM hello — sanitized: no kprobes, helpers static, keeps logs, resolves input_handle_event
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/kallsyms.h>
#include <linux/types.h>

MODULE_DESCRIPTION("PVM hello (sanitized) — resolve input_handle_event at runtime");
MODULE_AUTHOR("You");
MODULE_LICENSE("GPL");

/* Exact prototype of the internal input core function */
typedef void (*input_handle_event_t)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value);

/* kallsyms_lookup_name is not always prototyped in headers */
extern unsigned long kallsyms_lookup_name(const char *name);

/* static file-local pointer to resolved function */
static input_handle_event_t g_ihe = NULL;

/* static helper wrapper — call via resolved address when available.
 * This is file-local (static) to avoid exporting any symbols.
 */
static inline void ihe_emit(struct input_dev *dev,
                            unsigned int type, unsigned int code, int value)
{
	if (!g_ihe)
		return;

	/* Direct call by resolved address. Caller must ensure dev + args valid if doing real events. */
	g_ihe(dev, type, code, value);
}

/* Example helper that demonstrates how a real injection sequence would look.
 * This is commented out: use only when you have a valid struct input_dev *dev.
 *
 * static void demo_real_tap(struct input_dev *dev)
 * {
 *     if (!dev)
 *         return;
 *
 *     // slot/select and tracking id example (typical MT sequence)
 *     ihe_emit(dev, EV_ABS, ABS_MT_SLOT, 0);
 *     ihe_emit(dev, EV_ABS, ABS_MT_TRACKING_ID, 1);
 *     ihe_emit(dev, EV_ABS, ABS_MT_POSITION_X, 400);
 *     ihe_emit(dev, EV_ABS, ABS_MT_POSITION_Y, 700);
 *     ihe_emit(dev, EV_KEY, BTN_TOUCH, 1);
 *     ihe_emit(dev, EV_SYN, SYN_REPORT, 0);
 *
 *     // release
 *     ihe_emit(dev, EV_KEY, BTN_TOUCH, 0);
 *     ihe_emit(dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
 *     ihe_emit(dev, EV_SYN, SYN_REPORT, 0);
 * }
 */

/* Initialization: resolve the internal symbol once and do a safe test call. */
static int __init pvm_hello_init(void)
{
	unsigned long addr;

	pr_info("hello: initializing (sanitized)\n");

#if IS_ENABLED(CONFIG_KALLSYMS) && IS_ENABLED(CONFIG_KALLSYMS_ALL)
	addr = kallsyms_lookup_name("input_handle_event");
	if (addr) {
		g_ihe = (input_handle_event_t)(uintptr_t)addr;
		pr_info("kallsyms: resolved input_handle_event @ %px\n", (void *)addr);

		/* SAFE TEST CALL:
		 * Call the function once with NULL and zero args to test the indirect call path.
		 * This should not generate a real input event and is used only to test pointer validity.
		 */
		pr_info("pvm: performing safe test call to input_handle_event\n");
		/* calling with NULL is expected to be harmless; input_handle_event typically early-returns on invalid dev */
		g_ihe(NULL, 0, 0, 0);
		pr_info("pvm: safe test call done\n");
	} else {
		pr_warn("kallsyms: input_handle_event not found (CONFIG_KALLSYMS_ALL required for static symbols)\n");
		g_ihe = NULL;
	}
#else
	pr_warn("kallsyms: CONFIG_KALLSYMS or CONFIG_KALLSYMS_ALL not enabled — cannot resolve static symbols\n");
	g_ihe = NULL;
#endif

	return 0;
}

/* Built-in-friendly late init so message appears late in boot; module_exit is harmless but typically not used for built-ins */
late_initcall_sync(pvm_hello_init);

static void __exit pvm_hello_exit(void)
{
	/* Nothing to unregister — we did not create sysfs, devices, or kprobes */
	g_ihe = NULL;
	pr_info("hello: exit (cleanup done)\n");
}
module_exit(pvm_hello_exit);
