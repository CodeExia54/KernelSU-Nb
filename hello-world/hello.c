// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/string.h>

/* Exact prototype of the internal function in drivers/input/input.c */
typedef void (*input_handle_event_t)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value);

extern unsigned long kallsyms_lookup_name(const char *name);

/* file-local resolved pointer (static: not exported) */
static input_handle_event_t g_ihe = NULL;

/* Find the touch device by exact name "fts_fs".
 * Returns with a reference held via input_get_device(); caller must input_put_device().
 */
static struct input_dev *pvm_find_touch_dev_by_name(const char *target)
{
	struct input_dev *dev, *found = NULL;
	struct list_head *input_dev_list_sym;
	struct mutex *input_mutex_sym;

	input_dev_list_sym = (struct list_head *)kallsyms_lookup_name("input_dev_list");
	input_mutex_sym    = (struct mutex *)kallsyms_lookup_name("input_mutex");
	if (!input_dev_list_sym || !input_mutex_sym) {
		pr_warn("pvm: could not resolve input_dev_list or input_mutex\n");
		return NULL;
	}

	mutex_lock(input_mutex_sym);
	list_for_each_entry(dev, input_dev_list_sym, node) {
		const char *name = dev->name ? dev->name : "";
		if (!strcmp(name, target)) {
			/* hold a reference so device remains valid after we unlock */
			input_get_device(dev);
			found = dev;
			break;
		}
	}
	mutex_unlock(input_mutex_sym);

	if (found) {
		pr_info("pvm: found device \"%s\" bus=%u vendor=%u product=%u ver=%u\n",
		        found->name ?: "?", found->id.bustype, found->id.vendor,
		        found->id.product, found->id.version);
	} else {
		pr_warn("pvm: no input device named \"%s\" found\n", target);
	}
	return found;
}

static int __init pvm_hello_init(void)
{
	unsigned long addr;

	pr_info("pvm: hello init (safe test, target dev=\"fts_fs\")\n");

#if IS_ENABLED(CONFIG_KALLSYMS) && IS_ENABLED(CONFIG_KALLSYMS_ALL)
	addr = kallsyms_lookup_name("input_handle_event");
	if (!addr) {
		pr_warn("pvm: kallsyms: input_handle_event not found (need KALLSYMS_ALL)\n");
		g_ihe = NULL;
		pr_info("pvm: init done.\n");
		return 0;
	}

	g_ihe = (input_handle_event_t)(uintptr_t)addr;
	pr_info("pvm: resolved input_handle_event @ %px\n", (void *)addr);

	/* SAFE TEST CALL: only if we find the real device */
	if (g_ihe) {
		struct input_dev *dev = pvm_find_touch_dev_by_name("fts_fs");
		if (dev) {
			/* A single SYN_REPORT is a benign event frame completion */
			g_ihe(dev, EV_SYN, SYN_REPORT, 0);
			pr_info("pvm: test call OK (SYN_REPORT on \"%s\")\n", dev->name ?: "?");
			input_put_device(dev);
		} else {
			pr_warn("pvm: skipping test call: device not found\n");
		}
	}
#else
	pr_warn("pvm: CONFIG_KALLSYMS and CONFIG_KALLSYMS_ALL required to resolve static symbols\n");
	g_ihe = NULL;
#endif

	pr_info("pvm: hello init done.\n");
	return 0;
}

/* Built-in-friendly init (late so you see logs near boot end). For modules, module_exit is present. */
late_initcall_sync(pvm_hello_init);

static void __exit pvm_hello_exit(void)
{
	g_ihe = NULL;
	pr_info("pvm: hello exit.\n");
}
module_exit(pvm_hello_exit);
