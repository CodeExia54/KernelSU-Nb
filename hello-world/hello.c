// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/string.h>

/*
 * Safe built-in module that:
 *  - resolves input_handle_event at runtime (via kallsyms)
 *  - finds input device named "fts_ts"
 *  - performs a single benign test call (EV_SYN/SYN_REPORT)
 *  - produces clean "pvm:" logs only
 */

/* Correct prototype from drivers/input/input.c */
typedef void (*input_handle_event_t)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value);

extern unsigned long kallsyms_lookup_name(const char *name);

/* Static global (not exported anywhere) */
static input_handle_event_t g_ihe = NULL;

/* Find the input device "fts_ts" safely */
static struct input_dev *pvm_find_touch_dev_by_name(const char *target)
{
	struct input_dev *dev, *found = NULL;
	struct list_head *input_dev_list_sym;
	struct mutex *input_mutex_sym;

	input_dev_list_sym = (struct list_head *)kallsyms_lookup_name("input_dev_list");
	input_mutex_sym    = (struct mutex *)kallsyms_lookup_name("input_mutex");

	if (!input_dev_list_sym || !input_mutex_sym) {
		pr_warn("cannot resolve input_dev_list or input_mutex\n");
		return NULL;
	}

	mutex_lock(input_mutex_sym);
	list_for_each_entry(dev, input_dev_list_sym, node) {
		const char *name = dev->name ? dev->name : "";
		if (!strcmp(name, target)) {
			input_get_device(dev);
			found = dev;
			break;
		}
	}
	mutex_unlock(input_mutex_sym);

	if (found) {
		pr_info("found input device \"%s\" bus=%u vendor=%u product=%u ver=%u\n",
		        found->name ?: "?", found->id.bustype, found->id.vendor,
		        found->id.product, found->id.version);
	} else {
		pr_warn("no input device named \"%s\" found\n", target);
	}
	return found;
}

static int __init pvm_hello_init(void)
{
	unsigned long addr;

	pr_info("hello init: starting safe input_handle_event resolver\n");

#if IS_ENABLED(CONFIG_KALLSYMS) && IS_ENABLED(CONFIG_KALLSYMS_ALL)
	addr = kallsyms_lookup_name("input_handle_event");
	if (!addr) {
		pr_warn("cannot resolve input_handle_event (need KALLSYMS_ALL)\n");
		return 0;
	}

	g_ihe = (input_handle_event_t)(uintptr_t)addr;
	pr_info("resolved input_handle_event @ %px\n", (void *)addr);

	struct input_dev *dev = pvm_find_touch_dev_by_name("fts_ts");
	if (dev && g_ihe) {
		g_ihe(dev, EV_SYN, SYN_REPORT, 0);
		pr_info("test call executed successfully on \"%s\"\n", dev->name ?: "?");
		input_put_device(dev);
	} else {
		pr_warn("skipped test call: device not found or func unresolved\n");
	}
#else
	pr_warn("KALLSYMS and KALLSYMS_ALL required for runtime symbol resolution\n");
#endif

	pr_info("hello init done.\n");
	return 0;
}

/* Built-in init — runs late, no exit needed for built-in */
late_initcall_sync(pvm_hello_init);

static void __exit pvm_hello_exit(void)
{
	g_ihe = NULL;
	pr_info("hello exit.\n");
}
module_exit(pvm_hello_exit);
