// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>

MODULE_LICENSE("GPL");

/* internal function prototype from drivers/input/input.c */
typedef void (*input_handle_event_t)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value);

extern unsigned long kallsyms_lookup_name(const char *name);

static input_handle_event_t g_ihe;

/* Symbols we read via kallsyms */
static struct list_head *g_input_dev_list;
static struct mutex *g_input_mutex;

/* retry finder */
static struct delayed_work pvm_find_work;
static int pvm_find_attempts;
static const int pvm_find_attempts_max = 20;          /* try up to 20 times */
static const unsigned long pvm_retry_delay = HZ / 2;  /* ~500ms between tries */

/* List all current input devices (under input_mutex) */
static void pvm_log_all_input_devices_locked(void)
{
	struct input_dev *dev;
	int idx = 0;

	list_for_each_entry(dev, g_input_dev_list, node) {
		pr_info("input[%02d]: name=\"%s\" bus=%u vendor=%u product=%u ver=%u\n",
			idx++,
			dev->name ? dev->name : "?",
			dev->id.bustype, dev->id.vendor,
			dev->id.product, dev->id.version);
	}
	if (!idx)
		pr_info("no input devices registered yet.\n");
}

/* Find device by exact name with ref held (caller must input_put_device) */
static struct input_dev *pvm_find_dev_by_name_locked(const char *target)
{
	struct input_dev *dev;

	list_for_each_entry(dev, g_input_dev_list, node) {
		const char *name = dev->name ? dev->name : "";
		if (!strcmp(name, target)) {
			input_get_device(dev); /* hold a ref after we unlock */
			return dev;
		}
	}
	return NULL;
}

static void pvm_try_find_and_ping(struct work_struct *w)
{
	struct input_dev *dev = NULL;

	/* Guard: we need kallsyms-resolved mutex/list */
	if (!g_input_mutex || !g_input_dev_list) {
		pr_warn("input symbols not resolved; stopping retries.\n");
		return;
	}

	mutex_lock(g_input_mutex);

	/* Log all devices each attempt so you can see what exists at that moment */
	pr_info("attempt %d/%d: listing input devices...\n",
		pvm_find_attempts + 1, pvm_find_attempts_max);
	pvm_log_all_input_devices_locked();

	/* Try to find fts_ts now */
	dev = pvm_find_dev_by_name_locked("fts_ts");
	mutex_unlock(g_input_mutex);

	if (dev) {
		pr_info("found target device: \"%s\" — sending benign SYN_REPORT test.\n",
			dev->name ? dev->name : "?");

		if (g_ihe) {
			g_ihe(dev, EV_SYN, SYN_REPORT, 0);
			pr_info("test call OK on \"%s\".\n", dev->name ? dev->name : "?");
		} else {
			/* Fallback: use public API if you prefer */
			input_event(dev, EV_SYN, SYN_REPORT, 0);
			pr_info("test call via input_event OK on \"%s\".\n",
				dev->name ? dev->name : "?");
		}

		input_put_device(dev);
		return; /* success, stop retrying */
	}

	/* Schedule another try if we still have budget */
	pvm_find_attempts++;
	if (pvm_find_attempts < pvm_find_attempts_max) {
		pr_info("fts_ts not present yet; retrying...\n");
		schedule_delayed_work(&pvm_find_work, pvm_retry_delay);
	} else {
		pr_warn("fts_ts not found after %d attempts; giving up.\n",
			pvm_find_attempts_max);
	}
}

static int __init pvm_hello_init(void)
{
	unsigned long addr;

	pr_info("hello: init — resolving symbols and enumerating input devices\n");

	/* resolve input core globals */
	g_input_dev_list = (struct list_head *)kallsyms_lookup_name("input_dev_list");
	g_input_mutex    = (struct mutex *)kallsyms_lookup_name("input_mutex");
	if (!g_input_dev_list || !g_input_mutex) {
		pr_warn("could not resolve input_dev_list/input_mutex; logging unavailable.\n");
	}

	/* resolve the internal handler (may be static; needs KALLSYMS_ALL) */
#if IS_ENABLED(CONFIG_KALLSYMS) && IS_ENABLED(CONFIG_KALLSYMS_ALL)
	addr = kallsyms_lookup_name("input_handle_event");
	if (addr) {
		g_ihe = (input_handle_event_t)(uintptr_t)addr;
		pr_info("resolved input_handle_event @ %px\n", (void *)addr);
	} else {
		pr_warn("could not resolve input_handle_event; will use input_event fallback.\n");
		g_ihe = NULL;
	}
#else
	pr_warn("KALLSYMS/KALLSYMS_ALL not enabled; using input_event fallback.\n");
	g_ihe = NULL;
#endif

	/* First enumeration + find try runs immediately */
	INIT_DELAYED_WORK(&pvm_find_work, pvm_try_find_and_ping);
	pvm_find_attempts = 0;
	schedule_delayed_work(&pvm_find_work, 0); /* run now */

	return 0;
}

late_initcall_sync(pvm_hello_init);

static void __exit pvm_hello_exit(void)
{
	cancel_delayed_work_sync(&pvm_find_work);
	pr_info("hello: exit.\n");
}
module_exit(pvm_hello_exit);
