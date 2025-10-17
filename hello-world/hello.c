// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/input.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>

MODULE_LICENSE("GPL");

/*
 * Safe plan:
 *  - Wait pvm_delay_ms, then register an input_handler.
 *  - Attach only to device named "fts_ts".
 *  - Do NOT inject inside .connect(); schedule a work item and emit once later.
 *  - Use exported input_event() for the benign test (no kallsyms, no CFI issues).
 */

static unsigned int pvm_delay_ms = 15000;   /* ~boot complete */
module_param(pvm_delay_ms, uint, 0444);
MODULE_PARM_DESC(pvm_delay_ms, "Delay (ms) before registering input handler");

static struct input_handle *pvm_handle; /* our attachment handle */
static struct input_dev    *pvm_dev;    /* cached dev (owned by input core) */

/* Work to emit a single benign event AFTER connect has finished */
static struct delayed_work pvm_emit_work;

static void pvm_emit_workfn(struct work_struct *w)
{
	struct input_dev *dev = READ_ONCE(pvm_dev);

	if (!dev) {
		pr_warn("emit: device gone, skipping\n");
		return;
	}

	/* Benign frame completion: safe on all input stacks */
	input_event(dev, EV_SYN, SYN_REPORT, 0);
	pr_info("emit: test via input_event done on \"%s\"\n", dev->name ?: "?");

	/* If you want to try the private function later (after you confirm stability):
	 * typedef void (*input_handle_event_t)(struct input_dev *, unsigned int, unsigned int, int);
	 * extern unsigned long kallsyms_lookup_name(const char *name);
	 * unsigned long addr = kallsyms_lookup_name("input_handle_event");
	 * if (addr) ((input_handle_event_t)(uintptr_t)addr)(dev, EV_SYN, SYN_REPORT, 0);
	 */
}

static void pvm_event(struct input_handle *handle,
                      unsigned int type, unsigned int code, int value)
{
	/* Keep empty to avoid recursion/log spam. */
	/* Uncomment for debugging:
	 * pr_info("evt: %u %u %d\n", type, code, value);
	 */
}

static int pvm_connect(struct input_handler *handler, struct input_dev *dev,
                       const struct input_device_id *id)
{
	int ret;
	struct input_handle *handle;

	/* Manual name filter (struct input_device_id lacks .name on many GKI trees) */
	if (!dev->name || strcmp(dev->name, "fts_ts"))
		return -ENODEV;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev     = dev;
	handle->handler = handler;
	handle->name    = "pvm_handle";

	ret = input_register_handle(handle);
	if (ret) {
		kfree(handle);
		return ret;
	}

	ret = input_open_device(handle);
	if (ret) {
		input_unregister_handle(handle);
		kfree(handle);
		return ret;
	}

	pvm_handle = handle;
	pvm_dev    = dev;

	pr_info("attached to \"%s\" (bus=%u vendor=%u product=%u ver=%u)\n",
	        dev->name, dev->id.bustype, dev->id.vendor, dev->id.product, dev->id.version);

	/* Schedule a one-shot benign emit AFTER connect fully completes */
	INIT_DELAYED_WORK(&pvm_emit_work, pvm_emit_workfn);
	schedule_delayed_work(&pvm_emit_work, msecs_to_jiffies(500)); /* 0.5s later */

	return 0;
}

static void pvm_disconnect(struct input_handle *handle)
{
	if (handle && handle->dev && handle->dev->name)
		pr_info("detaching from \"%s\"\n", handle->dev->name);

	cancel_delayed_work_sync(&pvm_emit_work);

	input_close_device(handle);
	input_unregister_handle(handle);

	if (handle == pvm_handle) {
		pvm_handle = NULL;
		pvm_dev    = NULL;
	}
	kfree(handle);
}

/* Wildcard table; we filter by name in .connect */
static const struct input_device_id pvm_ids[] = {
	{ .driver_info = 1 }, /* wildcard entry */
	{ },
};
MODULE_DEVICE_TABLE(input, pvm_ids);

static struct input_handler pvm_handler = {
	.event      = pvm_event,
	.connect    = pvm_connect,
	.disconnect = pvm_disconnect,
	.name       = "pvm",
	.id_table   = pvm_ids,
};

/* Register handler after a delay (avoids early-boot races) */
static struct delayed_work pvm_register_work;
static bool pvm_handler_registered;

static void pvm_register_workfn(struct work_struct *w)
{
	int ret;

	if (pvm_handler_registered)
		return;

	ret = input_register_handler(&pvm_handler);
	if (ret) {
		pr_warn("input_register_handler failed: %d (not retrying)\n", ret);
		return;
	}
	pvm_handler_registered = true;
	pr_info("input handler registered (delayed %u ms)\n", pvm_delay_ms);
}

static int __init pvm_init(void)
{
	INIT_DELAYED_WORK(&pvm_register_work, pvm_register_workfn);
	schedule_delayed_work(&pvm_register_work, msecs_to_jiffies(pvm_delay_ms));
	pr_info("scheduled input handler registration in %u ms\n", pvm_delay_ms);
	return 0;
}

static void __exit pvm_exit(void)
{
	cancel_delayed_work_sync(&pvm_emit_work);
	cancel_delayed_work_sync(&pvm_register_work);
	if (pvm_handler_registered) {
		input_unregister_handler(&pvm_handler);
		pvm_handler_registered = false;
	}
	pr_info("exit\n");
}

module_init(pvm_init);
module_exit(pvm_exit);
