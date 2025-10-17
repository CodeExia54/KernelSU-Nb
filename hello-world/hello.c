// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/input.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>

MODULE_LICENSE("GPL");

/*
 * Behavior:
 *  - Waits pvm_delay_ms after boot, then registers an input_handler.
 *  - The handler attaches when device "fts_ts" is registered (now or later).
 *  - On attach, logs details and sends a benign EV_SYN/SYN_REPORT test.
 *  - Resolves input_handle_event via kallsyms (if available), else uses input_event().
 *  - No kprobes, no sysfs, no exports. Logs keep "pvm:" prefix.
 */

static unsigned int pvm_delay_ms = 15000;   /* default ~boot complete on Android */
module_param(pvm_delay_ms, uint, 0444);
MODULE_PARM_DESC(pvm_delay_ms, "Delay (ms) before registering input handler");

/* Optional: resolve the internal input core function */
typedef void (*input_handle_event_t)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value);
extern unsigned long kallsyms_lookup_name(const char *name);

static input_handle_event_t g_ihe;      /* resolved at init if possible */
static struct input_handle *pvm_handle; /* our attachment handle (for logs) */
static struct input_dev    *pvm_dev;    /* cached device ptr (no extra ref) */

static void pvm_event(struct input_handle *handle,
                      unsigned int type, unsigned int code, int value)
{
    /* Uncomment to watch events:
     * pr_info("evt: %u %u %d\n", type, code, value);
     */
}

static int pvm_connect(struct input_handler *handler, struct input_dev *dev,
                       const struct input_device_id *id)
{
    int ret;
    struct input_handle *handle;

    /* Manual name match (struct input_device_id has no .name in many GKI trees) */
    if (!dev->name || strcmp(dev->name, "fts_ts"))
        return -ENODEV;

    handle = kzalloc(sizeof(*handle), GFP_KERNEL);
    if (!handle)
        return -ENOMEM;

    handle->dev     = dev;
    handle->handler = handler;
    handle->name    = "pvm_handle";

    ret = input_register_handle(handle);
    if (ret)
        goto err_free;

    ret = input_open_device(handle);
    if (ret)
        goto err_unreg;

    pvm_handle = handle;
    pvm_dev    = dev;

    pr_info("attached to \"%s\" (bus=%u vendor=%u product=%u ver=%u)\n",
            dev->name, dev->id.bustype, dev->id.vendor, dev->id.product, dev->id.version);

    /* Benign test: complete a frame with a SYN_REPORT */
    if (g_ihe) {
        g_ihe(dev, EV_SYN, SYN_REPORT, 0);
        pr_info("test via input_handle_event done on \"%s\"\n", dev->name);
    } else {
        input_event(dev, EV_SYN, SYN_REPORT, 0);
        pr_info("test via input_event fallback done on \"%s\"\n", dev->name);
    }

    return 0;

err_unreg:
    input_unregister_handle(handle);
err_free:
    kfree(handle);
    return ret;
}

static void pvm_disconnect(struct input_handle *handle)
{
    if (handle && handle->dev && handle->dev->name)
        pr_info("detaching from \"%s\"\n", handle->dev->name);

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

/* Register the handler after a delay (simulating "boot complete") */
static struct delayed_work pvm_register_work;
static bool pvm_handler_registered;

static void pvm_register_workfn(struct work_struct *w)
{
    int ret;

    if (pvm_handler_registered)
        return;

    ret = input_register_handler(&pvm_handler);
    if (ret) {
        pr_warn("input_register_handler failed: %d (will not retry)\n", ret);
        return;
    }
    pvm_handler_registered = true;
    pr_info("input handler registered (delayed %u ms)\n", pvm_delay_ms);
}

static int __init pvm_init(void)
{
#if IS_ENABLED(CONFIG_KALLSYMS) && IS_ENABLED(CONFIG_KALLSYMS_ALL)
    unsigned long addr = kallsyms_lookup_name("input_handle_event");
    if (addr) {
        g_ihe = (input_handle_event_t)(uintptr_t)addr;
        pr_info("resolved input_handle_event @ %px\n", (void *)addr);
    } else {
        g_ihe = NULL;
        pr_info("could not resolve input_handle_event; using input_event fallback\n");
    }
#else
    g_ihe = NULL;
    pr_info("KALLSYMS(_ALL) not available; using input_event fallback\n");
#endif

    INIT_DELAYED_WORK(&pvm_register_work, pvm_register_workfn);
    schedule_delayed_work(&pvm_register_work, msecs_to_jiffies(pvm_delay_ms));
    pr_info("scheduled input handler registration in %u ms\n", pvm_delay_ms);
    return 0;
}

static void __exit pvm_exit(void)
{
    cancel_delayed_work_sync(&pvm_register_work);
    if (pvm_handler_registered) {
        input_unregister_handler(&pvm_handler);
        pvm_handler_registered = false;
    }
    pr_info("exit\n");
}

module_init(pvm_init);
module_exit(pvm_exit);
