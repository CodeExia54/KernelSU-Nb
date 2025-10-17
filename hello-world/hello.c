// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/input.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kallsyms.h>


/* Optional: resolve the internal input core function.
 * We'll fall back to input_event() if we can't resolve it.
 */
typedef void (*input_handle_event_t)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value);
extern unsigned long kallsyms_lookup_name(const char *name);

static input_handle_event_t g_ihe;      /* resolved at init if possible */
static struct input_handle *pvm_handle; /* our attachment handle (for detach logs) */
static struct input_dev    *pvm_dev;    /* cached device pointer (no extra ref beyond input core's) */

/* Optional event tap (kept minimal to avoid log spam) */
static void pvm_event(struct input_handle *handle,
                      unsigned int type, unsigned int code, int value)
{
    /* Uncomment for debugging:
     * pr_info("evt: type=%u code=%u value=%d\n", type, code, value);
     */
}

/* We only care about a device named exactly "fts_ts". The id_table below will
 * filter, but we also re-check in .connect for safety.
 */
static int pvm_connect(struct input_handler *handler, struct input_dev *dev,
                       const struct input_device_id *id)
{
    int ret;
    struct input_handle *handle;

    if (!dev->name || strcmp(dev->name, "fts_ts")) {
        return -ENODEV;
    }

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

    /* BENIGN TEST: one SYN_REPORT – confirms call path without changing state */
    if (g_ihe) {
        g_ihe(dev, EV_SYN, SYN_REPORT, 0);
        pr_info("test via input_handle_event done on \"%s\"\n", dev->name);
    } else {
        input_event(dev, EV_SYN, SYN_REPORT, 0);
        pr_info("test via input_event fallback done on \"%s\"\n", dev->name);
    }

    return 0;
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

/* Match only our target device by name */
static const struct input_device_id pvm_ids[] = {
    { .name = "fts_ts" },
    { }, /* end */
};
MODULE_DEVICE_TABLE(input, pvm_ids);

static struct input_handler pvm_handler = {
    .event     = pvm_event,     /* optional */
    .connect   = pvm_connect,
    .disconnect= pvm_disconnect,
    .name      = "pvm",
    .id_table  = pvm_ids,
};

static int __init pvm_init(void)
{
#if IS_ENABLED(CONFIG_KALLSYMS) && IS_ENABLED(CONFIG_KALLSYMS_ALL)
    unsigned long addr = kallsyms_lookup_name("input_handle_event");
    if (addr) {
        g_ihe = (input_handle_event_t)(uintptr_t)addr;
        pr_info("resolved input_handle_event @ %px\n", (void *)addr);
    } else {
        g_ihe = NULL;
        pr_info("could not resolve input_handle_event, will use input_event fallback\n");
    }
#else
    g_ihe = NULL;
    pr_info("KALLSYMS(_ALL) not available; using input_event fallback\n");
#endif

    /* Register our input handler so we attach exactly when fts_ts appears */
    return input_register_handler(&pvm_handler);
}

static void __exit pvm_exit(void)
{
    input_unregister_handler(&pvm_handler);
    pr_info("exit\n");
}

module_init(pvm_init);
module_exit(pvm_exit);
