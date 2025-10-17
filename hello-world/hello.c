// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/input.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");

/*
 * Clean, cross-version safe version:
 * - Works on Android GKI 5.10–6.6
 * - Hooks when fts_ts input device is registered
 * - Logs with pvm: tag
 * - Sends benign EV_SYN/SYN_REPORT test event
 * - No .name field in id_table (manual string match)
 */

typedef void (*input_handle_event_t)(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value);
extern unsigned long kallsyms_lookup_name(const char *name);

static input_handle_event_t g_ihe;
static struct input_handle *pvm_handle;
static struct input_dev *pvm_dev;

static void pvm_event(struct input_handle *handle,
                      unsigned int type, unsigned int code, int value)
{
    /* Uncomment if you ever want to log raw events:
     * pr_info("evt: %u %u %d\n", type, code, value);
     */
}

static int pvm_connect(struct input_handler *handler, struct input_dev *dev,
                       const struct input_device_id *id)
{
    int ret;
    struct input_handle *handle;

    /* Manual name check, since struct input_device_id lacks .name */
    if (!dev->name || strcmp(dev->name, "fts_ts"))
        return -ENODEV;

    handle = kzalloc(sizeof(*handle), GFP_KERNEL);
    if (!handle)
        return -ENOMEM;

    handle->dev = dev;
    handle->handler = handler;
    handle->name = "pvm_handle";

    ret = input_register_handle(handle);
    if (ret)
        goto err_free;

    ret = input_open_device(handle);
    if (ret)
        goto err_unreg;

    pvm_handle = handle;
    pvm_dev = dev;

    pr_info("attached to \"%s\" (bus=%u vendor=%u product=%u ver=%u)\n",
            dev->name, dev->id.bustype, dev->id.vendor,
            dev->id.product, dev->id.version);

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
    kfree(handle);

    if (handle == pvm_handle) {
        pvm_handle = NULL;
        pvm_dev = NULL;
    }
}

/* Generic table – must exist, even if empty, for handler registration */
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

static int __init pvm_init(void)
{
#if IS_ENABLED(CONFIG_KALLSYMS) && IS_ENABLED(CONFIG_KALLSYMS_ALL)
    unsigned long addr = kallsyms_lookup_name("input_handle_event");
    if (addr) {
        g_ihe = (input_handle_event_t)(uintptr_t)addr;
        pr_info("resolved input_handle_event @ %px\n", (void *)addr);
    } else {
        pr_info("could not resolve input_handle_event; using input_event fallback\n");
        g_ihe = NULL;
    }
#else
    g_ihe = NULL;
    pr_info("KALLSYMS(_ALL) not available; using input_event fallback\n");
#endif

    return input_register_handler(&pvm_handler);
}

static void __exit pvm_exit(void)
{
    input_unregister_handler(&pvm_handler);
    pr_info("exit\n");
}

module_init(pvm_init);
module_exit(pvm_exit);
