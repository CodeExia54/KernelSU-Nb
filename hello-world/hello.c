// SPDX-License-Identifier: GPL-2.0
// Minimal PVM hello (built-in friendly, no delays)
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

static int __init pvm_hello_init(void)
{
	pr_info("hello: late init — built-in initialized.\n");
	return 0;
}

/*
 * Use a late initcall so the message appears near the end of kernel init.
 * When built-in (CONFIG_PVM_MOD=y), this becomes an initcall.
 * When built as a module (=m), this is ignored; module_init/module_exit take over.
 */
late_initcall_sync(pvm_hello_init);

static void __exit pvm_hello_exit(void)
{
	/* Only meaningful if built as a module. */
	pr_info("hello: exit.\n");
}
module_exit(pvm_hello_exit);

MODULE_DESCRIPTION("PVM hello logger (late init, no delay)");
MODULE_AUTHOR("You");
MODULE_LICENSE("GPL");
