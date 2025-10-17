// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "pvm: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

/* Minimal built-in / in-tree hello that prints a pvm: message at late init. */

static int __init pvm_hello_init(void)
{
 pr_info("hello: built-in initialized.\n");
 return 0;
}

/* When built-in this runs as an initcall; when built as a module (not here) module_init would be used. */
late_initcall_sync(pvm_hello_init);

/* Keep exit for symmetry; it will only run if built as a module (not used when built-in). */
static void __exit pvm_hello_exit(void)
{
 pr_info("hello: exit.\n");
}
module_exit(pvm_hello_exit);
