// SPDX-License-Identifier: GPL
#include "kprobe_kallsyms.h"
#include <linux/kernel.h>

static struct kprobe kp = { .symbol_name = NULL };

int kpks_init(const char *symbol_name)
{
	kp.symbol_name = symbol_name;
	return register_kprobe(&kp);          /* kp.addr will hold kallsyms_lookup_name */
}

void kpks_exit(void)
{
	unregister_kprobe(&kp);
}

/* Thin wrapper – call just like kallsyms_lookup_name(). */
unsigned long kpks_lookup(const char *name)
{
	if (!kp.addr)
		return 0;
	return ((unsigned long (*)(const char *))kp.addr)(name);
}
