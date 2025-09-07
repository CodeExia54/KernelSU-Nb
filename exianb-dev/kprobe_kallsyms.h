#ifndef KPROBE_KALLSYMS_H
#define KPROBE_KALLSYMS_H

#include <linux/kprobes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Register a kprobe on the given symbol (usually “kallsyms_lookup_name”). */
int  kpks_init(const char *symbol_name);

/* Unregister the kprobe – call from module_exit. */
void kpks_exit(void);

/* Drop-in replacement for kallsyms_lookup_name. */
unsigned long kpks_lookup(const char *name);

/* Same as kpks_lookup() but prints
 *   "kprobe_kallsyms: resolved <sym> = <addr>"
 * to the kernel log every time it is called. */
unsigned long kpks_lookup_log(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* KPROBE_KALLSYMS_H */
