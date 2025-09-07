#ifndef KPROBE_KALLSYMS_H
#define KPROBE_KALLSYMS_H

#include <linux/kprobes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Register a kprobe on the given kernel symbol (normally “kallsyms_lookup_name”).
 * Returns 0 on success or a negative errno. */
int  kpks_init(const char *symbol_name);

/* Unregister the kprobe – call from your module’s exit path. */
void kpks_exit(void);

/* Wrapper that behaves exactly like kallsyms_lookup_name().
 * You may call it from anywhere after kpks_init() succeeded. */
unsigned long kpks_lookup(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* KPROBE_KALLSYMS_H */
