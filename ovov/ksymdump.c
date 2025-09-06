#include <linux/kallsyms.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "ksymdump.h"

#define MAX_SYMBOLS_CACHE 128

struct symbol_cache_entry {
    const char *name;
    void *addr;
};

static struct symbol_cache_entry g_symbol_cache[MAX_SYMBOLS_CACHE];
static int g_symbol_cache_count = 0;

static const char * const *g_lookup_list = NULL;

static int kallsyms_callback(void *data, const char *name, struct module *mod, unsigned long addr)
{
    int i;
    (void)data;

    if (!g_lookup_list)
        return 0;

    for (i = 0; g_lookup_list[i] != NULL; i++) {
        if (strcmp(name, g_lookup_list[i]) == 0) {
            if (g_symbol_cache_count < MAX_SYMBOLS_CACHE) {
                g_symbol_cache[g_symbol_cache_count].name = g_lookup_list[i];
                g_symbol_cache[g_symbol_cache_count].addr = (void *)addr;
                pr_info("[ksymdump] Resolved symbol: %s at %p\n", name, (void *)addr);
                g_symbol_cache_count++;
            }
            break;
        }
    }
    return 0; // continue enumeration
}

void resolve_and_cache_symbols(const char * const symbol_names[])
{
    g_lookup_list = symbol_names;
    /* Reset count if first call */
    if (symbol_names == NULL || symbol_names[0] == NULL)
        return;

    /* Optional: could clear or keep old cache entries here */
    kallsyms_on_each_symbol(kallsyms_callback, NULL);
}

void *get_cached_symbol_addr(const char *name)
{
    int i;
    for (i = 0; i < g_symbol_cache_count; i++) {
        if (strcmp(g_symbol_cache[i].name, name) == 0)
            return g_symbol_cache[i].addr;
    }
    return NULL;
}
