#ifndef KSYMDUMP_H
#define KSYMDUMP_H

/*
 * Resolve and cache addresses of symbols specified in ascii NULL-terminated array.
 * Logs resolved symbols with their addresses.
 */
void resolve_and_cache_symbols(const char * const symbol_names[]);

/*
 * Retrieve cached symbol address by name.
 * Returns NULL if symbol not found.
 */
void *get_cached_symbol_addr(const char *name);

#endif // KSYMDUMP_H
