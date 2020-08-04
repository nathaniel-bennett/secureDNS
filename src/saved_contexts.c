#include <stdlib.h>
#include <string.h>

#include "dns_hashmap.h"
#include "str_hashmap.h"


hmap_str *dns_hashmap = NULL;


static void free_dns_hashmap();
static void free_dns_hashmap_entry(void *entry);


/**
 * Retrieves the socket context with identifier \p fd from the internal hashmap.
 * @param id The identifier of the socket context to retrieve.
 * @return A pointer to the socket context, or NULL if no socket context was
 * found with the associated fd.
 */
dns_context *get_dns_context(const char *hostname)
{
    if (dns_hashmap == NULL)
        return NULL;

    return (dns_context*) str_hashmap_get(dns_hashmap, hostname);
}


/**
 * Adds the given fd/dns_ctx pair to the internal socket hashmap.
 * @param id The identifier of the socket to add to the hashmap.
 * @param dns_ctx The socket context associated with \p fd.
 * @return 0 if the fd/dns_ctx pair were successfully added;
 * 1 if an entry already exists for the given fd; and
 * -1 if a memory failure occurred.
 */
int add_dns_context(const char *hostname, dns_context *dns_ctx)
{
    if (dns_hashmap == NULL) {
        dns_hashmap = str_hashmap_create(MAX_BUCKETS);
        if (dns_hashmap == NULL)
            return -1;

        atexit(free_dns_hashmap);
    }

    return str_hashmap_add(dns_hashmap, hostname, (void*) dns_ctx);
}


/**
 * Deletes the entry associated with \p fd from the internal socket hashmap.
 * @param fd The identifier of the entry to remove.
 * @return 0 if the entry was successfully deleted; or -1 if no entry exists
 * for the given fd.
 */
int del_dns_context(const char *hostname)
{
    if (dns_hashmap == NULL)
        return 1;

    return str_hashmap_del(dns_hashmap, hostname);
}


void free_dns_hashmap_entry(void *entry)
{
    dns_context_free((dns_context*) entry);
}


void free_dns_hashmap()
{
    if (dns_hashmap != NULL)
        str_hashmap_deep_free(dns_hashmap, free_dns_hashmap_entry);
}