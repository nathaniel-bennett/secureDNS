#include <stdlib.h>
#include <string.h>

#include "records_cache.h"
#include "str_hashmap.h"


#define MAX_CACHED_RECORDS 5000

/* static global hashmap for saving our cached records in */
static hsmap *cache_hashmap = NULL;

static void clear_expired_cache_entries();

static void free_cache_hashmap();
static void free_cache_hashmap_entry(void *entry);

/**
 * Retrieves the socket context with identifier \p fd from the internal hashmap.
 * @param id The identifier of the socket context to retrieve.
 * @return A pointer to the socket context, or NULL if no socket context was
 * found with the associated fd.
 */
dns_rr *get_cached_record(const char *hostname)
{
    if (cache_hashmap == NULL)
        return NULL;

    dns_rr *records = str_hashmap_get(cache_hashmap, hostname);
    if (records == NULL)
        return NULL;

    if (has_expired_records(records)) {
        str_hashmap_del(cache_hashmap, hostname);
        dns_records_free(records);
        return NULL;
    }

    return records;
}

/**
 * Adds the given fd/sock_ctx pair to the internal socket hashmap.
 * @param id The identifier of the socket to add to the hashmap.
 * @param sock_ctx The socket context associated with \p fd.
 * @return 0 if the fd/sock_ctx pair were successfully added;
 * 1 if an entry already exists for the given fd; and
 * -1 if a new entry could not be allocated (either due to malloc() failure or
 * the hashmap's maximum size being reached--errno will be set if the former
 * is true).
 */
int add_record_to_cache(const char *hostname, dns_rr *resp)
{
    if (cache_hashmap == NULL) {
        cache_hashmap = str_hashmap_create(MAX_BUCKETS);
        if (cache_hashmap == NULL)
            return -1;

        atexit(free_cache_hashmap);
    }

    if (str_hashmap_size(cache_hashmap) >= MAX_CACHED_RECORDS) {
        clear_expired_cache_entries();
        if (str_hashmap_size(cache_hashmap) >= MAX_CACHED_RECORDS)
            return -1;
    }

    return str_hashmap_add(cache_hashmap, hostname, (void*) resp);
}

/**
 * Deletes the entry associated with \p hostname from the internal socket hashmap.
 * @param hostname The identifier of the entry to remove.
 * @return 0 if the entry was successfully deleted; or -1 if no entry exists
 * for the given fd.
 */
int del_cached_record(const char *hostname)
{
    if (cache_hashmap == NULL)
        return 1;

    return str_hashmap_del(cache_hashmap, hostname);
}


void clear_expired_cache_entries()
{
    hsmap_iterator *iter = hsmap_iterator_start(cache_hashmap);

    while (iter != NULL) {
        dns_rr *records = (dns_rr*) hsmap_iterator_value(iter);

        if (has_expired_records(records)) {
            dns_records_free(records);

            hsmap_iterator *tmp = hsmap_iterate(cache_hashmap, iter);
            hsmap_iterator_del(cache_hashmap, iter);
            iter = tmp;

        } else {
            iter = hsmap_iterate(cache_hashmap, iter);
        }
    }
}

void free_cache_hashmap()
{
    str_hashmap_deep_free(cache_hashmap, free_cache_hashmap_entry);
}

static void free_cache_hashmap_entry(void *entry)
{
    dns_records_free((dns_rr*) entry);
}
