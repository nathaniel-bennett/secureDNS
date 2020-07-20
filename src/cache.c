#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cache.h"


#define MAX_BUCKETS 127

typedef struct node_st node;

struct node_st {
    char *hostname;
    dns_rr *resp;
    node *next;
};


/* static global hashmap for saving our socket contexts in */
static node *hashmap[MAX_BUCKETS] = {0};

int has_expired_records(dns_rr *records);

/**
 * Hashes the given hostname into an index within the hashmap's range.
 * @param fd The identifier to hash.
 * @return Some index between 0 and MAX_BUCKETS-1.
 */
static int get_index(const char *hostname)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *hostname++) != 0) {
        hash = ((hash << 5u) + hash) + c; /* hash * 33 + c */

        if (hash > (ULONG_MAX / 35)) /* avoid overflow */
            hash = hash % MAX_BUCKETS;
    }

    return (int) (hash % MAX_BUCKETS);
}


/**
 * Retrieves the socket context with identifier \p fd from the internal hashmap.
 * @param id The identifier of the socket context to retrieve.
 * @return A pointer to the socket context, or NULL if no socket context was
 * found with the associated fd.
 */
dns_rr *get_cached_record(const char *hostname)
{
    node *curr = hashmap[get_index(hostname)];

    while (curr != NULL) {
        if (strcmp(curr->hostname, hostname) == 0) {

            if (has_expired_records(curr->resp)) {
                del_cached_record(hostname);
                dns_records_free(curr->resp);
                return NULL;

            } else {
                return curr->resp;
            }
        }

        curr = curr->next;
    }

    return NULL;
}

/**
 * Adds the given fd/sock_ctx pair to the internal socket hashmap.
 * @param id The identifier of the socket to add to the hashmap.
 * @param sock_ctx The socket context associated with \p fd.
 * @return 0 if the fd/sock_ctx pair were successfully added;
 * 1 if an entry already exists for the given fd; and
 * -1 if a new entry could not be allocated.
 */
int add_record_to_cache(const char *hostname, dns_rr *resp)
{
    static int cleanup_handler_installed = 0;
    node *curr;
    node *new_node;
    int index;

    if (!cleanup_handler_installed) {
        atexit(clear_cache);
        cleanup_handler_installed = 1;
    }

    new_node = malloc(sizeof(node));
    if (new_node == NULL)
        return -1;

    new_node->hostname = strdup(hostname);
    new_node->resp = resp;
    new_node->next = NULL;

    if (new_node->hostname == NULL) {
        free(new_node);
        return -1;
    }

    index = get_index(hostname);

    curr = hashmap[index];
    if (curr == NULL) {
        hashmap[index] = new_node;
        return 0;
    }

    if (strcmp(curr->hostname, hostname) == 0) {
        free(new_node->hostname);
        free(new_node);
        return 1;
    }

    while (curr->next != NULL) {
        curr = curr->next;

        if (strcmp(curr->hostname, hostname) == 0) {
            new_node->hostname;
            free(new_node);
            return 1;
        }
    }

    curr->next = new_node;
    return 0;
}

/**
 * Deletes the entry associated with \p hostname from the internal socket hashmap.
 * @param hostname The identifier of the entry to remove.
 * @return 0 if the entry was successfully deleted; or -1 if no entry exists
 * for the given fd.
 */
int del_cached_record(const char *hostname)
{
    node *curr;
    node *next;
    int index = get_index(hostname);

    curr = hashmap[index];
    if (curr == NULL)
        return -1;

    if (strcmp(curr->hostname, hostname) == 0) {
        free(curr->hostname);
        free(curr);
        hashmap[index] = NULL;
        return 0;
    }

    while (curr->next != NULL) {
        next = curr->next;
        if (strcmp(next->hostname, hostname) == 0) {
            curr->next = next->next;
            free(next->hostname);
            free(next);
            return 0;
        }

        curr = curr->next;
    }

    return -1;
}

void clear_cache()
{
    int i;

    for (i = 0; i < MAX_BUCKETS; i++) {
        node *curr = hashmap[i];

        while (curr != NULL) {
            node *next = curr->next;

            free(curr->hostname);
            dns_records_free(curr->resp);
            free(curr);

            curr = next;
        }

        hashmap[i] = NULL;
    }
}



int has_expired_records(dns_rr *records)
{
    time_t curr_time = time(NULL);

    if (records == NULL)
        return 0;

    if (curr_time < 0)
        return 1;

    while (records != NULL) {
        if (curr_time > records->ttl)
            return 1;

        records = records->next;
    }

    return 0;
}
