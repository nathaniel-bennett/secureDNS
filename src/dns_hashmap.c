#include <stdlib.h>
#include <string.h>

#include "dns_hashmap.h"


#define MAX_BUCKETS 127

typedef struct node_st node;

struct node_st {
    char *hostname;
    dns_context *dns_ctx;
    node *next;
};

/**
 * Hashes the given ID into an index within the hashmap's range.
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


/* static global hashmap for saving our socket contexts in */
static node *hashmap[MAX_BUCKETS] = {0};


/**
 * Retrieves the socket context with identifier \p fd from the internal hashmap.
 * @param id The identifier of the socket context to retrieve.
 * @return A pointer to the socket context, or NULL if no socket context was
 * found with the associated fd.
 */
dns_context *get_dns_context(const char *hostname)
{
    node *curr = hashmap[get_index(hostname)];

    while (curr != NULL) {
        if (strcmp(curr->hostname, hostname) == 0)
            return curr->dns_ctx;

        curr = curr->next;
    }

    return NULL;
}

/**
 * Adds the given fd/dns_ctx pair to the internal socket hashmap.
 * @param id The identifier of the socket to add to the hashmap.
 * @param dns_ctx The socket context associated with \p fd.
 * @return 0 if the fd/dns_ctx pair were successfully added;
 * 1 if an entry already exists for the given fd; and
 * -1 if a new entry could not be allocated.
 */
int add_dns_context(const char *hostname, dns_context *dns_ctx)
{
    node *curr;
    node *new_node;
    int index = get_index(hostname);

    new_node = malloc(sizeof(node));
    if (new_node == NULL)
        return -1;


    new_node->hostname = strdup(hostname);
    if (new_node->hostname == NULL) {
        free(new_node);
        return -1;
    }

    new_node->dns_ctx = dns_ctx;
    new_node->next = NULL;



    curr = hashmap[index];
    if (curr == NULL) {
        hashmap[index] = new_node;
        return 0;
    }

    if (strcmp(curr->hostname, hostname) == 0) {
        free(new_node);
        return 1;
    }

    while (curr->next != NULL) {
        curr = curr->next;

        if (strcmp(curr->hostname, hostname) == 0) {
            free(new_node);
            return 1;
        }
    }

    curr->next = new_node;
    return 0;
}

/**
 * Deletes the entry associated with \p fd from the internal socket hashmap.
 * @param fd The identifier of the entry to remove.
 * @return 0 if the entry was successfully deleted; or -1 if no entry exists
 * for the given fd.
 */
int del_dns_context(const char *hostname)
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







