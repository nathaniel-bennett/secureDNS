#include <stdlib.h>

#include <string.h>

#include "str_hashmap.h"

#define STR_MATCH(s, n) (strcmp(s, n) == 0)



typedef struct hsmap_node_st hsmap_node;

struct hsmap_node_st {
    char *key;
    void *value;
    hsmap_node *next;
    hsmap_node *prev;
};

struct hsmap_st {
    hsmap_node **buckets;
    int num_buckets;
    int item_count;
};



/**
 * Creates an integer hash of the given string \p key and returns an index
 * suitable for insertion of an element into \p map.
 * @param map The map to hash the given key into.
 * @param key A unique null-terminated string to be used as the identifier.
 */
static int hash(hsmap* map, const char* key)
{
    int i;
    int hash_val = 0;

    for (i = 0; i < strlen(key); ++i)
        hash_val += key[i];

    return hash_val % map->num_buckets;
}

/**
 * Creates a new string hashmap that is \p num_buckets in size. Note that
 * the hashmap will be capable of storing much more than \p num_buckets;
 * it is simply the array size for the hashmap.
 * @param num_buckets the size of the hashmap.
 * @returns A new string hashmap pointer, or NULL on failure.
 */
hsmap *str_hashmap_create(int num_buckets)
{
    hsmap *map = (hsmap*) malloc(sizeof(hsmap));
    if (map == NULL)
        return NULL;

    map->item_count = 0;
    map->num_buckets = num_buckets;
    map->buckets = (hsmap_node**) calloc(num_buckets, sizeof(hsmap_node*));
    if (map->buckets == NULL) {
        free(map);
        return NULL;
    }

    return map;
}



void str_hashmap_clear(hsmap *map, void (*free_func)(void*))
{
    hsmap_node *cur = NULL;
    hsmap_node *tmp = NULL;
    int i;

    for (i = 0; i < MAX_BUCKETS; i++) {
        cur = map->buckets[i];
        while (cur != NULL) {
            tmp = cur->next;
            if (free_func != NULL)
                free_func(cur->value);

            free(cur->key);
            free(cur);
            cur = tmp;
        }
        map->buckets[i] = NULL;
    }
}


/**
 * Frees all entries from the given string hashmap \p map, and frees
 * the values of each entry using \p free_func.
 * @param map The map to free.
 * @param free_func The function used to free each value from the hashmap.
 */
void str_hashmap_deep_free(hsmap *map, void (*free_func)(void*))
{
    str_hashmap_clear(map, free_func);

    free(map->buckets);
    free(map);
}


/**
 * Frees all entries from the given string hashmap \p map, but leaves the
 * values of each entry alone.
 * @param map The map to be freed.
 */
/*
void str_hashmap_free(hsmap* map)
{
    str_hashmap_deep_free(map, NULL);
    return;
}
 */

/**
 * Retrieves the value associated with \p key from \p map.
 * @param map The string hashmap to retrieve a value from.
 * @param key The key associated with the value to retrieve.
 * @returns A pointer to the value associated with \p key,
 * or NULL if no entry exists in the hashmap for \p key.
 */
void* str_hashmap_get(hsmap* map, const char* key)
{
    hsmap_node *curr;
    int index = hash(map, key);

    curr = map->buckets[index];
    if (curr == NULL)
        return NULL; /* Not found */

    if (STR_MATCH(curr->key, key))
        return curr->value;

    while (curr->next != NULL) {
        if (STR_MATCH(curr->next->key, key))
            return curr->next->value;

        curr = curr->next;
    }

    return NULL; /* Not found */
}


/**
 * Adds the given key:value pair to \p map.
 * @param map The map to add a new element to.
 * @param key The null-terminated string used to lookup the value in \p map.
 * @param value A pointer to a data structure to be stored in \p map.
 * @returns 0 on success; 1 if the entry could not be found; or -1 on
 * malloc failure.
 */
int str_hashmap_add(hsmap* map, const char* key, void* value)
{
    hsmap_node *curr, *new_node;
    int index = hash(map, key);

    new_node = (hsmap_node*) malloc(sizeof(hsmap_node));
    if (new_node == NULL)
        return -1; /* malloc() failure */

    new_node->key = strdup(key);
    if (new_node->key == NULL) {
        free(new_node);
        return -1; /* malloc() failure */
    }

    new_node->value = value;
    new_node->next = NULL;
    new_node->prev = NULL;

    curr = map->buckets[index];
    if (curr == NULL) {
        map->buckets[index] = new_node;
        map->item_count++;
        return 0;
    }

    if (STR_MATCH(curr->key, key)) {
        free(new_node->key);
        free(new_node);
        return 1; /* Duplicate entry */
    }

    while (curr->next != NULL) {
        curr = curr->next;

        if(STR_MATCH(curr->key, key)) {
            free(new_node->key);
            free(new_node);
            return 1; /* Duplicate entry */
        }
    }

    curr->next = new_node;
    new_node->prev = curr;
    map->item_count++;

    return 0;
}


/**
 * Deletes the entry associated with \p key from \p map.
 * @param map The map to delete an entry from.
 * @param key A null-terminated string that identifies the entry to delete.
 * @returns 0 on success, or 1 if no entry exists for \p key.
 */
int str_hashmap_del(hsmap* map, const char* key)
{
    hsmap_node *curr;
    int index = hash(map, key);

    curr = map->buckets[index];
    if (curr == NULL)
        return 1; /* not found */

    while (curr != NULL) {
        if (STR_MATCH(curr->key,key)) {
            if (curr->prev == NULL)
                map->buckets[index] = curr->next;
            else
                curr->prev->next = curr->next;

            if (curr->next != NULL)
                curr->next->prev = curr->prev;

            free(curr->key);
            free(curr);
            map->item_count--;
            return 0;
        }

        curr = curr->next;
    }

    return 1; /* not found */
}


int str_hashmap_size(hsmap *map)
{
    return map->item_count;
}


/*******************************************************************************
 *
 ******************************************************************************/

hsmap_iterator *hsmap_iterator_start(hsmap *map)
{
    hsmap_iterator *iter = NULL;
    int i;

    for (i = 0; i < map->num_buckets; i++) {
        if (map->buckets[i] != NULL) {
            iter = (hsmap_iterator*) map->buckets[i];
            break;
        }
    }

    if (iter == NULL)
        return NULL;

    iter->prev = NULL;

    return iter;
}


hsmap_iterator *hsmap_iterate(hsmap *map, hsmap_iterator *iter)
{
    int bucket_pos, i;

    if (iter->next != NULL)
        return iter->next;

    bucket_pos = hash(map, iter->key);

    for (i = bucket_pos + 1; i < map->num_buckets; i++) {
        if (map->buckets[i] != NULL)
            return map->buckets[i];
    }

    return NULL;
}


void hsmap_iterator_del(hsmap *map, hsmap_iterator *iter)
{
    int bucket_pos = hash(map, iter->key);

    if (iter->prev == NULL)
        map->buckets[bucket_pos] = iter->next;
    else
        iter->prev->next = iter->next;

    if (iter->next != NULL)
        iter->next->prev = iter->prev;

    free(iter->key);
    free(iter);
    map->item_count -= 1;
}


void *hsmap_iterator_value(hsmap_iterator *iter)
{
    return iter->value;
}
