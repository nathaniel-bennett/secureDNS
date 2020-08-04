#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "string_hashmap.h"

#define STR_MATCH(s, n) (strcmp(s, n) == 0)


/**
 * Creates an integer hash of the given string \p key and returns an index
 * suitable for insertion of an element into \p map.
 * @param map The map to hash the given key into.
 * @param key A unique null-terminated string to be used as the identifier.
 */
static int hash(string_hashmap* map, const char* key)
{
    int i;
    int hash_val = 0;

    for (i = 0; i < strlen(key); ++i)
        hash_val += key[i];

    return hash_val % MAX_BUCKETS;
}

/**
 * Creates a new string hashmap that is \p num_buckets in size. Note that
 * the hashmap will be capable of storing much more than \p num_buckets;
 * it is simply the array size for the hashmap.
 * @param num_buckets the size of the hashmap.
 * @returns A new string hashmap pointer, or NULL on failure.
 */
string_hashmap *str_hashmap_create(int num_buckets)
{
    string_hashmap *map = (string_hashmap*) malloc(sizeof(string_hashmap));
    if (map == NULL)
        return NULL;

    map->item_count = 0;
    map->num_buckets = num_buckets;
    map->buckets = (hashmap_node**) calloc(1, sizeof(hashmap_node*));
    if (map->buckets == NULL) {
        free(map);
        return NULL;
    }

    return map;
}


/**
 * Frees all entries from the given string hashmap \p map, and frees
 * the values of each entry using \p free_func.
 * @param map The map to free.
 * @param free_func The function used to free each value from the hashmap.
 */
void str_hashmap_deep_free(string_hashmap *map, void (*free_func)(void*))
{
    hashmap_node *cur = NULL;
    hashmap_node *tmp = NULL;
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
    }

    free(map->buckets);
    free(map);
    return;
}


/**
 * Frees all entries from the given string hashmap \p map, but leaves the
 * values of each entry alone.
 * @param map The map to be freed.
 */
void str_hashmap_free(string_hashmap* map)
{
    str_hashmap_deep_free(map, NULL);
    return;
}


/**
 * Retrieves the value associated with \p key from \p map.
 * @param map The string hashmap to retrieve a value from.
 * @param key The key associated with the value to retrieve.
 * @returns A pointer to the value associated with \p key,
 * or NULL if no entry exists in the hashmap for \p key.
 */
void* str_hashmap_get(string_hashmap* map, const char* key)
{
    hashmap_node *curr;
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
int str_hashmap_add(string_hashmap* map, const char* key, void* value)
{
    hashmap_node *curr, *new_node;
    int index = hash(map, key);

    new_node = (hashmap_node*) malloc(sizeof(hashmap_node));
    if (new_node == NULL)
        return -1; /* malloc() failure */

    new_node->key = strdup(key);
    if (new_node->key == NULL) {
        free(new_node);
        return -1; /* malloc() failure */
    }

    new_node->value = value;
    new_node->next = NULL;

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
    map->item_count++;

    return 0;
}


/**
 * Deletes the entry associated with \p key from \p map.
 * @param map The map to delete an entry from.
 * @param key A null-terminated string that identifies the entry to delete.
 * @returns 0 on success, or 1 if no entry exists for \p key.
 */
int str_hashmap_del(string_hashmap* map, const char* key)
{
    hashmap_node *curr, *tmp;
    int index = hash(map, key);

    curr = map->buckets[index];
    if (curr == NULL)
        return 1; /* not found */

    if (STR_MATCH(curr->key, key)) {
        map->buckets[index] = curr->next;
        free(curr->key);
        free(curr);
        map->item_count--;
        return 0;
    }
    while (curr->next != NULL) {
        tmp = curr->next;

        if (STR_MATCH(tmp->key,key)) {
            curr->next = tmp->next;
            free(tmp->key);
            free(tmp);
            map->item_count--;
            return 0;
        }

        curr = tmp;
    }

    return 1; /* not found */
}