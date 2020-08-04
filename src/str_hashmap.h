#ifndef SECUREDNS_STRING_HASHMAP_H
#define SECUREDNS_STRING_HASHMAP_H


#define MAX_BUCKETS 127


typedef struct hashmap_node_st {
    char* key;
    void* value;
    struct hashmap_node_st* next;
} hashmap_node;


typedef struct string_hashmap_st {
    hashmap_node **buckets;
    int num_buckets;
    int item_count;
} string_hashmap;


/**
 * Creates a new string hashmap that is \p num_buckets buckets for hashing.
 * @param num_buckets The number of hashing buckets for the hashmap.
 * @returns A pointer to an allocated string_hashmap, or NULL on failure.
 */
string_hashmap *str_hashmap_create(int num_buckets);


/**
 * Frees all entries from the given string hashmap \p map, but leaves the
 * values of each entry alone.
 * @param map The map to be freed.
 */
void str_hashmap_free(string_hashmap *map);


/**
 * Frees all entries from the given string hashmap \p map, and frees
 * the values of each entry using \p free_func.
 * @param map The map to free.
 * @param free_func The function used to free each value from the hashmap.
 */
void str_hashmap_deep_free(string_hashmap *map, void (*free_func)(void*));


/**
 * Adds the given key:value pair to \p map.
 * @param map The map to add a new element to.
 * @param key The null-terminated string used to lookup the value in \p map.
 * @param value A pointer to a data structure to be stored in \p map.
 * @returns 0 on success; 1 if the entry could not be found; or -1 on
 * malloc failure.
 */
int str_hashmap_add(string_hashmap *map, const char *key, void *value);


/**
 * Deletes the entry associated with \p key from \p map.
 * @param map The map to delete an entry from.
 * @param key A null-terminated string that identifies the entry to delete.
 * @returns 0 on success, or 1 if no entry exists for \p key.
 */
int str_hashmap_del(string_hashmap *map, const char *key);


/**
 * Retrieves the value associated with \p key from \p map.
 * @param map The string hashmap to retrieve a value from.
 * @param key The key associated with the value to retrieve.
 * @returns A pointer to the value associated with \p key,
 * or NULL if no entry exists in the hashmap for \p key.
 */
void *str_hashmap_get(string_hashmap *map, const char *key);

#endif
