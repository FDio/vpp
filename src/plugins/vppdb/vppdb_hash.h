#ifndef included_db_hash_h
#define included_db_hash_h

#include <stdint.h>

/*
 * Each directory is a pool of entries.
 *  - pointer to name
 *  - leaf, inline or directory (type)
 *
 * Each directory has a search hash
 *  -> which as it's value has the pool index.
 *  -> linked list for collisions.
 */


typedef struct ds_hash_entry_ {
  char *key;
  uint32_t value;
  struct ds_hash_entry_ *next;
} ds_hash_entry_t;

typedef struct {
  uint32_t elts;
} ds_hash_t;

void ds_hash_set(void *v, char *key, uint32_t value);
ds_hash_entry_t *ds_hash_get(void *v, char *key);
void *ds_hash_create(uint32_t elements);

#endif
