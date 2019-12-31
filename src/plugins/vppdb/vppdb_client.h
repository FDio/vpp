#ifndef included_vppdb_client_h
#define included_vppdb_client_h

#include "vppdb.h"

typedef struct {
  void *base;
  size_t memory_size;
} ds_main_t;

extern ds_main_t ds_main;
int ds_client_map_init (const char *socket_name, void **memaddr, size_t *memory_size);
int ds_client_lookup(ds_inode_t *root, const char *pathname, ds_inode_t **result);

void ds_set_offset(intptr_t);
intptr_t ds_get_offset(void);
void *ds_pointer_adjust (void *pointer);

#endif
