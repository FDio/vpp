#ifndef included_vppdb_h
#define included_vppdb_h

#include <stdint.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>
#include <vppinfra/lock.h>
#include <vppinfra/hash.h>

//
// Create objects with a path
// Path is a set of hashes
// A inode points to one of leaf or directory
//
// A directory is a pool of inodes
// A hash of names
// 
// Optimistic locking per directory (epoch)??
//
//
// Data types:
// - inline (value is stored in inode)
// - arbitrary data structure (pointer to void) (e.g. 2x vector)
// - symlink into data-structure (offset from start of data structure +
//   1) offset directly into data-structre (rewrite all on change)
//   2) base offset stored (somewhere)??? and index


// Interning
// Single vector of strings or pointer to strings.
// Reused across the whole directory structure.
//

// Pointer usage
// "VPP address space" pointers used in shared memory segment. Client responsible for mapping.
//
typedef enum {
  DS_INODE_TYPE_DIR = 0,
  DS_INODE_TYPE_INLINE,
  DS_INODE_TYPE_POINTER,
} ds_inode_type_t;

typedef struct ds_inode ds_inode_t;
struct ds_inode
{
  ds_inode_type_t type;
  union {
    struct {
      ds_inode_t *directory_vector; 	/* Pool of inodes */
      uword *directory_vector_by_name;
    };
    u64 value;
    void *data;
  };
  char *name;
};

typedef struct
{
  clib_spinlock_t lockp;
  volatile uint64_t epoch;
  volatile uint64_t in_progress;
  ds_inode_t *root;
} ds_directory_t;
  
/*
 * Shared header first in the shared memory segment.
 */
typedef struct
{
  uint64_t version;
  intptr_t base;
  ds_directory_t fs;
} ds_segment_shared_header_t;


int ds_mkdir(ds_directory_t *fs, const char *pathname);
void vppdb_init(ds_directory_t *fs);
ds_inode_t *ds_create (ds_inode_t *dir, char *file, ds_inode_type_t type);
ds_inode_t *ds_lookup(ds_directory_t *fs, const char *pathname);

/* Shared memory segment */
int ds_segment_map_init (char *mem_name, ssize_t memory_size, void **heap, void **memaddr, int *mfd);

#endif
