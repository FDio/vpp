#ifndef included_cdb_h
#define included_cdb_h

#include <stdint.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>
#include <vppinfra/lock.h>
#include <vppinfra/hash.h>

typedef enum {
  CDB_INODE_TYPE_DIR = 0,
  CDB_INODE_TYPE_INLINE,
  CDB_INODE_TYPE_POINTER,
  CDB_INODE_TYPE_LINK,
} cdb_inode_type_t;

struct cdb_inode;
typedef void cdb_subscriber_fn (void *data, int type, u32 index);
typedef void cdb_format_fn (struct cdb_inode *d);
typedef struct cdb_inode cdb_inode_t;
struct cdb_inode {
  cdb_inode_type_t type;
  union {
    struct {
      cdb_inode_t *directory_vector; 	/* Pool of inodes */
      uword *directory_vector_by_name;
    };
    u64 value;
    void *data;
  };
  char *parent;
  cdb_subscriber_fn **subscribers;
  cdb_format_fn *format;
  char *name;
};

typedef struct {
  clib_spinlock_t lockp;
  cdb_inode_t *root;
  char *name;
} cdb_db_t;
  
void cdb_add (u32 cdb, char *path, void *data, u32 size, cdb_format_fn *format);
int cdb_mkdir(cdb_db_t *fs, const char *pathname);
u32 cdb_init(char *name);
cdb_inode_t *cdb_create (cdb_inode_t *dir, char *file, cdb_inode_type_t type);
cdb_inode_t *cdb_lookup(cdb_db_t *fs, const char *pathname);
void cdb_subscribe(u32 cdb, char *path, cdb_subscriber_fn *f);
void cdb_notify_path (u32 cdb, char *path);
cdb_db_t *cdb_get_cdb(u32 index);

#endif
