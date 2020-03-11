#include <vppinfra/pool.h>
#include "cdb.h"
#include <assert.h>

/* Pool of configuration datastores */
cdb_db_t *cdbpool;

void cdb_lock (cdb_db_t *d)
{
  assert (d);
  clib_spinlock_lock (&d->lockp);
}

void cdb_unlock (cdb_db_t *d)
{
  assert (d);
  clib_spinlock_unlock (&d->lockp);
}

/*
 * Split a path string into a vector of path elements
 */
static char **
split_path(const char *pathname)
{
  assert(pathname);
  char **result = 0;
  const char *p = pathname;
  size_t s;
  const char *end = rindex(pathname, '\0');
  while (p < end) {
    s = strcspn(p, "/");
    if (s > 0) {
      char *slice = 0;
      vec_add(slice, p, s);
      vec_add1(result, slice);
    }
    p  = p + s + 1;
  }
  return result;
}

static void split_path_free(char **paths)
{
  assert(*paths);
  char **p;
  vec_foreach(p, paths) {
    vec_free(*p);
  }
  vec_free(paths);
}

static char * merge_path(char **paths, int elem)
{
  u8 *s = 0;
  int i = 0;
  assert(*paths);

  if (elem > vec_len(paths)) {
    clib_warning("Paths error");
    return 0;
  }
  while (i < elem) {
    s = format(s, "/%s", paths[i]);
    i++;
  }
  if (!s)
    s = format(s, "/%c", 0);
  else
    s = format(s, "%c", 0);
  return (char *)s;
}

cdb_inode_t *
new_node(cdb_inode_t *parent, char *name)
{
  cdb_inode_t *d;
  pool_get_zero (parent->directory_vector, d);
  u32 index = d - parent->directory_vector;
  hash_set (parent->directory_vector_by_name, name, index);
  d->name = name;
  return d;
}

/*
 * Create a new directory node
 */
int cdb_mkdir (cdb_db_t *fs, const char *pathname)
{
  hash_pair_t *hp;
  int rv = 0;
  assert (fs);
  assert (pathname);

  /* Split path into individual elements */
  char **paths = split_path (pathname);
  cdb_lock (fs);
  cdb_inode_t *dir = fs->root, *d;
  int i;
  vec_foreach_index (i, paths) {
    hp = hash_get_pair (dir->directory_vector_by_name, paths[i]);
    if (!hp) {
      if (!dir->directory_vector_by_name) {
	dir->directory_vector_by_name =
	  hash_create_string (0, sizeof (uword));
      }
      d = new_node(dir, (char *)format (0, "%s%c", paths[i], 0));
      d->parent = merge_path(paths, i);
      dir = d;
    } else {
      dir = &dir->directory_vector[hp->value[0]];
      if (dir->type != CDB_INODE_TYPE_DIR) {
	rv = -1;
	break;
      }
    }
  }
  cdb_unlock (fs);
  split_path_free (paths);
  return rv;
}

/*
 * Look up a path in the directory hierarchy
 */
cdb_inode_t *cdb_lookup (cdb_db_t *fs, const char *pathname)
{
  hash_pair_t *hp;
  int i;

  assert (fs);
  assert (pathname);

  /* Split path into individual elements */
  char **paths = split_path (pathname);
  if (!paths) return 0;

  cdb_lock (fs);
  cdb_inode_t *dir = fs->root;
  vec_foreach_index (i, paths)
  {
    hp = hash_get_pair (dir->directory_vector_by_name, paths[i]);
    if (!hp)
      {
        dir = 0;
        break;
      }
    dir = &dir->directory_vector[hp->value[0]];
    if (dir->type != CDB_INODE_TYPE_DIR)
      {
        if (i != vec_len (paths) - 1)
          {
            dir = 0;
          }
        break;
      }
  }
  cdb_unlock (fs);
  split_path_free (paths);
  return dir;
}

/*
 * Create a leaf
 */
cdb_inode_t *cdb_create (cdb_inode_t *dir, char *filename, cdb_inode_type_t type)
{
  assert (dir);
  assert (filename);

  cdb_inode_t *d;
  pool_get_zero (dir->directory_vector, d);
  assert (d);

  u32 index = d - dir->directory_vector;
  char *n = (char *)format (0, "%s%c", filename, 0);
  assert (n);

  if (!dir->directory_vector_by_name)
    {
      dir->directory_vector_by_name = hash_create_string (0, sizeof (uword));
      assert (dir->directory_vector_by_name);
    }
  hash_set (dir->directory_vector_by_name, n, index);
  d->name = n;
  d->type = type;

  return d;
}

static cdb_inode_t *
cdb_create_root (void)
{
  cdb_inode_t *root = clib_mem_alloc (sizeof (*root));
  clib_memset(root, 0, sizeof(*root));
  root->type = CDB_INODE_TYPE_DIR;
  root->directory_vector = 0;
  root->directory_vector_by_name = 0;
  return root;
}

u32 cdb_init (char *name)
{
  cdb_db_t *fs;

  pool_get(cdbpool, fs);
  clib_spinlock_init (&fs->lockp);
  fs->root = cdb_create_root ();
  fs->name = (char *)format(0, "%s%c", name, 0);
  return fs - cdbpool;
}

static void cdb_notify (cdb_db_t *db, cdb_inode_t *dir, u32 index)
{
  cdb_subscriber_fn **f;

  vec_foreach(f, dir->subscribers) {
    (*f)(dir->data, 1, index);
  }
  if (dir->parent) {
    cdb_inode_t *d = cdb_lookup(db, dir->parent);
    if (d) {
      cdb_notify(db, d, index);
    }
  }
}

cdb_db_t *cdb_get_cdb(u32 index) {
  return pool_elt_at_index(cdbpool, index);
}

void cdb_notify_path (u32 index, char *path)
{
  cdb_db_t *db = pool_elt_at_index(cdbpool, index);
  cdb_inode_t *dir = cdb_lookup(db, path);
  if (dir)
    cdb_notify(db, dir, 0);
}

void
cdb_add (u32 index, char *path, void *data, u32 size, cdb_format_fn *format)
{
  cdb_db_t *db = pool_elt_at_index(cdbpool, index);

  /* Add entry to database */
  cdb_inode_t *dir = cdb_lookup(db, path);
  if (!dir) {
    int rv = cdb_mkdir(db, path);
    assert(rv == 0);
    dir = cdb_lookup(db, path);
  }
  assert(dir);

  vec_add(dir->data, data, size);
  dir->type = CDB_INODE_TYPE_POINTER;
  dir->format = format;
  /* Call interested parties */
  cdb_notify(db, dir, (vec_len(dir->data)/size) - 1);
}

void cdb_subscribe(u32 index, char *path, cdb_subscriber_fn *f)
{
  cdb_db_t *db = pool_elt_at_index(cdbpool, index);
  cdb_inode_t *dir = cdb_lookup(db, path);
  if (!dir) {
    cdb_mkdir(db, path);
    dir = cdb_lookup(db, path);
  }
  vec_add1(dir->subscribers, f);
}
