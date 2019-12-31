
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "vppdb.h"
#include "vppdb_inlines.h"

/*
 *  Used only by VPP writers
 */
void ds_lock (ds_directory_t *d)
{
  assert (d);
  clib_spinlock_lock (&d->lockp);
  d->in_progress = 1;
}

void ds_unlock (ds_directory_t *d)
{
  assert (d);
  d->epoch++;
  d->in_progress = 0;
  clib_spinlock_unlock (&d->lockp);
}

/*
 * Create a new directory node
 */
int ds_mkdir (ds_directory_t *fs, const char *pathname)
{
  char **p;
  hash_pair_t *hp;
  int rv = 0;
  assert (fs);
  assert (pathname);

  /* Split path into individual elements */
  char **paths = split_path (pathname);
  ds_lock (fs);
  ds_inode_t *dir = fs->root;
  vec_foreach (p, paths)
  {
    hp = hash_get_pair (dir->directory_vector_by_name, *p);
    if (!hp)
      {
        if (!dir->directory_vector_by_name)
          {
            dir->directory_vector_by_name =
                hash_create_string (0, sizeof (uword));
          }

        ds_inode_t *d;
        pool_get_zero (dir->directory_vector, d);
        u32 index = d - dir->directory_vector;
        char *n = (char *)format (0, "%s%c", *p, 0);
        hash_set (dir->directory_vector_by_name, n, index);
        d->name = n;
        dir = d;
      }
    else
      {
        dir = &dir->directory_vector[hp->value[0]];
        if (dir->type != DS_INODE_TYPE_DIR)
          {
            rv = -1;
            break;
          }
      }
  }
  ds_unlock (fs);
  split_path_free (paths);
  return rv;
}

/*
 * Look up a path in the directory hierarchy
 */
ds_inode_t *ds_lookup (ds_directory_t *fs, const char *pathname)
{
  hash_pair_t *hp;
  int i;

  assert (fs);
  assert (pathname);

  /* Split path into individual elements */
  char **paths = split_path (pathname);
  ds_lock (fs);
  ds_inode_t *dir = fs->root;
  vec_foreach_index (i, paths)
  {
    hp = hash_get_pair (dir->directory_vector_by_name, paths[i]);
    if (!hp)
      {
        dir = 0;
        break;
      }
    dir = &dir->directory_vector[hp->value[0]];
    if (dir->type != DS_INODE_TYPE_DIR)
      {
        if (i != vec_len (paths) - 1)
          {
            dir = 0;
          }
        break;
      }
  }
  ds_unlock (fs);
  split_path_free (paths);
  return dir;
}

/*
 * Create a leaf
 */
ds_inode_t *ds_create (ds_inode_t *dir, char *filename, ds_inode_type_t type)
{
  assert (dir);
  assert (filename);

  ds_inode_t *d;
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

static ds_inode_t *vppdb_create_root (void)
{
  ds_inode_t *root = clib_mem_alloc (sizeof (*root));
  root->type = DS_INODE_TYPE_DIR;
  root->directory_vector = 0;
  root->directory_vector_by_name = 0;
  return root;
}

void vppdb_init (ds_directory_t *fs)
{
  clib_spinlock_init (&fs->lockp);
  fs->epoch = 0;
  fs->in_progress = 0;
  fs->root = vppdb_create_root ();
}
