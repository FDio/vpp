#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <vppinfra/mem.h>
#include "vppdb.h"
#include "vppdb_client.h"

#if 0
static void
test_walktree (ds_inode_t *root)
{
  ds_inode_t *d;
  static int level;
  pool_foreach(d, root->directory_vector,
	       ({
		 switch (d->type) {
		 case DS_INODE_TYPE_DIR:
		   printf("%*s%s\n", 2*level, " ", d->name);
		   level++;
		   test_walktree(d);
		   level--;
		   break;
		 case DS_INODE_TYPE_INLINE:
		   printf("%*s%s %lu (inline)\n", 2*level, " ", d->name, d->value);
		   break;
		 case DS_INODE_TYPE_POINTER:
		   printf("%*s%s (pointer)\n", 2*level, " ", d->name);
		   break;
		 default:
		   printf("%*s%s (unknown)\n", 2*level, " ", d->name);
		 }
	       }));
}
  
#endif

static void
test_mkdir (ds_directory_t *fs)
{
  assert(ds_mkdir(fs, "/sys/foobar/") == 0);
  assert(ds_mkdir(fs, "/sys/foobar") == 0);
  assert(ds_mkdir(fs, "/sys/bar") == 0);
  assert(ds_mkdir(fs, "/bar") == 0);
  printf("Testing creating path %s\n", "/sys/foobar/");

  ds_inode_t *d = ds_lookup(fs, "/sys");
  assert(d);
}

#if 0
static void
test_create (ds_inode_t *root)
{
  ds_inode_t *dir = ds_lookup(root, "/sys22");
  assert(!dir);
  dir = ds_lookup(root, "/sys");
  assert(dir);

  ds_inode_t *d = ds_create(dir, "error_counter", DS_INODE_TYPE_INLINE);
  assert(d);
  d = ds_create(dir, "error_counter_two", DS_INODE_TYPE_INLINE);
  d->value = 1234;
  assert(strcmp((const char *)d->name, "error_counter_two") == 0);
  assert(ds_mkdir(root, "/sys/error_counter/foobar") == -1);
  test_walktree(root);
}

static void
test_add_value (ds_inode_t *root)
{
  u64 **counters = 0; 
  int i;
  int index = 40;

  vec_validate (counters, 5);
  for (i = 0; i < 5; i++)
    vec_validate (counters[i], index);

  /* Add to directory */
  ds_inode_t *dir = ds_lookup(root, "/err");
  if (!dir)
    ds_mkdir(root, "/err");
  dir = ds_lookup(root, "/err");
  assert(dir);  
  ds_inode_t *d = ds_create(dir, "error_counter", DS_INODE_TYPE_POINTER);
  d->data = counters;
}

static void
test_check_value (ds_inode_t *root)
{
  ds_inode_t *d = ds_lookup(root, "/err/error_counter");
  assert(d);
  u64 *p = d->data;
  printf("Counter length: %d %d\n", vec_len(d->data), vec_len(p[0]));
  //u64 counter = (u64)d->data[0][0];
  d = ds_lookup(root, "/err/");
  assert(d);

}

void *writer_func(void *args)
{
  ds_inode_t *root = args;

  int i;
  u8 *n = 0;
  for (i=0; i < 100; i++) {
    n = format(0, "/err%d", i);
    assert(ds_mkdir(root, (char *)n) == 0);
    vec_reset_length(n);
  }
  vec_free(n);
  return 0;
}
#endif
#if 0
void *reader_func(void *args)
{
  ds_inode_t *root = args, *d;
  int i;
  int rv;
  int preempt = 0;
  int count = 100;
  for (i=0; i < count; i++) {
    rv = ds_client_lookup(root, "/err/", &d);
    if (rv == -4) {
      printf("Pre-empted by SUPER writer %d\n", i);
      preempt++;
      continue;
    }
    if (rv == -3) {
      printf("Pre-empted by NEW writer %d\n", i);
      preempt++;
      continue;
    }
    assert(d);
  }
  printf("Pre-empted: %d %f\n", preempt, (double)(100*preempt)/count);
  return 0;
}

static void
test_concurrent_directory (ds_inode_t *root)
{
  pthread_t writer, reader;

  assert(pthread_create(&writer, 0, writer_func, root) == 0);
  assert(pthread_create(&reader, 0, reader_func, root) == 0);

  // Create writer thread
  // Ensure root directory expands so it moves in memory
  
  // Create reader thread


  assert(pthread_join(writer, NULL) == 0);
  assert(pthread_join(reader, NULL) == 0);
}
#endif
int main (int argc, char **argv)
{


  /* Create a heap of 64MB */
  clib_mem_init (0, 64 << 20);
  ds_directory_t d;
  vppdb_init(&d);

  test_mkdir(&d);
#if 0
  test_create(d);

  test_add_value(d.root);
  test_walktree(d.root);
  test_check_value(d.root);
#endif
  //  test_concurrent_directory(root);

  // lsdir
  //assert(ds_lsdir("/") == 0);

  // Absolute vs relative paths?
  // ds_rmdir
  //

  // performance tests
  // offsets for shared memory support
  // attach arbitrary data structures
  // symlink (directly into another data structure???
  // locking
  // caching (by clients)
}
