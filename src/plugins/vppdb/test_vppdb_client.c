#include <assert.h>
#include <stddef.h>
#include "vppdb_client.h"

static void
test_walktree (ds_inode_t *root)
{
  ds_inode_t *d;
  static int level;
  ds_inode_t *vector = ds_pointer_adjust(root->directory_vector);
  u32 *indexes = 0;
  int i, j;
  pool_foreach_index(i, vector,
	       ({
		 vec_add1(indexes, i);
	       }));

  for (j = 0; j < vec_len(indexes); j++) {
    d = &vector[indexes[j]];
    char *name = ds_pointer_adjust(d->name);
    switch (d->type) {
    case DS_INODE_TYPE_DIR:
      printf("%*s%s\n", 2*level, " ", name);
      level++;
      test_walktree(d);
      level--;
      break;
    case DS_INODE_TYPE_INLINE:
      printf("%*s%s %lu (inline)\n", 2*level, " ", name, d->value);
      break;
    case DS_INODE_TYPE_POINTER:
      printf("%*s%s (pointer)\n", 2*level, " ", name);
      break;
    default:
      printf("%*s%s (unknown)\n", 2*level, " ", name);
    }
  }
  vec_free(indexes);
}

ds_main_t ds_main;

static void test_client(void)
{
  ds_main_t *dsm = &ds_main;

  size_t memory_size;
  void *memaddr;
  int rv = ds_client_map_init("\0test_vppdb", &memaddr, &memory_size);
  assert(rv == 0);
  printf("CHILD: Connecting to shared memory at: %p\n", memaddr);

  ds_segment_shared_header_t *shared_header_client = memaddr;
  assert(shared_header_client->version == 123);
  printf("VERSION: %lu\n", shared_header_client->version);
  printf("BASE: %p %p\n", (void *)shared_header_client->base, memaddr);
  intptr_t offset = memaddr - (void *)shared_header_client->base;
  ptrdiff_t diff = memaddr - (void *)shared_header_client->base;
  printf("p2-p1 = %td %lx\n", diff, diff);
  ds_set_offset(memaddr - (void *)shared_header_client->base);
  printf("OFFSET: %lx\n", offset);
  //printf("ROOT CHILD %p\n", (void *)offset + (intptr_t)shared_header_client->root);

  dsm->base = memaddr;
  dsm->memory_size = memory_size;

  //  sleep(1);
  //test_walktree(shared_header_client->root);
  //ds_inode_t *root = (ds_inode_t *)((intptr_t)shared_header_client->root + offset);
  int count = 100;
  int i;
  ds_inode_t *d;
  int preempt = 0;
  for (i=0; i < count; i++) {
    rv = ds_client_lookup(&shared_header_client->fs.root, "/err0", &d);
    //assert(rv == 0);
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
  test_walktree(ds_pointer_adjust(shared_header_client->root));
  printf("Pre-empted: %d %f\n", preempt, (double)(100*preempt)/count);
}

int main (void)
{
  /* Create a heap of 64MB */
  clib_mem_init (0, 64 << 20);

  test_client();
}
