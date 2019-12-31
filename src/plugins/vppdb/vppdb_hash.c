#include <assert.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>
#include "vppdb_client.h"

void
assert_pointer(void *p)
{
  ds_main_t *dsm = &ds_main;
  if (p) {
    assert(p >= dsm->base && p <= (dsm->base + dsm->memory_size));
  }
}

always_inline hash_pair_union_t *
get_pair (void *v, uword i)
{
  hash_t *h = hash_header (v);
  hash_pair_t *p;
  ASSERT (i < vec_len (v));
  p = v;
  p += i << h->log2_pair_size;
  assert_pointer(p);
  return (hash_pair_union_t *) p;
}

uword
ds_string_key_sum (hash_t * h, uword key)
{
  char *v = uword_to_pointer (key, char *);
  assert(v);
  //assert_pointer(v); //KEY is not in shared memory segment */
  return hash_memory (v, strlen (v), 0);
}


static uword
ds_string_key_equal (hash_t * h, uword key1, uword key2)
{
  void *v1 = uword_to_pointer (key1, void *);
  void *v2 = uword_to_pointer (key2, void *);
  assert(v1 && v2);
  v1 = ds_pointer_adjust(v1);
  assert_pointer(v1);
  //assert_pointer(v2); /* That's the key from outside */
  return v1 && v2 && 0 == strcmp (v1, v2);
}


static hash_pair_union_t *
get_indirect (void *v, hash_pair_indirect_t * pi, uword key)
{
  hash_t *h = hash_header (v);
  hash_pair_t *p0, *p1;

  p0 = p1 = pi->pairs;
  if (h->log2_pair_size > 0)
    p1 = hash_forward (h, p0, indirect_pair_get_len (pi));
  else
    p1 += vec_len (p0);
  assert_pointer(p0);
  assert_pointer(p1);
  while (p0 < p1)
    {
      if (ds_string_key_equal (h, p0->key, key))
	return (hash_pair_union_t *) p0;
      p0 = hash_forward1 (h, p0);
    }

  return (hash_pair_union_t *) 0;
}

hash_pair_t *
vppdb_lookup (void *v, uword key)
{
  v = ds_pointer_adjust(v);
  hash_t *h = hash_header (v);
  hash_pair_union_t *p = 0;
  uword found_key = 0;
  uword i;

  if (!v)
    return 0;

  assert_pointer(v);
  i = ds_string_key_sum (h, key) & (_vec_len (v) - 1);
  p = get_pair (v, i);
  assert_pointer(p);

  if (hash_is_user (v, i))
    {
      found_key = ds_string_key_equal (h, p->direct.key, key);
      if (!found_key)
	p = 0;
    }
  else
    {
      hash_pair_indirect_t *pi = &p->indirect;

      p = get_indirect (v, pi, key);
      found_key = p != 0;
    }

  return &p->direct;
}
