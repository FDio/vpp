/*
  Copyright (c) 2013 Cisco and/or its affiliates.

  * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <vppinfra/pfhash.h>
#include <vppinfra/format.h>

/* This is incredibly handy when debugging */
u32 vl (void *v) __attribute__ ((weak));
u32
vl (void *v)
{
  return vec_len (v);
}

#if defined(CLIB_HAVE_VEC128) && ! defined (__ALTIVEC__)

typedef struct
{
  u8 *key[16];
  u64 value;
} pfhash_show_t;

static int
sh_compare (pfhash_show_t * sh0, pfhash_show_t * sh1)
{
  return ((i32) (sh0->value) - ((i32) sh1->value));
}

u8 *
format_pfhash (u8 * s, va_list * args)
{
  pfhash_t *p = va_arg (*args, pfhash_t *);
  int verbose = va_arg (*args, int);

  if (p == 0 || p->overflow_hash == 0 || p->buckets == 0)
    {
      s = format (s, "*** uninitialized ***");
      return s;
    }

  s = format (s, "Prefetch hash '%s'\n", p->name);
  s =
    format (s, " %d buckets, %u bucket overflows, %.1f%% bucket overflow \n",
	    vec_len (p->buckets), p->overflow_count,
	    100.0 * ((f64) p->overflow_count) / ((f64) vec_len (p->buckets)));
  if (p->nitems)
    s =
      format (s,
	      "  %u items, %u items in overflow, %.1f%% items in overflow\n",
	      p->nitems, p->nitems_in_overflow,
	      100.0 * ((f64) p->nitems_in_overflow) / ((f64) p->nitems));

  if (verbose)
    {
      pfhash_show_t *shs = 0, *sh;
      hash_pair_t *hp;
      int i, j;

      for (i = 0; i < vec_len (p->buckets); i++)
	{
	  pfhash_kv_t *kv;
	  pfhash_kv_16_t *kv16;
	  pfhash_kv_8_t *kv8;
	  pfhash_kv_8v8_t *kv8v8;
	  pfhash_kv_4_t *kv4;

	  if (p->buckets[i] == 0 || p->buckets[i] == PFHASH_BUCKET_OVERFLOW)
	    continue;

	  kv = pool_elt_at_index (p->kvp, p->buckets[i]);

	  switch (p->key_size)
	    {
	    case 16:
	      kv16 = &kv->kv16;
	      for (j = 0; j < 3; j++)
		{
		  if (kv16->values[j] != (u32) ~ 0)
		    {
		      vec_add2 (shs, sh, 1);
		      clib_memcpy (sh->key, &kv16->kb.k_u32x4[j],
				   p->key_size);
		      sh->value = kv16->values[j];
		    }
		}
	      break;
	    case 8:
	      if (p->value_size == 4)
		{
		  kv8 = &kv->kv8;
		  for (j = 0; j < 5; j++)
		    {
		      if (kv8->values[j] != (u32) ~ 0)
			{
			  vec_add2 (shs, sh, 1);
			  clib_memcpy (sh->key, &kv8->kb.k_u64[j],
				       p->key_size);
			  sh->value = kv8->values[j];
			}
		    }
		}
	      else
		{
		  kv8v8 = &kv->kv8v8;
		  for (j = 0; j < 4; j++)
		    {
		      if (kv8v8->values[j] != (u64) ~ 0)
			{
			  vec_add2 (shs, sh, 1);
			  clib_memcpy (sh->key, &kv8v8->kb.k_u64[j],
				       p->key_size);
			  sh->value = kv8v8->values[j];
			}
		    }

		}
	      break;
	    case 4:
	      kv4 = &kv->kv4;
	      for (j = 0; j < 8; j++)
		{
		  if (kv4->values[j] != (u32) ~ 0)
		    {
		      vec_add2 (shs, sh, 1);
		      clib_memcpy (sh->key, &kv4->kb.kb[j], p->key_size);
		      sh->value = kv4->values[j];
		    }
		}
	      break;
	    }
	}

      /* *INDENT-OFF* */
      hash_foreach_pair (hp, p->overflow_hash,
      ({
        vec_add2 (shs, sh, 1);
        clib_memcpy (sh->key, (u8 *)hp->key, p->key_size);
        sh->value = hp->value[0];
      }));
      /* *INDENT-ON* */

      vec_sort_with_function (shs, sh_compare);

      for (i = 0; i < vec_len (shs); i++)
	{
	  sh = vec_elt_at_index (shs, i);
	  s = format (s, " %U value %u\n", format_hex_bytes, sh->key,
		      p->key_size, sh->value);
	}
      vec_free (shs);
    }
  return s;
}


void abort (void);

void
pfhash_init (pfhash_t * p, char *name, u32 key_size, u32 value_size,
	     u32 nbuckets)
{
  pfhash_kv_t *kv;
  memset (p, 0, sizeof (*p));
  u32 key_bytes;

  switch (key_size)
    {
    case 4:
      key_bytes = 4;
      break;
    case 8:
      key_bytes = 8;
      break;
    case 16:
      key_bytes = 16;
      break;
    default:
      ASSERT (0);
      abort ();
    }

  switch (value_size)
    {
    case 4:
    case 8:
      break;
    default:
      ASSERT (0);
      abort ();
    }


  p->name = format (0, "%s", name);
  vec_add1 (p->name, 0);
  p->overflow_hash = hash_create_mem (0, key_bytes, sizeof (uword));

  nbuckets = 1 << (max_log2 (nbuckets));

  /* This sets the entire bucket array to zero */
  vec_validate (p->buckets, nbuckets - 1);
  p->key_size = key_size;
  p->value_size = value_size;

  /*
   * Unset buckets implicitly point at the 0th pool elt.
   * All search routines will return ~0 if they go there.
   */
  pool_get_aligned (p->kvp, kv, 16);
  memset (kv, 0xff, sizeof (*kv));
}

static pfhash_kv_16_t *
pfhash_get_kv_16 (pfhash_t * p, u32 bucket_contents,
		  u32x4 * key, u32 * match_index)
{
  u32x4 diff[3];
  u32 is_equal[3];
  pfhash_kv_16_t *kv = 0;

  *match_index = (u32) ~ 0;

  kv = &p->kvp[bucket_contents].kv16;

  diff[0] = u32x4_sub (kv->kb.k_u32x4[0], key[0]);
  diff[1] = u32x4_sub (kv->kb.k_u32x4[1], key[0]);
  diff[2] = u32x4_sub (kv->kb.k_u32x4[2], key[0]);

  is_equal[0] = u32x4_zero_byte_mask (diff[0]) == 0xffff;
  is_equal[1] = u32x4_zero_byte_mask (diff[1]) == 0xffff;
  is_equal[2] = u32x4_zero_byte_mask (diff[2]) == 0xffff;

  if (is_equal[0])
    *match_index = 0;
  if (is_equal[1])
    *match_index = 1;
  if (is_equal[2])
    *match_index = 2;

  return kv;
}

static pfhash_kv_8_t *
pfhash_get_kv_8 (pfhash_t * p, u32 bucket_contents,
		 u64 * key, u32 * match_index)
{
  pfhash_kv_8_t *kv;

  *match_index = (u32) ~ 0;

  kv = &p->kvp[bucket_contents].kv8;

  if (kv->kb.k_u64[0] == key[0])
    *match_index = 0;
  if (kv->kb.k_u64[1] == key[0])
    *match_index = 1;
  if (kv->kb.k_u64[2] == key[0])
    *match_index = 2;
  if (kv->kb.k_u64[3] == key[0])
    *match_index = 3;
  if (kv->kb.k_u64[4] == key[0])
    *match_index = 4;

  return kv;
}

static pfhash_kv_8v8_t *
pfhash_get_kv_8v8 (pfhash_t * p,
		   u32 bucket_contents, u64 * key, u32 * match_index)
{
  pfhash_kv_8v8_t *kv;

  *match_index = (u32) ~ 0;

  kv = &p->kvp[bucket_contents].kv8v8;

  if (kv->kb.k_u64[0] == key[0])
    *match_index = 0;
  if (kv->kb.k_u64[1] == key[0])
    *match_index = 1;
  if (kv->kb.k_u64[2] == key[0])
    *match_index = 2;
  if (kv->kb.k_u64[3] == key[0])
    *match_index = 3;

  return kv;
}

static pfhash_kv_4_t *
pfhash_get_kv_4 (pfhash_t * p, u32 bucket_contents,
		 u32 * key, u32 * match_index)
{
  u32x4 vector_key;
  u32x4 is_equal[2];
  u32 zbm[2], winner_index;
  pfhash_kv_4_t *kv;

  *match_index = (u32) ~ 0;

  kv = &p->kvp[bucket_contents].kv4;

  vector_key = u32x4_splat (key[0]);

  is_equal[0] = u32x4_is_equal (kv->kb.k_u32x4[0], vector_key);
  is_equal[1] = u32x4_is_equal (kv->kb.k_u32x4[1], vector_key);
  zbm[0] = ~u32x4_zero_byte_mask (is_equal[0]) & 0xFFFF;
  zbm[1] = ~u32x4_zero_byte_mask (is_equal[1]) & 0xFFFF;

  if (PREDICT_FALSE ((zbm[0] == 0) && (zbm[1] == 0)))
    return kv;

  winner_index = min_log2 (zbm[0]) >> 2;
  winner_index = zbm[1] ? (4 + (min_log2 (zbm[1]) >> 2)) : winner_index;

  *match_index = winner_index;
  return kv;
}

static pfhash_kv_t *
pfhash_get_internal (pfhash_t * p, u32 bucket_contents,
		     void *key, u32 * match_index)
{
  pfhash_kv_t *kv = 0;

  switch (p->key_size)
    {
    case 16:
      kv =
	(pfhash_kv_t *) pfhash_get_kv_16 (p, bucket_contents, key,
					  match_index);
      break;
    case 8:
      if (p->value_size == 4)
	kv = (pfhash_kv_t *) pfhash_get_kv_8 (p, bucket_contents,
					      key, match_index);
      else
	kv = (pfhash_kv_t *) pfhash_get_kv_8v8 (p, bucket_contents,
						key, match_index);
      break;
    case 4:
      kv =
	(pfhash_kv_t *) pfhash_get_kv_4 (p, bucket_contents, key,
					 match_index);
      break;
    default:
      ASSERT (0);
    }
  return kv;
}

u64
pfhash_get (pfhash_t * p, u32 bucket, void *key)
{
  pfhash_kv_t *kv;
  u32 match_index = ~0;
  pfhash_kv_16_t *kv16;
  pfhash_kv_8_t *kv8;
  pfhash_kv_8v8_t *kv8v8;
  pfhash_kv_4_t *kv4;

  u32 bucket_contents = pfhash_read_bucket_prefetch_kv (p, bucket);

  if (bucket_contents == PFHASH_BUCKET_OVERFLOW)
    {
      uword *hp;

      hp = hash_get_mem (p->overflow_hash, key);
      if (hp)
	return hp[0];
      return (u64) ~ 0;
    }

  kv = pfhash_get_internal (p, bucket_contents, key, &match_index);
  if (match_index == (u32) ~ 0)
    return (u64) ~ 0;

  kv16 = (void *) kv;
  kv8 = (void *) kv;
  kv4 = (void *) kv;
  kv8v8 = (void *) kv;

  switch (p->key_size)
    {
    case 16:
      return (kv16->values[match_index] == (u32) ~ 0)
	? (u64) ~ 0 : (u64) kv16->values[match_index];
    case 8:
      if (p->value_size == 4)
	return (kv8->values[match_index] == (u32) ~ 0)
	  ? (u64) ~ 0 : (u64) kv8->values[match_index];
      else
	return kv8v8->values[match_index];
    case 4:
      return (kv4->values[match_index] == (u32) ~ 0)
	? (u64) ~ 0 : (u64) kv4->values[match_index];
    default:
      ASSERT (0);
    }
  return (u64) ~ 0;
}

void
pfhash_set (pfhash_t * p, u32 bucket, void *key, void *value)
{
  u32 bucket_contents = pfhash_read_bucket_prefetch_kv (p, bucket);
  u32 match_index = (u32) ~ 0;
  pfhash_kv_t *kv;
  pfhash_kv_16_t *kv16;
  pfhash_kv_8_t *kv8;
  pfhash_kv_8v8_t *kv8v8;
  pfhash_kv_4_t *kv4;
  int i;
  u8 *kcopy;

  if (bucket_contents == PFHASH_BUCKET_OVERFLOW)
    {
      hash_pair_t *hp;
      hp = hash_get_pair_mem (p->overflow_hash, key);
      if (hp)
	{
	  clib_warning ("replace value 0x%08x with value 0x%08x",
			hp->value[0], (u64) value);
	  hp->value[0] = (u64) value;
	  return;
	}
      kcopy = clib_mem_alloc (p->key_size);
      clib_memcpy (kcopy, key, p->key_size);
      hash_set_mem (p->overflow_hash, kcopy, value);
      p->nitems++;
      p->nitems_in_overflow++;
      return;
    }

  if (bucket_contents == 0)
    {
      pool_get_aligned (p->kvp, kv, 16);
      memset (kv, 0xff, sizeof (*kv));
      p->buckets[bucket] = kv - p->kvp;
    }
  else
    kv = pfhash_get_internal (p, bucket_contents, key, &match_index);

  kv16 = (void *) kv;
  kv8 = (void *) kv;
  kv8v8 = (void *) kv;
  kv4 = (void *) kv;

  p->nitems++;

  if (match_index != (u32) ~ 0)
    {
      switch (p->key_size)
	{
	case 16:
	  kv16->values[match_index] = (u32) (u64) value;
	  return;

	case 8:
	  if (p->value_size == 4)
	    kv8->values[match_index] = (u32) (u64) value;
	  else
	    kv8v8->values[match_index] = (u64) value;
	  return;

	case 4:
	  kv4->values[match_index] = (u64) value;
	  return;

	default:
	  ASSERT (0);
	}
    }

  switch (p->key_size)
    {
    case 16:
      for (i = 0; i < 3; i++)
	{
	  if (kv16->values[i] == (u32) ~ 0)
	    {
	      clib_memcpy (&kv16->kb.k_u32x4[i], key, p->key_size);
	      kv16->values[i] = (u32) (u64) value;
	      return;
	    }
	}
      /* copy bucket contents to overflow hash tbl */
      for (i = 0; i < 3; i++)
	{
	  kcopy = clib_mem_alloc (p->key_size);
	  clib_memcpy (kcopy, &kv16->kb.k_u32x4[i], p->key_size);
	  hash_set_mem (p->overflow_hash, kcopy, kv16->values[i]);
	  p->nitems_in_overflow++;
	}
      /* Add new key to overflow */
      kcopy = clib_mem_alloc (p->key_size);
      clib_memcpy (kcopy, key, p->key_size);
      hash_set_mem (p->overflow_hash, kcopy, value);
      p->buckets[bucket] = PFHASH_BUCKET_OVERFLOW;
      p->overflow_count++;
      p->nitems_in_overflow++;
      return;

    case 8:
      if (p->value_size == 4)
	{
	  for (i = 0; i < 5; i++)
	    {
	      if (kv8->values[i] == (u32) ~ 0)
		{
		  clib_memcpy (&kv8->kb.k_u64[i], key, 8);
		  kv8->values[i] = (u32) (u64) value;
		  return;
		}
	    }
	  /* copy bucket contents to overflow hash tbl */
	  for (i = 0; i < 5; i++)
	    {
	      kcopy = clib_mem_alloc (p->key_size);
	      clib_memcpy (kcopy, &kv8->kb.k_u64[i], 8);
	      hash_set_mem (p->overflow_hash, kcopy, kv8->values[i]);
	      p->nitems_in_overflow++;
	    }
	}
      else
	{
	  for (i = 0; i < 4; i++)
	    {
	      if (kv8v8->values[i] == (u64) ~ 0)
		{
		  clib_memcpy (&kv8v8->kb.k_u64[i], key, 8);
		  kv8v8->values[i] = (u64) value;
		  return;
		}
	    }
	  /* copy bucket contents to overflow hash tbl */
	  for (i = 0; i < 4; i++)
	    {
	      kcopy = clib_mem_alloc (p->key_size);
	      clib_memcpy (kcopy, &kv8v8->kb.k_u64[i], 8);
	      hash_set_mem (p->overflow_hash, kcopy, kv8v8->values[i]);
	      p->nitems_in_overflow++;
	    }

	}
      /* Add new key to overflow */
      kcopy = clib_mem_alloc (p->key_size);
      clib_memcpy (kcopy, key, p->key_size);
      hash_set_mem (p->overflow_hash, kcopy, value);
      p->buckets[bucket] = PFHASH_BUCKET_OVERFLOW;
      p->overflow_count++;
      p->nitems_in_overflow++;
      return;

    case 4:
      for (i = 0; i < 8; i++)
	{
	  if (kv4->values[i] == (u32) ~ 0)
	    {
	      clib_memcpy (&kv4->kb.kb[i], key, 4);
	      kv4->values[i] = (u32) (u64) value;
	      return;
	    }
	}
      /* copy bucket contents to overflow hash tbl */
      for (i = 0; i < 8; i++)
	{
	  kcopy = clib_mem_alloc (p->key_size);
	  clib_memcpy (kcopy, &kv4->kb.kb[i], 4);
	  hash_set_mem (p->overflow_hash, kcopy, kv4->values[i]);
	  p->nitems_in_overflow++;
	}
      /* Add new key to overflow */
      kcopy = clib_mem_alloc (p->key_size);
      clib_memcpy (kcopy, key, p->key_size);
      hash_set_mem (p->overflow_hash, kcopy, value);
      p->buckets[bucket] = PFHASH_BUCKET_OVERFLOW;
      p->overflow_count++;
      p->nitems_in_overflow++;
      return;

    default:
      ASSERT (0);
    }
}

void
pfhash_unset (pfhash_t * p, u32 bucket, void *key)
{
  u32 bucket_contents = pfhash_read_bucket_prefetch_kv (p, bucket);
  u32 match_index = (u32) ~ 0;
  pfhash_kv_t *kv;
  pfhash_kv_16_t *kv16;
  pfhash_kv_8_t *kv8;
  pfhash_kv_8v8_t *kv8v8;
  pfhash_kv_4_t *kv4;
  void *oldkey;

  if (bucket_contents == PFHASH_BUCKET_OVERFLOW)
    {
      hash_pair_t *hp;
      hp = hash_get_pair_mem (p->overflow_hash, key);
      if (hp)
	{
	  oldkey = (void *) hp->key;
	  hash_unset_mem (p->overflow_hash, key);
	  clib_mem_free (oldkey);
	  p->nitems--;
	  p->nitems_in_overflow--;
	}
      return;
    }

  kv = pfhash_get_internal (p, bucket_contents, key, &match_index);
  if (match_index == (u32) ~ 0)
    return;

  p->nitems--;

  kv16 = (void *) kv;
  kv8 = (void *) kv;
  kv8v8 = (void *) kv;
  kv4 = (void *) kv;

  switch (p->key_size)
    {
    case 16:
      kv16->values[match_index] = (u32) ~ 0;
      return;

    case 8:
      if (p->value_size == 4)
	kv8->values[match_index] = (u32) ~ 0;
      else
	kv8v8->values[match_index] = (u64) ~ 0;
      return;

    case 4:
      kv4->values[match_index] = (u32) ~ 0;
      return;

    default:
      ASSERT (0);
    }
}

void
pfhash_free (pfhash_t * p)
{
  hash_pair_t *hp;
  int i;
  u8 **keys = 0;

  vec_free (p->name);

  pool_free (p->kvp);

  /* *INDENT-OFF* */
  hash_foreach_pair (hp, p->overflow_hash,
  ({
    vec_add1 (keys, (u8 *)hp->key);
  }));
  /* *INDENT-ON* */
  hash_free (p->overflow_hash);
  for (i = 0; i < vec_len (keys); i++)
    vec_free (keys[i]);
  vec_free (keys);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
