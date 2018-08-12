/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include "lpm.h"
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <arpa/inet.h>
#include <vnet/ip/format.h>

static uint32_t
masked_address32 (uint32_t addr, uint8_t len)
{
  u32 a = ntohl(addr);
  return htonl(len == 32 ? a : a & ~(~0u >> len));
}
static uint64_t
masked_address64 (uint64_t addr, uint8_t len)
{
  return len == 64 ? addr : addr & ~(~0ull >> len);
}

static void
lpm_32_add (lpm_t *lpm, void *addr_v, u8 pfxlen,
	    u32 value)
{
  uword * hash, * result;
  u32 key;
  ip4_address_t *addr = addr_v;
  key = masked_address32(addr->data_u32, pfxlen);
  hash = lpm->hash[pfxlen];
  result = hash_get (hash, key);
  if (result) /* Entry exists */
    clib_warning("%U/%d already exists in table for domain %d",
		 format_ip4_address, addr, pfxlen, result[0]);

  /*
   * adding a new entry
   */
  if (hash == NULL) {
    hash = hash_create (32 /* elts */, sizeof (uword));
    hash_set_flags (hash, HASH_FLAG_NO_AUTO_SHRINK);
  }
  hash = hash_set(hash, key, value);
  lpm->hash[pfxlen] = hash;
}

static void
lpm_32_delete (lpm_t *lpm, void *addr_v, u8 pfxlen)
{
  uword * hash, * result;
  u32 key;
  ip4_address_t *addr = addr_v;
  key = masked_address32(addr->data_u32, pfxlen);
  hash = lpm->hash[pfxlen];
  result = hash_get (hash, key);
  if (result)
    hash_unset(hash, key);
  lpm->hash[pfxlen] = hash;
}

static u32
lpm_32_lookup (lpm_t *lpm, void *addr_v, u8 pfxlen)
{
  uword * hash, * result;
  i32 mask_len;
  u32 key;
  ip4_address_t *addr = addr_v;
  for (mask_len = pfxlen; mask_len >= 0; mask_len--) {
    hash = lpm->hash[mask_len];
    if (hash) {
      key = masked_address32(addr->data_u32, mask_len);
      result = hash_get (hash, key);
      if (result != NULL) {
	return (result[0]);
      }
    }
  }
  return (~0);
}

static int
lpm_128_lookup_core (lpm_t *lpm, ip6_address_t *addr, u8 pfxlen, u32 *value)
{
  BVT(clib_bihash_kv) kv, v;
  int rv;
  kv.key[0] = masked_address64(addr->as_u64[0], pfxlen > 64 ? 64 : pfxlen);
  kv.key[1] = masked_address64(addr->as_u64[1], pfxlen > 64 ? pfxlen - 64 : 0);
  kv.key[2] = pfxlen;
  rv = BV(clib_bihash_search_inline_2)(&lpm->bihash, &kv, &v);
  if (rv != 0)
    return -1;
  *value = v.value;
  return 0;
}

static u32
lpm_128_lookup (lpm_t *lpm, void *addr_v, u8 pfxlen)
{
  ip6_address_t *addr = addr_v;
  int i = 0, rv;
  u32 value;
  clib_bitmap_foreach (i, lpm->prefix_lengths_bitmap,
    ({
      rv = lpm_128_lookup_core(lpm, addr, i, &value);
      if (rv == 0)
	return value;
    }));
  return ~0;
}

static void
lpm_128_add (lpm_t *lpm, void *addr_v, u8 pfxlen, u32 value)
{
  BVT(clib_bihash_kv) kv;
  ip6_address_t *addr = addr_v;

  kv.key[0] = masked_address64(addr->as_u64[0], pfxlen > 64 ? 64 : pfxlen);
  kv.key[1] = masked_address64(addr->as_u64[1], pfxlen > 64 ? pfxlen - 64 : 0);
  kv.key[2] = pfxlen;
  kv.value = value;
  BV(clib_bihash_add_del)(&lpm->bihash, &kv, 1);
  lpm->prefix_length_refcount[pfxlen]++;
  lpm->prefix_lengths_bitmap = clib_bitmap_set (lpm->prefix_lengths_bitmap, 128 - pfxlen, 1);
}

static void
lpm_128_delete (lpm_t *lpm, void *addr_v, u8 pfxlen)
{
  ip6_address_t *addr = addr_v;
  BVT(clib_bihash_kv) kv;
  kv.key[0] = masked_address64(addr->as_u64[0], pfxlen > 64 ? 64 : pfxlen);
  kv.key[1] = masked_address64(addr->as_u64[1], pfxlen > 64 ? pfxlen - 64 : 0);
  kv.key[2] = pfxlen;
  BV(clib_bihash_add_del)(&lpm->bihash, &kv, 0);

  /* refcount accounting */
  ASSERT (lpm->prefix_length_refcount[pfxlen] > 0);
  if (--lpm->prefix_length_refcount[pfxlen] == 0) {
    lpm->prefix_lengths_bitmap = clib_bitmap_set (lpm->prefix_lengths_bitmap, 
						  128 - pfxlen, 0);
  }
}

lpm_t *
lpm_table_init (enum lpm_type_e lpm_type)
{
  lpm_t * lpm = clib_mem_alloc(sizeof(*lpm));
  memset(lpm, 0, sizeof(*lpm));

  switch (lpm_type) {
  case LPM_TYPE_KEY32:
    lpm->add = lpm_32_add;
    lpm->delete = lpm_32_delete;
    lpm->lookup = lpm_32_lookup;
    break;
  case LPM_TYPE_KEY128:
    lpm->add = lpm_128_add;
    lpm->delete = lpm_128_delete;
    lpm->lookup = lpm_128_lookup;
    /* Make bihash sizes configurable */
    BV (clib_bihash_init) (&(lpm->bihash),
			   "LPM 128", 64*1024, 32<<20);

    break;
  default:
    ASSERT(0);
  }
  return lpm;
}
