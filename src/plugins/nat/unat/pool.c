#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip.h>
#include "pool.h"
#include "unat.h"
#include "lpm.h"

/*
 * Generic prefix pool
 *
 * Create a new pool (prefix)
 * Lookup in a prefix in a pool
 * Get address from pool (adj load balancing algorithm)
 * (ip4_compute_flow_hash (ip0, lb0->lb_hash_config);)
 * Support just a single pool at the moment.
 */


/*
 * Function to create pool as a subset. Take "psid" as input.
 *
 *
 */

unat_pool_t *pools;
lpm_t *pools_lpm;

#define PSID_OFFSET 0

static void
address_normalize (ip4_address_t * ip4, u8 preflen)
{
  ASSERT (preflen <= 32);
  if (preflen == 0)
    ip4->data_u32 = 0;
  else
    ip4->data_u32 &= clib_net_to_host_u32 (0xffffffff << (32 - preflen));
}

u32
pool_add_addr_pool (ip4_address_t * prefix, u8 prefixlen,
		    u8 psid_length, u16 psid, u32 vrf_id, u32 thread_index)
{
  unat_pool_t *p;
  pool_get(pools, p);

  if (pools_lpm == 0)
    pools_lpm = lpm_table_init (LPM_TYPE_KEY32);

  /* Must have at least one address */
  /* Ensure psid can be represented in psid_length bits */
  if (prefixlen > 32 ||
      psid_length > 16 ||
      (psid > (0x1 << psid_length)))
    return ~0;

  /* Port sharing */
  if (prefixlen == 32 && psid_length > 0) {
    u16 lshift = 16 - PSID_OFFSET - psid_length;
    p->psid = psid << lshift;
    p->psid_length = psid_length;
    p->psid_mask = ((1 << psid_length) - 1) << lshift;
  }
  address_normalize (prefix, prefixlen);
  p->vrf_id = vrf_id;
  p->prefix.as_u32 = prefix->as_u32;
  p->prefixlen = prefixlen;

  p->count = prefixlen > 0 ? 0x1 << (32 - prefixlen) : 0;
  p->thread_index = thread_index;

  u32 index = pools_lpm->lookup(pools_lpm, prefix, 32);
  if (index != ~0)
    pools_lpm->add(pools_lpm, prefix, prefixlen, p - pools);

  return p - pools;
}

void
pool_del_addr_pool (u32 poolindex)
{
  unat_pool_t *p = pool_elt_at_index(pools, poolindex);

  u32 index = pools_lpm->lookup(pools_lpm, &p->prefix, 32);
  if (index != ~0)
    pools_lpm->delete(pools_lpm, &p->prefix, p->prefixlen);
  pool_put(pools, p);
}

bool
unat_is_pool_address (ip4_address_t *a)
{
  u32 index = pools_lpm->lookup(pools_lpm, a, 32);
  return index == ~0 ? false : true;
}

unat_pool_t *
unat_pool_get (u32 index)
{
  return pool_elt_at_index(pools, index);
}

u32
unat_pool_len (void)
{
  return pool_elts(pools);
}

u8 *
format_unat_pool (u8 * s, va_list * args)
{
  unat_pool_t *p = va_arg (*args, unat_pool_t *);

  s = format (s, "%U/%u%%%u @ worker %u", format_ip4_address, &p->prefix, p->prefixlen, p->vrf_id, p->thread_index);
  if (p->psid_length > 0) {
    u16 rshift = 16 - PSID_OFFSET - p->psid_length;
    s = format (s, "\n    PSID: %u PSID Length: %u", p->psid >> rshift, p->psid_length);
  }
  s = format (s, "\n");
  return s;
}


