#include <stddef.h>
#include <netinet/in.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/plugin/plugin.h>
#include <acl/acl.h>
#include "bihash_40_8.h"

#include <vppinfra/bihash_template.h>
/*
included in fa_node.c
#include <vppinfra/bihash_template.c>
*/

#include "hash_lookup.h"

void
hash_acl_apply(u32 sw_if_index, u8 is_input, int acl_index)
{
  clib_warning("HASH ACL apply: sw_if_index %d is_input %d acl %d", sw_if_index, is_input, acl_index);
}

void
hash_acl_unapply(u32 sw_if_index, u8 is_input, int acl_index)
{
  clib_warning("HASH ACL unapply: sw_if_index %d is_input %d acl %d", sw_if_index, is_input, acl_index);
}


void hash_acl_add(int acl_index)
{
  clib_warning("HASH ACL add : %d", acl_index);
  /* walk the newly added ACL entries and ensure that for each of them there
     is a mask type, increment a reference count for that mask type */

  /* if an ACL is applied somewhere, fill the corresponding lookup data structures (call hash_acl_apply) */
}
void hash_acl_delete(int acl_index)
{
  clib_warning("HASH ACL delete : %d", acl_index);
  /* if the ACL is applied somewhere, remove the references of it (call hash_acl_unapply) */

  /* walk the mask types for the ACL about-to-be-deleted, and decrease
   * the reference count, possibly freeing up some of them */
}

u8
full_acl_match_5tuple_by_hash (u32 sw_if_index, fa_5tuple_t * pkt_5tuple, int is_l2,
                       int is_ip6, int is_input, u32 * acl_match_p,
                       u32 * rule_match_p, u32 * trace_bitmap)
{
  return 0;
}
