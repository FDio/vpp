/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_sfdp_common_h__
#define __included_sfdp_common_h__

#include <vnet/vnet.h>

#define foreach_sfdp_buffer_flag                                              \
  _ (SV_REASSEMBLED, "sv_reassembled")                                        \
  _ (FULL_REASSEMBLED, "full_reassembled")                                    \
  _ (IP6_FINAL_PROTO_VALID, "ip6_final_proto_valid")

enum
{
#define _(sym, str) SFDP_BUFFER_FLAG_BIT_##sym,
  foreach_sfdp_buffer_flag
#undef _
};

enum
{
#define _(sym, str) SFDP_BUFFER_FLAG_##sym = 0x1 << SFDP_BUFFER_FLAG_BIT_##sym,
  foreach_sfdp_buffer_flag
#undef _
};

/* tenant_index is the index of the tenant in the tenant pool */
typedef u32 sfdp_tenant_index_t;

/* tenant_id is the user-provided value associated with a tenant entry */
typedef u32 sfdp_tenant_id_t;

typedef u64 sfdp_bitmap_t;
typedef u16 session_version_t;
typedef struct
{
  sfdp_bitmap_t service_bitmap;
  sfdp_tenant_index_t tenant_index;
  session_version_t session_version_before_handoff;
  u8 flags;
  u8 tcp_flags;
  u8 ip6_final_proto;
} __attribute__ ((may_alias)) sfdp_buffer_opaque_t;

STATIC_ASSERT (sizeof (sfdp_buffer_opaque_t) <=
		 sizeof (vnet_buffer ((vlib_buffer_t *) 0)->unused),
	       "size of sfdp_buffer_opaque_t must be <= size of "
	       "vnet_buffer_opaque_t->unused");

#define sfdp_buffer(b) ((sfdp_buffer_opaque_t *) vnet_buffer (b)->unused)

/* Sometimes a VDCP packet needs to undergo an excursion outside of SFDP (e.g.,
 * for reassembly). This is used to save the SFDP metadata during this
 * excursion
 */
#define sfdp_buffer2(b) ((sfdp_buffer_opaque_t *) vnet_buffer2 (b)->unused)

#endif
