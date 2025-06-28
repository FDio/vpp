// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_common_h
#define included_vcdp_common_h

#include <vnet/vnet.h>

// TODO: Is this used?
#define foreach_vcdp_buffer_flag \
_(REASSEMBLED, "reassembled") \
_(VISITED, "visited")

enum {
#define _(sym, str) VCDP_BUFFER_FLAG_BIT_##sym,
  foreach_vcdp_buffer_flag
#undef _
};

enum {
#define _(sym, str) VCDP_BUFFER_FLAG_##sym = 0x1 << VCDP_BUFFER_FLAG_BIT_##sym,
  foreach_vcdp_buffer_flag
#undef _
};

typedef struct {
  u32 pad[2];		/* do not overlay w/ ip.adj_index[0,1] */
  u32 service_bitmap;
  u32 context_id;
  u32 rx_id;
  u16 tenant_index;
  u8 flags;
  u8 pad8;
} vcdp_buffer_opaque_t;

STATIC_ASSERT(sizeof(vcdp_buffer_opaque_t) <= sizeof(vnet_buffer((vlib_buffer_t *) 0)->unused),
              "size of vcdp_buffer_opaque_t must be <= size of "
              "vnet_buffer_opaque_t->unused");

#define vcdp_buffer(b) ((vcdp_buffer_opaque_t *) vnet_buffer(b)->unused)

/* Sometimes a VDCP packet needs to undergo an excursion outside of VCDP (e.g.,
 * for reassembly). This is used to save the VCDP metadata during this
 * excursion
 */
#define vcdp_buffer2(b) ((vcdp_buffer_opaque_t *) vnet_buffer2(b)->unused)

#endif
