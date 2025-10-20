/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/buffer_funcs.h>
#include <vppinfra/error.h>
#include <vppinfra/vector/compress.h>
#include <vppinfra/vector/array_mask.h>
#include <vppinfra/vector/mask_compare.h>
#include <vppinfra/vector/toeplitz.h>
#include <vnet/feature/feature.h>
#include <vnet/ethernet/packet.h>
#include <soft-rss/soft_rss.h>

#define foreach_soft_rss_error _ (NOT_ENABLED, "soft-rss not enabled")

typedef enum
{
#define _(sym, str) SOFT_RSS_ERROR_##sym,
  foreach_soft_rss_error
#undef _
    SOFT_RSS_N_ERROR,
} soft_rss_error_t;

static char *soft_rss_error_strings[] = {
#define _(sym, str) str,
  foreach_soft_rss_error
#undef _
};

static_always_inline void
vlan_advance (u8 **data)
{
  u16 tpid = *(u16u *) *data;
  const u32x4 tpid_masks = {
    clib_host_to_net_u16 (ETHERNET_TYPE_VLAN),
    clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD),
    clib_host_to_net_u16 (ETHERNET_TYPE_VLAN_9100),
    clib_host_to_net_u16 (ETHERNET_TYPE_VLAN_9200),
  };
  const u32x4 adv_bytes = { 4, 8, 8, 12 };

  *data += u32x4_sum_elts (adv_bytes & (u32x4_splat (tpid) == tpid_masks));
}

static_always_inline u16
match_and_hash (soft_rss_rt_match_t *match, u32 n_match,
		clib_toeplitz_hash_key_t *k, u8 *d)
{
  for (soft_rss_rt_match_t *m = match; m < match + n_match; m++)
    if (u8x16_is_equal (*(u8x16u *) d & m->mask, m->match))
      return clib_toeplitz_hash (k, d + m->key_start, m->key_len);
  return 0;
}

static_always_inline void
soft_rss_one_interface (vlib_main_t *vm, vlib_node_runtime_t *node,
			soft_rss_rt_data_t *rt, u32 *buffer_indices, i16 *cds,
			u32 n_pkts)
{
  i64 i, n_left = n_pkts;
  u8 *data[VLIB_FRAME_SIZE + 4], **d = data;
  u16 hashes[VLIB_FRAME_SIZE], *h = hashes;
  const u32 n_match = rt->n_match;
  soft_rss_rt_match_t *match = rt->match;
  clib_toeplitz_hash_key_t *k = rt->key;
  clib_thread_index_t *reta;

  /* get pointer to b->data out of buffer indices */
  vlib_get_buffers_with_offset (vm, buffer_indices, (void **) d, n_pkts,
				STRUCT_OFFSET_OF (vlib_buffer_t, data) +
				  rt->match_offset);

  /* duplicate last pointer 4 more times to satisfy prefetch stride */
  clib_ptr_array_pad_tail ((void **) d, n_pkts, 4);

  /* apply current_data offset and reset hash array */
  for (i64 i = n_pkts; i > 0; i -= 32, d += 32, cds += 32, h += 32)
    for (u32 j = 0; j < 32; j++)
      d[j] += cds[j];

  for (d = data, h = hashes; n_left >= 4; n_left -= 4, d += 4, h += 4)
    {
      clib_prefetch_load (d[4]);
      clib_prefetch_load (d[5]);

      vlan_advance (d + 0);
      h[0] = match_and_hash (match, n_match, k, d[0]);
      clib_cl_demote (d[0]);

      clib_prefetch_load (d[6]);

      vlan_advance (d + 1);
      h[1] = match_and_hash (match, n_match, k, d[1]);
      clib_cl_demote (d[1]);

      clib_prefetch_load (d[7]);

      vlan_advance (d + 2);
      h[2] = match_and_hash (match, n_match, k, d[2]);
      clib_cl_demote (d[2]);

      vlan_advance (d + 3);
      h[3] = match_and_hash (match, n_match, k, d[3]);
      clib_cl_demote (d[3]);
    }

  for (; n_left > 0; n_left--, d++, h++)
    {
      vlan_advance (d);
      h[0] = match_and_hash (match, n_match, k, d[0]);
      clib_cl_demote (d[0]);
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      for (u32 j = 0; j < n_pkts; j++)
	{
	  vlib_buffer_t *tb;
	  soft_rss_trace_t *t;

	  tb = vlib_get_buffer (vm, buffer_indices[j]);
	  if (!(tb->flags & VLIB_BUFFER_IS_TRACED))
	    continue;

	  t = vlib_add_trace (vm, node, tb, sizeof (*t));
	  t->sw_if_index = vnet_buffer (tb)->sw_if_index[VLIB_RX];
	  t->hash = hashes[j];
	  t->thread_index = rt->reta[hashes[j] & rt->reta_mask];
	}
    }

  /* mask hashes with reta mask */
  for (h = hashes, i = n_pkts; i > 0; i -= 32, h += 32)
    clib_array_mask_u16 (h, rt->reta_mask, 32);

  /* lookup from reta table */
  for (h = hashes, reta = rt->reta, i = n_pkts; i > 0; i -= 16, h += 16)
    for (u32 j = 0; j < 16; j++)
      h[j] = reta[h[j]];

  vlib_buffer_enqueue_to_thread (vm, node, soft_rss_main.frame_queue_index,
				 buffer_indices, hashes, n_pkts, 0);
}

VLIB_NODE_FN (soft_rss_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_pkts = frame->n_vectors, n_left = n_pkts;
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 4], **b = buffers;
  vlib_frame_bitmap_t avail_bmp, selected_bmp;
  u32 sw_if_indices[VLIB_FRAME_SIZE], *sii = sw_if_indices;
  i16 cds[VLIB_FRAME_SIZE], *cd = cds;

  vlib_get_buffers (vm, from, b, n_pkts);

  /* duplicate last pointer 4 more times to satisfy prefetch stride */
  clib_ptr_array_pad_tail ((void **) b, n_pkts, 4);

  for (; n_left >= 4; b += 4, sii += 4, cd += 4, n_left -= 4)
    {
      clib_prefetch_load (b[4]);
      clib_prefetch_load (b[5]);

      sii[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      cd[0] = b[0]->current_data;
      clib_cl_demote (b[0]);

      clib_prefetch_load (b[6]);

      sii[1] = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
      cd[1] = b[1]->current_data;
      clib_cl_demote (b[1]);

      clib_prefetch_load (b[7]);

      sii[2] = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
      cd[2] = b[2]->current_data;
      clib_cl_demote (b[2]);

      sii[3] = vnet_buffer (b[3])->sw_if_index[VLIB_RX];
      cd[3] = b[3]->current_data;
      clib_cl_demote (b[3]);
    }

  for (; n_left > 0; b += 1, sii += 1, n_left -= 1)
    {
      sii[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      cd[0] = b[0]->current_data;
      clib_cl_demote (b[0]);
    }

  vlib_frame_bitmap_init (avail_bmp, n_pkts);

  for (u32 n_left = n_pkts; n_left > 0;)
    {
      soft_rss_main_t *srm = &soft_rss_main;
      u32 n_sel, first_set_bit = vlib_frame_bitmap_find_first_set (avail_bmp);
      u32 sw_if_index = sw_if_indices[first_set_bit];
      u32 to[VLIB_FRAME_SIZE];

      vlib_frame_bitmap_clear (selected_bmp);
      clib_mask_compare_u32 (sw_if_index, sw_if_indices, selected_bmp, n_pkts);
      vlib_frame_bitmap_xor (avail_bmp, selected_bmp);
      n_sel = vlib_frame_bitmap_count_set_bits (selected_bmp);

      clib_compress_u32 ((u32 *) to, from, selected_bmp, n_pkts);
      n_left -= n_sel;

      if (vec_len (srm->rt_by_sw_if_index) > sw_if_index &&
	  srm->rt_by_sw_if_index[sw_if_index])
	{
	  i16 *to_cds[VLIB_FRAME_SIZE];
	  clib_compress_u16 ((u16 *) to_cds, (u16 *) cds, selected_bmp,
			     n_pkts);
	  soft_rss_one_interface (vm, node,
				  srm->rt_by_sw_if_index[sw_if_index],
				  (u32 *) to, (i16 *) to_cds, n_sel);
	}
      else
	{
	  vlib_buffer_free (vm, to, n_sel);
	  vlib_node_increment_counter (vm, node->node_index,
				       SOFT_RSS_ERROR_NOT_ENABLED, n_sel);
	}
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (soft_rss_node) = {
  .name = "soft-rss",
  .vector_size = sizeof (u32),
  .format_trace = format_soft_rss_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (soft_rss_error_strings),
  .error_strings = soft_rss_error_strings,
};

VLIB_NODE_FN (soft_rss_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left, n_pkts = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE + 4], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  vlib_get_buffers (vm, from, bufs, n_pkts);
  clib_ptr_array_pad_tail ((void **) b, n_pkts, 4);

  for (n_left = n_pkts; n_left >= 4; n_left -= 4, b += 4, next += 4)
    {
      clib_prefetch_load (b[4]);
      clib_prefetch_load (b[5]);

      vnet_feature_next_u16 (next + 0, b[0]);

      clib_prefetch_load (b[6]);
      clib_prefetch_slc_load (b[4]->data);

      vnet_feature_next_u16 (next + 1, b[1]);

      clib_prefetch_load (b[7]);
      clib_prefetch_slc_load (b[5]->data);

      vnet_feature_next_u16 (next + 2, b[2]);

      clib_prefetch_slc_load (b[6]->data);

      vnet_feature_next_u16 (next + 3, b[3]);

      clib_prefetch_slc_load (b[7]->data);
    }

  for (; n_left > 0; n_left -= 1, b += 1, next += 1)
    vnet_feature_next_u16 (next + 0, b[0]);

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    for (u32 i = 0; i < n_pkts; i++)
      if (bufs[i]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  soft_rss_handoff_trace_t *t =
	    vlib_add_trace (vm, node, bufs[i], sizeof (*t));
	  t->sw_if_index = vnet_buffer (bufs[i])->sw_if_index[VLIB_RX];
	  t->next_index = nexts[i];
	}

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_pkts);
  return n_pkts;
}

VLIB_REGISTER_NODE (soft_rss_handoff_node) = {
  .name = "soft-rss-handoff",
  .vector_size = sizeof (u32),
  .sibling_of = "soft-rss",
  .format_trace = format_soft_rss_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};
