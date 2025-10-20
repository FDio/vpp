/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/buffer_funcs.h>
#include <vppinfra/error.h>
#include <vppinfra/vector/compress.h>
#include <vppinfra/vector/mask_compare.h>
#include <vppinfra/vector/toeplitz.h>
#include <vnet/feature/feature.h>
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
soft_rss_one_interface (vlib_main_t *vm, vlib_node_runtime_t *node,
			soft_rss_rt_data_t *rt, u32 *buffer_indices,
			u16 *next_indices, i16 *cds, u32 n_pkts)
{
  i64 n_left = n_pkts;
  u8 *data[VLIB_FRAME_SIZE], **d = data;
  const u32 n_match = rt->n_match;
  soft_rss_rt_match_t *match = rt->match;
  clib_toeplitz_hash_key_t *k = rt->key;

  fformat (stderr, "[%u]: n_pkts %u\n%U\n%U\n", vm->thread_index, n_pkts,
	   format_hexdump_u32, buffer_indices, n_pkts, format_hexdump_u16,
	   next_indices, n_pkts);

  vlib_get_buffers_with_offset (vm, buffer_indices, (void **) data, n_pkts,
				STRUCT_OFFSET_OF (vlib_buffer_t, data) +
				  rt->match_offset);

  for (i64 i = n_left; i > 0; i -= 16, d += 16, cds += 16)
    for (u32 j = 0; j < 16; j++)
      d[j] += cds[j];

  d = data;
  for (; n_left > 0; n_left--, d++)
    {
      u8x16 r = *(u8x16u *) d[0];
      fformat (stderr, "r  %U\n", format_hexdump, d[0], 32);
      for (soft_rss_rt_match_t *m = match; m < match + n_match; m++)
	{
	  u8x16 v = r & m->mask;
	  fformat (stderr, "%u: %U\n   %U\n   %U\n", m - match,
		   format_hex_bytes, &m->mask, 16, format_hex_bytes, &v, 16,
		   format_hex_bytes, &m->match, 16);
	  if (u8x16_is_equal (r & m->mask, m->match))
	    {
	      u32 hash =
		clib_toeplitz_hash (k, d[0] + m->key_start, m->key_len);
	      fformat (stderr, "   KEY: %U\n", format_hex_bytes,
		       d[0] + m->key_start, m->key_len);
	      fformat (stderr, "   HASH: %08x\n", hash);
	      fformat (stderr, "   RETA: %08x -> %u\n", hash & rt->reta_mask,
		       rt->reta[hash & rt->reta_mask]);
	      break;
	    }
	}
    }
}

static_always_inline uword
soft_rss_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame, int trace)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_pkts = frame->n_vectors, n_left = n_pkts;
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 4], **b = buffers;
  u32 sw_if_indices[VLIB_FRAME_SIZE], *sii = sw_if_indices;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  i16 cds[VLIB_FRAME_SIZE], *cd = cds;

  vlib_get_buffers (vm, from, b, n_pkts);
  clib_memset_u64 ((u64 *) (b + n_pkts), pointer_to_uword (b[n_pkts - 1]), 4);

  for (; n_left >= 4; b += 4, sii += 4, next += 4, cd += 4, n_left -= 4)
    {
      clib_prefetch_load (b[4]);
      clib_prefetch_load (b[5]);

      vnet_feature_next_u16 (next + 0, b[0]);
      sii[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      cd[0] = b[0]->current_data;

      clib_prefetch_load (b[6]);

      vnet_feature_next_u16 (next + 1, b[1]);
      sii[1] = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
      cd[1] = b[1]->current_data;

      clib_prefetch_load (b[7]);

      vnet_feature_next_u16 (next + 2, b[2]);
      sii[2] = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
      cd[2] = b[2]->current_data;

      vnet_feature_next_u16 (next + 3, b[3]);
      sii[3] = vnet_buffer (b[3])->sw_if_index[VLIB_RX];
      cd[3] = b[3]->current_data;
    }

  for (; n_left > 0; b += 1, sii += 1, next += 1, n_left -= 1)
    {
      vnet_feature_next_u16 (next + 0, b[0]);
      sii[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      cd[0] = b[0]->current_data;
    }

  vlib_frame_bitmap_t avail_bmp, selected_bmp;
  vlib_frame_bitmap_init (avail_bmp, n_pkts);

  for (u32 n_left = n_pkts; n_left > 0;)
    {
      soft_rss_main_t *srm = &soft_rss_main;
      u32 n_sel, first_set_bit = vlib_frame_bitmap_find_first_set (avail_bmp);
      u32 sw_if_index = sw_if_indices[first_set_bit];
      u32 *to[VLIB_FRAME_SIZE];
      u16 *to_nexts[VLIB_FRAME_SIZE];

      vlib_frame_bitmap_clear (selected_bmp);
      clib_mask_compare_u32 (sw_if_index, sw_if_indices, selected_bmp, n_pkts);
      vlib_frame_bitmap_xor (avail_bmp, selected_bmp);
      n_sel = vlib_frame_bitmap_count_set_bits (selected_bmp);

      clib_compress_u32 ((u32 *) to, from, selected_bmp, n_pkts);
      clib_compress_u16 ((u16 *) to_nexts, nexts, selected_bmp, n_pkts);
      n_left -= n_sel;

      if (vec_len (srm->rt_by_sw_if_index) > sw_if_index &&
	  srm->rt_by_sw_if_index[sw_if_index])
	{
	  i16 *to_cds[VLIB_FRAME_SIZE];
	  clib_compress_u16 ((u16 *) to_cds, (u16 *) cds, selected_bmp,
			     n_pkts);
	  soft_rss_one_interface (
	    vm, node, srm->rt_by_sw_if_index[sw_if_index], (u32 *) to,
	    (u16 *) to_nexts, (i16 *) to_cds, n_sel);
	}
      else
	{
	  vlib_buffer_enqueue_to_next (vm, node, (u32 *) to, (u16 *) to_nexts,
				       n_sel);
	  vlib_node_increment_counter (vm, node->node_index,
				       SOFT_RSS_ERROR_NOT_ENABLED, n_sel);
	}
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (soft_rss_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return soft_rss_node_inline (vm, node, frame, 1);

  return soft_rss_node_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (soft_rss_node) = {
  .name = "soft-rss",
  .vector_size = sizeof (u32),
  .format_trace = format_soft_rss_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (soft_rss_error_strings),
  .error_strings = soft_rss_error_strings,
};
