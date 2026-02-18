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
match_and_hash (soft_rss_rt_match_t *match4, u32 n_match4, soft_rss_rt_match_t *match6,
		u32 n_match6, clib_toeplitz_hash_key_t *k, u8 *d)
{
  u16 ethertype = *(u16u *) d;
  if (PREDICT_TRUE (ethertype == clib_host_to_net_u16 (ETHERNET_TYPE_IP4)))
    {
      for (soft_rss_rt_match_t *m = match4; m < match4 + n_match4; m++)
	if (u8x16_is_equal (*(u8x16u *) d & m->mask, m->match))
	  {
	    CLIB_ASSUME (m->key_len <= 12);
	    switch (m->key_len)
	      {
	      case 4:
		return clib_toeplitz_hash (k, d + m->key_start, 4);
	      case 8:
		return clib_toeplitz_hash (k, d + m->key_start, 8);
	      case 12:
		return clib_toeplitz_hash (k, d + m->key_start, 12);
	      default:
		ASSERT (0);
		break;
	      }
	  }
    }
  else if (PREDICT_TRUE (ethertype == clib_host_to_net_u16 (ETHERNET_TYPE_IP6)))
    {
      for (soft_rss_rt_match_t *m = match6; m < match6 + n_match6; m++)
	if (u8x16_is_equal (*(u8x16u *) d & m->mask, m->match))
	  {
	    CLIB_ASSUME (m->key_len <= 36);
	    switch (m->key_len)
	      {
	      case 16:
		return clib_toeplitz_hash (k, d + m->key_start, 16);
	      case 32:
		return clib_toeplitz_hash (k, d + m->key_start, 32);
	      case 36:
		return clib_toeplitz_hash (k, d + m->key_start, 36);
	      default:
		ASSERT (0);
		break;
	      }
	  }
    }

  return 0;
}

static_always_inline void
soft_rss_one_interface (vlib_main_t *vm, vlib_node_runtime_t *node,
			soft_rss_rt_data_t *rt, u32 *buffer_indices, i16 *cds,
			u32 n_pkts)
{
  i64 n_left = n_pkts;
  u8 *data[VLIB_FRAME_SIZE + 4], **d = data;
  u8 hashes[VLIB_FRAME_SIZE] __clib_aligned (64);
  u8 *h = hashes;
  u16 thread_indices[VLIB_FRAME_SIZE] __clib_aligned (64);
  const u16 reta_mask = rt->reta_mask;
  const u32 n_match4 = rt->n_match4;
  const u32 n_match6 = rt->n_match6;
  soft_rss_rt_match_t *match4 = rt->match4;
  soft_rss_rt_match_t *match6 = rt->match6;
  clib_toeplitz_hash_key_t *k = rt->key;
  u8 *reta = rt->reta;

  /* get pointer to b->data out of buffer indices */
  vlib_get_buffers_with_offset (vm, buffer_indices, (void **) d, n_pkts,
				STRUCT_OFFSET_OF (vlib_buffer_t, data) +
				  rt->match_offset);

  /* duplicate last pointer 4 more times to satisfy prefetch stride */
  clib_ptr_array_pad_tail ((void **) d, n_pkts, 4);

  /* apply current_data offset and reset hash array */
  for (i64 i = n_pkts; i > 0; i -= 32, d += 32, cds += 32)
    for (u32 j = 0; j < 32; j++)
      d[j] += cds[j];

  for (d = data, h = hashes; n_left >= 4; n_left -= 4, d += 4, h += 4)
    {
      clib_prefetch_load (d[4]);
      clib_prefetch_load (d[5]);

      vlan_advance (d + 0);
      h[0] = match_and_hash (match4, n_match4, match6, n_match6, k, d[0]);
      clib_cl_demote (d[0]);

      clib_prefetch_load (d[6]);

      vlan_advance (d + 1);
      h[1] = match_and_hash (match4, n_match4, match6, n_match6, k, d[1]);
      clib_cl_demote (d[1]);

      clib_prefetch_load (d[7]);

      vlan_advance (d + 2);
      h[2] = match_and_hash (match4, n_match4, match6, n_match6, k, d[2]);
      clib_cl_demote (d[2]);

      vlan_advance (d + 3);
      h[3] = match_and_hash (match4, n_match4, match6, n_match6, k, d[3]);
      clib_cl_demote (d[3]);
    }

  for (; n_left > 0; n_left--, d++, h++)
    {
      vlan_advance (d);
      h[0] = match_and_hash (match4, n_match4, match6, n_match6, k, d[0]);
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
	  t->thread_index = reta[hashes[j] & reta_mask];
	}
    }

#if defined(CLIB_HAVE_VEC512_PERMUTE)
  u8x64 *dp = (u8x64 *) hashes;
  u16x32 *ti = (u16x32 *) thread_indices;
  u8x64 mask = u8x64_splat (reta_mask);
  u8x64 table = ((u8x64u *) reta)[0];

  for (int n_data = n_pkts; n_data > 0; n_data -= 64, dp++, ti += 2)
    {
      u8x64 r = u8x64_permute (*dp & mask, table);
      ti[0] = u16x32_from_u8x32 (u8x64_extract_u8x32 (r, 0));
      ti[1] = u16x32_from_u8x32 (u8x64_extract_u8x32 (r, 1));
    }

#elif defined(CLIB_HAVE_VEC256_PERMUTE2)
  u8x32 *dp = (u8x32 *) hashes;
  u16x16 *ti = (u16x16 *) thread_indices;
  u8x32 mask = u8x32_splat (reta_mask);
  u8x32 t0 = ((u8x32u *) reta)[0];
  u8x32 t1 = ((u8x32u *) reta)[1];

  for (int n_data = n_pkts; n_data > 0; n_data -= 32, dp++, ti += 2)
    {
      u8x32 r = u8x32_permute2 (*dp & mask, t0, t1);
      ti[0] = u16x16_from_u8x16 (u8x32_extract_lo (r));
      ti[1] = u16x16_from_u8x16 (u8x32_extract_hi (r));
    }
#elif defined(CLIB_HAVE_VEC256)
  u8x32 *dp = (u8x32 *) hashes;
  u16x16 *ti = (u16x16 *) thread_indices;
  u8x32 t0 = u8x32_splat_u8x16 (((u8x16u *) reta)[0]);
  u8x32 t1 = u8x32_splat_u8x16 (((u8x16u *) reta)[1]);
  u8x32 t2 = u8x32_splat_u8x16 (((u8x16u *) reta)[2]);
  u8x32 t3 = u8x32_splat_u8x16 (((u8x16u *) reta)[3]);
  u8x32 grp_mask = u8x32_splat (0x30 & reta_mask);
  u8x32 lo_mask = u8x32_splat (0x0f & reta_mask);
  u8x32 g0 = u8x32_splat (0x00);
  u8x32 g1 = u8x32_splat (0x10);
  u8x32 g2 = u8x32_splat (0x20);
  u8x32 g3 = u8x32_splat (0x30);

  for (int n_data = n_pkts; n_data > 0; n_data -= 32, dp++, ti += 2)
    {
      u8x32 r = *dp;
      u8x32 lo = r & lo_mask;
      u8x32 grp = r & grp_mask;

      r = u8x32_shuffle_dynamic (t0, lo) & (grp == g0);
      r |= u8x32_shuffle_dynamic (t1, lo) & (grp == g1);
      r |= u8x32_shuffle_dynamic (t2, lo) & (grp == g2);
      r |= u8x32_shuffle_dynamic (t3, lo) & (grp == g3);
      ti[0] = u16x16_from_u8x16 (u8x32_extract_lo (r));
      ti[1] = u16x16_from_u8x16 (u8x32_extract_hi (r));
    }
#elif defined(CLIB_HAVE_VEC128) && defined(__x86_64__)
  u8x16 *dp = (u8x16 *) hashes;
  u16x8 *ti = (u16x8 *) thread_indices;
  u8x16 t0 = ((u8x16u *) reta)[0];
  u8x16 t1 = ((u8x16u *) reta)[1];
  u8x16 t2 = ((u8x16u *) reta)[2];
  u8x16 t3 = ((u8x16u *) reta)[3];
  u8x16 grp_mask = u8x16_splat (0x30 & reta_mask);
  u8x16 lo_mask = u8x16_splat (0x0f & reta_mask);
  u8x16 g0 = u8x16_splat (0x00);
  u8x16 g1 = u8x16_splat (0x10);
  u8x16 g2 = u8x16_splat (0x20);
  u8x16 g3 = u8x16_splat (0x30);

  for (int n_data = n_pkts; n_data > 0; n_data -= 16, dp++, ti += 2)
    {
      u8x16 r = *dp;
      u8x16 lo = r & lo_mask;
      u8x16 grp = r & grp_mask;

      r = u8x16_permute (lo, t0) & (grp == g0);
      r |= u8x16_permute (lo, t1) & (grp == g1);
      r |= u8x16_permute (lo, t2) & (grp == g2);
      r |= u8x16_permute (lo, t3) & (grp == g3);
      ti[0] = u16x8_from_u8x16 (r);
      ti[1] = u16x8_from_u8x16_high (r);
    }
#elif defined(CLIB_HAVE_VEC128) && defined(__aarch64__)
  u8x16 *dp = (u8x16 *) hashes;
  u16x8 *ti = (u16x8 *) thread_indices;
  u8x16 mask = u8x16_splat (reta_mask);
  const uint8x16x4_t t = rt->reta_neon;

  for (int n_data = n_pkts; n_data > 0; n_data -= 16, dp++, ti += 2)
    {
      u8x16 r = vqtbl4q_u8 (t, *dp & mask);
      ti[0] = u16x8_from_u8x16 (r);
      ti[1] = u16x8_from_u8x16_high (r);
    }
#else
  for (u32 i = 0; i < n_pkts; i++)
    thread_indices[i] = reta[hashes[i] & reta_mask];
#endif

  vlib_buffer_enqueue_to_thread (vm, node, soft_rss_main.frame_queue_index, buffer_indices,
				 thread_indices, n_pkts, 0);
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

  for (; n_left > 0; b += 1, sii += 1, cd += 1, n_left -= 1)
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

      if (vec_len (srm->rt_by_sw_if_index) > sw_if_index && srm->rt_by_sw_if_index[sw_if_index])
	{
	  i16 to_cds[VLIB_FRAME_SIZE + 4], *tail = to_cds + n_sel;
	  soft_rss_rt_data_t rt = *srm->rt_by_sw_if_index[sw_if_index];
	  clib_compress_u16 ((u16 *) to_cds, (u16 *) cds, selected_bmp, n_pkts);
	  tail[0] = tail[1] = tail[2] = tail[3] = 0;
	  soft_rss_one_interface (vm, node, &rt, to, to_cds, n_sel);
	}
      else
	{
	  vlib_buffer_free (vm, to, n_sel);
	  vlib_node_increment_counter (vm, node->node_index, SOFT_RSS_ERROR_NOT_ENABLED, n_sel);
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
