/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_16_8.h>
#include <hll/hll.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 new_src_mac[6];
  u8 new_dst_mac[6];
} hll_trace_t;

#ifndef CLIB_MARCH_VARIANT
static u8 *
my_format_mac_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		 a[0], a[1], a[2], a[3], a[4], a[5]);
}

/* packet trace format function */
static u8 *
format_hll_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hll_trace_t *t = va_arg (*args, hll_trace_t *);

  s = format (s, "HLL: sw_if_index %d, next index %d\n",
	      t->sw_if_index, t->next_index);
  s = format (s, "  new src %U -> new dst %U",
	      my_format_mac_address, t->new_src_mac,
	      my_format_mac_address, t->new_dst_mac);
  return s;
}

vlib_node_registration_t hll_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_hll_error \
	_(SWAPPED, "Mac swap packets processed")

typedef enum
{
#define _(sym,str) HLL_ERROR_##sym,
  foreach_hll_error
#undef _
    HLL_N_ERROR,
} hll_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *hll_error_strings[] = {
#define _(sym,string) string,
  foreach_hll_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  HLL_NEXT_INTERFACE_OUTPUT,
  HLL_N_NEXT,
} hll_next_t;

#define foreach_mac_address_offset              \
	_(0)                                            \
	_(1)                                            \
	_(2)                                            \
	_(3)                                            \
	_(4)                                            \
	_(5)

/* when a register in the hll sketch is updated, also the supported structure (hll_info_t) needs to be updated (raw_counters)*/
always_inline void
update_raw_count (hll_list_t * hll, hll_info_t * hll_info0,
		  u32 diff_raw_count0)
{
  u32 raw_count_index0 = hll_info0->raw_count_index;
  u32 updated_raw_count_value0 =
    hll->hll_raw_count_vec[raw_count_index0] + diff_raw_count0;

  /* swap index to mantain sort */
  if (raw_count_index0 < hll->multihll_size - 1)
    {
      u32 next_raw_count_index0 = raw_count_index0 + 1;
      if (hll->hll_raw_count_vec[next_raw_count_index0] <=
	  updated_raw_count_value0)
	{
	  hll->n_swaps = hll->n_swaps + 1;
	  u32 tmp_swap = hll->reverse_hll_vec[next_raw_count_index0];
	  hll->reverse_hll_vec[next_raw_count_index0] =
	    hll->reverse_hll_vec[raw_count_index0];
	  hll->reverse_hll_vec[raw_count_index0] = tmp_swap;

	  hll->hll_raw_count_vec[raw_count_index0] =
	    hll->hll_raw_count_vec[next_raw_count_index0];
	  hll->hll_raw_count_vec[next_raw_count_index0] =
	    updated_raw_count_value0;

	  ((hll_info_t *) hll->hll_info_vec[tmp_swap])->raw_count_index =
	    raw_count_index0;
	  hll_info0->raw_count_index = next_raw_count_index0;
	}
      else
	{
	  hll->hll_raw_count_vec[raw_count_index0] = updated_raw_count_value0;
	}
    }
  else
    {
      hll->hll_raw_count_vec[raw_count_index0] = updated_raw_count_value0;
    }
}


/* if the pkt belongs to a not monitored flow, this function decides if start monitoring or not, and allocates an hll for it*/
always_inline int
hll_not_found_x1 (hll_list_t * hll, clib_bihash_kv_16_8_t kv0, u64 hash0,
		  u32 hll_index0)
{
  /* There is not a hit in the hash */
  if (hll->hll_assigned < hll->multihll_size)
    {
      hll_value_t *result_val0 = (hll_value_t *) & kv0.value;
      hll_index0 = hll->hll_assigned;
      result_val0->hll_index = hll_index0;

      vec_validate (hll->hll_info_vec, hll_index0);
      hll_info_t *hll_info0 = (hll_info_t *) hll->hll_info_vec[hll_index0];
      hll_info0->hll_key_as_u64[0] = kv0.key[0];
      hll_info0->hll_key_as_u64[1] = kv0.key[1];

      /* init hll raw_counter */
      u32 raw_count_index0 = (hll->multihll_size - 1) - hll->hll_assigned;
      hll_info0->raw_count_index = raw_count_index0;

      vec_validate (hll->hll_raw_count_vec, raw_count_index0);
      hll->hll_raw_count_vec[raw_count_index0] = 0;

      vec_validate (hll->reverse_hll_vec, raw_count_index0);
      hll->reverse_hll_vec[raw_count_index0] = hll_index0;

      /* insert in HT */
      BV (clib_bihash_add_del) (hll->hll_list_hash, &kv0, 1);
      hll->hll_assigned = hll->hll_assigned + 1;
    }
  else
    {
      /* XXX Randomized access policy, not yet implemented */
      hll->deniedaccess = hll->deniedaccess + 1;
      return ~0;
    }

  return hll_index0;
}


/* returns the position of the leftmost 1 in the binary representation of the hash -> */
/* from a statistical point of view, after n distinct elements, rank(h(x)) roughly approximate the log_2 of the number of distinct elements. */
always_inline u8
hll_rank (u64 hash, u8 bits)
{
  u8 i;

  /* the bit of the hash from (64-bits) and 64 are used to select the register in the single sketch */
  for (i = 1; i <= 64 - bits; i++)
    {
      if (hash & 1)
	break;

      hash >>= 1;
    }

  return i;
}

/* hll_add_x1 check if pkt0 belongs to a flow monitored and update the hll sketch if needed */
always_inline void
hll_add_x1 (hll_list_t * hll, hll_key_t * pkt0)
{
  clib_bihash_kv_16_8_t kv0 = { };
  clib_bihash_kv_16_8_t result0 = { };
  hll_value_t *result_val0 = (hll_value_t *) & result0.value;
  u32 hll_index0 = 0;
  u64 hash0 = 0;

  /* compute hash of the pkt structure defined for hll */
  if (hll->mode == 4)
    {
      /* 4 <dst_ip , 5-tuple> */
      kv0.key[0] = (u64) pkt0->as_u64[0];
      kv0.key[1] = (u64) pkt0->as_u64[1];
      hash0 = clib_bihash_hash_16_8 (&kv0);

      kv0.key[0] = (u64) pkt0->dst_address;
      kv0.key[1] = (u64) 0;
    }
  else if (hll->mode == 3)
    {
      /* 3 <src_ip , 5-tuple> */
      kv0.key[0] = (u64) pkt0->as_u64[0];
      kv0.key[1] = (u64) pkt0->as_u64[1];
      hash0 = clib_bihash_hash_16_8 (&kv0);

      kv0.key[0] = (u64) pkt0->src_address;
      kv0.key[1] = (u64) 0;
    }
  else if (hll->mode == 2)
    {
      /* 2 <dst_ip , src_ip> */
      kv0.key[0] = (u64) pkt0->src_address;
      kv0.key[1] = (u64) 0;
      hash0 = clib_bihash_hash_16_8 (&kv0);

      kv0.key[0] = (u64) pkt0->dst_address;
      kv0.key[1] = (u64) 0;
    }
  else
    {
      /* 1 <src_ip , dst_ip> */
      kv0.key[0] = (u64) pkt0->dst_address;
      kv0.key[1] = (u64) 0;
      hash0 = clib_bihash_hash_16_8 (&kv0);

      kv0.key[0] = (u64) pkt0->src_address;
      kv0.key[1] = (u64) 0;
    }

  int res =
    clib_bihash_search_inline_2_16_8 (hll->hll_list_hash, &kv0, &result0);

  if (res != 0)
    {
      /* There is not a hit in the hash */
      // XXX actually, the flows can be added only manually through the vppctl
      //hll_index0 = hll_not_found_x1 (hll, kv0, hash0, hll_index0);
      hll_index0 = ~0;
      /* hll_index0 == ~0 means the access policy has decided to not insert the flow */
      if (hll_index0 == ~0)
	return;
    }
  else
    {
      hll_index0 = result_val0->hll_index;
    }


  /* compute the hll-substream in which add the element */
  u64 index0 = hash0 >> (64 - hll->bits);
  /* compute the element rank */
  u8 rank0 = hll_rank (hash0, hll->bits);

  u8 *registers0 = (u8 *) hll->hllreg_vec[hll_index0];
  u8 old_rank0 = registers0[index0];
  /* if the rank is greater than the one saved in the specific register, update it */
  if (rank0 > old_rank0)
    {
      u32 diff_raw_count = (1 << rank0) - (1 << old_rank0);
      registers0[index0] = rank0;
      hll_info_t *hll_info0 = (hll_info_t *) hll->hll_info_vec[hll_index0];
      update_raw_count (hll, hll_info0, diff_raw_count);
    }
}


VLIB_NODE_FN (hll_node) (vlib_main_t * vm,
			 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  hll_main_t *hllm = &hll_main;
  u32 n_left_from, *from, *to_next;
  hll_next_t next_index;
  u32 pkts_counter = 0;
  pkts_counter = hllm->counter;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);


      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 sw_if_index0;
	  ethernet_header_t *eth0;
	  u16 ethertype0;
	  ip4_header_t *ip4_0 = 0;
	  udp_header_t *udp_0 = 0;
	  tcp_header_t *tcp_0 = 0;
	  hll_key_t pkt0_key = { };

	  //u32 next0 = HLL_NEXT_INTERFACE_OUTPUT;
	  u32 next0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  /*
	   * Direct from the driver, we should be at offset 0
	   * aka at &b0->data[0]
	   */
	  ASSERT (b0->current_data == 0);

	  eth0 = vlib_buffer_get_current (b0);
	  ethertype0 = clib_net_to_host_u16 (eth0->type);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  vec_validate (hllm->input_hll_vec_by_sw_if_index, sw_if_index0);
	  hll_list_t *hll_srcif =
	    (hll_list_t *) hllm->input_hll_vec_by_sw_if_index[sw_if_index0];
	  u8 mode = hll_srcif->mode;

	  /* key = src_ip -> count differente src ip */
	  if (mode == 3 || mode == 4)
	    {
	      if (ethertype0 == ETHERNET_TYPE_IP4)
		{
		  ip4_0 = (ip4_header_t *) (eth0 + 1);
		  pkt0_key.src_address = ip4_0->src_address.as_u32;
		  pkt0_key.dst_address = ip4_0->dst_address.as_u32;
		  pkt0_key.protocol = ip4_0->protocol;
		  if (pkt0_key.protocol == IP_PROTOCOL_UDP)
		    {
		      udp_0 = (udp_header_t *) (ip4_0 + 1);
		      pkt0_key.src_port = udp_0->src_port;
		      pkt0_key.dst_port = udp_0->dst_port;
		    }
		  else if (pkt0_key.protocol == IP_PROTOCOL_TCP)
		    {
		      tcp_0 = (tcp_header_t *) (ip4_0 + 1);
		      pkt0_key.src_port = tcp_0->src_port;
		      pkt0_key.dst_port = tcp_0->dst_port;
		    }
		}

	      /* DEFAULT: key = dst_ip -> count different dst ip */
	    }
	  else
	    {
	      if (ethertype0 == ETHERNET_TYPE_IP4)
		{
		  ip4_0 = (ip4_header_t *) (eth0 + 1);
		  pkt0_key.src_address = ip4_0->src_address.as_u32;
		  pkt0_key.dst_address = ip4_0->dst_address.as_u32;
		}
	    }

	  hll_add_x1 (hll_srcif, &pkt0_key);

	  pkts_counter += 1;
	  hll_srcif->pkt_count = hll_srcif->pkt_count + 1;

	  /* speculatively get the next0 */
	  vnet_feature_next (&next0, b0);

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  hllm->counter = pkts_counter;

  vlib_node_increment_counter (vm, hll_node.index,
			       HLL_ERROR_SWAPPED, pkts_counter);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (hll_node) =
{
	.name = "hll",
	.vector_size = sizeof (u32),
	.format_trace = format_hll_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,

	.n_errors = ARRAY_LEN(hll_error_strings),
	.error_strings = hll_error_strings,

	.n_next_nodes = HLL_N_NEXT,

	/* edit / add dispositions here */
	.next_nodes = {
		[HLL_NEXT_INTERFACE_OUTPUT] = "interface-output",
	},
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
