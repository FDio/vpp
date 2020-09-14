/*
 * l2_fwd.c : layer 2 forwarding using l2fib
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
#include <vnet/ethernet/ethernet.h>
#include <vlib/cli.h>

#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_bvi.h>
#include <vnet/l2/l2_fwd.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/l2/feat_bitmap.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/sparse_vec.h>


/**
 * @file
 * @brief Ethernet Forwarding.
 *
 * Code in this file handles forwarding Layer 2 packets. This file calls
 * the FIB lookup, packet learning and the packet flooding as necessary.
 * Packet is then sent to the next graph node.
 */

typedef struct
{

  /* Hash table */
  BVT (clib_bihash) * mac_table;

  /* next node index for the L3 input node of each ethertype */
  next_by_ethertype_t l3_next;

  /* Next nodes for each feature */
  u32 feat_next_node_index[32];

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2fwd_main_t;

typedef struct
{
  /* per-pkt trace data */
  u8 dst_and_src[12];
  u32 sw_if_index;
  u16 bd_index;
  l2fib_entry_result_t result;
} l2fwd_trace_t;

/* packet trace format function */
static u8 *
format_l2fwd_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2fwd_trace_t *t = va_arg (*args, l2fwd_trace_t *);

  s =
    format (s,
	    "l2-fwd:   sw_if_index %d dst %U src %U bd_index %d result [0x%llx, %d] %U",
	    t->sw_if_index, format_ethernet_address, t->dst_and_src,
	    format_ethernet_address, t->dst_and_src + 6,
	    t->bd_index, t->result.raw,
	    t->result.fields.sw_if_index, format_l2fib_entry_result_flags,
	    t->result.fields.flags);
  return s;
}

#ifndef CLIB_MARCH_VARIANT
l2fwd_main_t l2fwd_main;
#else
extern l2fwd_main_t l2fwd_main;
#endif

extern vlib_node_registration_t l2fwd_node;

#define foreach_l2fwd_error				\
_(L2FWD,         "L2 forward packets")			\
_(FLOOD,         "L2 forward misses")			\
_(HIT,           "L2 forward hits")			\
_(BVI_BAD_MAC,   "BVI L3 MAC mismatch")  		\
_(BVI_ETHERTYPE, "BVI packet with unhandled ethertype")	\
_(FILTER_DROP,   "Filter Mac Drop")			\
_(REFLECT_DROP,  "Reflection Drop")			\
_(STALE_DROP,    "Stale entry Drop")

typedef enum
{
#define _(sym,str) L2FWD_ERROR_##sym,
  foreach_l2fwd_error
#undef _
    L2FWD_N_ERROR,
} l2fwd_error_t;

static char *l2fwd_error_strings[] = {
#define _(sym,string) string,
  foreach_l2fwd_error
#undef _
};

typedef enum
{
  L2FWD_NEXT_L2_OUTPUT,
  L2FWD_NEXT_DROP,
  L2FWD_N_NEXT,
} l2fwd_next_t;

/** Forward one packet based on the mac table lookup result. */

static_always_inline void
l2fwd_process (vlib_main_t * vm,
	       vlib_node_runtime_t * node,
	       l2fwd_main_t * msm,
	       vlib_error_main_t * em,
	       vlib_buffer_t * b0,
	       u32 sw_if_index0, l2fib_entry_result_t * result0, u16 * next0)
{
  int try_flood = result0->raw == ~0;
  int flood_error;

  if (PREDICT_FALSE (try_flood))
    {
      flood_error = L2FWD_ERROR_FLOOD;
    }
  else
    {
      /* lookup hit, forward packet  */
#ifdef COUNTERS
      em->counters[node_counter_base_index + L2FWD_ERROR_HIT] += 1;
#endif

      vnet_buffer (b0)->sw_if_index[VLIB_TX] = result0->fields.sw_if_index;
      *next0 = L2FWD_NEXT_L2_OUTPUT;
      int l2fib_seq_num_valid = 1;

      /* check l2fib seq num for stale entries */
      if (!l2fib_entry_result_is_set_AGE_NOT (result0))
	{
	  l2fib_seq_num_t in_sn = vnet_buffer (b0)->l2.l2fib_sn;
	  l2fib_seq_num_t expected_sn = l2_fib_update_seq_num (in_sn,
							       l2_input_seq_num
							       (result0->fields.sw_if_index));

	  l2fib_seq_num_valid = expected_sn == result0->fields.sn;
	}

      if (PREDICT_FALSE (!l2fib_seq_num_valid))
	{
	  flood_error = L2FWD_ERROR_STALE_DROP;
	  try_flood = 1;
	}
      /* perform reflection check */
      else if (PREDICT_FALSE (sw_if_index0 == result0->fields.sw_if_index))
	{
	  b0->error = node->errors[L2FWD_ERROR_REFLECT_DROP];
	  *next0 = L2FWD_NEXT_DROP;
	}
      /* perform filter check */
      else if (PREDICT_FALSE (l2fib_entry_result_is_set_FILTER (result0)))
	{
	  b0->error = node->errors[L2FWD_ERROR_FILTER_DROP];
	  *next0 = L2FWD_NEXT_DROP;
	}
      /* perform BVI check */
      else if (PREDICT_FALSE (l2fib_entry_result_is_set_BVI (result0)))
	{
	  u32 rc;
	  rc = l2_to_bvi (vm,
			  msm->vnet_main,
			  b0,
			  vnet_buffer (b0)->sw_if_index[VLIB_TX],
			  &msm->l3_next, next0);

	  if (PREDICT_FALSE (rc))
	    {
	      if (rc == TO_BVI_ERR_BAD_MAC)
		{
		  b0->error = node->errors[L2FWD_ERROR_BVI_BAD_MAC];
		  *next0 = L2FWD_NEXT_DROP;
		}
	      else if (rc == TO_BVI_ERR_ETHERTYPE)
		{
		  b0->error = node->errors[L2FWD_ERROR_BVI_ETHERTYPE];
		  *next0 = L2FWD_NEXT_DROP;
		}
	    }
	}
    }

  /* flood */
  if (PREDICT_FALSE (try_flood))
    {
      /*
       * lookup miss, so flood which is typically the next feature
       * unless some other feature is inserted before uu_flood
       */
      if (vnet_buffer (b0)->l2.feature_bitmap &
	  (L2INPUT_FEAT_UU_FLOOD | L2INPUT_FEAT_UU_FWD))
	{
	  *next0 = vnet_l2_feature_next (b0, msm->feat_next_node_index,
					 L2INPUT_FEAT_FWD);
	}
      else
	{
	  /* Flooding is disabled */
	  b0->error = node->errors[flood_error];
	  *next0 = L2FWD_NEXT_DROP;
	}
    }
}


static_always_inline uword
l2fwd_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * frame, int do_trace)
{
  u32 n_left, *from;
  l2fwd_main_t *msm = &l2fwd_main;
  vlib_node_t *n = vlib_get_node (vm, l2fwd_node.index);
  CLIB_UNUSED (u32 node_counter_base_index) = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;
  l2fib_entry_key_t cached_key;
  l2fib_entry_result_t cached_result;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  /* Clear the one-entry cache in case mac table was updated */
  cached_key.raw = ~0;
  cached_result.raw = ~0;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;	/* number of packets to process */
  vlib_get_buffers (vm, from, bufs, n_left);
  next = nexts;
  b = bufs;

  while (n_left >= 8)
    {
      u32 sw_if_index0, sw_if_index1, sw_if_index2, sw_if_index3;
      const ethernet_header_t *h0, *h1, *h2, *h3;
      l2fib_entry_key_t key0, key1, key2, key3;
      l2fib_entry_result_t result0, result1, result2, result3;

      /* Prefetch next iteration. */
      {
	vlib_prefetch_buffer_header (b[4], LOAD);
	vlib_prefetch_buffer_header (b[5], LOAD);
	vlib_prefetch_buffer_header (b[6], LOAD);
	vlib_prefetch_buffer_header (b[7], LOAD);

	CLIB_PREFETCH (b[4]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	CLIB_PREFETCH (b[5]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	CLIB_PREFETCH (b[6]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	CLIB_PREFETCH (b[7]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      }

      /* RX interface handles */
      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      sw_if_index1 = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
      sw_if_index2 = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
      sw_if_index3 = vnet_buffer (b[3])->sw_if_index[VLIB_RX];

      h0 = vlib_buffer_get_current (b[0]);
      h1 = vlib_buffer_get_current (b[1]);
      h2 = vlib_buffer_get_current (b[2]);
      h3 = vlib_buffer_get_current (b[3]);

#ifdef COUNTERS
      em->counters[node_counter_base_index + L2FWD_ERROR_L2FWD] += 4;
#endif
      /* *INDENT-OFF* */
      l2fib_lookup_4 (msm->mac_table, &cached_key, &cached_result,
                      h0->dst_address, h1->dst_address,
                      h2->dst_address, h3->dst_address,
                      vnet_buffer (b[0])->l2.bd_index,
                      vnet_buffer (b[1])->l2.bd_index,
                      vnet_buffer (b[2])->l2.bd_index,
                      vnet_buffer (b[3])->l2.bd_index,
                      &key0,	/* not used */
                      &key1,	/* not used */
                      &key2,	/* not used */
                      &key3,	/* not used */
                      &result0,
                      &result1,
                      &result2,
                      &result3);
      /* *INDENT-ON* */
      l2fwd_process (vm, node, msm, em, b[0], sw_if_index0, &result0, next);
      l2fwd_process (vm, node, msm, em, b[1], sw_if_index1, &result1,
		     next + 1);
      l2fwd_process (vm, node, msm, em, b[2], sw_if_index2, &result2,
		     next + 2);
      l2fwd_process (vm, node, msm, em, b[3], sw_if_index3, &result3,
		     next + 3);

      /* verify speculative enqueues, maybe switch current next frame */
      /* if next0==next1==next_index then nothing special needs to be done */
      if (do_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l2fwd_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->bd_index = vnet_buffer (b[0])->l2.bd_index;
	      clib_memcpy_fast (t->dst_and_src, h0->dst_address,
				sizeof (h0->dst_address) +
				sizeof (h0->src_address));
	      t->result = result0;
	    }
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l2fwd_trace_t *t = vlib_add_trace (vm, node, b[1], sizeof (*t));
	      t->sw_if_index = sw_if_index1;
	      t->bd_index = vnet_buffer (b[1])->l2.bd_index;
	      clib_memcpy_fast (t->dst_and_src, h1->dst_address,
				sizeof (h1->dst_address) +
				sizeof (h1->src_address));
	      t->result = result1;
	    }
	  if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l2fwd_trace_t *t = vlib_add_trace (vm, node, b[2], sizeof (*t));
	      t->sw_if_index = sw_if_index2;
	      t->bd_index = vnet_buffer (b[2])->l2.bd_index;
	      clib_memcpy_fast (t->dst_and_src, h2->dst_address,
				sizeof (h2->dst_address) +
				sizeof (h2->src_address));
	      t->result = result2;
	    }
	  if (b[3]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l2fwd_trace_t *t = vlib_add_trace (vm, node, b[3], sizeof (*t));
	      t->sw_if_index = sw_if_index3;
	      t->bd_index = vnet_buffer (b[3])->l2.bd_index;
	      clib_memcpy_fast (t->dst_and_src, h3->dst_address,
				sizeof (h3->dst_address) +
				sizeof (h3->src_address));
	      t->result = result3;
	    }
	}

      next += 4;
      b += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      u32 sw_if_index0;
      ethernet_header_t *h0;
      l2fib_entry_key_t key0;
      l2fib_entry_result_t result0;

      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];

      h0 = vlib_buffer_get_current (b[0]);

      /* process 1 pkt */
#ifdef COUNTERS
      em->counters[node_counter_base_index + L2FWD_ERROR_L2FWD] += 1;
#endif
      l2fib_lookup_1 (msm->mac_table, &cached_key, &cached_result,
		      h0->dst_address, vnet_buffer (b[0])->l2.bd_index, &key0,
		      /* not used */ &result0);
      l2fwd_process (vm, node, msm, em, b[0], sw_if_index0, &result0, next);

      if (do_trace && PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  l2fwd_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->bd_index = vnet_buffer (b[0])->l2.bd_index;
	  clib_memcpy_fast (t->dst_and_src, h0->dst_address,
			    sizeof (h0->dst_address) +
			    sizeof (h0->src_address));
	  t->result = result0;
	}

      /* verify speculative enqueue, maybe switch current next frame */
      next += 1;
      b += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (l2fwd_node) (vlib_main_t * vm,
			   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return l2fwd_node_inline (vm, node, frame, 1 /* do_trace */ );
  return l2fwd_node_inline (vm, node, frame, 0 /* do_trace */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2fwd_node) = {
  .name = "l2-fwd",
  .vector_size = sizeof (u32),
  .format_trace = format_l2fwd_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2fwd_error_strings),
  .error_strings = l2fwd_error_strings,

  .n_next_nodes = L2FWD_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [L2FWD_NEXT_L2_OUTPUT] = "l2-output",
    [L2FWD_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
clib_error_t *
l2fwd_init (vlib_main_t * vm)
{
  l2fwd_main_t *mp = &l2fwd_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2fwd_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       mp->feat_next_node_index);

  /* init the hash table ptr */
  mp->mac_table = get_mac_table ();

  /* Initialize the next nodes for each ethertype */
  next_by_ethertype_init (&mp->l3_next);

  return 0;
}

VLIB_INIT_FUNCTION (l2fwd_init);


/** Add the L3 input node for this ethertype to the next nodes structure. */
void
l2fwd_register_input_type (vlib_main_t * vm,
			   ethernet_type_t type, u32 node_index)
{
  l2fwd_main_t *mp = &l2fwd_main;
  u32 next_index;

  next_index = vlib_node_add_next (vm, l2fwd_node.index, node_index);

  next_by_ethertype_register (&mp->l3_next, type, next_index);
}


/**
 * Set subinterface forward enable/disable.
 * The CLI format is:
 *   set interface l2 forward <interface> [disable]
 */
static clib_error_t *
int_fwd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;
  u32 enable;

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  enable = 1;
  if (unformat (input, "disable"))
    {
      enable = 0;
    }

  /* set the interface flag */
  if (l2input_intf_config (sw_if_index))
    {
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_XCONNECT, enable);
    }
  else
    {
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_FWD, enable);
    }

done:
  return error;
}

/*?
 * Layer 2 unicast forwarding can be enabled and disabled on each
 * interface and on each bridge-domain. Use this command to
 * manage interfaces. It is enabled by default.
 *
 * @cliexpar
 * Example of how to enable forwarding:
 * @cliexcmd{set interface l2 forward GigabitEthernet0/8/0}
 * Example of how to disable forwarding:
 * @cliexcmd{set interface l2 forward GigabitEthernet0/8/0 disable}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (int_fwd_cli, static) = {
  .path = "set interface l2 forward",
  .short_help = "set interface l2 forward <interface> [disable]",
  .function = int_fwd,
};
/* *INDENT-ON* */

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
