/*
 * l2_learn.c : layer 2 learning using l2fib
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
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/l2/l2_learn.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>

#ifndef CLIB_MARCH_VARIANT
l2learn_main_t l2learn_main;
#endif

/**
 * @file
 * @brief Ethernet Bridge Learning.
 *
 * Populate the mac table with entries mapping the packet's source mac + bridge
 * domain ID to the input sw_if_index.
 *
 * Note that learning and forwarding are separate graph nodes. This means that
 * for a set of packets, all learning is performed first, then all nodes are
 * forwarded. The forwarding is done based on the end-state of the mac table,
 * instead of the state after each packet. Thus the forwarding results could
 * differ in certain cases (mac move tests), but this not expected to cause
 * problems in real-world networks. It is much simpler to separate learning
 * and forwarding into separate nodes.
 */


typedef struct
{
  u8 src[6];
  u8 dst[6];
  u32 sw_if_index;
  u16 bd_index;
} l2learn_trace_t;


/* packet trace format function */
static u8 *
format_l2learn_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2learn_trace_t *t = va_arg (*args, l2learn_trace_t *);

  s = format (s, "l2-learn: sw_if_index %d dst %U src %U bd_index %d",
	      t->sw_if_index,
	      format_ethernet_address, t->dst,
	      format_ethernet_address, t->src, t->bd_index);
  return s;
}

static vlib_node_registration_t l2learn_node;

#define foreach_l2learn_error				\
_(L2LEARN,           "L2 learn packets")		\
_(MISS,              "L2 learn misses")			\
_(MAC_MOVE,          "L2 mac moves")			\
_(MAC_MOVE_VIOLATE,  "L2 mac move violations")		\
_(LIMIT,             "L2 not learned due to limit")	\
_(HIT_UPDATE,        "L2 learn hit updates")		\
_(FILTER_DROP,       "L2 filter mac drops")

typedef enum
{
#define _(sym,str) L2LEARN_ERROR_##sym,
  foreach_l2learn_error
#undef _
    L2LEARN_N_ERROR,
} l2learn_error_t;

static char *l2learn_error_strings[] = {
#define _(sym,string) string,
  foreach_l2learn_error
#undef _
};

typedef enum
{
  L2LEARN_NEXT_L2FWD,
  L2LEARN_NEXT_DROP,
  L2LEARN_N_NEXT,
} l2learn_next_t;


/** Perform learning on one packet based on the mac table lookup result. */

static_always_inline void
l2learn_process (vlib_node_runtime_t * node,
		 l2learn_main_t * msm,
		 u64 * counter_base,
		 vlib_buffer_t * b0,
		 u32 sw_if_index0,
		 l2fib_entry_key_t * key0,
		 l2fib_entry_key_t * cached_key,
		 u32 * count,
		 l2fib_entry_result_t * result0, u16 * next0, u8 timestamp)
{
  /* Set up the default next node (typically L2FWD) */
  *next0 = vnet_l2_feature_next (b0, msm->feat_next_node_index,
				 L2INPUT_FEAT_LEARN);

  /* Check mac table lookup result */
  if (PREDICT_TRUE (result0->fields.sw_if_index == sw_if_index0))
    {
      /* Entry in L2FIB with matching sw_if_index matched - normal fast path */
      u32 dtime = timestamp - result0->fields.timestamp;
      u32 dsn = result0->fields.sn.as_u16 - vnet_buffer (b0)->l2.l2fib_sn;
      u32 check = (dtime && vnet_buffer (b0)->l2.bd_age) || dsn;

      if (PREDICT_TRUE (check == 0))
	return;			/* MAC entry up to date */
      if (l2fib_entry_result_is_set_AGE_NOT (result0))
	return;			/* Static MAC always age_not */
      if (msm->global_learn_count > msm->global_learn_limit)
	return;			/* Above learn limit - do not update */

      /* Limit updates per l2-learn node call to avoid prolonged update burst
       * as dtime advance over 1 minute mark, unless more than 1 min behind
       * or SN obsolete */
      if ((*count > 2) && (dtime == 1) && (dsn == 0))
	return;

      counter_base[L2LEARN_ERROR_HIT_UPDATE] += 1;
      *count += 1;
    }
  else if (result0->raw == ~0)
    {
      /* Entry not in L2FIB - add it  */
      counter_base[L2LEARN_ERROR_MISS] += 1;

      if (msm->global_learn_count >= msm->global_learn_limit)
	{
	  /*
	   * Global limit reached. Do not learn the mac but forward the packet.
	   * In the future, limits could also be per-interface or bridge-domain.
	   */
	  counter_base[L2LEARN_ERROR_LIMIT] += 1;
	  return;
	}

      /* Do not learn if mac is 0 */
      l2fib_entry_key_t key = *key0;
      key.fields.bd_index = 0;
      if (key.raw == 0)
	return;

      /* It is ok to learn */
      msm->global_learn_count++;
      result0->raw = 0;		/* clear all fields */
      result0->fields.sw_if_index = sw_if_index0;
      if (msm->client_pid != 0)
	l2fib_entry_result_set_LRN_EVT (result0);
      else
	l2fib_entry_result_clear_LRN_EVT (result0);
    }
  else
    {
      /* Entry in L2FIB with different sw_if_index - mac move or filter */
      if (l2fib_entry_result_is_set_FILTER (result0))
	{
	  ASSERT (result0->fields.sw_if_index == ~0);
	  /* drop packet because lookup matched a filter mac entry */
	  b0->error = node->errors[L2LEARN_ERROR_FILTER_DROP];
	  *next0 = L2LEARN_NEXT_DROP;
	  return;
	}

      if (l2fib_entry_result_is_set_STATIC (result0))
	{
	  /*
	   * Don't overwrite a static mac
	   * TODO: Check violation policy. For now drop the packet
	   */
	  b0->error = node->errors[L2LEARN_ERROR_MAC_MOVE_VIOLATE];
	  *next0 = L2LEARN_NEXT_DROP;
	  return;
	}

      /*
       * TODO: may want to rate limit mac moves
       * TODO: check global/bridge domain/interface learn limits
       */
      result0->fields.sw_if_index = sw_if_index0;
      if (l2fib_entry_result_is_set_AGE_NOT (result0))
	{
	  /* The mac was provisioned */
	  msm->global_learn_count++;
	  l2fib_entry_result_clear_AGE_NOT (result0);
	}
      if (msm->client_pid != 0)
	l2fib_entry_result_set_bits (result0,
				     (L2FIB_ENTRY_RESULT_FLAG_LRN_EVT |
				      L2FIB_ENTRY_RESULT_FLAG_LRN_MOV));
      else
	l2fib_entry_result_clear_bits (result0,
				       (L2FIB_ENTRY_RESULT_FLAG_LRN_EVT |
					L2FIB_ENTRY_RESULT_FLAG_LRN_MOV));
      counter_base[L2LEARN_ERROR_MAC_MOVE] += 1;
    }

  /* Update the entry */
  result0->fields.timestamp = timestamp;
  result0->fields.sn.as_u16 = vnet_buffer (b0)->l2.l2fib_sn;

  BVT (clib_bihash_kv) kv;
  kv.key = key0->raw;
  kv.value = result0->raw;
  BV (clib_bihash_add_del) (msm->mac_table, &kv, 1 /* is_add */ );

  /* Invalidate the cache */
  cached_key->raw = ~0;
}


static_always_inline uword
l2learn_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * frame, int do_trace)
{
  u32 n_left, *from;
  l2learn_main_t *msm = &l2learn_main;
  vlib_node_t *n = vlib_get_node (vm, l2learn_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;
  l2fib_entry_key_t cached_key;
  l2fib_entry_result_t cached_result;
  u8 timestamp = (u8) (vlib_time_now (vm) / 60);
  u32 count = 0;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;	/* number of packets to process */
  vlib_get_buffers (vm, from, bufs, n_left);
  next = nexts;
  b = bufs;

  /* Clear the one-entry cache in case mac table was updated */
  cached_key.raw = ~0;
  cached_result.raw = ~0;	/* warning be gone */

  while (n_left > 8)
    {
      u32 sw_if_index0, sw_if_index1, sw_if_index2, sw_if_index3;
      const ethernet_header_t *h0, *h1, *h2, *h3;
      l2fib_entry_key_t key0, key1, key2, key3;
      l2fib_entry_result_t result0, result1, result2, result3;

      /* Prefetch next iteration. */
      {
	/* buffer header is read and written, so use LOAD
	 * prefetch */
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

      /* Process 4 x pkts */

      h0 = vlib_buffer_get_current (b[0]);
      h1 = vlib_buffer_get_current (b[1]);
      h2 = vlib_buffer_get_current (b[2]);
      h3 = vlib_buffer_get_current (b[3]);

      if (do_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l2learn_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->bd_index = vnet_buffer (b[0])->l2.bd_index;
	      clib_memcpy (t->src, h0->src_address, 6);
	      clib_memcpy (t->dst, h0->dst_address, 6);
	    }
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l2learn_trace_t *t =
		vlib_add_trace (vm, node, b[1], sizeof (*t));
	      t->sw_if_index = sw_if_index1;
	      t->bd_index = vnet_buffer (b[1])->l2.bd_index;
	      clib_memcpy (t->src, h1->src_address, 6);
	      clib_memcpy (t->dst, h1->dst_address, 6);
	    }
	  if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l2learn_trace_t *t =
		vlib_add_trace (vm, node, b[2], sizeof (*t));
	      t->sw_if_index = sw_if_index2;
	      t->bd_index = vnet_buffer (b[2])->l2.bd_index;
	      clib_memcpy (t->src, h2->src_address, 6);
	      clib_memcpy (t->dst, h2->dst_address, 6);
	    }
	  if (b[3]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l2learn_trace_t *t =
		vlib_add_trace (vm, node, b[3], sizeof (*t));
	      t->sw_if_index = sw_if_index3;
	      t->bd_index = vnet_buffer (b[3])->l2.bd_index;
	      clib_memcpy (t->src, h3->src_address, 6);
	      clib_memcpy (t->dst, h3->dst_address, 6);
	    }
	}

      /* process 4 pkts */
      vlib_node_increment_counter (vm, l2learn_node.index,
				   L2LEARN_ERROR_L2LEARN, 4);

      l2fib_lookup_4 (msm->mac_table, &cached_key, &cached_result,
		      h0->src_address,
		      h1->src_address,
		      h2->src_address,
		      h3->src_address,
		      vnet_buffer (b[0])->l2.bd_index,
		      vnet_buffer (b[1])->l2.bd_index,
		      vnet_buffer (b[2])->l2.bd_index,
		      vnet_buffer (b[3])->l2.bd_index,
		      &key0, &key1, &key2, &key3,
		      &result0, &result1, &result2, &result3);

      l2learn_process (node, msm, &em->counters[node_counter_base_index],
		       b[0], sw_if_index0, &key0, &cached_key,
		       &count, &result0, next, timestamp);

      l2learn_process (node, msm, &em->counters[node_counter_base_index],
		       b[1], sw_if_index1, &key1, &cached_key,
		       &count, &result1, next + 1, timestamp);

      l2learn_process (node, msm, &em->counters[node_counter_base_index],
		       b[2], sw_if_index2, &key2, &cached_key,
		       &count, &result2, next + 2, timestamp);

      l2learn_process (node, msm, &em->counters[node_counter_base_index],
		       b[3], sw_if_index3, &key3, &cached_key,
		       &count, &result3, next + 3, timestamp);

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

      if (do_trace && PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  l2learn_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->bd_index = vnet_buffer (b[0])->l2.bd_index;
	  clib_memcpy (t->src, h0->src_address, 6);
	  clib_memcpy (t->dst, h0->dst_address, 6);
	}

      /* process 1 pkt */
      vlib_node_increment_counter (vm, l2learn_node.index,
				   L2LEARN_ERROR_L2LEARN, 1);


      l2fib_lookup_1 (msm->mac_table, &cached_key, &cached_result,
		      h0->src_address, vnet_buffer (b[0])->l2.bd_index,
		      &key0, &result0);

      l2learn_process (node, msm, &em->counters[node_counter_base_index],
		       b[0], sw_if_index0, &key0, &cached_key,
		       &count, &result0, next, timestamp);

      next += 1;
      b += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (l2learn_node) (vlib_main_t * vm,
			     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return l2learn_node_inline (vm, node, frame, 1 /* do_trace */ );
  return l2learn_node_inline (vm, node, frame, 0 /* do_trace */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2learn_node,static) = {
  .name = "l2-learn",
  .vector_size = sizeof (u32),
  .format_trace = format_l2learn_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2learn_error_strings),
  .error_strings = l2learn_error_strings,

  .n_next_nodes = L2LEARN_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [L2LEARN_NEXT_DROP] = "error-drop",
        [L2LEARN_NEXT_L2FWD] = "l2-fwd",
  },
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
clib_error_t *
l2learn_init (vlib_main_t * vm)
{
  l2learn_main_t *mp = &l2learn_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2learn_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       mp->feat_next_node_index);

  /* init the hash table ptr */
  mp->mac_table = get_mac_table ();

  /*
   * Set the default number of dynamically learned macs to the number
   * of buckets.
   */
  mp->global_learn_limit = L2LEARN_DEFAULT_LIMIT;

  return 0;
}

VLIB_INIT_FUNCTION (l2learn_init);


/**
 * Set subinterface learn enable/disable.
 * The CLI format is:
 *    set interface l2 learn <interface> [disable]
 */
static clib_error_t *
int_learn (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd)
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
  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_LEARN, enable);

done:
  return error;
}

/*?
 * Layer 2 learning can be enabled and disabled on each
 * interface and on each bridge-domain. Use this command to
 * manage interfaces. It is enabled by default.
 *
 * @cliexpar
 * Example of how to enable learning:
 * @cliexcmd{set interface l2 learn GigabitEthernet0/8/0}
 * Example of how to disable learning:
 * @cliexcmd{set interface l2 learn GigabitEthernet0/8/0 disable}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (int_learn_cli, static) = {
  .path = "set interface l2 learn",
  .short_help = "set interface l2 learn <interface> [disable]",
  .function = int_learn,
};
/* *INDENT-ON* */


static clib_error_t *
l2learn_config (vlib_main_t * vm, unformat_input_t * input)
{
  l2learn_main_t *mp = &l2learn_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "limit %d", &mp->global_learn_limit))
	;

      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (l2learn_config, "l2learn");

#endif


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
