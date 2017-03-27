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
_(HIT,               "L2 learn hits")			\
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
		 u32 * bucket0,
		 l2fib_entry_result_t * result0, u32 * next0, u8 timestamp)
{
  u32 feature_bitmap;

  /* Set up the default next node (typically L2FWD) */

  /* Remove ourself from the feature bitmap */
  feature_bitmap = vnet_buffer (b0)->l2.feature_bitmap & ~L2INPUT_FEAT_LEARN;

  /* Save for next feature graph nodes */
  vnet_buffer (b0)->l2.feature_bitmap = feature_bitmap;

  /* Determine the next node */
  *next0 = feat_bitmap_get_next_node_index (msm->feat_next_node_index,
					    feature_bitmap);

  /* Check mac table lookup result */

  if (PREDICT_TRUE (result0->fields.sw_if_index == sw_if_index0))
    {
      /*
       * The entry was in the table, and the sw_if_index matched, the normal case
       */
      counter_base[L2LEARN_ERROR_HIT] += 1;
      if (PREDICT_FALSE (result0->fields.timestamp != timestamp))
	result0->fields.timestamp = timestamp;
      if (PREDICT_FALSE
	  (result0->fields.int_sn != vnet_buffer (b0)->l2.int_sn))
	result0->fields.int_sn = vnet_buffer (b0)->l2.int_sn;
      if (PREDICT_FALSE (result0->fields.bd_sn != vnet_buffer (b0)->l2.bd_sn))
	result0->fields.bd_sn = vnet_buffer (b0)->l2.bd_sn;
    }
  else if (result0->raw == ~0)
    {

      /* The entry was not in table, so add it  */

      counter_base[L2LEARN_ERROR_MISS] += 1;

      if (msm->global_learn_count == msm->global_learn_limit)
	{
	  /*
	   * Global limit reached. Do not learn the mac but forward the packet.
	   * In the future, limits could also be per-interface or bridge-domain.
	   */
	  counter_base[L2LEARN_ERROR_LIMIT] += 1;
	  goto done;

	}
      else
	{
	  BVT (clib_bihash_kv) kv;
	  /* It is ok to learn */

	  result0->raw = 0;	/* clear all fields */
	  result0->fields.sw_if_index = sw_if_index0;
	  result0->fields.timestamp = timestamp;
	  result0->fields.bd_sn = vnet_buffer (b0)->l2.bd_sn;
	  result0->fields.int_sn = vnet_buffer (b0)->l2.int_sn;
	  kv.key = key0->raw;
	  kv.value = result0->raw;

	  BV (clib_bihash_add_del) (msm->mac_table, &kv, 1 /* is_add */ );

	  cached_key->raw = ~0;	/* invalidate the cache */
	  msm->global_learn_count++;
	}

    }
  else
    {

      /* The entry was in the table, but with the wrong sw_if_index mapping (mac move) */
      counter_base[L2LEARN_ERROR_MAC_MOVE] += 1;

      if (result0->fields.static_mac)
	{
	  /*
	   * Don't overwrite a static mac
	   * TODO: Check violation policy. For now drop the packet
	   */
	  b0->error = node->errors[L2LEARN_ERROR_MAC_MOVE_VIOLATE];
	  *next0 = L2LEARN_NEXT_DROP;
	}
      else
	{
	  /*
	   * Update the entry
	   * TODO: may want to rate limit mac moves
	   * TODO: check global/bridge domain/interface learn limits
	   */
	  BVT (clib_bihash_kv) kv;

	  result0->raw = 0;	/* clear all fields */
	  result0->fields.sw_if_index = sw_if_index0;
	  result0->fields.timestamp = timestamp;
	  result0->fields.bd_sn = vnet_buffer (b0)->l2.bd_sn;
	  result0->fields.int_sn = vnet_buffer (b0)->l2.int_sn;

	  kv.key = key0->raw;
	  kv.value = result0->raw;

	  cached_key->raw = ~0;	/* invalidate the cache */

	  BV (clib_bihash_add_del) (msm->mac_table, &kv, 1 /* is_add */ );
	}
    }

  if (result0->fields.filter)
    {
      /* drop packet because lookup matched a filter mac entry */

      if (*next0 != L2LEARN_NEXT_DROP)
	{
	  /* if we're not already dropping the packet, do it now */
	  b0->error = node->errors[L2LEARN_ERROR_FILTER_DROP];
	  *next0 = L2LEARN_NEXT_DROP;
	}
    }

done:
  return;
}


static_always_inline uword
l2learn_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * frame, int do_trace)
{
  u32 n_left_from, *from, *to_next;
  l2learn_next_t next_index;
  l2learn_main_t *msm = &l2learn_main;
  vlib_node_t *n = vlib_get_node (vm, l2learn_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;
  l2fib_entry_key_t cached_key;
  l2fib_entry_result_t cached_result;
  u8 timestamp = (u8) (vlib_time_now (vm) / 60);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;	/* number of packets to process */
  next_index = node->cached_next_index;

  /* Clear the one-entry cache in case mac table was updated */
  cached_key.raw = ~0;
  cached_result.raw = ~0;	/* warning be gone */

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      /* get space to enqueue frame to graph node "next_index" */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  u32 bi0, bi1, bi2, bi3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  u32 next0, next1, next2, next3;
	  u32 sw_if_index0, sw_if_index1, sw_if_index2, sw_if_index3;
	  ethernet_header_t *h0, *h1, *h2, *h3;
	  l2fib_entry_key_t key0, key1, key2, key3;
	  l2fib_entry_result_t result0, result1, result2, result3;
	  u32 bucket0, bucket1, bucket2, bucket3;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p4, *p5, *p6, *p7;;

	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);
	    p6 = vlib_get_buffer (vm, from[6]);
	    p7 = vlib_get_buffer (vm, from[7]);

	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    vlib_prefetch_buffer_header (p6, LOAD);
	    vlib_prefetch_buffer_header (p7, LOAD);

	    CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p6->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p7->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  /* bi is "buffer index", b is pointer to the buffer */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next[2] = bi2 = from[2];
	  to_next[3] = bi3 = from[3];
	  from += 4;
	  to_next += 4;
	  n_left_from -= 4;
	  n_left_to_next -= 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  /* RX interface handles */
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	  sw_if_index2 = vnet_buffer (b2)->sw_if_index[VLIB_RX];
	  sw_if_index3 = vnet_buffer (b3)->sw_if_index[VLIB_RX];

	  /* Process 4 x pkts */

	  h0 = vlib_buffer_get_current (b0);
	  h1 = vlib_buffer_get_current (b1);
	  h2 = vlib_buffer_get_current (b2);
	  h3 = vlib_buffer_get_current (b3);

	  if (do_trace)
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2learn_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  t->bd_index = vnet_buffer (b0)->l2.bd_index;
		  clib_memcpy (t->src, h0->src_address, 6);
		  clib_memcpy (t->dst, h0->dst_address, 6);
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2learn_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  t->bd_index = vnet_buffer (b1)->l2.bd_index;
		  clib_memcpy (t->src, h1->src_address, 6);
		  clib_memcpy (t->dst, h1->dst_address, 6);
		}
	      if (b2->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2learn_trace_t *t =
		    vlib_add_trace (vm, node, b2, sizeof (*t));
		  t->sw_if_index = sw_if_index2;
		  t->bd_index = vnet_buffer (b2)->l2.bd_index;
		  clib_memcpy (t->src, h2->src_address, 6);
		  clib_memcpy (t->dst, h2->dst_address, 6);
		}
	      if (b3->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2learn_trace_t *t =
		    vlib_add_trace (vm, node, b3, sizeof (*t));
		  t->sw_if_index = sw_if_index3;
		  t->bd_index = vnet_buffer (b3)->l2.bd_index;
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
			  vnet_buffer (b0)->l2.bd_index,
			  vnet_buffer (b1)->l2.bd_index,
			  vnet_buffer (b2)->l2.bd_index,
			  vnet_buffer (b3)->l2.bd_index,
			  &key0, &key1, &key2, &key3,
			  &bucket0, &bucket1, &bucket2, &bucket3,
			  &result0, &result1, &result2, &result3);

	  l2learn_process (node, msm, &em->counters[node_counter_base_index],
			   b0, sw_if_index0, &key0, &cached_key,
			   &bucket0, &result0, &next0, timestamp);

	  l2learn_process (node, msm, &em->counters[node_counter_base_index],
			   b1, sw_if_index1, &key1, &cached_key,
			   &bucket1, &result1, &next1, timestamp);

	  l2learn_process (node, msm, &em->counters[node_counter_base_index],
			   b2, sw_if_index2, &key2, &cached_key,
			   &bucket2, &result2, &next2, timestamp);

	  l2learn_process (node, msm, &em->counters[node_counter_base_index],
			   b3, sw_if_index3, &key3, &cached_key,
			   &bucket3, &result3, &next3, timestamp);

	  /* verify speculative enqueues, maybe switch current next frame */
	  /* if next0==next1==next_index then nothing special needs to be done */
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 sw_if_index0;
	  ethernet_header_t *h0;
	  l2fib_entry_key_t key0;
	  l2fib_entry_result_t result0;
	  u32 bucket0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  h0 = vlib_buffer_get_current (b0);

	  if (do_trace && PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      l2learn_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->bd_index = vnet_buffer (b0)->l2.bd_index;
	      clib_memcpy (t->src, h0->src_address, 6);
	      clib_memcpy (t->dst, h0->dst_address, 6);
	    }

	  /* process 1 pkt */
	  vlib_node_increment_counter (vm, l2learn_node.index,
				       L2LEARN_ERROR_L2LEARN, 1);


	  l2fib_lookup_1 (msm->mac_table, &cached_key, &cached_result,
			  h0->src_address, vnet_buffer (b0)->l2.bd_index,
			  &key0, &bucket0, &result0);

	  l2learn_process (node, msm, &em->counters[node_counter_base_index],
			   b0, sw_if_index0, &key0, &cached_key,
			   &bucket0, &result0, &next0, timestamp);

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
l2learn_node_fn (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return l2learn_node_inline (vm, node, frame, 1 /* do_trace */ );
  return l2learn_node_inline (vm, node, frame, 0 /* do_trace */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2learn_node,static) = {
  .function = l2learn_node_fn,
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

VLIB_NODE_FUNCTION_MULTIARCH (l2learn_node, l2learn_node_fn)
     clib_error_t *l2learn_init (vlib_main_t * vm)
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
  mp->global_learn_limit = L2FIB_NUM_BUCKETS * 16;

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


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
