/*
 * l2_flood.c : layer 2 flooding
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
#include <vnet/l2/l2_bvi.h>
#include <vnet/replication.h>
#include <vnet/l2/l2_fib.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>


/**
 * @file
 * @brief Ethernet Flooding.
 *
 * Flooding uses the packet replication infrastructure to send a copy of the
 * packet to each member interface. Logically the replication infrastructure
 * expects two graph nodes: a prep node that initiates replication and sends the
 * packet to the first destination, and a recycle node that is passed the packet
 * after it has been transmitted.
 *
 * To decrease the amount of code, l2 flooding implements both functions in
 * the same graph node. This node can tell if is it being called as the "prep"
 * or "recycle" using replication_is_recycled().
 */


typedef struct
{

  /* Next nodes for each feature */
  u32 feat_next_node_index[32];

  /* next node index for the L3 input node of each ethertype */
  next_by_ethertype_t l3_next;

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2flood_main_t;

typedef struct
{
  u8 src[6];
  u8 dst[6];
  u32 sw_if_index;
  u16 bd_index;
} l2flood_trace_t;


/* packet trace format function */
static u8 *
format_l2flood_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2flood_trace_t *t = va_arg (*args, l2flood_trace_t *);

  s = format (s, "l2-flood: sw_if_index %d dst %U src %U bd_index %d",
	      t->sw_if_index,
	      format_ethernet_address, t->dst,
	      format_ethernet_address, t->src, t->bd_index);
  return s;
}

l2flood_main_t l2flood_main;

static vlib_node_registration_t l2flood_node;

#define foreach_l2flood_error					\
_(L2FLOOD,           "L2 flood packets")			\
_(REPL_FAIL,         "L2 replication failures")			\
_(NO_MEMBERS,        "L2 replication complete")			\
_(BVI_BAD_MAC,       "BVI L3 mac mismatch")		        \
_(BVI_ETHERTYPE,     "BVI packet with unhandled ethertype")

typedef enum
{
#define _(sym,str) L2FLOOD_ERROR_##sym,
  foreach_l2flood_error
#undef _
    L2FLOOD_N_ERROR,
} l2flood_error_t;

static char *l2flood_error_strings[] = {
#define _(sym,string) string,
  foreach_l2flood_error
#undef _
};

typedef enum
{
  L2FLOOD_NEXT_L2_OUTPUT,
  L2FLOOD_NEXT_DROP,
  L2FLOOD_N_NEXT,
} l2flood_next_t;

/*
 * Perform flooding on one packet
 *
 * Due to the way BVI processing can modify the packet, the BVI interface
 * (if present) must be processed last in the replication. The member vector
 * is arranged so that the BVI interface is always the first element.
 * Flooding walks the vector in reverse.
 *
 * BVI processing causes the packet to go to L3 processing. This strips the
 * L2 header, which is fine because the replication infrastructure restores
 * it. However L3 processing can trigger larger changes to the packet. For
 * example, an ARP request could be turned into an ARP reply, an ICMP request
 * could be turned into an ICMP reply. If BVI processing is not performed
 * last, the modified packet would be replicated to the remaining members.
 */

static_always_inline void
l2flood_process (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 l2flood_main_t * msm,
		 u64 * counter_base,
		 vlib_buffer_t * b0,
		 u32 * sw_if_index0,
		 l2fib_entry_key_t * key0,
		 u32 * bucket0, l2fib_entry_result_t * result0, u32 * next0)
{
  u16 bd_index0;
  l2_bridge_domain_t *bd_config;
  l2_flood_member_t *members;
  i32 current_member;		/* signed */
  replication_context_t *ctx;
  u8 in_shg = vnet_buffer (b0)->l2.shg;

  if (!replication_is_recycled (b0))
    {

      /* Do flood "prep node" processing */

      /* Get config for the bridge domain interface */
      bd_index0 = vnet_buffer (b0)->l2.bd_index;
      bd_config = vec_elt_at_index (l2input_main.bd_configs, bd_index0);
      members = bd_config->members;

      /* Find first member that passes the reflection and SHG checks */
      current_member = bd_config->flood_count - 1;
      while ((current_member >= 0) &&
	     ((members[current_member].sw_if_index == *sw_if_index0) ||
	      (in_shg && members[current_member].shg == in_shg)))
	{
	  current_member--;
	}

      if (current_member < 0)
	{
	  /* No members to flood to */
	  *next0 = L2FLOOD_NEXT_DROP;
	  b0->error = node->errors[L2FLOOD_ERROR_NO_MEMBERS];
	  return;
	}

      if ((current_member > 0) &&
	  ((current_member > 1) ||
	   ((members[0].sw_if_index != *sw_if_index0) &&
	    (!in_shg || members[0].shg != in_shg))))
	{
	  /* If more than one member then initiate replication */
	  ctx =
	    replication_prep (vm, b0, l2flood_node.index, 1 /* l2_packet */ );
	  ctx->feature_replicas = (uword) members;
	  ctx->feature_counter = current_member;
	}

    }
  else
    {
      vnet_buffer_opaque_t *vnet_buff_op;

      /* Do flood "recycle node" processing */

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_REPL_FAIL))
	{
	  (void) replication_recycle (vm, b0, 1 /* is_last */ );
	  *next0 = L2FLOOD_NEXT_DROP;
	  b0->error = node->errors[L2FLOOD_ERROR_REPL_FAIL];
	  return;
	}

      ctx = replication_get_ctx (b0);
      replication_clear_recycled (b0);

      members = (l2_flood_member_t *) (intptr_t) ctx->feature_replicas;
      current_member = (i32) ctx->feature_counter - 1;

      /* Need to update input index from saved packet context */
      vnet_buff_op = (vnet_buffer_opaque_t *) ctx->vnet_buffer;
      *sw_if_index0 = vnet_buff_op->sw_if_index[VLIB_RX];

      /* Find next member that passes the reflection and SHG check */
      while ((current_member >= 0) &&
	     ((members[current_member].sw_if_index == *sw_if_index0) ||
	      (in_shg && members[current_member].shg == in_shg)))
	{
	  current_member--;
	}

      if (current_member < 0)
	{
	  /*
	   * No more members to flood to.
	   * Terminate replication and drop packet.
	   */

	  replication_recycle (vm, b0, 1 /* is_last */ );

	  *next0 = L2FLOOD_NEXT_DROP;
	  /* Ideally we woudn't bump a counter here, just silently complete */
	  b0->error = node->errors[L2FLOOD_ERROR_NO_MEMBERS];
	  return;
	}

      /* Restore packet and context and continue replication */
      ctx->feature_counter = current_member;
      replication_recycle (vm, b0, ((current_member == 0) ||	/*is_last */
				    ((current_member == 1) &&
				     ((members[0].sw_if_index ==
				       *sw_if_index0) || (in_shg
							  && members[0].shg ==
							  in_shg)))));
    }

  /* Forward packet to the current member */
  if (PREDICT_FALSE (members[current_member].flags & L2_FLOOD_MEMBER_BVI))
    {
      /* Do BVI processing */
      u32 rc;
      rc = l2_to_bvi (vm,
		      msm->vnet_main,
		      b0,
		      members[current_member].sw_if_index,
		      &msm->l3_next, next0);

      if (PREDICT_FALSE (rc))
	{
	  if (rc == TO_BVI_ERR_BAD_MAC)
	    {
	      b0->error = node->errors[L2FLOOD_ERROR_BVI_BAD_MAC];
	      *next0 = L2FLOOD_NEXT_DROP;
	    }
	  else if (rc == TO_BVI_ERR_ETHERTYPE)
	    {
	      b0->error = node->errors[L2FLOOD_ERROR_BVI_ETHERTYPE];
	      *next0 = L2FLOOD_NEXT_DROP;
	    }
	}
    }
  else
    {
      /* Do normal L2 forwarding */
      vnet_buffer (b0)->sw_if_index[VLIB_TX] =
	members[current_member].sw_if_index;
      *next0 = L2FLOOD_NEXT_L2_OUTPUT;

    }

}


static uword
l2flood_node_fn (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  l2flood_next_t next_index;
  l2flood_main_t *msm = &l2flood_main;
  vlib_node_t *n = vlib_get_node (vm, l2flood_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;	/* number of packets to process */
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      /* get space to enqueue frame to graph node "next_index" */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 6 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u32 sw_if_index0, sw_if_index1;
	  l2fib_entry_key_t key0, key1;
	  l2fib_entry_result_t result0, result1;
	  u32 bucket0, bucket1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3, *p4, *p5;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);

	    /* Prefetch the buffer header for the N+2 loop iteration */
	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);

	    /* Prefetch the replication context for the N+1 loop iteration */
	    /* This depends on the buffer header above */
	    replication_prefetch_ctx (p2);
	    replication_prefetch_ctx (p3);

	    /* Prefetch the packet for the N+1 loop iteration */
	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  /* bi is "buffer index", b is pointer to the buffer */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /* RX interface handles */
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  /* process 2 pkts */
	  em->counters[node_counter_base_index + L2FLOOD_ERROR_L2FLOOD] += 2;

	  l2flood_process (vm, node, msm,
			   &em->counters[node_counter_base_index], b0,
			   &sw_if_index0, &key0, &bucket0, &result0, &next0);

	  l2flood_process (vm, node, msm,
			   &em->counters[node_counter_base_index], b1,
			   &sw_if_index1, &key1, &bucket1, &result1, &next1);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  l2flood_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  ethernet_header_t *h0 = vlib_buffer_get_current (b0);
		  t->sw_if_index = sw_if_index0;
		  t->bd_index = vnet_buffer (b0)->l2.bd_index;
		  clib_memcpy (t->src, h0->src_address, 6);
		  clib_memcpy (t->dst, h0->dst_address, 6);
		}
	      if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
		{
		  l2flood_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  ethernet_header_t *h1 = vlib_buffer_get_current (b1);
		  t->sw_if_index = sw_if_index1;
		  t->bd_index = vnet_buffer (b1)->l2.bd_index;
		  clib_memcpy (t->src, h1->src_address, 6);
		  clib_memcpy (t->dst, h1->dst_address, 6);
		}
	    }

	  /* verify speculative enqueues, maybe switch current next frame */
	  /* if next0==next1==next_index then nothing special needs to be done */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 sw_if_index0;
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

	  /* process 1 pkt */
	  em->counters[node_counter_base_index + L2FLOOD_ERROR_L2FLOOD] += 1;

	  l2flood_process (vm, node, msm,
			   &em->counters[node_counter_base_index], b0,
			   &sw_if_index0, &key0, &bucket0, &result0, &next0);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2flood_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      ethernet_header_t *h0 = vlib_buffer_get_current (b0);
	      t->sw_if_index = sw_if_index0;
	      t->bd_index = vnet_buffer (b0)->l2.bd_index;
	      clib_memcpy (t->src, h0->src_address, 6);
	      clib_memcpy (t->dst, h0->dst_address, 6);
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2flood_node,static) = {
  .function = l2flood_node_fn,
  .name = "l2-flood",
  .vector_size = sizeof (u32),
  .format_trace = format_l2flood_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2flood_error_strings),
  .error_strings = l2flood_error_strings,

  .n_next_nodes = L2FLOOD_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [L2FLOOD_NEXT_L2_OUTPUT] = "l2-output",
        [L2FLOOD_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (l2flood_node, l2flood_node_fn)
     clib_error_t *l2flood_init (vlib_main_t * vm)
{
  l2flood_main_t *mp = &l2flood_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2flood_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       mp->feat_next_node_index);

  return 0;
}

VLIB_INIT_FUNCTION (l2flood_init);



/** Add the L3 input node for this ethertype to the next nodes structure. */
void
l2flood_register_input_type (vlib_main_t * vm,
			     ethernet_type_t type, u32 node_index)
{
  l2flood_main_t *mp = &l2flood_main;
  u32 next_index;

  next_index = vlib_node_add_next (vm, l2flood_node.index, node_index);

  next_by_ethertype_register (&mp->l3_next, type, next_index);
}


/**
 * Set subinterface flood enable/disable.
 * The CLI format is:
 * set interface l2 flood <interface> [disable]
 */
static clib_error_t *
int_flood (vlib_main_t * vm,
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
  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_FLOOD, enable);

done:
  return error;
}

/*?
 * Layer 2 flooding can be enabled and disabled on each
 * interface and on each bridge-domain. Use this command to
 * manage interfaces. It is enabled by default.
 *
 * @cliexpar
 * Example of how to enable flooding:
 * @cliexcmd{set interface l2 flood GigabitEthernet0/8/0}
 * Example of how to disable flooding:
 * @cliexcmd{set interface l2 flood GigabitEthernet0/8/0 disable}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (int_flood_cli, static) = {
  .path = "set interface l2 flood",
  .short_help = "set interface l2 flood <interface> [disable]",
  .function = int_flood,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
