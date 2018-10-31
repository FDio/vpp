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

  /* per-cpu vector of cloned packets */
  u32 **clones;
  l2_flood_member_t ***members;
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
static uword
l2flood_node_fn (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  l2flood_next_t next_index;
  l2flood_main_t *msm = &l2flood_main;
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u16 n_clones, n_cloned, clone0;
	  l2_bridge_domain_t *bd_config;
	  u32 sw_if_index0, bi0, ci0;
	  l2_flood_member_t *member;
	  vlib_buffer_t *b0, *c0;
	  u16 next0;
	  u8 in_shg;
	  i32 mi;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  next0 = L2FLOOD_NEXT_L2_OUTPUT;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Get config for the bridge domain interface */
	  bd_config = vec_elt_at_index (l2input_main.bd_configs,
					vnet_buffer (b0)->l2.bd_index);
	  in_shg = vnet_buffer (b0)->l2.shg;
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  vec_validate (msm->members[thread_index],
			vec_len (bd_config->members));

	  vec_reset_length (msm->members[thread_index]);

	  /* Find first members that passes the reflection and SHG checks */
	  for (mi = bd_config->flood_count - 1; mi >= 0; mi--)
	    {
	      member = &bd_config->members[mi];
	      if ((member->sw_if_index != sw_if_index0) &&
		  (!in_shg || (member->shg != in_shg)))
		{
		  vec_add1 (msm->members[thread_index], member);
		}
	    }

	  n_clones = vec_len (msm->members[thread_index]);

	  if (0 == n_clones)
	    {
	      /* No members to flood to */
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;

	      b0->error = node->errors[L2FLOOD_ERROR_NO_MEMBERS];
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next,
					       bi0, L2FLOOD_NEXT_DROP);
	      continue;
	    }
	  else if (n_clones > 1)
	    {
	      vec_validate (msm->clones[thread_index], n_clones);
	      vec_reset_length (msm->clones[thread_index]);

	      /*
	       * the header offset needs to be large enough to incorporate
	       * all the L3 headers that could be touched when doing BVI
	       * processing. So take the current l2 length plus 2 * IPv6
	       * headers (for tunnel encap)
	       */
	      n_cloned = vlib_buffer_clone (vm, bi0,
					    msm->clones[thread_index],
					    n_clones,
					    VLIB_BUFFER_CLONE_HEAD_SIZE);

	      if (PREDICT_FALSE (n_cloned != n_clones))
		{
		  b0->error = node->errors[L2FLOOD_ERROR_REPL_FAIL];
		}

	      /*
	       * for all but the last clone, these are not BVI bound
	       */
	      for (clone0 = 0; clone0 < n_cloned - 1; clone0++)
		{
		  member = msm->members[thread_index][clone0];
		  ci0 = msm->clones[thread_index][clone0];
		  c0 = vlib_get_buffer (vm, ci0);

		  to_next[0] = ci0;
		  to_next += 1;
		  n_left_to_next -= 1;

		  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
				     (b0->flags & VLIB_BUFFER_IS_TRACED)))
		    {
		      ethernet_header_t *h0;
		      l2flood_trace_t *t;

		      if (c0 != b0)
			vlib_buffer_copy_trace_flag (vm, b0, ci0);

		      t = vlib_add_trace (vm, node, c0, sizeof (*t));
		      h0 = vlib_buffer_get_current (c0);
		      t->sw_if_index = sw_if_index0;
		      t->bd_index = vnet_buffer (c0)->l2.bd_index;
		      clib_memcpy (t->src, h0->src_address, 6);
		      clib_memcpy (t->dst, h0->dst_address, 6);
		    }

		  /* Do normal L2 forwarding */
		  vnet_buffer (c0)->sw_if_index[VLIB_TX] =
		    member->sw_if_index;

		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   ci0, next0);
		  if (PREDICT_FALSE (0 == n_left_to_next))
		    {
		      vlib_put_next_frame (vm, node, next_index,
					   n_left_to_next);
		      vlib_get_next_frame (vm, node, next_index, to_next,
					   n_left_to_next);
		    }
		}
	      member = msm->members[thread_index][clone0];
	      ci0 = msm->clones[thread_index][clone0];
	    }
	  else
	    {
	      /* one clone */
	      ci0 = bi0;
	      member = msm->members[thread_index][0];
	    }

	  /*
	   * the last clone that might go to a BVI
	   */
	  c0 = vlib_get_buffer (vm, ci0);

	  to_next[0] = ci0;
	  to_next += 1;
	  n_left_to_next -= 1;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      ethernet_header_t *h0;
	      l2flood_trace_t *t;

	      if (c0 != b0)
		vlib_buffer_copy_trace_flag (vm, b0, ci0);

	      t = vlib_add_trace (vm, node, c0, sizeof (*t));
	      h0 = vlib_buffer_get_current (c0);
	      t->sw_if_index = sw_if_index0;
	      t->bd_index = vnet_buffer (c0)->l2.bd_index;
	      clib_memcpy (t->src, h0->src_address, 6);
	      clib_memcpy (t->dst, h0->dst_address, 6);
	    }


	  /* Forward packet to the current member */
	  if (PREDICT_FALSE (member->flags & L2_FLOOD_MEMBER_BVI))
	    {
	      /* Do BVI processing */
	      u32 rc;
	      rc = l2_to_bvi (vm,
			      msm->vnet_main,
			      c0, member->sw_if_index, &msm->l3_next, &next0);

	      if (PREDICT_FALSE (rc != TO_BVI_ERR_OK))
		{
		  if (rc == TO_BVI_ERR_BAD_MAC)
		    {
		      c0->error = node->errors[L2FLOOD_ERROR_BVI_BAD_MAC];
		    }
		  else if (rc == TO_BVI_ERR_ETHERTYPE)
		    {
		      c0->error = node->errors[L2FLOOD_ERROR_BVI_ETHERTYPE];
		    }
		  next0 = L2FLOOD_NEXT_DROP;
		}
	    }
	  else
	    {
	      /* Do normal L2 forwarding */
	      vnet_buffer (c0)->sw_if_index[VLIB_TX] = member->sw_if_index;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   ci0, next0);
	  if (PREDICT_FALSE (0 == n_left_to_next))
	    {
	      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	      vlib_get_next_frame (vm, node, next_index,
				   to_next, n_left_to_next);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       L2FLOOD_ERROR_L2FLOOD, frame->n_vectors);

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

VLIB_NODE_FUNCTION_MULTIARCH (l2flood_node, l2flood_node_fn)
/* *INDENT-ON* */

clib_error_t *
l2flood_init (vlib_main_t * vm)
{
  l2flood_main_t *mp = &l2flood_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();

  vec_validate (mp->clones, vlib_num_workers ());
  vec_validate (mp->members, vlib_num_workers ());

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2flood_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       mp->feat_next_node_index);

  return NULL;
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
