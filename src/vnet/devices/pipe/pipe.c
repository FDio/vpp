/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/devices/pipe/pipe.h>

#include <vppinfra/sparse_vec.h>

/**
 * @file
 * @brief Pipe Interfaces.
 *
 * A pipe interface, like the UNIX pipe, is a pair of interfaces
 * that are joined.
 */
const static pipe_t PIPE_INVALID = {
  .sw_if_index = ~0,
  .subint = {0},
};

/**
 * Various 'module' lavel variables
 */
typedef struct pipe_main_t_
{
  /**
   * Allocated pipe instances
   */
  uword *instances;

  /**
   * the per-swif-index array of pipes. Each end of the pipe is stored againt
   * its respective sw_if_index
   */
  pipe_t *pipes;
} pipe_main_t;

static pipe_main_t pipe_main;

/*
 * The pipe rewrite is the same size as an ethernet header (since it
 * is an ethernet interface and the DP is optimised for writing
 * sizeof(ethernet_header_t) rewirtes. Hwoever, there are no MAC addresses
 * since pipes don't have them.
 */
static u8 *
pipe_build_rewrite (vnet_main_t * vnm,
		    u32 sw_if_index,
		    vnet_link_t link_type, const void *dst_address)
{
  ethernet_header_t *h;
  ethernet_type_t type;
  u8 *rewrite = NULL;

  switch (link_type)
    {
#define _(a,b) case VNET_LINK_##a: type = ETHERNET_TYPE_##b; break
      _(IP4, IP4);
      _(IP6, IP6);
      _(MPLS, MPLS);
      _(ARP, ARP);
#undef _
    default:
      return NULL;
    }

  vec_validate (rewrite, sizeof (ethernet_header_t));

  h = (ethernet_header_t *) rewrite;
  h->type = clib_host_to_net_u16 (type);

  return (rewrite);
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (pipe_hw_interface_class) = {
  .name = "Pipe",
  .build_rewrite = pipe_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

pipe_t *
pipe_get (u32 sw_if_index)
{
  vec_validate_init_empty (pipe_main.pipes, sw_if_index, PIPE_INVALID);

  return (&pipe_main.pipes[sw_if_index]);
}

uword
unformat_pipe_interface (unformat_input_t * input, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  u32 *result = va_arg (*args, u32 *);
  u32 hw_if_index;
  ethernet_main_t *em = &ethernet_main;
  ethernet_interface_t *eif;

  if (!unformat_user (input, unformat_vnet_hw_interface, vnm, &hw_if_index))
    return 0;

  eif = ethernet_get_interface (em, hw_if_index);
  if (eif)
    {
      *result = hw_if_index;
      return 1;
    }
  return 0;
}

#define VNET_PIPE_TX_NEXT_ETHERNET_INPUT VNET_INTERFACE_TX_N_NEXT

/*
 * The TX function bounces the packets back to pipe-rx with the TX interface
 * swapped to the RX.
 */
static uword
pipe_tx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, n_left_to_next, n_copy, *from, *to_next;
  u32 next_index = VNET_PIPE_TX_NEXT_ETHERNET_INPUT;
  u32 i, sw_if_index = 0;
  u32 n_pkts = 0, n_bytes = 0;
  u32 thread_index = vm->thread_index;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_buffer_t *b;
  pipe_t *pipe;

  n_left_from = frame->n_vectors;
  from = vlib_frame_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      n_copy = clib_min (n_left_from, n_left_to_next);

      clib_memcpy (to_next, from, n_copy * sizeof (from[0]));
      n_left_to_next -= n_copy;
      n_left_from -= n_copy;
      i = 0;
      while (i < n_copy)
	{
	  b = vlib_get_buffer (vm, from[i]);
	  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];

	  pipe = &pipe_main.pipes[sw_if_index];
	  // Set up RX index to be recv'd by the other end of the pipe
	  vnet_buffer (b)->sw_if_index[VLIB_RX] = pipe->sw_if_index;
	  vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;

	  i++;
	  n_pkts++;
	  n_bytes += vlib_buffer_length_in_chain (vm, b);
	}
      from += n_copy;

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

      /* increment TX interface stat */
      vlib_increment_combined_counter (im->combined_sw_if_counters +
				       VNET_INTERFACE_COUNTER_TX,
				       thread_index, sw_if_index, n_pkts,
				       n_bytes);
    }

  return n_left_from;
}

static u8 *
format_pipe_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "pipe%d", dev_instance);
}

static clib_error_t *
pipe_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi;
  u32 id, sw_if_index;

  u32 hw_flags = ((flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
		  VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  /* *INDENT-OFF* */
  hi = vnet_get_hw_interface (vnm, hw_if_index);
  hash_foreach (id, sw_if_index, hi->sub_interface_sw_if_index_by_id,
  ({
    vnet_sw_interface_set_flags (vnm, sw_if_index, flags);
  }));
  /* *INDENT-ON* */

  return (NULL);
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (pipe_device_class) = {
  .name = "Pipe",
  .format_device_name = format_pipe_name,
  .tx_function = pipe_tx,
  .admin_up_down_function = pipe_admin_up_down,
};
/* *INDENT-ON* */

#define foreach_pipe_rx_next                    \
  _ (DROP, "error-drop")

typedef enum pipe_rx_next_t_
{
#define _(s,n) PIPE_RX_NEXT_##s,
  foreach_pipe_rx_next
#undef _
    PIPE_RX_N_NEXT,
} pipe_rx_next_t;

typedef struct pipe_rx_trace_t_
{
  u8 packet_data[32];
} pipe_rx_trace_t;

static u8 *
format_pipe_rx_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  pipe_rx_trace_t *t = va_arg (*va, pipe_rx_trace_t *);

  s = format (s, "%U", format_ethernet_header, t->packet_data);

  return s;
}

/*
 * The pipe-rx node is a sibling of ethernet-input so steal it's
 * next node mechanism
 */
static_always_inline void
pipe_determine_next_node (ethernet_main_t * em,
			  u32 is_l20,
			  u32 type0,
			  vlib_buffer_t * b0, pipe_rx_next_t * next0)
{
  if (is_l20)
    {
      *next0 = em->l2_next;
    }
  else if (type0 == ETHERNET_TYPE_IP4)
    {
      *next0 = em->l3_next.input_next_ip4;
    }
  else if (type0 == ETHERNET_TYPE_IP6)
    {
      *next0 = em->l3_next.input_next_ip6;
    }
  else if (type0 == ETHERNET_TYPE_MPLS)
    {
      *next0 = em->l3_next.input_next_mpls;

    }
  else if (em->redirect_l3)
    {
      // L3 Redirect is on, the cached common next nodes will be
      // pointing to the redirect node, catch the uncommon types here
      *next0 = em->redirect_l3_next;
    }
  else
    {
      // uncommon ethertype, check table
      u32 i0;
      i0 = sparse_vec_index (em->l3_next.input_next_by_type, type0);
      *next0 = vec_elt (em->l3_next.input_next_by_type, i0);

      // The table is not populated with LLC values, so check that now.
      if (type0 < 0x600)
	{
	  *next0 = PIPE_RX_NEXT_DROP;
	}
    }
}

static_always_inline uword
pipe_rx (vlib_main_t * vm,
	 vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 n_left_to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node,
				   from,
				   n_left_from,
				   sizeof (from[0]),
				   sizeof (pipe_rx_trace_t));

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, sw_if_index0, bi1, sw_if_index1;
	  pipe_rx_next_t next0, next1;
	  ethernet_header_t *e0, *e1;
	  vlib_buffer_t *b0, *b1;
	  pipe_t *pipe0, *pipe1;
	  u8 is_l20, is_l21;
	  u16 type0, type1;

	  // Prefetch next iteration
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
	    vlib_prefetch_buffer_header (p2, STORE);
	    vlib_prefetch_buffer_header (p3, STORE);
	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];
	  to_next[0] = bi0;
	  bi1 = from[1];
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  e0 = vlib_buffer_get_current (b0);
	  e1 = vlib_buffer_get_current (b1);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	  type0 = clib_net_to_host_u16 (e0->type);
	  type1 = clib_net_to_host_u16 (e1->type);
	  pipe0 = &pipe_main.pipes[sw_if_index0];
	  pipe1 = &pipe_main.pipes[sw_if_index1];

	  vnet_buffer (b0)->l2_hdr_offset = b0->current_data;
	  vnet_buffer (b1)->l2_hdr_offset = b1->current_data;

	  vnet_buffer (b0)->l3_hdr_offset =
	    vnet_buffer (b0)->l2_hdr_offset + sizeof (ethernet_header_t);
	  vnet_buffer (b1)->l3_hdr_offset =
	    vnet_buffer (b1)->l2_hdr_offset + sizeof (ethernet_header_t);
	  b0->flags |=
	    VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	    VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
	  b1->flags |=
	    VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	    VNET_BUFFER_F_L3_HDR_OFFSET_VALID;

	  is_l20 = pipe0->subint.flags & SUBINT_CONFIG_L2;
	  is_l21 = pipe1->subint.flags & SUBINT_CONFIG_L2;

	  /*
	   * from discussion with Neale - we do not support the tagged traffic.
	   * So assume a simple ethernet header
	   */
	  vnet_buffer (b0)->l2.l2_len = sizeof (ethernet_header_t);
	  vnet_buffer (b1)->l2.l2_len = sizeof (ethernet_header_t);
	  vlib_buffer_advance (b0, is_l20 ? 0 : sizeof (ethernet_header_t));
	  vlib_buffer_advance (b1, is_l21 ? 0 : sizeof (ethernet_header_t));

	  pipe_determine_next_node (&ethernet_main, is_l20, type0, b0,
				    &next0);
	  pipe_determine_next_node (&ethernet_main, is_l21, type1, b1,
				    &next1);

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, sw_if_index0;
	  vlib_buffer_t *b0;
	  pipe_rx_next_t next0;
	  ethernet_header_t *e0;
	  pipe_t *pipe0;
	  u16 type0;
	  u8 is_l20;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  e0 = vlib_buffer_get_current (b0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  type0 = clib_net_to_host_u16 (e0->type);
	  pipe0 = &pipe_main.pipes[sw_if_index0];

	  vnet_buffer (b0)->l2_hdr_offset = b0->current_data;
	  vnet_buffer (b0)->l3_hdr_offset =
	    vnet_buffer (b0)->l2_hdr_offset + sizeof (ethernet_header_t);
	  b0->flags |=
	    VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	    VNET_BUFFER_F_L3_HDR_OFFSET_VALID;

	  is_l20 = pipe0->subint.flags & SUBINT_CONFIG_L2;

	  vnet_buffer (b0)->l2.l2_len = sizeof (ethernet_header_t);
	  vlib_buffer_advance (b0, is_l20 ? 0 : sizeof (ethernet_header_t));

	  pipe_determine_next_node (&ethernet_main, is_l20, type0, b0,
				    &next0);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (pipe_rx_node) = {
  .function = pipe_rx,
  .name = "pipe-rx",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .format_trace = format_pipe_rx_trace,

  .sibling_of = "ethernet-input",
};
/* *INDENT-ON* */

/*
 * Maintain a bitmap of allocated pipe instance numbers.
 */
#define PIPE_MAX_INSTANCE		(16 * 1024)

static u32
pipe_instance_alloc (u8 is_specified, u32 want)
{
  /*
   * Check for dynamically allocaetd instance number.
   */
  if (!is_specified)
    {
      u32 bit;

      bit = clib_bitmap_first_clear (pipe_main.instances);
      if (bit >= PIPE_MAX_INSTANCE)
	{
	  return ~0;
	}
      pipe_main.instances = clib_bitmap_set (pipe_main.instances, bit, 1);
      return bit;
    }

  /*
   * In range?
   */
  if (want >= PIPE_MAX_INSTANCE)
    {
      return ~0;
    }

  /*
   * Already in use?
   */
  if (clib_bitmap_get (pipe_main.instances, want))
    {
      return ~0;
    }

  /*
   * Grant allocation request.
   */
  pipe_main.instances = clib_bitmap_set (pipe_main.instances, want, 1);

  return want;
}

static int
pipe_instance_free (u32 instance)
{
  if (instance >= PIPE_MAX_INSTANCE)
    {
      return -1;
    }

  if (clib_bitmap_get (pipe_main.instances, instance) == 0)
    {
      return -1;
    }

  pipe_main.instances = clib_bitmap_set (pipe_main.instances, instance, 0);
  return 0;
}

static clib_error_t *
pipe_create_sub_interface (vnet_hw_interface_t * hi,
			   u32 sub_id, u32 * sw_if_index)
{
  vnet_sw_interface_t template;

  memset (&template, 0, sizeof (template));
  template.type = VNET_SW_INTERFACE_TYPE_PIPE;
  template.flood_class = VNET_FLOOD_CLASS_NORMAL;
  template.sup_sw_if_index = hi->sw_if_index;
  template.sub.id = sub_id;

  return (vnet_create_sw_interface (vnet_get_main (),
				    &template, sw_if_index));
}

int
vnet_create_pipe_interface (u8 is_specified,
			    u32 user_instance,
			    u32 * parent_sw_if_index, u32 pipe_sw_if_index[2])
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  u8 address[6] = {
    [0] = 0x22,
    [1] = 0x22,
  };
  vnet_hw_interface_t *hi;
  clib_error_t *error;
  u32 hw_if_index;
  u32 instance;
  u32 slot;
  int rv = 0;

  ASSERT (parent_sw_if_index);

  memset (address, 0, sizeof (address));

  /*
   * Allocate a pipe instance.  Either select one dynamically
   * or try to use the desired user_instance number.
   */
  instance = pipe_instance_alloc (is_specified, user_instance);
  if (instance == ~0)
    {
      return VNET_API_ERROR_INVALID_REGISTRATION;
    }

  /*
   * Default MAC address (0000:0000:0000 + instance) is allocated
   */
  address[5] = instance;

  error = ethernet_register_interface (vnm, pipe_device_class.index,
				       instance, address, &hw_if_index,
				       /* flag change */ 0);

  if (error)
    {
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto oops;
    }

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  *parent_sw_if_index = hi->sw_if_index;
  slot = vlib_node_add_named_next_with_slot (vm, hi->tx_node_index,
					     "pipe-rx",
					     VNET_PIPE_TX_NEXT_ETHERNET_INPUT);
  ASSERT (slot == VNET_PIPE_TX_NEXT_ETHERNET_INPUT);

  /*
   * create two sub-interfaces, one for each end of the pipe.
   */
  error = pipe_create_sub_interface (hi, 0, &pipe_sw_if_index[0]);

  if (error)
    goto oops;

  error = pipe_create_sub_interface (hi, 1, &pipe_sw_if_index[1]);

  if (error)
    goto oops;

  hash_set (hi->sub_interface_sw_if_index_by_id, 0, pipe_sw_if_index[0]);
  hash_set (hi->sub_interface_sw_if_index_by_id, 1, pipe_sw_if_index[1]);

  vec_validate_init_empty (pipe_main.pipes, pipe_sw_if_index[0],
			   PIPE_INVALID);
  vec_validate_init_empty (pipe_main.pipes, pipe_sw_if_index[1],
			   PIPE_INVALID);

  pipe_main.pipes[pipe_sw_if_index[0]].sw_if_index = pipe_sw_if_index[1];
  pipe_main.pipes[pipe_sw_if_index[1]].sw_if_index = pipe_sw_if_index[0];

  return 0;

oops:
  clib_error_report (error);
  return rv;
}

typedef struct pipe_hw_walk_ctx_t_
{
  pipe_cb_fn_t cb;
  void *ctx;
} pipe_hw_walk_ctx_t;

static walk_rc_t
pipe_hw_walk (vnet_main_t * vnm, u32 hw_if_index, void *args)
{
  vnet_hw_interface_t *hi;
  pipe_hw_walk_ctx_t *ctx;

  ctx = args;
  hi = vnet_get_hw_interface (vnm, hw_if_index);

  if (hi->dev_class_index == pipe_device_class.index)
    {
      u32 pipe_sw_if_index[2], id, sw_if_index;

      /* *INDENT-OFF* */
      hash_foreach (id, sw_if_index, hi->sub_interface_sw_if_index_by_id,
      ({
        ASSERT(id < 2);
        pipe_sw_if_index[id] = sw_if_index;
      }));
      /* *INDENT-ON* */

      ctx->cb (hi->sw_if_index, pipe_sw_if_index, hi->dev_instance, ctx->ctx);
    }

  return (WALK_CONTINUE);
}

void
pipe_walk (pipe_cb_fn_t fn, void *ctx)
{
  pipe_hw_walk_ctx_t wctx = {
    .cb = fn,
    .ctx = ctx,
  };

  ASSERT (fn);

  vnet_hw_interface_walk (vnet_get_main (), pipe_hw_walk, &wctx);
}

static clib_error_t *
create_pipe_interfaces (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int rv;
  u32 sw_if_index;
  u32 pipe_sw_if_index[2];
  u8 is_specified = 0;
  u32 user_instance = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "instance %d", &user_instance))
	is_specified = 1;
      else
	break;
    }

  rv = vnet_create_pipe_interface (is_specified, user_instance,
				   &sw_if_index, pipe_sw_if_index);

  if (rv)
    return clib_error_return (0, "vnet_create_pipe_interface failed");

  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		   vnet_get_main (), sw_if_index);
  return 0;
}

/*?
 * Create a pipe interface.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{pipe create-interface [mac <mac-addr>] [instance <instance>]}
 * Example of how to create a pipe interface:
 * @cliexcmd{pipe create}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pipe_create_interface_command, static) = {
  .path = "pipe create",
  .short_help = "pipe create [instance <instance>]",
  .function = create_pipe_interfaces,
};
/* *INDENT-ON* */

int
vnet_delete_pipe_interface (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;
  vnet_hw_interface_t *hi;
  u32 instance, id;
  u32 hw_if_index;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  si = vnet_get_sw_interface (vnm, sw_if_index);
  hw_if_index = si->hw_if_index;
  hi = vnet_get_hw_interface (vnm, hw_if_index);
  instance = hi->dev_instance;

  if (pipe_instance_free (instance) < 0)
    {
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }

  /* *INDENT-OFF* */
  hash_foreach (id, sw_if_index, hi->sub_interface_sw_if_index_by_id,
  ({
    vnet_delete_sub_interface(sw_if_index);
    pipe_main.pipes[sw_if_index] = PIPE_INVALID;
  }));
  /* *INDENT-ON* */

  ethernet_delete_interface (vnm, hw_if_index);

  return 0;
}

static clib_error_t *
delete_pipe_interfaces (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface not specified");

  rv = vnet_delete_pipe_interface (sw_if_index);

  if (rv)
    return clib_error_return (0, "vnet_delete_pipe_interface failed");

  return 0;
}

/*?
 * Delete a pipe interface.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{pipe delete intfc <interface>}
 * Example of how to delete a pipe interface:
 * @cliexcmd{pipe delete-interface intfc loop0}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pipe_delete_interface_command, static) = {
  .path = "pipe delete",
  .short_help = "pipe delete <interface>",
  .function = delete_pipe_interfaces,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
