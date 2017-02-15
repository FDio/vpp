/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/l2/l2_xcrw.h>

/**
 * @file
 * General L2 / L3 cross-connect, used to set up
 * "L2 interface <--> your-favorite-tunnel-encap" tunnels.
 *
 * We set up a typical L2 cross-connect or (future) bridge
 * to hook L2 interface(s) up to the L3 stack in arbitrary ways.
 *
 * Each l2_xcrw adjacency specifies 3 things:
 *
 * 1. The next graph node (presumably in the L3 stack) to
 *    process the (L2 -> L3) packet
 *
 * 2. A new value for vnet_buffer(b)->sw_if_index[VLIB_TX]
 *    (i.e. a lookup FIB index),
 *
 * 3. A rewrite string to apply.
 *
 * Example: to cross-connect an L2 interface or (future) bridge
 * to an mpls-o-gre tunnel, set up the L2 rewrite string as shown in
 * mpls_gre_rewrite, and use "mpls-post-rewrite" to fix the
 * GRE IP header checksum and length fields.
 */

typedef struct
{
  u32 next_index;
  u32 tx_fib_index;
} l2_xcrw_trace_t;

/* packet trace format function */
static u8 *
format_l2_xcrw_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_xcrw_trace_t *t = va_arg (*args, l2_xcrw_trace_t *);

  s = format (s, "L2_XCRW: next index %d tx_fib_index %d",
	      t->next_index, t->tx_fib_index);
  return s;
}

l2_xcrw_main_t l2_xcrw_main;

static vlib_node_registration_t l2_xcrw_node;

static char *l2_xcrw_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_xcrw_error
#undef _
};

static uword
l2_xcrw_node_fn (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  l2_xcrw_next_t next_index;
  l2_xcrw_main_t *xcm = &l2_xcrw_main;
  vlib_node_t *n = vlib_get_node (vm, l2_xcrw_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u32 sw_if_index0, sw_if_index1;
	  l2_xcrw_adjacency_t *adj0, *adj1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  adj0 = vec_elt_at_index (xcm->adj_by_sw_if_index, sw_if_index0);
	  adj1 = vec_elt_at_index (xcm->adj_by_sw_if_index, sw_if_index1);

	  next0 = adj0->rewrite_header.next_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
	    adj0->rewrite_header.sw_if_index;

	  next1 = adj1->rewrite_header.next_index;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] =
	    adj1->rewrite_header.sw_if_index;

	  em->counters[node_counter_base_index + next1]++;

	  if (PREDICT_TRUE (next0 > 0))
	    {
	      u8 *h0 = vlib_buffer_get_current (b0);
	      vnet_rewrite_one_header (adj0[0], h0,
				       adj0->rewrite_header.data_bytes);
	      vlib_buffer_advance (b0, -adj0->rewrite_header.data_bytes);
	      em->counters[node_counter_base_index + L2_XCRW_ERROR_FWD]++;
	    }

	  if (PREDICT_TRUE (next1 > 0))
	    {
	      u8 *h1 = vlib_buffer_get_current (b1);
	      vnet_rewrite_one_header (adj1[0], h1,
				       adj1->rewrite_header.data_bytes);
	      vlib_buffer_advance (b1, -adj1->rewrite_header.data_bytes);
	      em->counters[node_counter_base_index + L2_XCRW_ERROR_FWD]++;
	    }


	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
				 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
		{
		  l2_xcrw_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->next_index = next0;
		  t->tx_fib_index = adj0->rewrite_header.sw_if_index;
		}
	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
				 && (b1->flags & VLIB_BUFFER_IS_TRACED)))
		{
		  l2_xcrw_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->next_index = next1;
		  t->tx_fib_index = adj1->rewrite_header.sw_if_index;
		}
	    }

	  /* verify speculative enqueues, maybe switch current next frame */
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
	  l2_xcrw_adjacency_t *adj0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  adj0 = vec_elt_at_index (xcm->adj_by_sw_if_index, sw_if_index0);

	  next0 = adj0->rewrite_header.next_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
	    adj0->rewrite_header.sw_if_index;

	  if (PREDICT_TRUE (next0 > 0))
	    {
	      u8 *h0 = vlib_buffer_get_current (b0);
	      vnet_rewrite_one_header (adj0[0], h0,
				       adj0->rewrite_header.data_bytes);
	      vlib_buffer_advance (b0, -adj0->rewrite_header.data_bytes);
	      em->counters[node_counter_base_index + L2_XCRW_ERROR_FWD]++;
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_xcrw_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	      t->tx_fib_index = adj0->rewrite_header.sw_if_index;
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
VLIB_REGISTER_NODE (l2_xcrw_node, static) = {
  .function = l2_xcrw_node_fn,
  .name = "l2-xcrw",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_xcrw_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2_xcrw_error_strings),
  .error_strings = l2_xcrw_error_strings,

  .n_next_nodes = L2_XCRW_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [L2_XCRW_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (l2_xcrw_node, l2_xcrw_node_fn)
     clib_error_t *l2_xcrw_init (vlib_main_t * vm)
{
  l2_xcrw_main_t *mp = &l2_xcrw_main;

  mp->vlib_main = vm;
  mp->vnet_main = &vnet_main;
  mp->tunnel_index_by_l2_sw_if_index = hash_create (0, sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION (l2_xcrw_init);

static uword
dummy_interface_tx (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

static u8 *
format_xcrw_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "xcrw%d", dev_instance);
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (xcrw_device_class,static) = {
  .name = "Xcrw",
  .format_device_name = format_xcrw_name,
  .tx_function = dummy_interface_tx,
};
/* *INDENT-ON* */

/* Create a sham tunnel interface and return its sw_if_index */
static u32
create_xcrw_interface (vlib_main_t * vm)
{
  vnet_main_t *vnm = vnet_get_main ();
  static u32 instance;
  u8 address[6];
  u32 hw_if_index;
  vnet_hw_interface_t *hi;
  u32 sw_if_index;

  /* mac address doesn't really matter */
  memset (address, 0, sizeof (address));
  address[2] = 0x12;

  /* can returns error iff phy != 0 */
  (void) ethernet_register_interface
    (vnm, xcrw_device_class.index, instance++, address, &hw_if_index,
     /* flag change */ 0);

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  sw_if_index = hi->sw_if_index;
  vnet_sw_interface_set_flags (vnm, sw_if_index,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  /* Output to the sham tunnel invokes the encap node */
  hi->output_node_index = l2_xcrw_node.index;

  return sw_if_index;
}

int
vnet_configure_l2_xcrw (vlib_main_t * vm, vnet_main_t * vnm,
			u32 l2_sw_if_index, u32 tx_fib_index,
			u8 * rewrite, u32 next_node_index, int is_add)
{
  l2_xcrw_main_t *xcm = &l2_xcrw_main;
  l2_xcrw_adjacency_t *a;
  l2_xcrw_tunnel_t *t;
  uword *p;

  if (is_add)
    {

      pool_get (xcm->tunnels, t);

      /* No interface allocated? Do it. Otherwise, set admin up */
      if (t->tunnel_sw_if_index == 0)
	t->tunnel_sw_if_index = create_xcrw_interface (vm);
      else
	vnet_sw_interface_set_flags (vnm, t->tunnel_sw_if_index,
				     VNET_SW_INTERFACE_FLAG_ADMIN_UP);

      t->l2_sw_if_index = l2_sw_if_index;

      vec_validate (xcm->adj_by_sw_if_index, t->l2_sw_if_index);

      a = vec_elt_at_index (xcm->adj_by_sw_if_index, t->l2_sw_if_index);
      memset (a, 0, sizeof (*a));

      a->rewrite_header.sw_if_index = tx_fib_index;

      /*
       * Add or find a dynamic disposition for the successor node,
       * e.g. so we can ship pkts to mpls_post_rewrite...
       */
      a->rewrite_header.next_index =
	vlib_node_add_next (vm, l2_xcrw_node.index, next_node_index);

      if (vec_len (rewrite))
	vnet_rewrite_set_data (a[0], rewrite, vec_len (rewrite));

      set_int_l2_mode (vm, vnm, MODE_L2_XC, t->l2_sw_if_index, 0, 0, 0,
		       t->tunnel_sw_if_index);
      hash_set (xcm->tunnel_index_by_l2_sw_if_index,
		t->l2_sw_if_index, t - xcm->tunnels);
      return 0;
    }
  else
    {
      p = hash_get (xcm->tunnel_index_by_l2_sw_if_index, l2_sw_if_index);
      if (p == 0)
	return VNET_API_ERROR_INVALID_SW_IF_INDEX;

      t = pool_elt_at_index (xcm->tunnels, p[0]);

      a = vec_elt_at_index (xcm->adj_by_sw_if_index, t->l2_sw_if_index);
      /* Reset adj to drop traffic */
      memset (a, 0, sizeof (*a));

      set_int_l2_mode (vm, vnm, MODE_L3, t->l2_sw_if_index, 0, 0, 0, 0);

      vnet_sw_interface_set_flags (vnm, t->tunnel_sw_if_index, 0 /* down */ );

      hash_unset (xcm->tunnel_index_by_l2_sw_if_index, l2_sw_if_index);
      pool_put (xcm->tunnels, t);
    }
  return 0;
}


static clib_error_t *
set_l2_xcrw_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  int is_add = 1;
  int is_ipv6 = 0;		/* for fib id -> fib index mapping */
  u32 tx_fib_id = ~0;
  u32 tx_fib_index = ~0;
  u32 next_node_index = ~0;
  u32 l2_sw_if_index;
  u8 *rw = 0;
  vnet_main_t *vnm = vnet_get_main ();
  int rv;
  clib_error_t *error = NULL;


  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat (line_input, "%U",
		 unformat_vnet_sw_interface, vnm, &l2_sw_if_index))
    {
      error = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "next %U",
		    unformat_vlib_node, vm, &next_node_index))
	;
      else if (unformat (line_input, "tx-fib-id %d", &tx_fib_id))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "ipv6"))
	is_ipv6 = 1;
      else if (unformat (line_input, "rw %U", unformat_hex_string, &rw));
      else
	break;
    }

  if (next_node_index == ~0)
    {
      error = clib_error_return (0, "next node not specified");
      goto done;
    }

  if (tx_fib_id != ~0)
    {
      uword *p;

      if (is_ipv6)
	p = hash_get (ip6_main.fib_index_by_table_id, tx_fib_id);
      else
	p = hash_get (ip4_main.fib_index_by_table_id, tx_fib_id);

      if (p == 0)
	{
	  error =
	    clib_error_return (0, "nonexistent tx_fib_id %d", tx_fib_id);
	  goto done;
	}

      tx_fib_index = p[0];
    }

  rv = vnet_configure_l2_xcrw (vm, vnm, l2_sw_if_index, tx_fib_index,
			       rw, next_node_index, is_add);

  switch (rv)
    {

    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      error = clib_error_return (0, "%U not cross-connected",
				 format_vnet_sw_if_index_name,
				 vnm, l2_sw_if_index);
      goto done;

    default:
      error = clib_error_return (0, "vnet_configure_l2_xcrw returned %d", rv);
      goto done;
    }

done:
  vec_free (rw);
  unformat_free (line_input);

  return error;
}

/*?
 * Add or delete a Layer 2 to Layer 3 rewrite cross-connect. This is
 * used to hook Layer 2 interface(s) up to the Layer 3 stack in
 * arbitrary ways. For example, cross-connect an L2 interface or
 * (future) bridge to an mpls-o-gre tunnel. Set up the L2 rewrite
 * string as shown in mpls_gre_rewrite, and use \"mpls-post-rewrite\"
 * to fix the GRE IP header checksum and length fields.
 *
 * @cliexpar
 * @todo This is incomplete. This needs a detailed description and a
 * practical example.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_l2_xcrw_command, static) = {
  .path = "set interface l2 xcrw",
  .short_help =
  "set interface l2 xcrw <interface> next <node-name>\n"
  "    [del] [tx-fib-id <id>] [ipv6] rw <hex-bytes>",
  .function = set_l2_xcrw_command_fn,
};
/* *INDENT-ON* */

static u8 *
format_l2xcrw (u8 * s, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  l2_xcrw_tunnel_t *t = va_arg (*args, l2_xcrw_tunnel_t *);
  l2_xcrw_main_t *xcm = &l2_xcrw_main;
  vlib_main_t *vm = vlib_get_main ();
  l2_xcrw_adjacency_t *a;
  u8 *rewrite_string;

  if (t == 0)
    {
      s = format (s, "%-25s%s", "L2 interface", "Tunnel Details");
      return s;
    }

  s = format (s, "%-25U %U ",
	      format_vnet_sw_if_index_name, vnm, t->l2_sw_if_index,
	      format_vnet_sw_if_index_name, vnm, t->tunnel_sw_if_index);

  a = vec_elt_at_index (xcm->adj_by_sw_if_index, t->l2_sw_if_index);

  s = format (s, "next %U ",
	      format_vlib_next_node_name, vm, l2_xcrw_node.index,
	      a->rewrite_header.next_index);

  if (a->rewrite_header.sw_if_index != ~0)
    s = format (s, "tx fib index %d ", a->rewrite_header.sw_if_index);

  if (a->rewrite_header.data_bytes)
    {
      rewrite_string = (u8 *) (a + 1);
      rewrite_string -= a->rewrite_header.data_bytes;
      s = format (s, "rewrite data: %U ",
		  format_hex_bytes, rewrite_string,
		  a->rewrite_header.data_bytes);
    }

  s = format (s, "\n");

  return s;
}


static clib_error_t *
show_l2xcrw_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  l2_xcrw_main_t *xcm = &l2_xcrw_main;
  l2_xcrw_tunnel_t *t;

  if (pool_elts (xcm->tunnels) == 0)
    {
      vlib_cli_output (vm, "No L2 / L3 rewrite cross-connects configured");
      return 0;
    }

  vlib_cli_output (vm, "%U", format_l2xcrw, 0, 0);

  /* *INDENT-OFF* */
  pool_foreach (t, xcm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_l2xcrw, vnm, t);
  }));
  /* *INDENT-ON* */

  return 0;
}

/*?
 * Display a Layer 2 to Layer 3 rewrite cross-connect. This is used to
 * hook Layer 2 interface(s) up to the Layer 3 stack in arbitrary ways.
 *
 * @todo This is incomplete. This needs a detailed description and a
 * practical example.
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_l2xcrw_command, static) = {
  .path = "show l2xcrw",
  .short_help = "show l2xcrw",
  .function = show_l2xcrw_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
