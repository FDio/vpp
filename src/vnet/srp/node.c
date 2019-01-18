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
/*
 * node.c: srp packet processing
 *
 * Copyright (c) 2011 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vnet/ip/ip_packet.h>	/* for ip_csum_fold */
#include <vnet/srp/srp.h>

srp_main_t srp_main;

typedef struct {
  u8 packet_data[32];
} srp_input_trace_t;

static u8 * format_srp_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  srp_input_trace_t * t = va_arg (*va, srp_input_trace_t *);

  s = format (s, "%U", format_srp_header, t->packet_data);

  return s;
}

typedef enum {
  SRP_INPUT_NEXT_ERROR,
  SRP_INPUT_NEXT_ETHERNET_INPUT,
  SRP_INPUT_NEXT_CONTROL,
  SRP_INPUT_N_NEXT,
} srp_input_next_t;

typedef struct {
  u8 next_index;
  u8 buffer_advance;
  u16 error;
} srp_input_disposition_t;

static srp_input_disposition_t srp_input_disposition_by_mode[8] = {
  [SRP_MODE_reserved0] = {
    .next_index = SRP_INPUT_NEXT_ERROR,
    .error = SRP_ERROR_UNKNOWN_MODE,
  },
  [SRP_MODE_reserved1] = {
    .next_index = SRP_INPUT_NEXT_ERROR,
    .error = SRP_ERROR_UNKNOWN_MODE,
  },
  [SRP_MODE_reserved2] = {
    .next_index = SRP_INPUT_NEXT_ERROR,
    .error = SRP_ERROR_UNKNOWN_MODE,
  },
  [SRP_MODE_reserved3] = {
    .next_index = SRP_INPUT_NEXT_ERROR,
    .error = SRP_ERROR_UNKNOWN_MODE,
  },
  [SRP_MODE_keep_alive] = {
    .next_index = SRP_INPUT_NEXT_ERROR,
    .error = SRP_ERROR_KEEP_ALIVE_DROPPED,
  },
  [SRP_MODE_data] = {
    .next_index = SRP_INPUT_NEXT_ETHERNET_INPUT,
    .buffer_advance = sizeof (srp_header_t),
  },
  [SRP_MODE_control_pass_to_host] = {
    .next_index = SRP_INPUT_NEXT_CONTROL,
  },
  [SRP_MODE_control_locally_buffered_for_host] = {
    .next_index = SRP_INPUT_NEXT_CONTROL,
  },
};

static uword
srp_input (vlib_main_t * vm,
	   vlib_node_runtime_t * node,
	   vlib_frame_t * from_frame)
{
  vnet_main_t * vnm = vnet_get_main();
  srp_main_t * sm = &srp_main;
  u32 n_left_from, next_index, * from, * to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node,
				   from,
				   n_left_from,
				   sizeof (from[0]),
				   sizeof (srp_input_trace_t));

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1, sw_if_index0, sw_if_index1;
	  vlib_buffer_t * b0, * b1;
	  u8 next0, next1, error0, error1;
	  srp_header_t * s0, * s1;
	  srp_input_disposition_t * d0, * d1;
	  vnet_hw_interface_t * hi0, * hi1;
	  srp_interface_t * si0, * si1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * b2, * b3;

	    b2 = vlib_get_buffer (vm, from[2]);
	    b3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (b2, LOAD);
	    vlib_prefetch_buffer_header (b3, LOAD);

	    CLIB_PREFETCH (b2->data, sizeof (srp_header_t), LOAD);
	    CLIB_PREFETCH (b3->data, sizeof (srp_header_t), LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  s0 = (void *) (b0->data + b0->current_data);
	  s1 = (void *) (b1->data + b1->current_data);

	  /* Data packets are always assigned to side A (outer ring) interface. */
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  hi0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);
	  hi1 = vnet_get_sup_hw_interface (vnm, sw_if_index1);

	  si0 = pool_elt_at_index (sm->interface_pool, hi0->hw_instance);
	  si1 = pool_elt_at_index (sm->interface_pool, hi1->hw_instance);

	  sw_if_index0 = (s0->mode == SRP_MODE_data
			  ? si0->rings[SRP_RING_OUTER].sw_if_index
			  : sw_if_index0);
	  sw_if_index1 = (s1->mode == SRP_MODE_data
			  ? si1->rings[SRP_RING_OUTER].sw_if_index
			  : sw_if_index1);
	    
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index0;
	  vnet_buffer (b1)->sw_if_index[VLIB_RX] = sw_if_index1;

	  d0 = srp_input_disposition_by_mode + s0->mode;
	  d1 = srp_input_disposition_by_mode + s1->mode;

	  next0 = d0->next_index;
	  next1 = d1->next_index;

	  error0 = d0->error;
	  error1 = d1->error;

	  vlib_buffer_advance (b0, d0->buffer_advance);
	  vlib_buffer_advance (b1, d1->buffer_advance);

	  b0->error = node->errors[error0];
	  b1->error = node->errors[error1];

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
    
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, sw_if_index0;
	  vlib_buffer_t * b0;
	  u8 next0, error0;
	  srp_header_t * s0;
	  srp_input_disposition_t * d0;
	  srp_interface_t * si0;
	  vnet_hw_interface_t * hi0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  s0 = (void *) (b0->data + b0->current_data);

	  /* Data packets are always assigned to side A (outer ring) interface. */
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  hi0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

	  si0 = pool_elt_at_index (sm->interface_pool, hi0->hw_instance);

	  sw_if_index0 = (s0->mode == SRP_MODE_data
			  ? si0->rings[SRP_RING_OUTER].sw_if_index
			  : sw_if_index0);
	    
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index0;

	  d0 = srp_input_disposition_by_mode + s0->mode;

	  next0 = d0->next_index;

	  error0 = d0->error;

	  vlib_buffer_advance (b0, d0->buffer_advance);

	  b0->error = node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static char * srp_error_strings[] = {
#define _(f,s) s,
  foreach_srp_error
#undef _
};

static vlib_node_registration_t srp_input_node = {
  .function = srp_input,
  .name = "srp-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = SRP_N_ERROR,
  .error_strings = srp_error_strings,

  .n_next_nodes = SRP_INPUT_N_NEXT,
  .next_nodes = {
    [SRP_INPUT_NEXT_ERROR] = "error-drop",
    [SRP_INPUT_NEXT_ETHERNET_INPUT] = "ethernet-input",
    [SRP_INPUT_NEXT_CONTROL] = "srp-control",
  },

  .format_buffer = format_srp_header_with_length,
  .format_trace = format_srp_input_trace,
  .unformat_buffer = unformat_srp_header,
};

static uword
srp_topology_packet (vlib_main_t * vm, u32 sw_if_index, u8 ** contents)
{
  vnet_main_t * vnm = vnet_get_main();
  vnet_hw_interface_t * hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  srp_topology_header_t * t;
  srp_topology_mac_binding_t * mb;
  u32 nb, nmb;

  t = (void *) *contents;

  nb = clib_net_to_host_u16 (t->n_bytes_of_data_that_follows);
  nmb = (nb - sizeof (t->originator_address)) / sizeof (mb[0]);
  if (vec_len (*contents) < sizeof (t[0]) + nmb * sizeof (mb[0]))
    return SRP_ERROR_TOPOLOGY_BAD_LENGTH;

  /* Fill in our source MAC address. */
  clib_memcpy_fast (t->ethernet.src_address, hi->hw_address, vec_len (hi->hw_address));

  /* Make space for our MAC binding. */
  vec_resize (*contents, sizeof (srp_topology_mac_binding_t));
  t = (void *) *contents;
  t->n_bytes_of_data_that_follows = clib_host_to_net_u16 (nb + sizeof (mb[0]));

  mb = t->bindings + nmb;

  mb->flags =
    ((t->srp.is_inner_ring ? SRP_TOPOLOGY_MAC_BINDING_FLAG_IS_INNER_RING : 0)
     | (/* is wrapped FIXME */ 0));
  clib_memcpy_fast (mb->address, hi->hw_address, vec_len (hi->hw_address));

  t->control.checksum
    = ~ip_csum_fold (ip_incremental_checksum (0, &t->control,
					      vec_len (*contents) - STRUCT_OFFSET_OF (srp_generic_control_header_t, control)));

  {
    vlib_frame_t * f; 
    vlib_buffer_t * b;
    u32 * to_next;
    u32 bi = ~0;

    if (vlib_buffer_add_data (vm, /* buffer to append to */ &bi,
                              *contents, vec_len (*contents)))
      {
        /* complete or partial buffer allocation failure */
        if (bi != ~0)
          vlib_buffer_free (vm, &bi, 1);
        return SRP_ERROR_CONTROL_PACKETS_PROCESSED;
      }
    b = vlib_get_buffer (vm, bi);
    vnet_buffer (b)->sw_if_index[VLIB_RX] = vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;
    f = vlib_get_frame_to_node (vm, hi->output_node_index);
    to_next = vlib_frame_vector_args (f);
    to_next[0] = bi;
    f->n_vectors = 1;
    vlib_put_frame_to_node (vm, hi->output_node_index, f);
  }

  return SRP_ERROR_CONTROL_PACKETS_PROCESSED;
}

typedef uword (srp_control_handler_function_t) (vlib_main_t * vm,
						u32 sw_if_index,
						u8 ** contents);

static uword
srp_control_input (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  vlib_node_runtime_t * error_node;
  static u8 * contents;

  error_node = vlib_node_get_runtime (vm, srp_input_node.index);

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node,
				   from,
				   n_left_from,
				   sizeof (from[0]),
				   sizeof (srp_input_trace_t));

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, l2_len0, l3_len0;
	  vlib_buffer_t * b0;
	  u8 next0, error0;
	  srp_generic_control_header_t * s0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  s0 = (void *) (b0->data + b0->current_data);
	  l2_len0 = vlib_buffer_length_in_chain (vm, b0);
	  l3_len0 = l2_len0 - STRUCT_OFFSET_OF (srp_generic_control_header_t, control);

	  error0 = SRP_ERROR_CONTROL_PACKETS_PROCESSED;

	  error0 = s0->control.version != 0 ? SRP_ERROR_CONTROL_VERSION_NON_ZERO : error0;

	  {
	    u16 save0 = s0->control.checksum;
	    u16 computed0;
	    s0->control.checksum = 0;
	    computed0 = ~ip_csum_fold (ip_incremental_checksum (0, &s0->control, l3_len0));
	    error0 = save0 != computed0 ? SRP_ERROR_CONTROL_BAD_CHECKSUM : error0;
	  }

	  if (error0 == SRP_ERROR_CONTROL_PACKETS_PROCESSED)
	    {
	      static srp_control_handler_function_t * t[SRP_N_CONTROL_PACKET_TYPE] = {
		[SRP_CONTROL_PACKET_TYPE_topology] = srp_topology_packet,
	      };
	      srp_control_handler_function_t * f;

	      f = 0;
	      if (s0->control.type < ARRAY_LEN (t))
		f = t[s0->control.type];

	      if (f)
		{
		  vec_validate (contents, l2_len0 - 1);
		  vlib_buffer_contents (vm, bi0, contents);
		  error0 = f (vm, vnet_buffer (b0)->sw_if_index[VLIB_RX], &contents);
		}
	      else
		error0 = SRP_ERROR_UNKNOWN_CONTROL;
	    }

	  b0->error = error_node->errors[error0];
	  next0 = 0;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static vlib_node_registration_t srp_control_input_node = {
  .function = srp_control_input,
  .name = "srp-control",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },

  .format_buffer = format_srp_header_with_length,
  .format_trace = format_srp_input_trace,
  .unformat_buffer = unformat_srp_header,
};

static u8 * format_srp_ips_request_type (u8 * s, va_list * args)
{
  u32 x = va_arg (*args, u32);
  char * t = 0;
  switch (x)
    {
#define _(f,n) case SRP_IPS_REQUEST_##f: t = #f; break;
      foreach_srp_ips_request_type
#undef _
    default:
      return format (s, "unknown 0x%x", x);
    }
  return format (s, "%U", format_c_identifier, t);
}

static u8 * format_srp_ips_status (u8 * s, va_list * args)
{
  u32 x = va_arg (*args, u32);
  char * t = 0;
  switch (x)
    {
#define _(f,n) case SRP_IPS_STATUS_##f: t = #f; break;
      foreach_srp_ips_status
#undef _
    default:
      return format (s, "unknown 0x%x", x);
    }
  return format (s, "%U", format_c_identifier, t);
}

static u8 * format_srp_ips_state (u8 * s, va_list * args)
{
  u32 x = va_arg (*args, u32);
  char * t = 0;
  switch (x)
    {
#define _(f) case SRP_IPS_STATE_##f: t = #f; break;
      foreach_srp_ips_state
#undef _
    default:
      return format (s, "unknown 0x%x", x);
    }
  return format (s, "%U", format_c_identifier, t);
}

static u8 * format_srp_ring (u8 * s, va_list * args)
{
  u32 ring = va_arg (*args, u32);
  return format (s, "%s", ring == SRP_RING_INNER ? "inner" : "outer");
}

static u8 * format_srp_ips_header (u8 * s, va_list * args)
{
  srp_ips_header_t * h = va_arg (*args, srp_ips_header_t *);

  s = format (s, "%U, %U, %U, %s-path",
	      format_srp_ips_request_type, h->request_type,
	      format_ethernet_address, h->originator_address,
	      format_srp_ips_status, h->status,
	      h->is_long_path ? "long" : "short");

  return s;
}

static u8 * format_srp_interface (u8 * s, va_list * args)
{
  srp_interface_t * si = va_arg (*args, srp_interface_t *);
  srp_interface_ring_t * ir;

  s = format (s, "address %U, IPS state %U",
	      format_ethernet_address, si->my_address,
	      format_srp_ips_state, si->current_ips_state);
  for (ir = si->rings; ir < si->rings + SRP_N_RING; ir++)
    if (ir->rx_neighbor_address_valid)
      s = format (s, ", %U neighbor %U",
		  format_srp_ring, ir->ring,
		  format_ethernet_address, ir->rx_neighbor_address);

  return s;
}

u8 * format_srp_device (u8 * s, va_list * args)
{
  u32 hw_if_index = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);
  vnet_main_t * vnm = vnet_get_main();
  srp_main_t * sm = &srp_main;
  vnet_hw_interface_t * hi = vnet_get_hw_interface (vnm, hw_if_index);
  srp_interface_t * si = pool_elt_at_index (sm->interface_pool, hi->hw_instance);
  return format (s, "%U", format_srp_interface, si);
}

always_inline srp_interface_t *
srp_get_interface (u32 sw_if_index, srp_ring_type_t * ring)
{
  vnet_main_t * vnm = vnet_get_main();
  srp_main_t * sm = &srp_main;
  vnet_hw_interface_t * hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  srp_interface_t * si;

  ASSERT (hi->hw_class_index == srp_hw_interface_class.index);
  si = pool_elt_at_index (sm->interface_pool, hi->hw_instance);

  ASSERT (si->rings[SRP_RING_INNER].hw_if_index == hi->hw_if_index
	  || si->rings[SRP_RING_OUTER].hw_if_index == hi->hw_if_index);
  if (ring)
    *ring =
      (hi->hw_if_index == si->rings[SRP_RING_INNER].hw_if_index
       ? SRP_RING_INNER
       : SRP_RING_OUTER);

  return si;
}

static void init_ips_packet (srp_interface_t * si,
			     srp_ring_type_t tx_ring,
			     srp_ips_header_t * i)
{
  clib_memset (i, 0, sizeof (i[0]));

  i->srp.ttl = 1;
  i->srp.is_inner_ring = tx_ring;
  i->srp.priority = 7;
  i->srp.mode = SRP_MODE_control_locally_buffered_for_host;
  srp_header_compute_parity (&i->srp);

  clib_memcpy_fast (&i->ethernet.src_address, &si->my_address, sizeof (si->my_address));
  i->ethernet.type = clib_host_to_net_u16 (ETHERNET_TYPE_SRP_CONTROL);

  /* Checksum will be filled in later. */
  i->control.version = 0;
  i->control.type = SRP_CONTROL_PACKET_TYPE_ips;
  i->control.ttl = 255;

  clib_memcpy_fast (&i->originator_address, &si->my_address, sizeof (si->my_address));
}

static void tx_ips_packet (srp_interface_t * si,
			   srp_ring_type_t tx_ring,
			   srp_ips_header_t * i)
{
  srp_main_t * sm = &srp_main;
  vnet_main_t * vnm = vnet_get_main();
  vlib_main_t * vm = sm->vlib_main;
  vnet_hw_interface_t * hi = vnet_get_hw_interface (vnm, si->rings[tx_ring].hw_if_index);
  vlib_frame_t * f;
  vlib_buffer_t * b;
  u32 * to_next, bi = ~0;

  if (! vnet_sw_interface_is_admin_up (vnm, hi->sw_if_index))
    return;
  if (hi->hw_class_index != srp_hw_interface_class.index)
    return;

  i->control.checksum
    = ~ip_csum_fold (ip_incremental_checksum (0, &i->control,
					      sizeof (i[0]) - STRUCT_OFFSET_OF (srp_ips_header_t, control)));

  if (vlib_buffer_add_data (vm, /* buffer to append to */ &bi, i,
			    sizeof (i[0])))
    {
      /* complete or partial allocation failure */
      if (bi != ~0)
        vlib_buffer_free (vm, &bi, 1);
      return;
    }

  /* FIXME trace. */
  if (0)
    clib_warning ("%U %U",
		  format_vnet_sw_if_index_name, vnm, hi->sw_if_index,
		  format_srp_ips_header, i);

  b = vlib_get_buffer (vm, bi);
  vnet_buffer (b)->sw_if_index[VLIB_RX] = vnet_buffer (b)->sw_if_index[VLIB_TX] = hi->sw_if_index;

  f = vlib_get_frame_to_node (vm, hi->output_node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, hi->output_node_index, f);
}

static int requests_switch (srp_ips_request_type_t r)
{
  static u8 t[16] = {
    [SRP_IPS_REQUEST_forced_switch] = 1,
    [SRP_IPS_REQUEST_manual_switch] = 1,
    [SRP_IPS_REQUEST_signal_fail] = 1,
    [SRP_IPS_REQUEST_signal_degrade] = 1,
  };
  return (int) r < ARRAY_LEN (t) ? t[r] : 0;
}

/* Called when an IPS control packet is received on given interface. */
void srp_ips_rx_packet (u32 sw_if_index, srp_ips_header_t * h)
{
  vnet_main_t * vnm = vnet_get_main();
  vlib_main_t * vm = srp_main.vlib_main;
  srp_ring_type_t rx_ring;
  srp_interface_t * si = srp_get_interface (sw_if_index, &rx_ring);
  srp_interface_ring_t * ir = &si->rings[rx_ring];

  /* FIXME trace. */
  if (0)
    clib_warning ("%U %U %U",
		  format_time_interval, "h:m:s:u", vlib_time_now (vm),
		  format_vnet_sw_if_index_name, vnm, sw_if_index,
		  format_srp_ips_header, h);

  /* Ignore self-generated IPS packets. */
  if (! memcmp (h->originator_address, si->my_address, sizeof (h->originator_address)))
    goto done;

  /* Learn neighbor address from short path messages. */
  if (! h->is_long_path)
    {
      if (ir->rx_neighbor_address_valid
	  && memcmp (ir->rx_neighbor_address, h->originator_address, sizeof (ir->rx_neighbor_address)))
	{
	  ASSERT (0);
	}
      ir->rx_neighbor_address_valid = 1;
      clib_memcpy_fast (ir->rx_neighbor_address, h->originator_address, sizeof (ir->rx_neighbor_address));
    }

  switch (si->current_ips_state)
    {
    case SRP_IPS_STATE_idle:
      /* Received {REQ,NEIGHBOR,W,S} in idle state: wrap. */
      if (requests_switch (h->request_type)
	  && ! h->is_long_path
	  && h->status == SRP_IPS_STATUS_wrapped)
	{
	  srp_ips_header_t to_tx[2];

	  si->current_ips_state = SRP_IPS_STATE_wrapped;
	  si->hw_wrap_function (si->rings[SRP_SIDE_A].hw_if_index, /* enable_wrap */ 1);
	  si->hw_wrap_function (si->rings[SRP_SIDE_B].hw_if_index, /* enable_wrap */ 1);

	  init_ips_packet (si, rx_ring ^ 0, &to_tx[0]);
	  to_tx[0].request_type = SRP_IPS_REQUEST_idle;
	  to_tx[0].status = SRP_IPS_STATUS_wrapped;
	  to_tx[0].is_long_path = 0;
	  tx_ips_packet (si, rx_ring ^ 0, &to_tx[0]);

	  init_ips_packet (si, rx_ring ^ 1, &to_tx[1]);
	  to_tx[1].request_type = h->request_type;
	  to_tx[1].status = SRP_IPS_STATUS_wrapped;
	  to_tx[1].is_long_path = 1;
	  tx_ips_packet (si, rx_ring ^ 1, &to_tx[1]);
	}
      break;

    case SRP_IPS_STATE_wrapped:
      if (! h->is_long_path
	  && h->request_type == SRP_IPS_REQUEST_idle
	  && h->status == SRP_IPS_STATUS_idle)
	{
	  si->current_ips_state = SRP_IPS_STATE_idle;
	  si->hw_wrap_function (si->rings[SRP_SIDE_A].hw_if_index, /* enable_wrap */ 0);
	  si->hw_wrap_function (si->rings[SRP_SIDE_B].hw_if_index, /* enable_wrap */ 0);
	}
      break;

    case SRP_IPS_STATE_pass_thru:
      /* FIXME */
      break;

    default:
      abort ();
      break;
    }
 done:
  ;
}

/* Preform local IPS request on given interface. */
void srp_ips_local_request (u32 sw_if_index, srp_ips_request_type_t request)
{
  vnet_main_t * vnm = vnet_get_main();
  srp_main_t * sm = &srp_main;
  srp_ring_type_t rx_ring;
  srp_interface_t * si = srp_get_interface (sw_if_index, &rx_ring);
  srp_interface_ring_t * ir = &si->rings[rx_ring];

  if (request == SRP_IPS_REQUEST_wait_to_restore)
    {
      if (si->current_ips_state != SRP_IPS_STATE_wrapped)
	return;
      if (! ir->waiting_to_restore)
	{
	  ir->wait_to_restore_start_time = vlib_time_now (sm->vlib_main);
	  ir->waiting_to_restore = 1;
	}
    }
  else
    {
      /* FIXME handle local signal fail. */
      ir->wait_to_restore_start_time = 0;
      ir->waiting_to_restore = 0;
    }

  /* FIXME trace. */
  if (0)
    clib_warning ("%U %U",
		  format_vnet_sw_if_index_name, vnm, sw_if_index,
		  format_srp_ips_request_type, request);

}

static void maybe_send_ips_message (srp_interface_t * si)
{
  srp_main_t * sm = &srp_main;
  srp_ips_header_t to_tx[2];
  srp_ring_type_t rx_ring = SRP_RING_OUTER;
  srp_interface_ring_t * r0 = &si->rings[rx_ring ^ 0];
  srp_interface_ring_t * r1 = &si->rings[rx_ring ^ 1];
  f64 now = vlib_time_now (sm->vlib_main);

  if (! si->ips_process_enable)
    return;

  if (si->current_ips_state == SRP_IPS_STATE_wrapped
      && r0->waiting_to_restore
      && r1->waiting_to_restore
      && now >= r0->wait_to_restore_start_time + si->config.wait_to_restore_idle_delay
      && now >= r1->wait_to_restore_start_time + si->config.wait_to_restore_idle_delay)
    {
      si->current_ips_state = SRP_IPS_STATE_idle;
      r0->waiting_to_restore = r1->waiting_to_restore = 0;
      r0->wait_to_restore_start_time = r1->wait_to_restore_start_time = 0;
    }

  if (si->current_ips_state != SRP_IPS_STATE_idle)
    return;

  init_ips_packet (si, rx_ring ^ 0, &to_tx[0]);
  init_ips_packet (si, rx_ring ^ 1, &to_tx[1]);

  if (si->current_ips_state == SRP_IPS_STATE_idle)
    {
      to_tx[0].request_type = to_tx[1].request_type = SRP_IPS_REQUEST_idle;
      to_tx[0].status = to_tx[1].status = SRP_IPS_STATUS_idle;
      to_tx[0].is_long_path = to_tx[1].is_long_path = 0;
    }

  else if (si->current_ips_state == SRP_IPS_STATE_wrapped)
    {
      to_tx[0].request_type =
	(si->rings[rx_ring ^ 0].waiting_to_restore
	 ? SRP_IPS_REQUEST_wait_to_restore
	 : SRP_IPS_REQUEST_signal_fail);
      to_tx[1].request_type =
	(si->rings[rx_ring ^ 1].waiting_to_restore
	 ? SRP_IPS_REQUEST_wait_to_restore
	 : SRP_IPS_REQUEST_signal_fail);
      to_tx[0].status = to_tx[1].status = SRP_IPS_STATUS_wrapped;
      to_tx[0].is_long_path = 0;
      to_tx[1].is_long_path = 1;
    }

  tx_ips_packet (si, rx_ring ^ 0, &to_tx[0]);
  tx_ips_packet (si, rx_ring ^ 1, &to_tx[1]);
}

static uword
srp_ips_process (vlib_main_t * vm,
		 vlib_node_runtime_t * rt,
		 vlib_frame_t * f)
{
  srp_main_t * sm = &srp_main;
  srp_interface_t * si;

  while (1)
    {
      pool_foreach (si, sm->interface_pool, ({
	maybe_send_ips_message (si);
      }));
      vlib_process_suspend (vm, 1.0);
    }

  return 0;
}

vlib_node_registration_t srp_ips_process_node = {
    .function = srp_ips_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "srp-ips-process",
    .state = VLIB_NODE_STATE_DISABLED,
};

static clib_error_t * srp_init (vlib_main_t * vm)
{
  srp_main_t * sm = &srp_main;

  sm->default_data_ttl = 255;
  sm->vlib_main = vm;
  vlib_register_node (vm, &srp_ips_process_node);
  vlib_register_node (vm, &srp_input_node);
  vlib_register_node (vm, &srp_control_input_node);
  srp_setup_node (vm, srp_input_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (srp_init);
