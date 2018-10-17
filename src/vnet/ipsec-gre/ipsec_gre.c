/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief L2-GRE over IPSec packet processing.
 *
 * Add GRE header to thr packet and send it to the esp-encrypt node.
*/

#include <vnet/vnet.h>
#include <vnet/ipsec-gre/ipsec_gre.h>

ipsec_gre_main_t ipsec_gre_main;

/**
 * @brief IPv4 and GRE header union.
 *
*/
typedef struct
{
  union
  {
    ip4_and_gre_header_t ip4_and_gre;
    u64 as_u64[3];
  };
} ip4_and_gre_union_t;

/**
 * @brief Packet trace.
 *
*/
typedef struct
{
  u32 tunnel_id; /**< Tunnel-id / index in tunnel vector */

  u32 length; /**< pkt length */

  ip4_address_t src; /**< tunnel src IPv4 address */
  ip4_address_t dst; /**< tunnel dst IPv4 address */

  u32 sa_id; /**< tunnel IPSec SA id */
} ipsec_gre_tx_trace_t;

u8 *
format_ipsec_gre_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_gre_tx_trace_t *t = va_arg (*args, ipsec_gre_tx_trace_t *);

  s = format (s, "GRE: tunnel %d len %d src %U dst %U sa-id %d",
	      t->tunnel_id, clib_net_to_host_u16 (t->length),
	      format_ip4_address, &t->src.as_u8,
	      format_ip4_address, &t->dst.as_u8, t->sa_id);
  return s;
}

/**
 * @brief IPSec-GRE tunnel interface tx function.
 *
 * Add GRE header to the packet.
 *
 * @param vm vlib_main_t corresponding to the current thread.
 * @param node vlib_node_runtime_t data for this node.
 * @param frame vlib_frame_t whose contents should be dispatched.
 *
 * @par Graph mechanics: buffer metadata, next index usage
 *
 * <em>Uses:</em>
 * - <code>node->runtime_data</code>
 *     - Match tunnel by <code>rd->dev_instance</code> in IPSec-GRE tunnels
 *       pool.
 *
 * <em>Sets:</em>
 * - <code>vnet_buffer(b)->output_features.ipsec_sad_index</code>
 *     - Set IPSec Security Association for packet encryption.
 * - <code>vnet_buffer(b)->sw_if_index[VLIB_TX]</code>
 *     - Reset output sw_if_index.
 *
 * <em>Next Index:</em>
 * - Dispatches the packet to the esp-encrypt node.
*/
static uword
ipsec_gre_interface_tx (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ipsec_gre_main_t *igm = &ipsec_gre_main;
  u32 next_index;
  u32 *from, *to_next, n_left_from, n_left_to_next;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  ipsec_gre_tunnel_t *t = pool_elt_at_index (igm->tunnels, rd->dev_instance);

  /* Vector of buffer / pkt indices we're supposed to process */
  from = vlib_frame_vector_args (frame);

  /* Number of buffers / pkts */
  n_left_from = frame->n_vectors;

  /* Speculatively send the first buffer to the last disposition we used */
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      /* set up to enqueue to our disposition with index = next_index */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /*
       * As long as we have enough pkts left to process two pkts
       * and prefetch two pkts...
       */
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *b0, *b1;
	  ip4_header_t *ip0, *ip1;
	  ip4_and_gre_union_t *h0, *h1;
	  u32 bi0, next0, bi1, next1;
	  __attribute__ ((unused)) u8 error0, error1;
	  u16 gre_protocol0, gre_protocol1;

	  /* Prefetch the next iteration */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    /*
	     * Prefetch packet data. We expect to overwrite
	     * the inbound L2 header with an ip header and a
	     * gre header. Might want to prefetch the last line
	     * of rewrite space as well; need profile data
	     */
	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* Pick up the next two buffer indices */
	  bi0 = from[0];
	  bi1 = from[1];

	  /* Speculatively enqueue them where we sent the last buffer */
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  ip0 = vlib_buffer_get_current (b0);
	  gre_protocol0 = clib_net_to_host_u16 (0x01);

	  ip1 = vlib_buffer_get_current (b1);
	  gre_protocol1 = clib_net_to_host_u16 (0x01);

	  vlib_buffer_advance (b0, -sizeof (*h0));
	  vlib_buffer_advance (b1, -sizeof (*h1));

	  h0 = vlib_buffer_get_current (b0);
	  h1 = vlib_buffer_get_current (b1);
	  h0->as_u64[0] = 0;
	  h0->as_u64[1] = 0;
	  h0->as_u64[2] = 0;

	  h1->as_u64[0] = 0;
	  h1->as_u64[1] = 0;
	  h1->as_u64[2] = 0;

	  ip0 = &h0->ip4_and_gre.ip4;
	  h0->ip4_and_gre.gre.protocol = gre_protocol0;
	  ip0->ip_version_and_header_length = 0x45;
	  ip0->ttl = 254;
	  ip0->protocol = IP_PROTOCOL_GRE;

	  ip1 = &h1->ip4_and_gre.ip4;
	  h1->ip4_and_gre.gre.protocol = gre_protocol1;
	  ip1->ip_version_and_header_length = 0x45;
	  ip1->ttl = 254;
	  ip1->protocol = IP_PROTOCOL_GRE;

	  ip0->length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
	  ip1->length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b1));
	  ip0->src_address.as_u32 = t->tunnel_src.as_u32;
	  ip1->src_address.as_u32 = t->tunnel_src.as_u32;
	  ip0->dst_address.as_u32 = t->tunnel_dst.as_u32;
	  ip1->dst_address.as_u32 = t->tunnel_dst.as_u32;
	  ip0->checksum = ip4_header_checksum (ip0);
	  ip1->checksum = ip4_header_checksum (ip1);

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	    vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  vnet_buffer (b1)->sw_if_index[VLIB_RX] =
	    vnet_buffer (b1)->sw_if_index[VLIB_TX];

	  vnet_buffer (b0)->ipsec.sad_index = t->local_sa;
	  vnet_buffer (b1)->ipsec.sad_index = t->local_sa;

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  next0 = IPSEC_GRE_OUTPUT_NEXT_ESP_ENCRYPT;
	  next1 = IPSEC_GRE_OUTPUT_NEXT_ESP_ENCRYPT;
	  error0 = IPSEC_GRE_ERROR_NONE;
	  error1 = IPSEC_GRE_ERROR_NONE;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_gre_tx_trace_t *tr = vlib_add_trace (vm, node,
							 b0, sizeof (*tr));
	      tr->tunnel_id = t - igm->tunnels;
	      tr->length = ip0->length;
	      tr->src.as_u32 = ip0->src_address.as_u32;
	      tr->dst.as_u32 = ip0->dst_address.as_u32;
	      tr->sa_id = t->local_sa_id;
	    }

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_gre_tx_trace_t *tr = vlib_add_trace (vm, node,
							 b1, sizeof (*tr));
	      tr->tunnel_id = t - igm->tunnels;
	      tr->length = ip1->length;
	      tr->src.as_u32 = ip1->src_address.as_u32;
	      tr->dst.as_u32 = ip1->dst_address.as_u32;
	      tr->sa_id = t->local_sa_id;
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  ip4_header_t *ip0;
	  ip4_and_gre_union_t *h0;
	  u32 bi0, next0;
	  __attribute__ ((unused)) u8 error0;
	  u16 gre_protocol0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  gre_protocol0 = clib_net_to_host_u16 (0x01);

	  vlib_buffer_advance (b0, -sizeof (*h0));

	  h0 = vlib_buffer_get_current (b0);
	  h0->as_u64[0] = 0;
	  h0->as_u64[1] = 0;
	  h0->as_u64[2] = 0;

	  ip0 = &h0->ip4_and_gre.ip4;
	  h0->ip4_and_gre.gre.protocol = gre_protocol0;
	  ip0->ip_version_and_header_length = 0x45;
	  ip0->ttl = 254;
	  ip0->protocol = IP_PROTOCOL_GRE;
	  ip0->length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
	  ip0->src_address.as_u32 = t->tunnel_src.as_u32;
	  ip0->dst_address.as_u32 = t->tunnel_dst.as_u32;
	  ip0->checksum = ip4_header_checksum (ip0);

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	    vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  vnet_buffer (b0)->ipsec.sad_index = t->local_sa;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  next0 = IPSEC_GRE_OUTPUT_NEXT_ESP_ENCRYPT;
	  error0 = IPSEC_GRE_ERROR_NONE;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_gre_tx_trace_t *tr = vlib_add_trace (vm, node,
							 b0, sizeof (*tr));
	      tr->tunnel_id = t - igm->tunnels;
	      tr->length = ip0->length;
	      tr->src.as_u32 = ip0->src_address.as_u32;
	      tr->dst.as_u32 = ip0->dst_address.as_u32;
	      tr->sa_id = t->local_sa_id;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ipsec_gre_input_node.index,
			       IPSEC_GRE_ERROR_PKTS_ENCAP, frame->n_vectors);

  return frame->n_vectors;
}

static clib_error_t *
ipsec_gre_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				   u32 flags)
{
  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags (vnm, hw_if_index,
				 VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, hw_if_index, 0 /* down */ );

  return /* no error */ 0;
}

static u8 *
format_ipsec_gre_tunnel_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "ipsec-gre%d", dev_instance);
}

static u8 *
format_ipsec_gre_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);

  s = format (s, "IPSEC-GRE tunnel: id %d\n", dev_instance);
  return s;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ipsec_gre_device_class) = {
  .name = "IPSec GRE tunnel device",
  .format_device_name = format_ipsec_gre_tunnel_name,
  .format_device = format_ipsec_gre_device,
  .format_tx_trace = format_ipsec_gre_tx_trace,
  .tx_function = ipsec_gre_interface_tx,
  .admin_up_down_function = ipsec_gre_interface_admin_up_down,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (ipsec_gre_device_class,
				   ipsec_gre_interface_tx)


VNET_HW_INTERFACE_CLASS (ipsec_gre_hw_interface_class) = {
  .name = "IPSEC-GRE",
};
/* *INDENT-ON* */

static clib_error_t *
ipsec_gre_init (vlib_main_t * vm)
{
  ipsec_gre_main_t *igm = &ipsec_gre_main;
  clib_error_t *error;

  clib_memset (igm, 0, sizeof (igm[0]));
  igm->vlib_main = vm;
  igm->vnet_main = vnet_get_main ();

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;

  igm->tunnel_by_key = hash_create (0, sizeof (uword));

  return vlib_call_init_function (vm, ipsec_gre_input_init);
}

VLIB_INIT_FUNCTION (ipsec_gre_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
