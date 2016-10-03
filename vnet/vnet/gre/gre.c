/*
 * gre.c: gre
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/gre/gre.h>
#include <vnet/adj/adj.h>

gre_main_t gre_main;

typedef struct {
  union {
    ip4_and_gre_header_t ip4_and_gre;
    u64 as_u64[3];
  };
} ip4_and_gre_union_t;


/* Packet trace structure */
typedef struct {
  /* Tunnel-id / index in tunnel vector */
  u32 tunnel_id;

  /* pkt length */
  u32 length;

  /* tunnel ip4 addresses */
  ip4_address_t src;
  ip4_address_t dst;
} gre_tx_trace_t;

u8 * format_gre_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gre_tx_trace_t * t = va_arg (*args, gre_tx_trace_t *);

  s = format (s, "GRE: tunnel %d len %d src %U dst %U",
	      t->tunnel_id, clib_net_to_host_u16 (t->length),
	      format_ip4_address, &t->src.as_u8,
	      format_ip4_address, &t->dst.as_u8);
  return s;
}

u8 * format_gre_protocol (u8 * s, va_list * args)
{
  gre_protocol_t p = va_arg (*args, u32);
  gre_main_t * gm = &gre_main;
  gre_protocol_info_t * pi = gre_get_protocol_info (gm, p);

  if (pi)
    s = format (s, "%s", pi->name);
  else
    s = format (s, "0x%04x", p);

  return s;
}

u8 * format_gre_header_with_length (u8 * s, va_list * args)
{
  gre_main_t * gm = &gre_main;
  gre_header_t * h = va_arg (*args, gre_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  gre_protocol_t p = clib_net_to_host_u16 (h->protocol);
  uword indent, header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "gre header truncated");

  indent = format_get_indent (s);

  s = format (s, "GRE %U", format_gre_protocol, p);

  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    {
      gre_protocol_info_t * pi = gre_get_protocol_info (gm, p);
      vlib_node_t * node = vlib_get_node (gm->vlib_main, pi->node_index);
      if (node->format_buffer)
	s = format (s, "\n%U%U",
		    format_white_space, indent,
		    node->format_buffer, (void *) (h + 1),
		    max_header_bytes - header_bytes);
    }

  return s;
}

u8 * format_gre_header (u8 * s, va_list * args)
{
  gre_header_t * h = va_arg (*args, gre_header_t *);
  return format (s, "%U", format_gre_header_with_length, h, 0);
}

/* Returns gre protocol as an int in host byte order. */
uword
unformat_gre_protocol_host_byte_order (unformat_input_t * input,
				       va_list * args)
{
  u16 * result = va_arg (*args, u16 *);
  gre_main_t * gm = &gre_main;
  int i;

  /* Named type. */
  if (unformat_user (input, unformat_vlib_number_by_name,
		     gm->protocol_info_by_name, &i))
    {
      gre_protocol_info_t * pi = vec_elt_at_index (gm->protocol_infos, i);
      *result = pi->protocol;
      return 1;
    }

  return 0;
}

uword
unformat_gre_protocol_net_byte_order (unformat_input_t * input,
				      va_list * args)
{
  u16 * result = va_arg (*args, u16 *);
  if (! unformat_user (input, unformat_gre_protocol_host_byte_order, result))
    return 0;
  *result = clib_host_to_net_u16 ((u16) *result);
  return 1;
}

uword
unformat_gre_header (unformat_input_t * input, va_list * args)
{
  u8 ** result = va_arg (*args, u8 **);
  gre_header_t _h, * h = &_h;
  u16 p;

  if (! unformat (input, "%U",
		  unformat_gre_protocol_host_byte_order, &p))
    return 0;

  h->protocol = clib_host_to_net_u16 (p);

  /* Add header to result. */
  {
    void * p;
    u32 n_bytes = sizeof (h[0]);

    vec_add2 (*result, p, n_bytes);
    clib_memcpy (p, h, n_bytes);
  }

  return 1;
}

static uword gre_set_rewrite (vnet_main_t * vnm,
			       u32 sw_if_index,
			       u32 l3_type,
			       void * dst_address,
			       void * rewrite,
			       uword max_rewrite_bytes)
{
  /*
   * Conundrum: packets from tun/tap destined for the tunnel
   * actually have this rewrite applied. Transit packets do not.
   * To make the two cases equivalent, don't generate a
   * rewrite here, build the entire header in the fast path.
   */
  return 0;

#ifdef THINGS_WORKED_AS_ONE_MIGHT_LIKE
  ip4_and_gre_header_t * h = rewrite;
  gre_protocol_t protocol;

  if (max_rewrite_bytes < sizeof (h[0]))
    return 0;

  switch (l3_type) {
#define _(a,b) case VNET_L3_PACKET_TYPE_##a: protocol = GRE_PROTOCOL_##b; break
    _ (IP4, ip4);
    _ (IP6, ip6);
#undef _
  default:
    return 0;
  }

  memset (h, 0, sizeof (*h));
  h->ip4.ip_version_and_header_length = 0x45;
  h->ip4.ttl = 64;
  h->ip4.protocol = IP_PROTOCOL_GRE;
  h->gre.protocol = clib_host_to_net_u16 (protocol);

  return sizeof (h[0]);
#endif
}

static uword
gre_interface_tx (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  gre_main_t * gm = &gre_main;
  u32 next_index;
  u32 * from, * to_next, n_left_from, n_left_to_next;
  vnet_interface_output_runtime_t * rd = (void *) node->runtime_data;
  gre_tunnel_t *t = pool_elt_at_index (gm->tunnels, rd->dev_instance);

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
       * FIXME DUAL LOOP
       */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, adj_index0, next0;
	  const ip_adjacency_t * adj0;
	  const dpo_id_t *dpo0;
	  ip4_header_t * ip0;
	  vlib_buffer_t * b0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer(vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);

	  /* Fixup the checksum and len fields in the GRE tunnel encap
	   * that was applied at the midchain node */
	  ip0->length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
	  ip0->checksum = ip4_header_checksum (ip0);

	  /* Follow the DPO on which the midchain is stacked */
	  adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
	  adj0 = adj_get(adj_index0);
	  dpo0 = &adj0->sub_type.midchain.next_dpo;
	  next0 = dpo0->dpoi_next_node;
	  vnet_buffer(b0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

	  if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gre_tx_trace_t *tr = vlib_add_trace (vm, node,
						   b0, sizeof (*tr));
	      tr->tunnel_id = t - gm->tunnels;
	      tr->length = ip0->length;
	      tr->src.as_u32 = ip0->src_address.as_u32;
	      tr->dst.as_u32 = ip0->dst_address.as_u32;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, gre_input_node.index,
			       GRE_ERROR_PKTS_ENCAP, frame->n_vectors);

  return frame->n_vectors;
}

static uword
gre_l2_interface_tx (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * frame)
{
  gre_main_t * gm = &gre_main;
  u32 next_index;
  u32 * from, * to_next, n_left_from, n_left_to_next;
  vnet_interface_output_runtime_t * rd = (void *) node->runtime_data;
  const gre_tunnel_t *gt = pool_elt_at_index (gm->tunnels, rd->dev_instance);

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
       * FIXME DUAL LOOP
       */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * b0;
	  u32 bi0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer(vm, bi0);

	  vnet_buffer(b0)->ip.adj_index[VLIB_TX] = gt->adj_index[FIB_LINK_ETHERNET];

	  if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gre_tx_trace_t *tr = vlib_add_trace (vm, node,
						   b0, sizeof (*tr));
	      tr->tunnel_id = gt - gm->tunnels;
	      tr->length = vlib_buffer_length_in_chain (vm, b0);
	      tr->src.as_u32 = gt->tunnel_src.as_u32;
	      tr->dst.as_u32 = gt->tunnel_src.as_u32;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, gt->l2_tx_arc);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, gre_input_node.index,
			       GRE_ERROR_PKTS_ENCAP, frame->n_vectors);

  return frame->n_vectors;
}

static clib_error_t *
gre_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  gre_main_t * gm = &gre_main;
  vnet_hw_interface_t * hi;
  gre_tunnel_t *t;
  u32 ti;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  ti = gm->tunnel_index_by_sw_if_index[hi->sw_if_index];

  if (~0 == ti)
      /* not one of ours */
      return (NULL);

  t = pool_elt_at_index(gm->tunnels, ti);

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags (vnm, hw_if_index, VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, hw_if_index, 0 /* down */);

  gre_tunnel_stack(t);

  return /* no error */ 0;
}

static u8 * format_gre_tunnel_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "gre%d", dev_instance);
}

static u8 * format_gre_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);

  s = format (s, "GRE tunnel: id %d\n", dev_instance);
  return s;
}

static u8 * format_gre_l2_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);

  s = format (s, "GRE L2-tunnel: id %d\n", dev_instance);
  return s;
}

VNET_DEVICE_CLASS (gre_device_class) = {
  .name = "GRE tunnel device",
  .format_device_name = format_gre_tunnel_name,
  .format_device = format_gre_device,
  .format_tx_trace = format_gre_tx_trace,
  .tx_function = gre_interface_tx,
  .admin_up_down_function = gre_interface_admin_up_down,
#ifdef SOON
  .clear counter = 0;
#endif
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (gre_device_class,
				   gre_interface_tx)

VNET_DEVICE_CLASS (gre_l2_device_class) = {
  .name = "GRE L2 tunnel device",
  .format_device_name = format_gre_tunnel_name,
  .format_device = format_gre_l2_device,
  .format_tx_trace = format_gre_tx_trace,
  .tx_function = gre_l2_interface_tx,
  .admin_up_down_function = gre_interface_admin_up_down,
#ifdef SOON
  .clear counter = 0;
#endif
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (gre_l2_device_class,
				   gre_l2_interface_tx)


VNET_HW_INTERFACE_CLASS (gre_hw_interface_class) = {
  .name = "GRE",
  .format_header = format_gre_header_with_length,
  .unformat_header = unformat_gre_header,
  .set_rewrite = gre_set_rewrite,
};

static void add_protocol (gre_main_t * gm,
			  gre_protocol_t protocol,
			  char * protocol_name)
{
  gre_protocol_info_t * pi;
  u32 i;

  vec_add2 (gm->protocol_infos, pi, 1);
  i = pi - gm->protocol_infos;

  pi->name = protocol_name;
  pi->protocol = protocol;
  pi->next_index = pi->node_index = ~0;

  hash_set (gm->protocol_info_by_protocol, protocol, i);
  hash_set_mem (gm->protocol_info_by_name, pi->name, i);
}

static clib_error_t * gre_init (vlib_main_t * vm)
{
  gre_main_t * gm = &gre_main;
  clib_error_t * error;
  ip_main_t * im = &ip_main;
  ip_protocol_info_t * pi;

  memset (gm, 0, sizeof (gm[0]));
  gm->vlib_main = vm;
  gm->vnet_main = vnet_get_main();

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;

  /* Set up the ip packet generator */
  pi = ip_get_protocol_info (im, IP_PROTOCOL_GRE);
  pi->format_header = format_gre_header;
  pi->unformat_pg_edit = unformat_pg_gre_header;

  gm->protocol_info_by_name = hash_create_string (0, sizeof (uword));
  gm->protocol_info_by_protocol = hash_create (0, sizeof (uword));
  gm->tunnel_by_key = hash_create (0, sizeof (uword));

#define _(n,s) add_protocol (gm, GRE_PROTOCOL_##s, #s);
  foreach_gre_protocol
#undef _

  return vlib_call_init_function (vm, gre_input_init);
}

VLIB_INIT_FUNCTION (gre_init);

gre_main_t * gre_get_main (vlib_main_t * vm)
{
  vlib_call_init_function (vm, gre_init);
  return &gre_main;
}

