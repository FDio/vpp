/*
 * l2_efp_filter.c : layer 2 egress EFP Filter processing
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_output.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/error.h>
#include <vppinfra/cache.h>

/**
 * @file
 * @brief EFP-filter - Ethernet Flow Point Filter.
 *
 * It is possible to transmit a packet out a subinterface with VLAN tags
 * that are not compatible with that subinterface. In other words, if that
 * packet arrived on the output port, it would not be classified as coming
 * from the output subinterface. This can happen in various ways: through
 * misconfiguration, by putting subinterfaces with different VLAN encaps in
 * the same bridge-domain, etc. The EFP Filter Check detects such packets
 * and drops them. It consists of two checks, one that verifies the packet
 * prior to output VLAN tag rewrite and one that verifies the packet after
 * VLAN tag rewrite.
 *
 */
typedef struct
{
  /* Next nodes for L2 output features */
  u32 l2_out_feat_next[32];

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2_efp_filter_main_t;


typedef struct
{
  /* per-pkt trace data */
  u8 src[6];
  u8 dst[6];
  u8 raw[12];			/* raw data (vlans) */
  u32 sw_if_index;
} l2_efp_filter_trace_t;

/* packet trace format function */
static u8 *
format_l2_efp_filter_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_efp_filter_trace_t *t = va_arg (*args, l2_efp_filter_trace_t *);

  s = format (s, "l2-output-vtr: sw_if_index %d dst %U src %U data "
	      "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
	      t->sw_if_index,
	      format_ethernet_address, t->dst,
	      format_ethernet_address, t->src,
	      t->raw[0], t->raw[1], t->raw[2], t->raw[3], t->raw[4],
	      t->raw[5], t->raw[6], t->raw[7], t->raw[8], t->raw[9],
	      t->raw[10], t->raw[11]);
  return s;
}

l2_efp_filter_main_t l2_efp_filter_main;

static vlib_node_registration_t l2_efp_filter_node;

#define foreach_l2_efp_filter_error			\
_(L2_EFP_FILTER, "L2 EFP filter packets")		\
_(DROP,          "L2 EFP filter post-rewrite drops")

typedef enum
{
#define _(sym,str) L2_EFP_FILTER_ERROR_##sym,
  foreach_l2_efp_filter_error
#undef _
    L2_EFP_FILTER_N_ERROR,
} l2_efp_filter_error_t;

static char *l2_efp_filter_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_efp_filter_error
#undef _
};

typedef enum
{
  L2_EFP_FILTER_NEXT_DROP,
  L2_EFP_FILTER_N_NEXT,
} l2_efp_filter_next_t;


/**
 *  Extract fields from the packet that will be used in interface
 *  classification.
 */
static_always_inline void
extract_keys (vnet_main_t * vnet_main,
	      u32 sw_if_index0,
	      vlib_buffer_t * b0,
	      u32 * port_sw_if_index0,
	      u16 * first_ethertype0,
	      u16 * outer_id0, u16 * inner_id0, u32 * match_flags0)
{
  ethernet_header_t *e0;
  ethernet_vlan_header_t *h0;
  u32 tag_len;
  u32 tag_num;

  *port_sw_if_index0 =
    vnet_get_sup_sw_interface (vnet_main, sw_if_index0)->sw_if_index;

  e0 = vlib_buffer_get_current (b0);
  h0 = (ethernet_vlan_header_t *) (e0 + 1);

  *first_ethertype0 = clib_net_to_host_u16 (e0->type);
  *outer_id0 = clib_net_to_host_u16 (h0[0].priority_cfi_and_id);
  *inner_id0 = clib_net_to_host_u16 (h0[1].priority_cfi_and_id);

  tag_len = vnet_buffer (b0)->l2.l2_len - sizeof (ethernet_header_t);
  tag_num = tag_len / sizeof (ethernet_vlan_header_t);
  *match_flags0 = eth_create_valid_subint_match_flags (tag_num);
}

/*
 * EFP filtering is a basic switch feature which prevents an interface from
 * transmitting a packet that doesn't match the interface's ingress match
 * criteria. The check has two parts, one performed before egress vlan tag
 * rewrite and one after.
 *
 * The pre-rewrite check insures the packet matches what an ingress packet looks
 * like after going through the interface's ingress tag rewrite operation. Only
 * pushed tags are compared. So:
 * - if the ingress vlan tag rewrite pushes no tags (or is not enabled),
 *   any packet passes the filter
 * - if the ingress vlan tag rewrite pushes one tag,
 *   the packet must have at least one tag, and the outer tag must match the pushed tag
 * - if the ingress vlan tag rewrite pushes two tags,
 *   the packet must have at least two tags, and the outer two tags must match the pushed tags
 *
 * The pre-rewrite check is performed in the l2-output node.
 *
 * The post-rewrite check insures the packet matches what an ingress packet looks
 * like before going through the interface's ingress tag rewrite operation. It verifies
 * that such a packet arriving on the wire at this port would be classified as arriving
 * an input interface equal to the packet's output interface. This can be done by running
 * the output packet's vlan tags and output port through the interface classification,
 * and checking if the resulting interface matches the output interface.
 *
 * The post-rewrite check is performed here.
 */

static uword
l2_efp_filter_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  l2_efp_filter_next_t next_index;
  l2_efp_filter_main_t *msm = &l2_efp_filter_main;
  vlib_node_t *n = vlib_get_node (vm, l2_efp_filter_node.index);
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
	  u16 first_ethertype0, first_ethertype1;
	  u16 outer_id0, inner_id0, outer_id1, inner_id1;
	  u32 match_flags0, match_flags1;
	  u32 port_sw_if_index0, subint_sw_if_index0, port_sw_if_index1,
	    subint_sw_if_index1;
	  vnet_hw_interface_t *hi0, *hi1;
	  main_intf_t *main_intf0, *main_intf1;
	  vlan_intf_t *vlan_intf0, *vlan_intf1;
	  qinq_intf_t *qinq_intf0, *qinq_intf1;
	  u32 is_l20, is_l21;
	  __attribute__ ((unused)) u32 matched0, matched1;
	  u8 error0, error1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3, *p4, *p5;
	    __attribute__ ((unused)) u32 sw_if_index2, sw_if_index3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);

	    /* Prefetch the buffer header and packet for the N+2 loop iteration */
	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);

	    CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);

	    /*
	     * Prefetch the input config for the N+1 loop iteration
	     * This depends on the buffer header above
	     */
	    sw_if_index2 = vnet_buffer (p2)->sw_if_index[VLIB_TX];
	    sw_if_index3 = vnet_buffer (p3)->sw_if_index[VLIB_TX];
	    /*
	     * $$$ TODO
	     * CLIB_PREFETCH (vec_elt_at_index(l2output_main.configs, sw_if_index2), CLIB_CACHE_LINE_BYTES, LOAD);
	     * CLIB_PREFETCH (vec_elt_at_index(l2output_main.configs, sw_if_index3), CLIB_CACHE_LINE_BYTES, LOAD);
	     */
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

	  /* TX interface handles */
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];

	  /* process 2 packets */
	  em->counters[node_counter_base_index +
		       L2_EFP_FILTER_ERROR_L2_EFP_FILTER] += 2;

	  /* Determine next node */
	  next0 = vnet_l2_feature_next (b0, msm->l2_out_feat_next,
					L2OUTPUT_FEAT_EFP_FILTER);
	  next1 = vnet_l2_feature_next (b1, msm->l2_out_feat_next,
					L2OUTPUT_FEAT_EFP_FILTER);

	  /* perform the efp filter check on two packets */

	  extract_keys (msm->vnet_main,
			sw_if_index0,
			b0,
			&port_sw_if_index0,
			&first_ethertype0,
			&outer_id0, &inner_id0, &match_flags0);

	  extract_keys (msm->vnet_main,
			sw_if_index1,
			b1,
			&port_sw_if_index1,
			&first_ethertype1,
			&outer_id1, &inner_id1, &match_flags1);

	  eth_vlan_table_lookups (&ethernet_main,
				  msm->vnet_main,
				  port_sw_if_index0,
				  first_ethertype0,
				  outer_id0,
				  inner_id0,
				  &hi0,
				  &main_intf0, &vlan_intf0, &qinq_intf0);

	  eth_vlan_table_lookups (&ethernet_main,
				  msm->vnet_main,
				  port_sw_if_index1,
				  first_ethertype1,
				  outer_id1,
				  inner_id1,
				  &hi1,
				  &main_intf1, &vlan_intf1, &qinq_intf1);

	  matched0 = eth_identify_subint (hi0,
					  b0,
					  match_flags0,
					  main_intf0,
					  vlan_intf0,
					  qinq_intf0,
					  &subint_sw_if_index0,
					  &error0, &is_l20);

	  matched1 = eth_identify_subint (hi1,
					  b1,
					  match_flags1,
					  main_intf1,
					  vlan_intf1,
					  qinq_intf1,
					  &subint_sw_if_index1,
					  &error1, &is_l21);

	  if (PREDICT_FALSE (sw_if_index0 != subint_sw_if_index0))
	    {
	      /* Drop packet */
	      next0 = L2_EFP_FILTER_NEXT_DROP;
	      b0->error = node->errors[L2_EFP_FILTER_ERROR_DROP];
	    }

	  if (PREDICT_FALSE (sw_if_index1 != subint_sw_if_index1))
	    {
	      /* Drop packet */
	      next1 = L2_EFP_FILTER_NEXT_DROP;
	      b1->error = node->errors[L2_EFP_FILTER_ERROR_DROP];
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ethernet_header_t *h0 = vlib_buffer_get_current (b0);
		  l2_efp_filter_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  clib_memcpy (t->src, h0->src_address, 6);
		  clib_memcpy (t->dst, h0->dst_address, 6);
		  clib_memcpy (t->raw, &h0->type, sizeof (t->raw));
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ethernet_header_t *h1 = vlib_buffer_get_current (b1);
		  l2_efp_filter_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  clib_memcpy (t->src, h1->src_address, 6);
		  clib_memcpy (t->dst, h1->dst_address, 6);
		  clib_memcpy (t->raw, &h1->type, sizeof (t->raw));
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
	  u16 first_ethertype0;
	  u16 outer_id0, inner_id0;
	  u32 match_flags0;
	  u32 port_sw_if_index0, subint_sw_if_index0;
	  vnet_hw_interface_t *hi0;
	  main_intf_t *main_intf0;
	  vlan_intf_t *vlan_intf0;
	  qinq_intf_t *qinq_intf0;
	  u32 is_l20;
	  __attribute__ ((unused)) u32 matched0;
	  u8 error0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

	  /* process 1 packet */
	  em->counters[node_counter_base_index +
		       L2_EFP_FILTER_ERROR_L2_EFP_FILTER] += 1;

	  /* Determine next node */
	  next0 = vnet_l2_feature_next (b0, msm->l2_out_feat_next,
					L2OUTPUT_FEAT_EFP_FILTER);

	  /* perform the efp filter check on one packet */

	  extract_keys (msm->vnet_main,
			sw_if_index0,
			b0,
			&port_sw_if_index0,
			&first_ethertype0,
			&outer_id0, &inner_id0, &match_flags0);

	  eth_vlan_table_lookups (&ethernet_main,
				  msm->vnet_main,
				  port_sw_if_index0,
				  first_ethertype0,
				  outer_id0,
				  inner_id0,
				  &hi0,
				  &main_intf0, &vlan_intf0, &qinq_intf0);

	  matched0 = eth_identify_subint (hi0,
					  b0,
					  match_flags0,
					  main_intf0,
					  vlan_intf0,
					  qinq_intf0,
					  &subint_sw_if_index0,
					  &error0, &is_l20);

	  if (PREDICT_FALSE (sw_if_index0 != subint_sw_if_index0))
	    {
	      /* Drop packet */
	      next0 = L2_EFP_FILTER_NEXT_DROP;
	      b0->error = node->errors[L2_EFP_FILTER_ERROR_DROP];
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      ethernet_header_t *h0 = vlib_buffer_get_current (b0);
	      l2_efp_filter_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      clib_memcpy (t->src, h0->src_address, 6);
	      clib_memcpy (t->dst, h0->dst_address, 6);
	      clib_memcpy (t->raw, &h0->type, sizeof (t->raw));
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
VLIB_REGISTER_NODE (l2_efp_filter_node,static) = {
  .function = l2_efp_filter_node_fn,
  .name = "l2-efp-filter",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_efp_filter_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2_efp_filter_error_strings),
  .error_strings = l2_efp_filter_error_strings,

  .n_next_nodes = L2_EFP_FILTER_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
       [L2_EFP_FILTER_NEXT_DROP]  = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (l2_efp_filter_node, l2_efp_filter_node_fn)
     clib_error_t *l2_efp_filter_init (vlib_main_t * vm)
{
  l2_efp_filter_main_t *mp = &l2_efp_filter_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2_efp_filter_node.index,
			       L2OUTPUT_N_FEAT,
			       l2output_get_feat_names (),
			       mp->l2_out_feat_next);

  return 0;
}

VLIB_INIT_FUNCTION (l2_efp_filter_init);


/** Enable/disable the EFP Filter check on the subinterface. */
void
l2_efp_filter_configure (vnet_main_t * vnet_main, u32 sw_if_index, u32 enable)
{
  /* set the interface flag */
  l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_EFP_FILTER, enable);
}


/**
 * Set subinterface egress efp filter enable/disable.
 * The CLI format is:
 *    set interface l2 efp-filter <interface> [disable]]
 */
static clib_error_t *
int_l2_efp_filter (vlib_main_t * vm,
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

  /* enable/disable the feature */
  l2_efp_filter_configure (vnm, sw_if_index, enable);

done:
  return error;
}


/*?
 * EFP filtering is a basic switch feature which prevents an interface from
 * transmitting a packet that doesn't match the interface's ingress match
 * criteria. The check has two parts, one performed before egress vlan tag
 * rewrite and one after. This command enables or disables the EFP filtering
 * for a given sub-interface.
 *
 * @cliexpar
 * Example of how to enable a Layer 2 efp-filter on a sub-interface:
 * @cliexcmd{set interface l2 efp-filter GigabitEthernet0/8/0.200}
 * Example of how to disable a Layer 2 efp-filter on a sub-interface:
 * @cliexcmd{set interface l2 efp-filter GigabitEthernet0/8/0.200 disable}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (int_l2_efp_filter_cli, static) = {
  .path = "set interface l2 efp-filter",
  .short_help = "set interface l2 efp-filter <interface> [disable]",
  .function = int_l2_efp_filter,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
