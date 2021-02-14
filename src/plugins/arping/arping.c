/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <stddef.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip-neighbor/ip4_neighbor.h>
#include <vnet/ip-neighbor/ip6_neighbor.h>
#include <arping/arping.h>

arping_main_t arping_main;

#define foreach_arping_error _ (NONE, "no error")

typedef enum
{
#define _(f, s) ARPING_ERROR_##f,
  foreach_arping_error
#undef _
    ARPING_N_ERROR,
} arping__error_t;

static char *arping_error_strings[] = {
#define _(n, s) s,
  foreach_arping_error
#undef _
};

#define foreach_arping                                                        \
  _ (DROP, "error-drop")                                                      \
  _ (IO, "interface-output")

typedef enum
{
#define _(sym, str) ARPING_NEXT_##sym,
  foreach_arping
#undef _
    ARPING_N_NEXT,
} arping_next_t;

typedef struct arping_trace_t_
{
  u32 sw_if_index;
  u16 arp_opcode;
  ethernet_arp_ip4_over_ethernet_address_t reply;
} arping_trace_t;

typedef enum
{
#define _(sym, str) ARPING6_NEXT_##sym,
  foreach_arping
#undef _
    ARPING6_N_NEXT,
} arping6_next_t;

typedef CLIB_PACKED (struct {
  mac_address_t mac;
  ip6_address_t ip6;
}) ethernet_arp_ip6_over_ethernet_address_t;

typedef struct arping6_trace_t_
{
  u32 sw_if_index;
  u8 type;
  ethernet_arp_ip6_over_ethernet_address_t reply;
} arping6_trace_t;

/* packet trace format function */
static u8 *
format_arping_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  arping_trace_t *t = va_arg (*args, arping_trace_t *);

  s = format (s, "sw-if-index: %u, opcode: %U, from %U (%U)", t->sw_if_index,
	      format_ethernet_arp_opcode, t->arp_opcode, format_mac_address,
	      &t->reply.mac, format_ip4_address, &t->reply.ip4);

  return s;
}

static u8 *
format_arping6_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  arping6_trace_t *t = va_arg (*args, arping6_trace_t *);

  s = format (s, "sw-if-index: %u, type: %u, from %U (%U)", t->sw_if_index,
	      t->type, format_mac_address, &t->reply.mac, format_ip6_address,
	      &t->reply.ip6);

  return s;
}

VLIB_NODE_FN (arping_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  arping_next_t next_index;
  arping_main_t *am = &arping_main;

  next_index = node->cached_next_index;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 2 && n_left_to_next >= 2)
	{
	  u32 next0, next1, bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  ethernet_arp_header_t *arp0, *arp1;
	  u32 sw_if_index0, sw_if_index1;
	  arping_intf_t *aif0, *aif1;

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  next0 = next1 = ARPING_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  arp0 = vlib_buffer_get_current (b0);
	  arp1 = vlib_buffer_get_current (b1);

	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  if (PREDICT_TRUE (arp0->opcode ==
			    clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply)))
	    {
	      aif0 = am->interfaces[sw_if_index0];
	      if (PREDICT_TRUE (aif0->address.ip.ip4.as_u32 ==
				arp0->ip4_over_ethernet[0].ip4.as_u32))
		{
		  aif0->recv.from4.ip4.as_u32 =
		    arp0->ip4_over_ethernet[0].ip4.as_u32;
		  clib_memcpy_fast (&aif0->recv.from4.mac,
				    &arp0->ip4_over_ethernet[0].mac, 6);
		  aif0->reply_count++;
		}
	    }
	  if (PREDICT_TRUE (arp1->opcode ==
			    clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply)))
	    {
	      aif1 = am->interfaces[sw_if_index1];
	      if (PREDICT_TRUE (aif1->address.ip.ip4.as_u32 ==
				arp1->ip4_over_ethernet[0].ip4.as_u32))
		{
		  aif1->recv.from4.ip4.as_u32 =
		    arp1->ip4_over_ethernet[0].ip4.as_u32;
		  clib_memcpy_fast (&aif1->recv.from4.mac,
				    &arp0->ip4_over_ethernet[0].mac, 6);
		  aif1->reply_count++;
		}
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      arping_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->arp_opcode = clib_host_to_net_u16 (arp0->opcode);
	      t->reply.ip4.as_u32 = arp0->ip4_over_ethernet[0].ip4.as_u32;
	      clib_memcpy_fast (&t->reply.mac, &arp0->ip4_over_ethernet[0].mac,
				6);
	    }
	  if (PREDICT_FALSE ((b1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      arping_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	      t->arp_opcode = clib_host_to_net_u16 (arp1->opcode);
	      t->reply.ip4.as_u32 = arp1->ip4_over_ethernet[0].ip4.as_u32;
	      clib_memcpy_fast (&t->reply.mac, &arp1->ip4_over_ethernet[0].mac,
				6);
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 next0, bi0;
	  vlib_buffer_t *b0;
	  ethernet_arp_header_t *arp0;
	  arping_intf_t *aif0;
	  u32 sw_if_index0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  next0 = ARPING_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  arp0 = vlib_buffer_get_current (b0);

	  vnet_feature_next (&next0, b0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  if (PREDICT_TRUE (arp0->opcode ==
			    clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply)))
	    {
	      aif0 = am->interfaces[sw_if_index0];
	      if (PREDICT_TRUE (aif0->address.ip.ip4.as_u32 ==
				arp0->ip4_over_ethernet[0].ip4.as_u32))
		{
		  aif0->recv.from4.ip4.as_u32 =
		    arp0->ip4_over_ethernet[0].ip4.as_u32;
		  clib_memcpy_fast (&aif0->recv.from4.mac,
				    &arp0->ip4_over_ethernet[0].mac, 6);
		  aif0->reply_count++;
		}
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      arping_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->arp_opcode = clib_host_to_net_u16 (arp0->opcode);
	      t->reply.ip4.as_u32 = arp0->ip4_over_ethernet[0].ip4.as_u32;
	      clib_memcpy_fast (&t->reply.mac, &arp0->ip4_over_ethernet[0].mac,
				6);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (arping_input_node) =
{
  .name = "arping-input",.vector_size = sizeof (u32),.format_trace =
    format_arping_trace,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARPING_N_ERROR,.error_strings = arping_error_strings,.n_next_nodes =
    ARPING_N_NEXT,.next_nodes =
  {
  [ARPING_NEXT_DROP] = "error-drop",[ARPING_NEXT_IO] = "interface-output",}
,};

VNET_FEATURE_INIT (arping_feat_node, static) = {
  .arc_name = "arp",
  .node_name = "arping-input",
  .runs_before = VNET_FEATURES ("arp-reply"),
};

VLIB_NODE_FN (arping6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  arping_next_t next_index;
  arping_main_t *am = &arping_main;

  next_index = node->cached_next_index;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 2 && n_left_to_next >= 2)
	{
	  u32 next0, next1, bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  ip6_header_t *ip60, *ip61;
	  u32 sw_if_index0, sw_if_index1;
	  arping_intf_t *aif0, *aif1;
	  icmp6_neighbor_solicitation_or_advertisement_header_t *sol_adv0,
	    *sol_adv1;
	  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
	    *lladdr0,
	    *lladdr1;

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  next0 = next1 = ARPING6_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  ip60 = vlib_buffer_get_current (b0);
	  ip61 = vlib_buffer_get_current (b1);

	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  sol_adv0 = ip6_next_header (ip60);
	  lladdr0 = (void *) (sol_adv0 + 1);

	  if (PREDICT_TRUE (sol_adv0->icmp.type ==
			    ICMP6_neighbor_advertisement))
	    {
	      aif0 = am->interfaces[sw_if_index0];
	      if (PREDICT_TRUE (clib_memcmp (&aif0->address.ip.ip6,
					     &sol_adv0->target_address,
					     sizeof (aif0->address.ip.ip6)) ==
				0))
		{
		  clib_memcpy_fast (&aif0->recv.from6.ip6,
				    &sol_adv0->target_address,
				    sizeof (aif0->recv.from6.ip6));
		  clib_memcpy_fast (&aif0->recv.from6.mac,
				    lladdr0->ethernet_address, 6);
		  aif0->reply_count++;
		}
	    }

	  sol_adv1 = ip6_next_header (ip61);
	  lladdr1 = (void *) (sol_adv1 + 1);

	  if (PREDICT_TRUE (sol_adv1->icmp.type ==
			    ICMP6_neighbor_advertisement))
	    {
	      aif1 = am->interfaces[sw_if_index1];
	      if (PREDICT_TRUE (clib_memcmp (&aif1->address.ip.ip6,
					     &sol_adv1->target_address,
					     sizeof (aif1->address.ip.ip6)) ==
				0))
		{
		  clib_memcpy_fast (&aif1->recv.from6.ip6,
				    &sol_adv1->target_address,
				    sizeof (aif1->recv.from6.ip6));
		  clib_memcpy_fast (&aif1->recv.from6.mac,
				    lladdr1->ethernet_address, 6);
		  aif1->reply_count++;
		}
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      arping6_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->type = sol_adv0->icmp.type;
	      clib_memcpy_fast (&t->reply.ip6, &sol_adv0->target_address,
				sizeof (t->reply.ip6));
	      clib_memcpy_fast (&t->reply.mac, lladdr0->ethernet_address, 6);
	    }
	  if (PREDICT_FALSE ((b1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      arping6_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	      t->type = sol_adv1->icmp.type;
	      clib_memcpy_fast (&t->reply.ip6, &sol_adv1->target_address,
				sizeof (t->reply.ip6));
	      clib_memcpy_fast (&t->reply.mac, lladdr1->ethernet_address, 6);
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 next0, bi0;
	  vlib_buffer_t *b0;
	  arping_intf_t *aif0;
	  u32 sw_if_index0;
	  ip6_header_t *ip60;
	  icmp6_neighbor_solicitation_or_advertisement_header_t *sol_adv0;
	  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
	    *lladdr0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  next0 = ARPING_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip60 = vlib_buffer_get_current (b0);

	  vnet_feature_next (&next0, b0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  sol_adv0 = ip6_next_header (ip60);
	  lladdr0 = (void *) (sol_adv0 + 1);
	  if (PREDICT_TRUE (sol_adv0->icmp.type ==
			    ICMP6_neighbor_advertisement))
	    {
	      aif0 = am->interfaces[sw_if_index0];
	      if (PREDICT_TRUE (clib_memcmp (&aif0->address.ip.ip6,
					     &sol_adv0->target_address,
					     sizeof (aif0->address.ip.ip6)) ==
				0))
		{
		  clib_memcpy_fast (&aif0->recv.from6.ip6,
				    &sol_adv0->target_address,
				    sizeof (aif0->recv.from6.ip6));
		  clib_memcpy_fast (&aif0->recv.from6.mac,
				    lladdr0->ethernet_address, 6);
		  aif0->reply_count++;
		}
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      arping6_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->type = sol_adv0->icmp.type;
	      clib_memcpy_fast (&t->reply.ip6, &sol_adv0->target_address,
				sizeof (t->reply.ip6));
	      clib_memcpy_fast (&t->reply.mac, lladdr0->ethernet_address, 6);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (arping6_input_node) =
{
  .name = "arping6-input",.vector_size = sizeof (u32),.format_trace =
    format_arping6_trace,.type = VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARPING_N_ERROR,.error_strings = arping_error_strings,.n_next_nodes =
    ARPING_N_NEXT,.next_nodes =
  {
  [ARPING6_NEXT_DROP] = "error-drop",[ARPING6_NEXT_IO] = "interface-output",}
,};

VNET_FEATURE_INIT (arping6_feat_node, static) = {
  .arc_name = "ip6-local",
  .node_name = "arping6-input",
  .runs_before = VNET_FEATURES ("ip6-local-end-of-arc"),
};

static clib_error_t *
arping_neighbor_advertisement (vlib_main_t *vm, arping_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();

  while (args->repeat > 0)
    {
      if (args->address.version == AF_IP4)
	ip4_neighbor_advertise (vm, vnm, args->sw_if_index,
				&args->address.ip.ip4);
      else
	ip6_neighbor_advertise (vm, vnm, args->sw_if_index,
				&args->address.ip.ip6);
      args->repeat--;
      if ((args->interval > 0.0) && (args->repeat > 0))
	vlib_process_suspend (vm, args->interval);
    }

  return 0;
}

static void
arping_vnet_feature_enable_disable (vlib_main_t *vm, const char *arc_name,
				    const char *node_name, u32 sw_if_index,
				    int enable_disable, void *feature_config,
				    u32 n_feature_config_bytes)
{
  vlib_worker_thread_barrier_sync (vm);
  vnet_feature_enable_disable (arc_name, node_name, sw_if_index,
			       enable_disable, feature_config,
			       n_feature_config_bytes);
  vlib_worker_thread_barrier_release (vm);
}

static void
arping_vec_validate (vlib_main_t *vm, u32 sw_if_index)
{
  arping_main_t *am = &arping_main;

  if (sw_if_index >= vec_len (am->interfaces))
    {
      vlib_worker_thread_barrier_sync (vm);
      vec_validate (am->interfaces, sw_if_index);
      vlib_worker_thread_barrier_release (vm);
    }
}

static clib_error_t *
arping_neighbor_probe_dst (vlib_main_t *vm, arping_args_t *args)
{
  arping_main_t *am = &arping_main;
  u32 send_count = 0;
  clib_error_t *error;
  arping_intf_t aif;

  /* Disallow multiple sends on the same interface for now. Who needs it? */
  if (am->interfaces && (am->interfaces[args->sw_if_index] != 0))
    {
      error = clib_error_return (
	0, "arping command is in progress for the same interface. "
	   "Please try again later.");
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      return error;
    }

  arping_vec_validate (vm, args->sw_if_index);
  clib_memset (&aif, 0, sizeof (aif));
  aif.interval = args->interval;
  aif.repeat = args->repeat;
  aif.reply_count = 0;
  am->interfaces[args->sw_if_index] = &aif;

  clib_memcpy (&aif.address, &args->address, sizeof (aif.address));
  if (args->address.version == AF_IP4)
    arping_vnet_feature_enable_disable (vm, "arp", "arping-input",
					args->sw_if_index, 1, 0, 0);
  else
    arping_vnet_feature_enable_disable (vm, "ip6-local", "arping6-input",
					args->sw_if_index, 1, 0, 0);

  while (args->repeat > 0)
    {
      send_count++;
      if (args->address.version == AF_IP4)
	{
	  if (args->silence == 0)
	    vlib_cli_output (vm, "Sending %u ARP Request to %U", send_count,
			     format_ip4_address, &args->address.ip.ip4);
	  ip4_neighbor_probe_dst (args->sw_if_index, &args->address.ip.ip4);
	}
      else
	{
	  if (args->silence == 0)
	    vlib_cli_output (vm, "Sending %u ARP Request to %U", send_count,
			     format_ip6_address, &args->address.ip.ip6);
	  ip6_neighbor_probe_dst (args->sw_if_index, &args->address.ip.ip6);
	}
      args->repeat--;
      if ((args->interval > 0.0) && (args->repeat > 0))
	vlib_process_suspend (vm, args->interval);
    }

  /* wait for a second on the reply */
  u32 wait_count = 0;
  while ((aif.reply_count < send_count) && (wait_count < 10))
    {
      vlib_process_suspend (vm, 0.1);
      wait_count++;
    }

  if (args->address.version == AF_IP4)
    {
      clib_memcpy (&args->recv.from4, &aif.recv.from4,
		   sizeof (args->recv.from4));
      arping_vnet_feature_enable_disable (vm, "arp", "arping-input",
					  args->sw_if_index, 0, 0, 0);
    }
  else
    {
      clib_memcpy (&args->recv.from6, &aif.recv.from6,
		   sizeof (args->recv.from6));
      arping_vnet_feature_enable_disable (vm, "ip6-local", "arping6-input",
					  args->sw_if_index, 0, 0, 0);
    }
  args->reply_count = aif.reply_count;

  am->interfaces[args->sw_if_index] = 0;

  return 0;
}

void
arping_run_command (vlib_main_t *vm, arping_args_t *args)
{
  if (args->is_garp)
    args->error = arping_neighbor_advertisement (vm, args);
  else
    args->error = arping_neighbor_probe_dst (vm, args);
}

static clib_error_t *
arping_ip_address (vlib_main_t *vm, unformat_input_t *input,
		   vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  vnet_main_t *vnm = vnet_get_main ();
  arping_args_t args = { 0 };
  f64 interval = ARPING_DEFAULT_INTERVAL;

  args.repeat = ARPING_DEFAULT_REPEAT;
  args.interval = ARPING_DEFAULT_INTERVAL;
  args.sw_if_index = ~0;
  args.silence = 0;

  if (unformat (input, "gratuitous"))
    args.is_garp = 1;

  if (unformat (input, "%U", unformat_ip4_address, &args.address.ip.ip4))
    args.address.version = AF_IP4;
  else if (unformat (input, "%U", unformat_ip6_address, &args.address.ip.ip6))
    args.address.version = AF_IP6;
  else
    {
      error = clib_error_return (
	0,
	"expecting IP4/IP6 address `%U'. Usage: arping [gratuitous] <addr> "
	"<intf> [repeat <count>] [interval <secs>]",
	format_unformat_error, input);
      goto done;
    }

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm,
		      &args.sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  /* parse the rest of the parameters  in a cycle */
  while (!unformat_eof (input, NULL))
    {
      if (unformat (input, "interval"))
	{
	  if (!unformat (input, "%f", &interval))
	    {
	      error = clib_error_return (
		0, "expecting interval (floating point number) got `%U'",
		format_unformat_error, input);
	      goto done;
	    }
	  args.interval = interval;
	}
      else if (unformat (input, "repeat"))
	{
	  if (!unformat (input, "%u", &args.repeat))
	    {
	      error =
		clib_error_return (0, "expecting repeat count but got `%U'",
				   format_unformat_error, input);
	      goto done;
	    }
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  arping_run_command (vm, &args);

  if (args.reply_count)
    {
      if (args.address.version == AF_IP4)
	vlib_cli_output (vm, "Received %u ARP Replies from %U (%U)",
			 args.reply_count, format_mac_address,
			 &args.recv.from4.mac, format_ip4_address,
			 &args.recv.from4.ip4);
      else
	vlib_cli_output (
	  vm, "Received %u ICMP6 neighbor advertisements from %U (%U)",
	  args.reply_count, format_mac_address, &args.recv.from6.mac,
	  format_ip6_address, &args.recv.from6.ip6);
    }
  else
    vlib_cli_output (vm, "Received 0 Reply");

  error = args.error;
done:
  return error;
}

/*?
 * This command sends an ARP_REQUEST or gratuitous ARP to network hosts. The
 * address can be an IPv4 or IPv6 address.
 *
 * @cliexpar
 * @parblock
 * Example of how to send an IPv4 ARP REQUEST
 * @cliexstart{arping 100.1.1.10 VirtualEthernet0/0/0 repeat 3 interval 1)
 * Sending 1 ARP Request to 100.1.1.10
 * Sending 2 ARP Request to 100.1.1.10
 * Sending 3 ARP Request to 100.1.1.10
 * Received 3 ARP Replies from 52:53:00:00:04:01 (100.1.1.10)
 * @cliexend
 *
 * @parblock
 * Example of how to send an IPv6 ARP REQUEST
 * @cliexstart{arping 2001:192::2 VirtualEthernet0/0/0 repeat 3 interval 1)
 * Sending 1 ARP Request to 2001:192::2
 * Sending 2 ARP Request to 2001:192::2
 * Sending 3 ARP Request to 2001:192::2
 * Received 3 ICMP6 neighbor advertisements from 52:53:00:00:04:01
(2001:192::2)
 * @cliexend
 *
 * Example of how to send an IPv4 gratuitous ARP
 * @cliexstart{arping gratuitous 172.16.1.20 GigabitEthernet2/0/0 repeat 2}
 * @cliexend
 * @endparblock
?*/
VLIB_CLI_COMMAND (arping_command, static) = {
  .path = "arping",
  .function = arping_ip_address,
  .short_help = "arping [gratuitous] <addr> <interface>"
		" [interval <sec>] [repeat <cnt>]",
  .is_mp_safe = 1,
};

static clib_error_t *
arping_cli_init (vlib_main_t *vm)
{
  /* initialize binary API */
  arping_plugin_api_hookup (vm);

  return 0;
}

VLIB_INIT_FUNCTION (arping_cli_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Arping (arping)",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
