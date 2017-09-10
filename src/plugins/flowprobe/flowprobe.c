/*
 * flowprobe.c - ipfix probe plugin
 *
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
 * @brief Per-packet IPFIX flow record generator plugin
 *
 * This file implements vpp plugin registration mechanics,
 * debug CLI, and binary API handling.
 */

#include <vnet/vnet.h>
#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>
#include <flowprobe/flowprobe.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <flowprobe/flowprobe_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <flowprobe/flowprobe_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <flowprobe/flowprobe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <flowprobe/flowprobe_all_api_h.h>
#undef vl_printfun

flowprobe_main_t flowprobe_main;
vlib_node_registration_t flowprobe_walker_node;
static vlib_node_registration_t flowprobe_timer_node;
uword flowprobe_walker_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
				vlib_frame_t * f);

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <flowprobe/flowprobe_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE fm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* Define the per-interface configurable features */
/* *INDENT-OFF* */
VNET_FEATURE_INIT (flow_perpacket_ip4, static) =
{
  .arc_name = "ip4-output",
  .node_name = "flowprobe-ip4",
  .runs_before = VNET_FEATURES ("interface-output"),
};

VNET_FEATURE_INIT (flow_perpacket_ip6, static) =
{
  .arc_name = "ip6-output",
  .node_name = "flowprobe-ip6",
  .runs_before = VNET_FEATURES ("interface-output"),
};

VNET_FEATURE_INIT (flow_perpacket_l2, static) =
{
  .arc_name = "interface-output",
  .node_name = "flowprobe-l2",
  .runs_before = VNET_FEATURES ("interface-tx"),
};
/* *INDENT-ON* */

/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

static inline ipfix_field_specifier_t *
flowprobe_template_ip4_fields (ipfix_field_specifier_t * f)
{
#define flowprobe_template_ip4_field_count() 4
  /* sourceIpv4Address, TLV type 8, u32 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      sourceIPv4Address, 4);
  f++;
  /* destinationIPv4Address, TLV type 12, u32 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      destinationIPv4Address, 4);
  f++;
  /* protocolIdentifier, TLV type 4, u8 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      protocolIdentifier, 1);
  f++;
  /* octetDeltaCount, TLV type 1, u64 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      octetDeltaCount, 8);
  f++;
  return f;
}

static inline ipfix_field_specifier_t *
flowprobe_template_ip6_fields (ipfix_field_specifier_t * f)
{
#define flowprobe_template_ip6_field_count() 4
  /* sourceIpv6Address, TLV type 27, 16 octets */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      sourceIPv6Address, 16);
  f++;
  /* destinationIPv6Address, TLV type 28, 16 octets */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      destinationIPv6Address, 16);
  f++;
  /* protocolIdentifier, TLV type 4, u8 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      protocolIdentifier, 1);
  f++;
  /* octetDeltaCount, TLV type 1, u64 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      octetDeltaCount, 8);
  f++;
  return f;
}

static inline ipfix_field_specifier_t *
flowprobe_template_l2_fields (ipfix_field_specifier_t * f)
{
#define flowprobe_template_l2_field_count() 3
  /* sourceMacAddress, TLV type 56, u8[6] we hope */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      sourceMacAddress, 6);
  f++;
  /* destinationMacAddress, TLV type 80, u8[6] we hope */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      destinationMacAddress, 6);
  f++;
  /* ethernetType, TLV type 256, u16 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      ethernetType, 2);
  f++;
  return f;
}

static inline ipfix_field_specifier_t *
flowprobe_template_common_fields (ipfix_field_specifier_t * f)
{
#define flowprobe_template_common_field_count() 5
  /* ingressInterface, TLV type 10, u32 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      ingressInterface, 4);
  f++;

  /* egressInterface, TLV type 14, u32 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      egressInterface, 4);
  f++;

  /* packetDeltaCount, TLV type 2, u64 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      packetDeltaCount, 8);
  f++;

  /* flowStartNanoseconds, TLV type 156, u64 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      flowStartNanoseconds, 8);
  f++;

  /* flowEndNanoseconds, TLV type 157, u64 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      flowEndNanoseconds, 8);
  f++;

  return f;
}

static inline ipfix_field_specifier_t *
flowprobe_template_l4_fields (ipfix_field_specifier_t * f)
{
#define flowprobe_template_l4_field_count() 3
  /* sourceTransportPort, TLV type 7, u16 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      sourceTransportPort, 2);
  f++;
  /* destinationTransportPort, TLV type 11, u16 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      destinationTransportPort, 2);
  f++;
  /* tcpControlBits, TLV type 6, u16 */
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ ,
				      tcpControlBits, 2);
  f++;

  return f;
}

/**
 * @brief Create an IPFIX template packet rewrite string
 * @param frm flow_report_main_t *
 * @param fr flow_report_t *
 * @param collector_address ip4_address_t * the IPFIX collector address
 * @param src_address ip4_address_t * the source address we should use
 * @param collector_port u16 the collector port we should use, host byte order
 * @returns u8 * vector containing the indicated IPFIX template packet
 */
static inline u8 *
flowprobe_template_rewrite_inline (flow_report_main_t * frm,
				   flow_report_t * fr,
				   ip4_address_t * collector_address,
				   ip4_address_t * src_address,
				   u16 collector_port,
				   flowprobe_variant_t which)
{
  ip4_header_t *ip;
  udp_header_t *udp;
  ipfix_message_header_t *h;
  ipfix_set_header_t *s;
  ipfix_template_header_t *t;
  ipfix_field_specifier_t *f;
  ipfix_field_specifier_t *first_field;
  u8 *rewrite = 0;
  ip4_ipfix_template_packet_t *tp;
  u32 field_count = 0;
  flow_report_stream_t *stream;
  flowprobe_main_t *fm = &flowprobe_main;
  flowprobe_record_t flags = fr->opaque.as_uword;
  bool collect_ip4 = false, collect_ip6 = false;

  stream = &frm->streams[fr->stream_index];

  if (flags & FLOW_RECORD_L3)
    {
      collect_ip4 = which == FLOW_VARIANT_L2_IP4 || which == FLOW_VARIANT_IP4;
      collect_ip6 = which == FLOW_VARIANT_L2_IP6 || which == FLOW_VARIANT_IP6;
      if (which == FLOW_VARIANT_L2_IP4)
	flags |= FLOW_RECORD_L2_IP4;
      if (which == FLOW_VARIANT_L2_IP6)
	flags |= FLOW_RECORD_L2_IP6;
    }

  field_count += flowprobe_template_common_field_count ();
  if (flags & FLOW_RECORD_L2)
    field_count += flowprobe_template_l2_field_count ();
  if (collect_ip4)
    field_count += flowprobe_template_ip4_field_count ();
  if (collect_ip6)
    field_count += flowprobe_template_ip6_field_count ();
  if (flags & FLOW_RECORD_L4)
    field_count += flowprobe_template_l4_field_count ();

  /* allocate rewrite space */
  vec_validate_aligned
    (rewrite, sizeof (ip4_ipfix_template_packet_t)
     + field_count * sizeof (ipfix_field_specifier_t) - 1,
     CLIB_CACHE_LINE_BYTES);

  tp = (ip4_ipfix_template_packet_t *) rewrite;
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);
  h = (ipfix_message_header_t *) (udp + 1);
  s = (ipfix_set_header_t *) (h + 1);
  t = (ipfix_template_header_t *) (s + 1);
  first_field = f = (ipfix_field_specifier_t *) (t + 1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = src_address->as_u32;
  ip->dst_address.as_u32 = collector_address->as_u32;
  udp->src_port = clib_host_to_net_u16 (stream->src_port);
  udp->dst_port = clib_host_to_net_u16 (collector_port);
  udp->length = clib_host_to_net_u16 (vec_len (rewrite) - sizeof (*ip));

  /* FIXUP: message header export_time */
  /* FIXUP: message header sequence_number */
  h->domain_id = clib_host_to_net_u32 (stream->domain_id);

  /* Add TLVs to the template */
  f = flowprobe_template_common_fields (f);

  if (flags & FLOW_RECORD_L2)
    f = flowprobe_template_l2_fields (f);
  if (collect_ip4)
    f = flowprobe_template_ip4_fields (f);
  if (collect_ip6)
    f = flowprobe_template_ip6_fields (f);
  if (flags & FLOW_RECORD_L4)
    f = flowprobe_template_l4_fields (f);

  /* Back to the template packet... */
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);

  ASSERT (f - first_field);
  /* Field count in this template */
  t->id_count = ipfix_id_count (fr->template_id, f - first_field);

  fm->template_size[flags] = (u8 *) f - (u8 *) s;

  /* set length in octets */
  s->set_id_length =
    ipfix_set_id_length (2 /* set_id */ , (u8 *) f - (u8 *) s);

  /* message length in octets */
  h->version_length = version_length ((u8 *) f - (u8 *) h);

  ip->length = clib_host_to_net_u16 ((u8 *) f - (u8 *) ip);
  ip->checksum = ip4_header_checksum (ip);

  return rewrite;
}

static u8 *
flowprobe_template_rewrite_ip6 (flow_report_main_t * frm,
				flow_report_t * fr,
				ip4_address_t * collector_address,
				ip4_address_t * src_address,
				u16 collector_port)
{
  return flowprobe_template_rewrite_inline
    (frm, fr, collector_address, src_address, collector_port,
     FLOW_VARIANT_IP6);
}

static u8 *
flowprobe_template_rewrite_ip4 (flow_report_main_t * frm,
				flow_report_t * fr,
				ip4_address_t * collector_address,
				ip4_address_t * src_address,
				u16 collector_port)
{
  return flowprobe_template_rewrite_inline
    (frm, fr, collector_address, src_address, collector_port,
     FLOW_VARIANT_IP4);
}

static u8 *
flowprobe_template_rewrite_l2 (flow_report_main_t * frm,
			       flow_report_t * fr,
			       ip4_address_t * collector_address,
			       ip4_address_t * src_address,
			       u16 collector_port)
{
  return flowprobe_template_rewrite_inline
    (frm, fr, collector_address, src_address, collector_port,
     FLOW_VARIANT_L2);
}

static u8 *
flowprobe_template_rewrite_l2_ip4 (flow_report_main_t * frm,
				   flow_report_t * fr,
				   ip4_address_t * collector_address,
				   ip4_address_t * src_address,
				   u16 collector_port)
{
  return flowprobe_template_rewrite_inline
    (frm, fr, collector_address, src_address, collector_port,
     FLOW_VARIANT_L2_IP4);
}

static u8 *
flowprobe_template_rewrite_l2_ip6 (flow_report_main_t * frm,
				   flow_report_t * fr,
				   ip4_address_t * collector_address,
				   ip4_address_t * src_address,
				   u16 collector_port)
{
  return flowprobe_template_rewrite_inline
    (frm, fr, collector_address, src_address, collector_port,
     FLOW_VARIANT_L2_IP6);
}

/**
 * @brief Flush accumulated data
 * @param frm flow_report_main_t *
 * @param fr flow_report_t *
 * @param f vlib_frame_t *
 *
 * <em>Notes:</em>
 * This function must simply return the incoming frame, or no template packets
 * will be sent.
 */
vlib_frame_t *
flowprobe_data_callback_ip4 (flow_report_main_t * frm,
			     flow_report_t * fr,
			     vlib_frame_t * f, u32 * to_next, u32 node_index)
{
  flowprobe_flush_callback_ip4 ();
  return f;
}

vlib_frame_t *
flowprobe_data_callback_ip6 (flow_report_main_t * frm,
			     flow_report_t * fr,
			     vlib_frame_t * f, u32 * to_next, u32 node_index)
{
  flowprobe_flush_callback_ip6 ();
  return f;
}

vlib_frame_t *
flowprobe_data_callback_l2 (flow_report_main_t * frm,
			    flow_report_t * fr,
			    vlib_frame_t * f, u32 * to_next, u32 node_index)
{
  flowprobe_flush_callback_l2 ();
  return f;
}

static int
flowprobe_template_add_del (u32 domain_id, u16 src_port,
			    flowprobe_record_t flags,
			    vnet_flow_data_callback_t * flow_data_callback,
			    vnet_flow_rewrite_callback_t * rewrite_callback,
			    bool is_add, u16 * template_id)
{
  flow_report_main_t *frm = &flow_report_main;
  vnet_flow_report_add_del_args_t a = {
    .rewrite_callback = rewrite_callback,
    .flow_data_callback = flow_data_callback,
    .is_add = is_add,
    .domain_id = domain_id,
    .src_port = src_port,
    .opaque.as_uword = flags,
  };
  return vnet_flow_report_add_del (frm, &a, template_id);
}

static void
flowprobe_expired_timer_callback (u32 * expired_timers)
{
  vlib_main_t *vm = vlib_get_main ();
  flowprobe_main_t *fm = &flowprobe_main;
  u32 my_cpu_number = vm->thread_index;
  int i;
  u32 poolindex;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      poolindex = expired_timers[i] & 0x7FFFFFFF;
      vec_add1 (fm->expired_passive_per_worker[my_cpu_number], poolindex);
    }
}

static clib_error_t *
flowprobe_create_state_tables (u32 active_timer)
{
  flowprobe_main_t *fm = &flowprobe_main;
  vlib_thread_main_t *tm = &vlib_thread_main;
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error = 0;
  u32 num_threads;
  int i;

  /* Decide how many worker threads we have */
  num_threads = 1 /* main thread */  + tm->n_threads;

  /* Hash table per worker */
  fm->ht_log2len = FLOWPROBE_LOG2_HASHSIZE;

  /* Init per worker flow state and timer wheels */
  if (active_timer)
    {
      vec_validate (fm->timers_per_worker, num_threads - 1);
      vec_validate (fm->expired_passive_per_worker, num_threads - 1);
      vec_validate (fm->hash_per_worker, num_threads - 1);
      vec_validate (fm->pool_per_worker, num_threads - 1);

      for (i = 0; i < num_threads; i++)
	{
	  int j;
	  pool_alloc (fm->pool_per_worker[i], 1 << fm->ht_log2len);
	  vec_resize (fm->hash_per_worker[i], 1 << fm->ht_log2len);
	  for (j = 0; j < (1 << fm->ht_log2len); j++)
	    fm->hash_per_worker[i][j] = ~0;
	  fm->timers_per_worker[i] =
	    clib_mem_alloc (sizeof (TWT (tw_timer_wheel)));
	  tw_timer_wheel_init_2t_1w_2048sl (fm->timers_per_worker[i],
					    flowprobe_expired_timer_callback,
					    1.0, 1024);
	}
      fm->disabled = true;
    }
  else
    {
      f64 now = vlib_time_now (vm);
      vec_validate (fm->stateless_entry, num_threads - 1);
      for (i = 0; i < num_threads; i++)
	fm->stateless_entry[i].last_exported = now;
      fm->disabled = false;
    }
  fm->initialized = true;
  return error;
}

static int
validate_feature_on_interface (flowprobe_main_t * fm, u32 sw_if_index,
			       u8 which)
{
  vec_validate_init_empty (fm->flow_per_interface, sw_if_index, ~0);

  if (fm->flow_per_interface[sw_if_index] == (u8) ~ 0)
    return -1;
  else if (fm->flow_per_interface[sw_if_index] != which)
    return 0;
  else
    return 1;
}

/**
 * @brief configure / deconfigure the IPFIX flow-per-packet
 * @param fm flowprobe_main_t * fm
 * @param sw_if_index u32 the desired interface
 * @param is_add int 1 to enable the feature, 0 to disable it
 * @returns 0 if successful, non-zero otherwise
 */

static int
flowprobe_tx_interface_add_del_feature (flowprobe_main_t * fm,
					u32 sw_if_index, u8 which, int is_add)
{
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;
  u16 template_id = 0;
  flowprobe_record_t flags = fm->record;

  fm->flow_per_interface[sw_if_index] = (is_add) ? which : (u8) ~ 0;
  fm->template_per_flow[which] += (is_add) ? 1 : -1;
  if (is_add && fm->template_per_flow[which] > 1)
    template_id = fm->template_reports[flags];

  if ((is_add && fm->template_per_flow[which] == 1) ||
      (!is_add && fm->template_per_flow[which] == 0))
    {
      if (which == FLOW_VARIANT_L2)
	{
	  if (fm->record & FLOW_RECORD_L2)
	    {
	      rv = flowprobe_template_add_del (1, UDP_DST_PORT_ipfix, flags,
					       flowprobe_data_callback_l2,
					       flowprobe_template_rewrite_l2,
					       is_add, &template_id);
	    }
	  if (fm->record & FLOW_RECORD_L3 || fm->record & FLOW_RECORD_L4)
	    {
	      rv = flowprobe_template_add_del (1, UDP_DST_PORT_ipfix, flags,
					       flowprobe_data_callback_l2,
					       flowprobe_template_rewrite_l2_ip4,
					       is_add, &template_id);
	      fm->template_reports[flags | FLOW_RECORD_L2_IP4] =
		(is_add) ? template_id : 0;
	      rv =
		flowprobe_template_add_del (1, UDP_DST_PORT_ipfix, flags,
					    flowprobe_data_callback_l2,
					    flowprobe_template_rewrite_l2_ip6,
					    is_add, &template_id);
	      fm->template_reports[flags | FLOW_RECORD_L2_IP6] =
		(is_add) ? template_id : 0;

	      /* Special case L2 */
	      fm->context[FLOW_VARIANT_L2_IP4].flags =
		flags | FLOW_RECORD_L2_IP4;
	      fm->context[FLOW_VARIANT_L2_IP6].flags =
		flags | FLOW_RECORD_L2_IP6;

	      fm->template_reports[flags] = template_id;
	    }
	}
      else if (which == FLOW_VARIANT_IP4)
	rv = flowprobe_template_add_del (1, UDP_DST_PORT_ipfix, flags,
					 flowprobe_data_callback_ip4,
					 flowprobe_template_rewrite_ip4,
					 is_add, &template_id);
      else if (which == FLOW_VARIANT_IP6)
	rv = flowprobe_template_add_del (1, UDP_DST_PORT_ipfix, flags,
					 flowprobe_data_callback_ip6,
					 flowprobe_template_rewrite_ip6,
					 is_add, &template_id);
    }
  if (rv && rv != VNET_API_ERROR_VALUE_EXIST)
    {
      clib_warning ("vnet_flow_report_add_del returned %d", rv);
      return -1;
    }

  if (which != (u8) ~ 0)
    {
      fm->context[which].flags = fm->record;
      fm->template_reports[flags] = (is_add) ? template_id : 0;
    }

  if (which == FLOW_VARIANT_IP4)
    vnet_feature_enable_disable ("ip4-output", "flowprobe-ip4",
				 sw_if_index, is_add, 0, 0);
  else if (which == FLOW_VARIANT_IP6)
    vnet_feature_enable_disable ("ip6-output", "flowprobe-ip6",
				 sw_if_index, is_add, 0, 0);
  else if (which == FLOW_VARIANT_L2)
    vnet_feature_enable_disable ("interface-output", "flowprobe-l2",
				 sw_if_index, is_add, 0, 0);

  /* Stateful flow collection */
  if (is_add && !fm->initialized)
    {
      flowprobe_create_state_tables (fm->active_timer);
      if (fm->active_timer)
	vlib_process_signal_event (vm, flowprobe_timer_node.index, 1, 0);
    }

  return 0;
}

/**
 * @brief API message handler
 * @param mp vl_api_flowprobe_tx_interface_add_del_t * mp the api message
 */
void vl_api_flowprobe_tx_interface_add_del_t_handler
  (vl_api_flowprobe_tx_interface_add_del_t * mp)
{
  flowprobe_main_t *fm = &flowprobe_main;
  vl_api_flowprobe_tx_interface_add_del_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->which != FLOW_VARIANT_IP4 && mp->which != FLOW_VARIANT_L2
      && mp->which != FLOW_VARIANT_IP6)
    {
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }

  if (fm->record == 0)
    {
      clib_warning ("Please specify flowprobe params record first...");
      rv = VNET_API_ERROR_CANNOT_ENABLE_DISABLE_FEATURE;
      goto out;
    }

  rv = validate_feature_on_interface (fm, sw_if_index, mp->which);
  if ((rv == 1 && mp->is_add == 1) || rv == 0)
    {
      rv = VNET_API_ERROR_CANNOT_ENABLE_DISABLE_FEATURE;
      goto out;
    }

  rv = flowprobe_tx_interface_add_del_feature
    (fm, sw_if_index, mp->which, mp->is_add);

out:
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_FLOWPROBE_TX_INTERFACE_ADD_DEL_REPLY);
}

/**
 * @brief API message custom-dump function
 * @param mp vl_api_flowprobe_tx_interface_add_del_t * mp the api message
 * @param handle void * print function handle
 * @returns u8 * output string
 */
static void *vl_api_flowprobe_tx_interface_add_del_t_print
  (vl_api_flowprobe_tx_interface_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: flowprobe_tx_interface_add_del ");
  s = format (s, "sw_if_index %d is_add %d which %d ",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      (int) mp->is_add, (int) mp->which);
  FINISH;
}

#define vec_neg_search(v,E)         \
({              \
  word _v(i) = 0;         \
  while (_v(i) < vec_len(v) && v[_v(i)] == E)        \
  {             \
    _v(i)++;            \
  }             \
  if (_v(i) == vec_len(v))        \
    _v(i) = ~0;                 \
  _v(i);            \
})

static int
flowprobe_params (flowprobe_main_t * fm, u8 record_l2,
		  u8 record_l3, u8 record_l4,
		  u32 active_timer, u32 passive_timer)
{
  flowprobe_record_t flags = 0;

  if (vec_neg_search (fm->flow_per_interface, (u8) ~ 0) != ~0)
    return ~0;

  if (record_l2)
    flags |= FLOW_RECORD_L2;
  if (record_l3)
    flags |= FLOW_RECORD_L3;
  if (record_l4)
    flags |= FLOW_RECORD_L4;

  fm->record = flags;

  /*
   * Timers: ~0 is default, 0 is off
   */
  fm->active_timer =
    (active_timer == (u32) ~ 0 ? FLOWPROBE_TIMER_ACTIVE : active_timer);
  fm->passive_timer =
    (passive_timer == (u32) ~ 0 ? FLOWPROBE_TIMER_PASSIVE : passive_timer);

  return 0;
}

void
vl_api_flowprobe_params_t_handler (vl_api_flowprobe_params_t * mp)
{
  flowprobe_main_t *fm = &flowprobe_main;
  vl_api_flowprobe_params_reply_t *rmp;
  int rv = 0;

  rv = flowprobe_params
    (fm, mp->record_l2, mp->record_l3, mp->record_l4,
     clib_net_to_host_u32 (mp->active_timer),
     clib_net_to_host_u32 (mp->passive_timer));

  REPLY_MACRO (VL_API_FLOWPROBE_PARAMS_REPLY);
}

/* List of message types that this plugin understands */
#define foreach_flowprobe_plugin_api_msg				\
_(FLOWPROBE_TX_INTERFACE_ADD_DEL, flowprobe_tx_interface_add_del)	\
_(FLOWPROBE_PARAMS, flowprobe_params)

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Flow per Packet",
};
/* *INDENT-ON* */

u8 *
format_flowprobe_entry (u8 * s, va_list * args)
{
  flowprobe_entry_t *e = va_arg (*args, flowprobe_entry_t *);
  s = format (s, " %d/%d", e->key.rx_sw_if_index, e->key.tx_sw_if_index);

  s = format (s, " %U %U", format_ethernet_address, &e->key.src_mac,
	      format_ethernet_address, &e->key.dst_mac);
  s = format (s, " %U -> %U",
	      format_ip46_address, &e->key.src_address, IP46_TYPE_ANY,
	      format_ip46_address, &e->key.dst_address, IP46_TYPE_ANY);
  s = format (s, " %d", e->key.protocol);
  s = format (s, " %d %d\n", clib_net_to_host_u16 (e->key.src_port),
	      clib_net_to_host_u16 (e->key.dst_port));

  return s;
}

static clib_error_t *
flowprobe_show_table_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cm)
{
  flowprobe_main_t *fm = &flowprobe_main;
  int i;
  flowprobe_entry_t *e;

  vlib_cli_output (vm, "Dumping IPFIX table");

  for (i = 0; i < vec_len (fm->pool_per_worker); i++)
    {
      /* *INDENT-OFF* */
      pool_foreach (e, fm->pool_per_worker[i], (
	{
	  vlib_cli_output (vm, "%U",
			   format_flowprobe_entry,
			   e);
	}));
      /* *INDENT-ON* */

    }
  return 0;
}

static clib_error_t *
flowprobe_show_stats_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cm)
{
  flowprobe_main_t *fm = &flowprobe_main;
  int i;

  vlib_cli_output (vm, "IPFIX table statistics");
  vlib_cli_output (vm, "Flow entry size: %d\n", sizeof (flowprobe_entry_t));
  vlib_cli_output (vm, "Flow pool size per thread: %d\n",
		   0x1 << FLOWPROBE_LOG2_HASHSIZE);

  for (i = 0; i < vec_len (fm->pool_per_worker); i++)
    vlib_cli_output (vm, "Pool utilisation thread %d is %d%%\n", i,
		     (100 * pool_elts (fm->pool_per_worker[i])) /
		     (0x1 << FLOWPROBE_LOG2_HASHSIZE));
  return 0;
}

static clib_error_t *
flowprobe_tx_interface_add_del_feature_command_fn (vlib_main_t * vm,
						   unformat_input_t * input,
						   vlib_cli_command_t * cmd)
{
  flowprobe_main_t *fm = &flowprobe_main;
  u32 sw_if_index = ~0;
  int is_add = 1;
  u8 which = FLOW_VARIANT_IP4;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	is_add = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 fm->vnet_main, &sw_if_index));
      else if (unformat (input, "ip4"))
	which = FLOW_VARIANT_IP4;
      else if (unformat (input, "ip6"))
	which = FLOW_VARIANT_IP6;
      else if (unformat (input, "l2"))
	which = FLOW_VARIANT_L2;
      else
	break;
    }

  if (fm->record == 0)
    return clib_error_return (0,
			      "Please specify flowprobe params record first...");

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = validate_feature_on_interface (fm, sw_if_index, which);
  if (rv == 1)
    {
      if (is_add)
	return clib_error_return (0,
				  "Datapath is already enabled for given interface...");
    }
  else if (rv == 0)
    return clib_error_return (0,
			      "Interface has enable different datapath ...");

  rv =
    flowprobe_tx_interface_add_del_feature (fm, sw_if_index, which, is_add);
  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0, "ip6 not supported");
      break;

    default:
      return clib_error_return (0, "flowprobe_enable_disable returned %d",
				rv);
    }
  return 0;
}

static clib_error_t *
flowprobe_params_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  flowprobe_main_t *fm = &flowprobe_main;
  bool record_l2 = false, record_l3 = false, record_l4 = false;
  u32 active_timer = ~0;
  u32 passive_timer = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "active %d", &active_timer))
	;
      else if (unformat (input, "passive %d", &passive_timer))
	;
      else if (unformat (input, "record"))
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
	  {
	    if (unformat (input, "l2"))
	      record_l2 = true;
	    else if (unformat (input, "l3"))
	      record_l3 = true;
	    else if (unformat (input, "l4"))
	      record_l4 = true;
	    else
	      break;
	  }
      else
	break;
    }

  if (passive_timer > 0 && active_timer > passive_timer)
    return clib_error_return (0,
			      "Passive timer has to be greater than active one...");

  if (flowprobe_params (fm, record_l2, record_l3, record_l4,
			active_timer, passive_timer))
    return clib_error_return (0,
			      "Couldn't change flowperpacket params when feature is enabled on some interface ...");
  return 0;
}

/*?
 * '<em>flowprobe feature add-del</em>' commands to enable/disable
 * per-packet IPFIX flow record generation on an interface
 *
 * @cliexpar
 * @parblock
 * To enable per-packet IPFIX flow-record generation on an interface:
 * @cliexcmd{flowprobe feature add-del GigabitEthernet2/0/0}
 *
 * To disable per-packet IPFIX flow-record generation on an interface:
 * @cliexcmd{flowprobe feature add-del GigabitEthernet2/0/0 disable}
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (flowprobe_enable_disable_command, static) = {
    .path = "flowprobe feature add-del",
    .short_help =
    "flowprobe feature add-del <interface-name> <l2|ip4|ip6> disable",
    .function = flowprobe_tx_interface_add_del_feature_command_fn,
};
VLIB_CLI_COMMAND (flowprobe_params_command, static) = {
    .path = "flowprobe params",
    .short_help =
    "flowprobe params record <[l2] [l3] [l4]> [active <timer> passive <timer>]",
    .function = flowprobe_params_command_fn,
};
VLIB_CLI_COMMAND (flowprobe_show_table_command, static) = {
    .path = "show flowprobe table",
    .short_help = "show flowprobe table",
    .function = flowprobe_show_table_fn,
};
VLIB_CLI_COMMAND (flowprobe_show_stats_command, static) = {
    .path = "show flowprobe statistics",
    .short_help = "show flowprobe statistics",
    .function = flowprobe_show_stats_fn,
};
/* *INDENT-ON* */

/**
 * @brief Set up the API message handling tables
 * @param vm vlib_main_t * vlib main data structure pointer
 * @returns 0 to indicate all is well
 */
static clib_error_t *
flowprobe_plugin_api_hookup (vlib_main_t * vm)
{
  flowprobe_main_t *fm = &flowprobe_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + fm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_flowprobe_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <flowprobe/flowprobe_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (flowprobe_main_t * fm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + fm->msg_id_base);
  foreach_vl_msg_name_crc_flowprobe;
#undef _
}

/*
 * Main-core process, sending an interrupt to the per worker input
 * process that spins the per worker timer wheel.
 */
static uword
timer_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  uword *event_data = 0;
  vlib_main_t **worker_vms = 0, *worker_vm;
  flowprobe_main_t *fm = &flowprobe_main;

  /* Wait for Godot... */
  vlib_process_wait_for_event_or_clock (vm, 1e9);
  uword event_type = vlib_process_get_events (vm, &event_data);
  if (event_type != 1)
    clib_warning ("bogus kickoff event received, %d", event_type);
  vec_reset_length (event_data);

  int i;
  if (vec_len (vlib_mains) == 0)
    vec_add1 (worker_vms, vm);
  else
    {
      for (i = 0; i < vec_len (vlib_mains); i++)
	{
	  worker_vm = vlib_mains[i];
	  if (worker_vm)
	    vec_add1 (worker_vms, worker_vm);
	}
    }
  f64 sleep_duration = 0.1;

  while (1)
    {
      /* Send an interrupt to each timer input node */
      sleep_duration = 0.1;
      for (i = 0; i < vec_len (worker_vms); i++)
	{
	  worker_vm = worker_vms[i];
	  if (worker_vm)
	    {
	      vlib_node_set_interrupt_pending (worker_vm,
					       flowprobe_walker_node.index);
	      sleep_duration =
		(fm->expired_passive_per_worker[i] > 0) ? 1e-4 : 0.1;
	    }
	}
      vlib_process_suspend (vm, sleep_duration);
    }
  return 0;			/* or not */
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (flowprobe_timer_node,static) = {
  .function = timer_process,
  .name = "flowprobe-timer-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};
/* *INDENT-ON* */

/**
 * @brief Set up the API message handling tables
 * @param vm vlib_main_t * vlib main data structure pointer
 * @returns 0 to indicate all is well, or a clib_error_t
 */
static clib_error_t *
flowprobe_init (vlib_main_t * vm)
{
  flowprobe_main_t *fm = &flowprobe_main;
  vlib_thread_main_t *tm = &vlib_thread_main;
  clib_error_t *error = 0;
  u8 *name;
  u32 num_threads;
  int i;

  fm->vnet_main = vnet_get_main ();

  /* Construct the API name */
  name = format (0, "flowprobe_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  fm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  /* Hook up message handlers */
  error = flowprobe_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (fm, &api_main);

  vec_free (name);

  /* Set up time reference pair */
  fm->vlib_time_0 = vlib_time_now (vm);
  fm->nanosecond_time_0 = unix_time_now_nsec ();

  memset (fm->template_reports, 0, sizeof (fm->template_reports));
  memset (fm->template_size, 0, sizeof (fm->template_size));
  memset (fm->template_per_flow, 0, sizeof (fm->template_per_flow));

  /* Decide how many worker threads we have */
  num_threads = 1 /* main thread */  + tm->n_threads;

  /* Allocate per worker thread vectors per flavour */
  for (i = 0; i < FLOW_N_VARIANTS; i++)
    {
      vec_validate (fm->context[i].buffers_per_worker, num_threads - 1);
      vec_validate (fm->context[i].frames_per_worker, num_threads - 1);
      vec_validate (fm->context[i].next_record_offset_per_worker,
		    num_threads - 1);
    }

  fm->active_timer = FLOWPROBE_TIMER_ACTIVE;
  fm->passive_timer = FLOWPROBE_TIMER_PASSIVE;

  return error;
}

VLIB_INIT_FUNCTION (flowprobe_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
