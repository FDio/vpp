/*
 * flowperpkt.c - per-packet data capture flow report plugin
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <flowperpkt/flowperpkt.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <flowperpkt/flowperpkt_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <flowperpkt/flowperpkt_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <flowperpkt/flowperpkt_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <flowperpkt/flowperpkt_all_api_h.h>
#undef vl_printfun

flowperpkt_main_t flowperpkt_main;

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <flowperpkt/flowperpkt_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE fm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* Define the per-interface configurable features */
/* *INDENT-OFF* */
VNET_FEATURE_INIT (flow_perpacket_ipv4, static) =
{
  .arc_name = "ip4-output",
  .node_name = "flowperpkt-ipv4",
  .runs_before = VNET_FEATURES ("interface-output"),
};

VNET_FEATURE_INIT (flow_perpacket_l2, static) =
{
  .arc_name = "interface-output",
  .node_name = "flowperpkt-l2",
  .runs_before = VNET_FEATURES ("interface-tx"),
};
/* *INDENT-ON* */

/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

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
flowperpkt_template_rewrite_inline (flow_report_main_t * frm,
				    flow_report_t * fr,
				    ip4_address_t * collector_address,
				    ip4_address_t * src_address,
				    u16 collector_port, int variant)
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
  flowperpkt_main_t *fm = &flowperpkt_main;

  stream = &frm->streams[fr->stream_index];

  if (variant == FLOW_VARIANT_IPV4)
    {
      /*
       * ip4 Supported Fields:
       *
       * ingressInterface, TLV type 10, u32
       * egressInterface, TLV type 14, u32
       * sourceIpv4Address, TLV type 8, u32
       * destinationIPv4Address, TLV type 12, u32
       * ipClassOfService, TLV type 5, u8
       * flowStartNanoseconds, TLV type 156, dateTimeNanoseconds (f64)
       *   Implementation: f64 nanoseconds since VPP started
       *   warning: wireshark doesn't really understand this TLV
       * dataLinkFrameSize, TLV type 312, u16
       *   warning: wireshark doesn't understand this TLV at all
       */

      /* Currently 7 fields */
      field_count += 7;

      /* allocate rewrite space */
      vec_validate_aligned
	(rewrite,
	 sizeof (ip4_ipfix_template_packet_t)
	 + field_count * sizeof (ipfix_field_specifier_t) - 1,
	 CLIB_CACHE_LINE_BYTES);
    }
  else if (variant == FLOW_VARIANT_L2)
    {
      /*
       * L2 Supported Fields:
       *
       * ingressInterface, TLV type 10, u32
       * egressInterface, TLV type 14, u32
       * sourceMacAddress, TLV type 56, u8[6] we hope
       * destinationMacAddress, TLV type 57, u8[6] we hope
       * ethernetType, TLV type 256, u16
       * flowStartNanoseconds, TLV type 156, dateTimeNanoseconds (f64)
       *   Implementation: f64 nanoseconds since VPP started
       *   warning: wireshark doesn't really understand this TLV
       * dataLinkFrameSize, TLV type 312, u16
       *   warning: wireshark doesn't understand this TLV at all
       */

      /* Currently 7 fields */
      field_count += 7;

      /* allocate rewrite space */
      vec_validate_aligned
	(rewrite,
	 sizeof (ip4_ipfix_template_packet_t)
	 + field_count * sizeof (ipfix_field_specifier_t) - 1,
	 CLIB_CACHE_LINE_BYTES);
    }

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
  if (variant == FLOW_VARIANT_IPV4)
    {
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , ingressInterface,
			   4);
      f++;
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , egressInterface,
			   4);
      f++;
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , sourceIPv4Address,
			   4);
      f++;
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , destinationIPv4Address, 4);
      f++;
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , ipClassOfService,
			   1);
      f++;
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , flowStartNanoseconds,
			   8);
      f++;
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , dataLinkFrameSize,
			   2);
      f++;
    }
  else if (variant == FLOW_VARIANT_L2)
    {
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , ingressInterface,
			   4);
      f++;
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , egressInterface,
			   4);
      f++;
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , sourceMacAddress,
			   6);
      f++;
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , destinationMacAddress, 6);
      f++;
      f->e_id_length = ipfix_e_id_length (0 /* enterprise */ , ethernetType,
					  2);
      f++;
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , flowStartNanoseconds,
			   8);
      f++;
      f->e_id_length =
	ipfix_e_id_length (0 /* enterprise */ , dataLinkFrameSize,
			   2);
      f++;
    }

  /* Extend in the obvious way, right here... */

  /* Back to the template packet... */
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);

  ASSERT (f - first_field);
  /* Field count in this template */
  t->id_count = ipfix_id_count (fr->template_id, f - first_field);

  if (variant == FLOW_VARIANT_IPV4)
    fm->ipv4_report_id = fr->template_id;
  else if (variant == FLOW_VARIANT_L2)
    fm->l2_report_id = fr->template_id;

  /* set length in octets */
  s->set_id_length =
    ipfix_set_id_length (2 /* set_id */ , (u8 *) f - (u8 *) s);

  /* message length in octets */
  h->version_length = version_length ((u8 *) f - (u8 *) h);

  ip->length = clib_host_to_net_u16 ((u8 *) f - (u8 *) ip);
  ip->checksum = ip4_header_checksum (ip);

  return rewrite;
}

u8 *
flowperpkt_template_rewrite_ipv4 (flow_report_main_t * frm,
				  flow_report_t * fr,
				  ip4_address_t * collector_address,
				  ip4_address_t * src_address,
				  u16 collector_port)
{
  return flowperpkt_template_rewrite_inline
    (frm, fr, collector_address, src_address, collector_port,
     FLOW_VARIANT_IPV4);
}

u8 *
flowperpkt_template_rewrite_l2 (flow_report_main_t * frm,
				flow_report_t * fr,
				ip4_address_t * collector_address,
				ip4_address_t * src_address,
				u16 collector_port)
{
  return flowperpkt_template_rewrite_inline
    (frm, fr, collector_address, src_address, collector_port,
     FLOW_VARIANT_L2);
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
flowperpkt_data_callback_ipv4 (flow_report_main_t * frm,
			       flow_report_t * fr,
			       vlib_frame_t * f, u32 * to_next,
			       u32 node_index)
{
  flowperpkt_flush_callback_ipv4 ();
  return f;
}

vlib_frame_t *
flowperpkt_data_callback_l2 (flow_report_main_t * frm,
			     flow_report_t * fr,
			     vlib_frame_t * f, u32 * to_next, u32 node_index)
{
  flowperpkt_flush_callback_l2 ();
  return f;
}

/**
 * @brief configure / deconfigure the IPFIX flow-per-packet
 * @param fm flowperpkt_main_t * fm
 * @param sw_if_index u32 the desired interface
 * @param is_add int 1 to enable the feature, 0 to disable it
 * @returns 0 if successful, non-zero otherwise
 */

static int flowperpkt_tx_interface_add_del_feature
  (flowperpkt_main_t * fm, u32 sw_if_index, int which, int is_add)
{
  flow_report_main_t *frm = &flow_report_main;
  vnet_flow_report_add_del_args_t _a, *a = &_a;
  int rv;

  if (which == FLOW_VARIANT_IPV4 && !fm->ipv4_report_created)
    {
      memset (a, 0, sizeof (*a));
      a->rewrite_callback = flowperpkt_template_rewrite_ipv4;
      a->flow_data_callback = flowperpkt_data_callback_ipv4;
      a->is_add = 1;
      a->domain_id = 1;		/*$$$$ config parameter */
      a->src_port = 4739;	/*$$$$ config parameter */
      fm->ipv4_report_created = 1;

      rv = vnet_flow_report_add_del (frm, a);
      if (rv)
	{
	  clib_warning ("vnet_flow_report_add_del returned %d", rv);
	  return -1;
	}
    }
  else if (which == FLOW_VARIANT_L2 && !fm->l2_report_created)
    {
      memset (a, 0, sizeof (*a));
      a->rewrite_callback = flowperpkt_template_rewrite_l2;
      a->flow_data_callback = flowperpkt_data_callback_l2;
      a->is_add = 1;
      a->domain_id = 1;		/*$$$$ config parameter */
      a->src_port = 4739;	/*$$$$ config parameter */
      fm->l2_report_created = 1;

      rv = vnet_flow_report_add_del (frm, a);
      if (rv)
	{
	  clib_warning ("vnet_flow_report_add_del returned %d", rv);
	  return -1;
	}
    }

  if (which == FLOW_VARIANT_IPV4)
    vnet_feature_enable_disable ("ip4-output", "flowperpkt-ipv4",
				 sw_if_index, is_add, 0, 0);
  else if (which == FLOW_VARIANT_L2)
    vnet_feature_enable_disable ("interface-output", "flowperpkt-l2",
				 sw_if_index, is_add, 0, 0);

  return 0;
}

/**
 * @brief API message handler
 * @param mp vl_api_flowperpkt_tx_interface_add_del_t * mp the api message
 */
void vl_api_flowperpkt_tx_interface_add_del_t_handler
  (vl_api_flowperpkt_tx_interface_add_del_t * mp)
{
  flowperpkt_main_t *fm = &flowperpkt_main;
  vl_api_flowperpkt_tx_interface_add_del_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->which != FLOW_VARIANT_IPV4 && mp->which != FLOW_VARIANT_L2)
    {
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }

  rv = flowperpkt_tx_interface_add_del_feature (fm, sw_if_index, mp->which,
						mp->is_add);
out:
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_FLOWPERPKT_TX_INTERFACE_ADD_DEL_REPLY);
}

/**
 * @brief API message custom-dump function
 * @param mp vl_api_flowperpkt_tx_interface_add_del_t * mp the api message
 * @param handle void * print function handle
 * @returns u8 * output string
 */
static void *vl_api_flowperpkt_tx_interface_add_del_t_print
  (vl_api_flowperpkt_tx_interface_add_del_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: flowperpkt_tx_interface_add_del ");
  s = format (s, "sw_if_index %d is_add %d which %d ",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      (int) mp->is_add, (int) mp->which);
  FINISH;
}

/* List of message types that this plugin understands */
#define foreach_flowperpkt_plugin_api_msg                           \
_(FLOWPERPKT_TX_INTERFACE_ADD_DEL, flowperpkt_tx_interface_add_del)

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Flow per Packet",
};
/* *INDENT-ON* */

static clib_error_t *
flowperpkt_tx_interface_add_del_feature_command_fn (vlib_main_t * vm,
						    unformat_input_t * input,
						    vlib_cli_command_t * cmd)
{
  flowperpkt_main_t *fm = &flowperpkt_main;
  u32 sw_if_index = ~0;
  int is_add = 1;
  u8 which = FLOW_VARIANT_IPV4;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	is_add = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 fm->vnet_main, &sw_if_index));
      else if (unformat (input, "l2"))
	which = FLOW_VARIANT_L2;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv =
    flowperpkt_tx_interface_add_del_feature (fm, sw_if_index, which, is_add);
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
      return clib_error_return (0, "flowperpkt_enable_disable returned %d",
				rv);
    }
  return 0;
}

/*?
 * '<em>flowperpkt feature add-del</em>' commands to enable/disable
 * per-packet IPFIX flow record generation on an interface
 *
 * @cliexpar
 * @parblock
 * To enable per-packet IPFIX flow-record generation on an interface:
 * @cliexcmd{flowperpkt feature add-del GigabitEthernet2/0/0}
 *
 * To disable per-packet IPFIX flow-record generation on an interface:
 * @cliexcmd{flowperpkt feature add-del GigabitEthernet2/0/0 disable}
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (flowperpkt_enable_disable_command, static) = {
    .path = "flowperpkt feature add-del",
    .short_help =
    "flowperpkt feature add-del <interface-name> [disable]",
    .function = flowperpkt_tx_interface_add_del_feature_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief Set up the API message handling tables
 * @param vm vlib_main_t * vlib main data structure pointer
 * @returns 0 to indicate all is well
 */
static clib_error_t *
flowperpkt_plugin_api_hookup (vlib_main_t * vm)
{
  flowperpkt_main_t *fm = &flowperpkt_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + fm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_flowperpkt_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <flowperpkt/flowperpkt_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (flowperpkt_main_t * fm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + fm->msg_id_base);
  foreach_vl_msg_name_crc_flowperpkt;
#undef _
}

/**
 * @brief Set up the API message handling tables
 * @param vm vlib_main_t * vlib main data structure pointer
 * @returns 0 to indicate all is well, or a clib_error_t
 */
static clib_error_t *
flowperpkt_init (vlib_main_t * vm)
{
  flowperpkt_main_t *fm = &flowperpkt_main;
  vlib_thread_main_t *tm = &vlib_thread_main;
  clib_error_t *error = 0;
  u32 num_threads;
  u8 *name;

  fm->vnet_main = vnet_get_main ();

  /* Construct the API name */
  name = format (0, "flowperpkt_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  fm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  /* Hook up message handlers */
  error = flowperpkt_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (fm, &api_main);

  vec_free (name);

  /* Decide how many worker threads we have */
  num_threads = 1 /* main thread */  + tm->n_threads;

  /* Allocate per worker thread vectors */
  vec_validate (fm->ipv4_buffers_per_worker, num_threads - 1);
  vec_validate (fm->l2_buffers_per_worker, num_threads - 1);
  vec_validate (fm->ipv4_frames_per_worker, num_threads - 1);
  vec_validate (fm->l2_frames_per_worker, num_threads - 1);
  vec_validate (fm->ipv4_next_record_offset_per_worker, num_threads - 1);
  vec_validate (fm->l2_next_record_offset_per_worker, num_threads - 1);

  /* Set up time reference pair */
  fm->vlib_time_0 = vlib_time_now (vm);
  fm->nanosecond_time_0 = unix_time_now_nsec ();

  return error;
}

VLIB_INIT_FUNCTION (flowperpkt_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
