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

/* Define the per-interface configurable feature */
/* *INDENT-OFF* */
VNET_IP4_TX_FEATURE_INIT (flow_perpacket, static) = {
  .node_name = "flowperpkt",
  .runs_before = (char *[]){"interface-output", 0},
  .feature_index = &flowperpkt_main.ip4_tx_feature_index,
};
/* *INDENT-ON* */

/*
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */
#define REPLY_MACRO(t)                                          \
do {                                                            \
    unix_shared_memory_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+fm->msg_id_base);               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

#define VALIDATE_SW_IF_INDEX(mp)				\
 do { u32 __sw_if_index = ntohl(mp->sw_if_index);		\
    vnet_main_t *__vnm = vnet_get_main();                       \
    if (pool_is_free_index(__vnm->interface_main.sw_interfaces, \
                           __sw_if_index)) {                    \
        rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;                \
        goto bad_sw_if_index;                                   \
    }                                                           \
} while(0);

#define BAD_SW_IF_INDEX_LABEL                   \
do {                                            \
bad_sw_if_index:                                \
    ;                                           \
} while (0);

/**
 * @brief Create an IPFIX template packet rewrite string
 * @param frm flow_report_main_t *
 * @param fr flow_report_t *
 * @param collector_address ip4_address_t * the IPFIX collector address
 * @param src_address ip4_address_t * the source address we should use
 * @param collector_port u16 the collector port we should use, host byte order
 * @returns u8 * vector containing the indicated IPFIX template packet
 */
u8 *
flowperpkt_template_rewrite (flow_report_main_t * frm,
			     flow_report_t * fr,
			     ip4_address_t * collector_address,
			     ip4_address_t * src_address, u16 collector_port)
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

  stream = &frm->streams[fr->stream_index];

  /*
   * Supported Fields:
   *
   * egressInterface, TLV type 14, u32
   * ipClassOfService, TLV type 5, u8
   * flowStartNanoseconds, TLV type 156, dateTimeNanoseconds (f64)
   *   Implementation: f64 nanoseconds since VPP started
   *   warning: wireshark doesn't really understand this TLV
   * dataLinkFrameSize, TLV type 312, u16
   *   warning: wireshark doesn't understand this TLV at all
   */

  /* Currently 4 fields */
  field_count += 4;

  /* allocate rewrite space */
  vec_validate_aligned (rewrite,
			sizeof (ip4_ipfix_template_packet_t)
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
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ , egressInterface,
				      4);
  f++;
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ , ipClassOfService,
				      1);
  f++;
  f->e_id_length =
    ipfix_e_id_length (0 /* enterprise */ , flowStartNanoseconds,
		       8);
  f++;
  f->e_id_length = ipfix_e_id_length (0 /* enterprise */ , dataLinkFrameSize,
				      2);
  f++;
  /* Extend in the obvious way, right here... */

  /* Back to the template packet... */
  ip = (ip4_header_t *) & tp->ip4;
  udp = (udp_header_t *) (ip + 1);

  ASSERT (f - first_field);
  /* Field count in this template */
  t->id_count = ipfix_id_count (fr->template_id, f - first_field);

  /* set length in octets */
  s->set_id_length =
    ipfix_set_id_length (2 /* set_id */ , (u8 *) f - (u8 *) s);

  /* message length in octets */
  h->version_length = version_length ((u8 *) f - (u8 *) h);

  ip->length = clib_host_to_net_u16 ((u8 *) f - (u8 *) ip);
  ip->checksum = ip4_header_checksum (ip);

  return rewrite;
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
flowperpkt_data_callback (flow_report_main_t * frm,
			  flow_report_t * fr,
			  vlib_frame_t * f, u32 * to_next, u32 node_index)
{
  flowperpkt_flush_callback ();
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
  (flowperpkt_main_t * fm, u32 sw_if_index, int is_add)
{
  u32 ci;
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  vnet_feature_config_main_t *cm = &lm->feature_config_mains[VNET_IP_TX_FEAT];
  u32 feature_index;
  flow_report_main_t *frm = &flow_report_main;
  vnet_flow_report_add_del_args_t _a, *a = &_a;
  int rv;

  if (!fm->report_created)
    {
      memset (a, 0, sizeof (*a));
      a->rewrite_callback = flowperpkt_template_rewrite;
      a->flow_data_callback = flowperpkt_data_callback;
      a->is_add = 1;
      a->domain_id = 1;		/*$$$$ config parameter */
      a->src_port = 4739;	/*$$$$ config parameter */
      fm->report_created = 1;

      rv = vnet_flow_report_add_del (frm, a);
      if (rv)
	{
	  clib_warning ("vnet_flow_report_add_del returned %d", rv);
	  return -1;
	}
    }

  feature_index = fm->ip4_tx_feature_index;

  ci = cm->config_index_by_sw_if_index[sw_if_index];
  ci = (is_add
	? vnet_config_add_feature
	: vnet_config_del_feature)
    (fm->vlib_main, &cm->config_main,
     ci, feature_index, 0 /* config struct */ ,
     0 /* sizeof config struct */ );
  cm->config_index_by_sw_if_index[sw_if_index] = ci;

  vnet_config_update_tx_feature_count (lm, cm, sw_if_index, is_add);
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

  rv = flowperpkt_tx_interface_add_del_feature (fm, sw_if_index, mp->is_add);

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
  s = format (s, "sw_if_index %d is_add %d is_ipv6 %d ",
	      clib_host_to_net_u32 (mp->sw_if_index),
	      (int) mp->is_add, (int) mp->is_ipv6);
  FINISH;
}

/* List of message types that this plugin understands */
#define foreach_flowperpkt_plugin_api_msg                           \
_(FLOWPERPKT_TX_INTERFACE_ADD_DEL, flowperpkt_tx_interface_add_del)

/**
 * @brief plugin-api required function
 * @param vm vlib_main_t * vlib main data structure pointer
 * @param h vlib_plugin_handoff_t * handoff structure
 * @param from_early_init int notused
 *
 * <em>Notes:</em>
 * This routine exists to convince the vlib plugin framework that
 * we haven't accidentally copied a random .dll into the plugin directory.
 *
 * Also collects global variable pointers passed from the vpp engine
 */
clib_error_t *
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
		      int from_early_init)
{
  flowperpkt_main_t *fm = &flowperpkt_main;
  clib_error_t *error = 0;

  fm->vlib_main = vm;
  fm->vnet_main = h->vnet_main;

  return error;
}

static clib_error_t *
flowperpkt_tx_interface_add_del_feature_command_fn (vlib_main_t * vm,
						    unformat_input_t * input,
						    vlib_cli_command_t * cmd)
{
  flowperpkt_main_t *fm = &flowperpkt_main;
  u32 sw_if_index = ~0;
  int is_add = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	is_add = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 fm->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = flowperpkt_tx_interface_add_del_feature (fm, sw_if_index, is_add);
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

  /* Construct the API name */
  name = format (0, "flowperpkt_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  fm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  /* Hook up message handlers */
  error = flowperpkt_plugin_api_hookup (vm);

  vec_free (name);

  /* Decide how many worker threads we have */
  num_threads = 1 /* main thread */  + tm->n_eal_threads;

  /* Allocate per worker thread vectors */
  vec_validate (fm->buffers_per_worker, num_threads - 1);
  vec_validate (fm->frames_per_worker, num_threads - 1);
  vec_validate (fm->next_record_offset_per_worker, num_threads - 1);

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
