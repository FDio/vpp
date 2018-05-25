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

#include <vlib/vlib.h>
#include <vnet/dhcp/dhcp6_packet.h>
#include <vnet/dhcp/dhcp_proxy.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/mfib/ip6_mfib.h>
#include <vnet/fib/fib.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/ip/ip6_neighbor.h>
#include <vlibapi/api_common.h>
#include <vlibmemory/api.h>
#include <vnet/dhcp/dhcp6_pd_client_dp.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

typedef struct
{
  u8 entry_valid;
  u8 keep_sending_client_message;	/* when true then next fields are valid */
  dhcp6_pd_send_client_message_params_t params;
  f64 transaction_start;
  f64 sleep_interval;
  f64 due_time;
  u32 n_left;
  f64 start_time;
  u32 transaction_id;
  vlib_buffer_t *buffer;
  u32 elapsed_pos;
  u32 adj_index;
} dhcp6_pd_client_state_t;

typedef struct
{
  u8 *data;
  u16 len;
} server_id_t;

typedef struct
{
  dhcp6_pd_client_state_t *client_state_by_sw_if_index;
  server_id_t *server_ids;

  uword publisher_node;
  uword publisher_et;

  u32 seed;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} dhcp6_pd_client_main_t;

static dhcp6_pd_client_main_t dhcp6_pd_client_main;
dhcp6_pd_client_public_main_t dhcp6_pd_client_public_main;

typedef struct
{
  ip6_address_t prefix;
  u8 prefix_length;
  u32 valid_time;
  u32 preferred_time;
  u16 status_code;
} prefix_info_t;

typedef struct
{
  u32 sw_if_index;
  u32 server_index;
  u8 msg_type;
  u32 T1;
  u32 T2;
  u16 inner_status_code;
  u16 status_code;
  u8 preference;
  u32 n_prefixes;
  prefix_info_t *prefixes;
} report_t;

typedef union
{
  CLIB_PACKED (struct
	       {
	       u16 duid_type;
	       u16 hardware_type;
	       u32 time;
	       u8 lla[6];
	       });
  char bin_string[14];
} dhcpv6_duid_string_t;

static dhcpv6_duid_string_t client_duid;
#define CLIENT_DUID_LENGTH sizeof (client_duid)
#define DHCPV6_CLIENT_IAID 1

static void
signal_report (report_t * r)
{
  vlib_main_t *vm = vlib_get_main ();
  dhcp6_pd_client_main_t *cm = &dhcp6_pd_client_main;
  uword ni = cm->publisher_node;
  uword et = cm->publisher_et;

  if (ni == (uword) ~ 0)
    return;
  report_t *q = vlib_process_signal_event_data (vm, ni, et, 1, sizeof *q);

  *q = *r;
}

static int
publish_report (report_t * r)
{
  void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);
  vl_api_rpc_call_main_thread (signal_report, (u8 *) r, sizeof *r);
  return 0;
}

void
dhcp6_pd_set_publisher_node (uword node_index, uword event_type)
{
  dhcp6_pd_client_main_t *cm = &dhcp6_pd_client_main;
  cm->publisher_node = node_index;
  cm->publisher_et = event_type;
}

#define foreach_dhcpv6_pd_client \
  _(DROP, "error-drop")          \
  _(LOOKUP, "ip6-lookup")

typedef enum
{
#define _(sym,str) DHCPV6_PD_CLIENT_NEXT_##sym,
  foreach_dhcpv6_pd_client
#undef _
    DHCPV6_PD_CLIENT_N_NEXT,
} dhcpv6_pd_client_next_t;

/**
 * per-packet trace data
 */
typedef struct dhcpv6_pd_client_trace_t_
{
} dhcpv6_pd_client_trace_t;

static u8 *
format_dhcpv6_pd_client_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  //dhcpv6_pd_client_trace_t *t = va_arg (*args, dhcpv6_pd_client_trace_t *);

  s = format (s, "nothing");

  return s;
}

static u32
server_index_get_or_create (u8 * data, u16 len)
{
  dhcp6_pd_client_main_t *cm = &dhcp6_pd_client_main;
  u32 i;
  server_id_t *se;
  server_id_t new_se;

  for (i = 0; i < vec_len (cm->server_ids); i++)
    {
      se = &cm->server_ids[i];
      if (se->len == len && 0 == memcmp (se->data, data, len))
	return i;
    }

  new_se.len = len;
  new_se.data = 0;
  vec_validate (new_se.data, len - 1);
  memcpy (new_se.data, data, len);

  vec_add1 (cm->server_ids, new_se);

  return vec_len (cm->server_ids) - 1;
}

static void
stop_sending_client_message (vlib_main_t * vm,
			     dhcp6_pd_client_state_t * client_state)
{
  u32 bi0;

  client_state->keep_sending_client_message = 0;
  vec_free (client_state->params.prefixes);
  if (client_state->buffer)
    {
      bi0 = vlib_get_buffer_index (vm, client_state->buffer);
      vlib_buffer_free (vm, &bi0, 1);
      client_state->buffer = 0;
      adj_unlock (client_state->adj_index);
      client_state->adj_index = ~0;
    }
}

static uword
dhcpv6_pd_client_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  dhcp6_pd_client_main_t *cm = &dhcp6_pd_client_main;

  dhcpv6_pd_client_next_t next_index;
  u32 n_left_from, *from, *to_next;
  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  ip6_header_t *ip0;
	  u32 options_length;
	  dhcpv6_header_t *dhcpv60;
	  dhcpv6_option_t *option;
	  vlib_buffer_t *b0;
	  report_t report;
	  u32 next0 = DHCPV6_PD_CLIENT_NEXT_DROP;
	  u32 bi0;
	  u32 xid;
	  u32 sw_if_index;
	  u32 iaid;
	  u8 client_id_present = 0;
	  u8 discard = 0;

	  dhcp6_pd_client_state_t *client_state = NULL;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  dhcpv60 = vlib_buffer_get_current (b0);
	  ip0 = (void *) (b0->data + vnet_buffer (b0)->l3_hdr_offset);
	  u32 dhcpv6_ip6_palyoad_offset =
	    (u8 *) dhcpv60 - ((u8 *) ip0 + sizeof (*ip0));
	  options_length =
	    ntohs (ip0->payload_length) - dhcpv6_ip6_palyoad_offset -
	    sizeof (*dhcpv60);

	  memset (&report, 0, sizeof (report));

	  sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  if (sw_if_index >= vec_len (cm->client_state_by_sw_if_index))
	    client_state = 0;
	  else
	    client_state = &cm->client_state_by_sw_if_index[sw_if_index];

	  xid =
	    (dhcpv60->xid[0] << 16) + (dhcpv60->xid[1] << 8) +
	    dhcpv60->xid[2];
	  if (!client_state || client_state->transaction_id != xid)
	    {
	      clib_warning
		("Received DHCPv6 message with wrong Transaction ID");
	      discard = 1;
	    }

	  report.sw_if_index = sw_if_index;
	  report.msg_type = dhcpv60->msg_type;
	  report.server_index = ~0;

	  switch (dhcpv60->msg_type)
	    {
	    case DHCPV6_MSG_ADVERTISE:
	    case DHCPV6_MSG_REPLY:
	      option = (dhcpv6_option_t *) (dhcpv60 + 1);
	      while (options_length > 0)
		{
		  if (options_length <
		      ntohs (option->length) + sizeof (*option))
		    {
		      clib_warning
			("remaining payload length < option length (%d < %d)",
			 options_length,
			 ntohs (option->length) + sizeof (*option));
		      break;
		    }
		  u16 oo = ntohs (option->option);
		  if (oo == DHCPV6_OPTION_IA_PD)
		    {
		      u8 discard_ia_pd = 0;
		      dhcpv6_ia_header_t *ia_header = (void *) option;
		      iaid = ntohl (ia_header->iaid);
		      u32 T1 = ntohl (ia_header->t1);
		      u32 T2 = ntohl (ia_header->t2);
		      if (iaid != DHCPV6_CLIENT_IAID)
			discard_ia_pd = 1;
		      if (T1 != 0 && T2 != 0 && T1 > T2)
			discard_ia_pd = 1;
		      if (!discard_ia_pd)
			{
			  report.T1 = T1;
			  report.T2 = T2;
			}
		      dhcpv6_option_t *inner_option =
			(void *) ia_header->data;
		      u16 inner_options_length =
			ntohs (option->length) - (sizeof (*ia_header) -
						  sizeof (dhcpv6_option_t));
		      while (inner_options_length > 0)
			{
			  u16 inner_oo = ntohs (inner_option->option);
			  if (discard_ia_pd)
			    ;
			  else if (inner_oo == DHCPV6_OPTION_IAPREFIX)
			    {
			      dhcpv6_ia_opt_pd_t *iaprefix =
				(void *) inner_option;
			      vec_validate (report.prefixes,
					    report.n_prefixes);
			      prefix_info_t *prefix_info =
				&report.prefixes[report.n_prefixes];
			      report.n_prefixes++;
			      prefix_info->preferred_time =
				ntohl (iaprefix->preferred);
			      prefix_info->valid_time =
				ntohl (iaprefix->valid);
			      prefix_info->prefix_length = iaprefix->prefix;
			      prefix_info->prefix = iaprefix->addr;
			    }
			  else if (inner_oo == DHCPV6_OPTION_STATUS_CODE)
			    {
			      dhcpv6_status_code_t *sc =
				(void *) inner_option;
			      report.inner_status_code =
				ntohs (sc->status_code);
			    }
			  inner_options_length -=
			    sizeof (*inner_option) +
			    ntohs (inner_option->length);
			  inner_option =
			    (void *) ((u8 *) inner_option +
				      sizeof (*inner_option) +
				      ntohs (inner_option->length));
			}
		    }
		  else if (oo == DHCPV6_OPTION_CLIENTID)
		    {
		      if (client_id_present)
			{
			  clib_warning
			    ("Duplicate Client ID in received DHVPv6 message");
			  discard = 1;
			}
		      else
			{
			  u16 len = ntohs (option->length);
			  client_id_present = 1;
			  if (len != CLIENT_DUID_LENGTH ||
			      0 != memcmp (option->data,
					   client_duid.bin_string,
					   CLIENT_DUID_LENGTH))
			    {
			      clib_warning
				("Unrecognized client DUID inside received DHVPv6 message");
			      discard = 1;
			    }
			}
		    }
		  else if (oo == DHCPV6_OPTION_SERVERID)
		    {
		      if (report.server_index != ~0)
			{
			  clib_warning
			    ("Duplicate Server ID in received DHVPv6 message");
			  discard = 1;
			}
		      else
			report.server_index =
			  server_index_get_or_create (option->data,
						      ntohs (option->length));
		    }
		  else if (oo == DHCPV6_OPTION_PREFERENCE)
		    {
		      report.preference = option->data[0];
		    }
		  else if (oo == DHCPV6_OPTION_STATUS_CODE)
		    {
		      dhcpv6_status_code_t *sc = (void *) option;
		      report.status_code = ntohs (sc->status_code);
		    }
		  options_length -= sizeof (*option) + ntohs (option->length);
		  option =
		    (void *) ((u8 *) option + sizeof (*option) +
			      ntohs (option->length));
		}

	      if (!client_id_present)
		{
		  clib_warning
		    ("Missing Client ID in received DHVPv6 message");
		  discard = 1;
		}
	      if (report.server_index == ~0)
		{
		  clib_warning
		    ("Missing Server ID in received DHVPv6 message");
		  discard = 1;
		}

	      if (!discard)
		publish_report (&report);
	      else
		vec_free (report.prefixes);

	      break;
	    default:
	      break;
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      dhcpv6_pd_client_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
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
VLIB_REGISTER_NODE (dhcpv6_pd_client_node, static) = {
    .function = dhcpv6_pd_client_node_fn,
    .name = "dhcpv6-pd-client",
    .vector_size = sizeof (u32),

    .n_errors = 0,

    .n_next_nodes = DHCPV6_PD_CLIENT_N_NEXT,
    .next_nodes = {
  #define _(s,n) [DHCPV6_PD_CLIENT_NEXT_##s] = n,
      foreach_dhcpv6_pd_client
  #undef _
    },

    .format_trace = format_dhcpv6_pd_client_trace,
};
/* *INDENT-ON* */

static_always_inline f64
random_f64_from_to (f64 from, f64 to)
{
  static u32 seed = 0;
  static u8 seed_set = 0;
  if (!seed_set)
    {
      seed = random_default_seed ();
      seed_set = 1;
    }
  return random_f64 (&seed) * (to - from) + from;
}

static const ip6_address_t all_dhcp6_relay_agents_and_servers = {
  .as_u8 = {
	    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02}
};

static vlib_buffer_t *
create_buffer_for_client_message (vlib_main_t * vm,
				  u32 sw_if_index,
				  dhcp6_pd_client_state_t
				  * client_state, u32 type)
{
  dhcp6_pd_client_main_t *dm = &dhcp6_pd_client_main;
  vnet_main_t *vnm = vnet_get_main ();

  vlib_buffer_t *b;
  u32 bi;
  ip6_header_t *ip;
  udp_header_t *udp;
  dhcpv6_header_t *dhcp;
  ip6_address_t src_addr;
  u32 dhcp_opt_len = 0;
  client_state->transaction_start = vlib_time_now (vm);
  u32 n_prefixes;
  u32 i;

  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  vnet_sw_interface_t *sup_sw = vnet_get_sup_sw_interface (vnm, sw_if_index);
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);

  /* Interface(s) down? */
  if ((hw->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)
    return NULL;
  if ((sup_sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    return NULL;
  if ((sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    return NULL;

  /* Get a link-local address */
  src_addr = ip6_neighbor_get_link_local_address (sw_if_index);

  if (src_addr.as_u8[0] != 0xfe)
    {
      clib_warning ("Could not find source address to send DHCPv6 packet");
      return NULL;
    }

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("Buffer allocation failed");
      return NULL;
    }

  b = vlib_get_buffer (vm, bi);
  vnet_buffer (b)->sw_if_index[VLIB_RX] = sw_if_index;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;
  client_state->adj_index = adj_mcast_add_or_lock (FIB_PROTOCOL_IP6,
						   VNET_LINK_IP6,
						   sw_if_index);
  vnet_buffer (b)->ip.adj_index[VLIB_TX] = client_state->adj_index;
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  ip = (ip6_header_t *) vlib_buffer_get_current (b);
  udp = (udp_header_t *) (ip + 1);
  dhcp = (dhcpv6_header_t *) (udp + 1);

  ip->src_address = src_addr;
  ip->hop_limit = 255;
  ip->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x6 << 28);
  ip->payload_length = 0;
  ip->protocol = IP_PROTOCOL_UDP;

  udp->src_port = clib_host_to_net_u16 (DHCPV6_CLIENT_PORT);
  udp->dst_port = clib_host_to_net_u16 (DHCPV6_SERVER_PORT);
  udp->checksum = 0;
  udp->length = 0;

  dhcp->msg_type = type;
  dhcp->xid[0] = (client_state->transaction_id & 0x00ff0000) >> 16;
  dhcp->xid[1] = (client_state->transaction_id & 0x0000ff00) >> 8;
  dhcp->xid[2] = (client_state->transaction_id & 0x000000ff) >> 0;

  void *d = (void *) dhcp->data;
  dhcpv6_option_t *duid;
  dhcpv6_elapsed_t *elapsed;
  dhcpv6_ia_header_t *ia_hdr;
  dhcpv6_ia_opt_pd_t *opt_pd;
  if (type == DHCPV6_MSG_SOLICIT || type == DHCPV6_MSG_REQUEST ||
      type == DHCPV6_MSG_RENEW || type == DHCPV6_MSG_REBIND ||
      type == DHCPV6_MSG_RELEASE)
    {
      duid = (dhcpv6_option_t *) d;
      duid->option = clib_host_to_net_u16 (DHCPV6_OPTION_CLIENTID);
      duid->length = clib_host_to_net_u16 (CLIENT_DUID_LENGTH);
      clib_memcpy (duid + 1, client_duid.bin_string, CLIENT_DUID_LENGTH);
      d += sizeof (*duid) + CLIENT_DUID_LENGTH;

      if (client_state->params.server_index != ~0)
	{
	  server_id_t *se =
	    &dm->server_ids[client_state->params.server_index];

	  duid = (dhcpv6_option_t *) d;
	  duid->option = clib_host_to_net_u16 (DHCPV6_OPTION_SERVERID);
	  duid->length = clib_host_to_net_u16 (se->len);
	  clib_memcpy (duid + 1, se->data, se->len);
	  d += sizeof (*duid) + se->len;
	}

      elapsed = (dhcpv6_elapsed_t *) d;
      elapsed->opt.option = clib_host_to_net_u16 (DHCPV6_OPTION_ELAPSED_TIME);
      elapsed->opt.length =
	clib_host_to_net_u16 (sizeof (*elapsed) - sizeof (elapsed->opt));
      elapsed->elapsed_10ms = 0;
      client_state->elapsed_pos =
	(char *) &elapsed->elapsed_10ms -
	(char *) vlib_buffer_get_current (b);
      d += sizeof (*elapsed);

      ia_hdr = (dhcpv6_ia_header_t *) d;
      ia_hdr->opt.option = clib_host_to_net_u16 (DHCPV6_OPTION_IA_PD);
      ia_hdr->iaid = clib_host_to_net_u32 (DHCPV6_CLIENT_IAID);
      ia_hdr->t1 = clib_host_to_net_u32 (client_state->params.T1);
      ia_hdr->t2 = clib_host_to_net_u32 (client_state->params.T2);
      d += sizeof (*ia_hdr);

      n_prefixes = vec_len (client_state->params.prefixes);

      ia_hdr->opt.length =
	clib_host_to_net_u16 (sizeof (*ia_hdr) +
			      n_prefixes * sizeof (*opt_pd) -
			      sizeof (ia_hdr->opt));

      for (i = 0; i < n_prefixes; i++)
	{
	  dhcp6_pd_send_client_message_params_prefix_t *pref =
	    &client_state->params.prefixes[i];
	  opt_pd = (dhcpv6_ia_opt_pd_t *) d;
	  opt_pd->opt.option = clib_host_to_net_u16 (DHCPV6_OPTION_IAPREFIX);
	  opt_pd->opt.length =
	    clib_host_to_net_u16 (sizeof (*opt_pd) - sizeof (opt_pd->opt));
	  opt_pd->addr = pref->prefix;
	  opt_pd->prefix = pref->prefix_length;
	  opt_pd->valid = clib_host_to_net_u32 (pref->valid_lt);
	  opt_pd->preferred = clib_host_to_net_u32 (pref->preferred_lt);
	  d += sizeof (*opt_pd);
	}
    }
  else
    {
      clib_warning ("State not implemented");
    }

  dhcp_opt_len = ((u8 *) d) - dhcp->data;
  udp->length =
    clib_host_to_net_u16 (sizeof (*udp) + sizeof (*dhcp) + dhcp_opt_len);
  ip->payload_length = udp->length;
  b->current_length =
    sizeof (*ip) + sizeof (*udp) + sizeof (*dhcp) + dhcp_opt_len;

  ip->dst_address = all_dhcp6_relay_agents_and_servers;

  return b;
}

static inline u8
check_pd_send_client_message (vlib_main_t * vm,
			      dhcp6_pd_client_state_t * client_state,
			      f64 current_time, f64 * due_time)
{
  vlib_buffer_t *p0;
  vlib_frame_t *f;
  u32 *to_next;
  u32 next_index;
  vlib_buffer_t *c0;
  ip6_header_t *ip;
  udp_header_t *udp;
  u32 ci0;
  int bogus_length = 0;

  dhcp6_pd_send_client_message_params_t *params;

  f64 now = vlib_time_now (vm);

  if (!client_state->keep_sending_client_message)
    return false;

  params = &client_state->params;

  if (client_state->due_time > current_time)
    {
      *due_time = client_state->due_time;
      return true;
    }

  p0 = client_state->buffer;

  next_index = ip6_rewrite_mcast_node.index;

  c0 = vlib_buffer_copy (vm, p0);
  ci0 = vlib_get_buffer_index (vm, c0);

  ip = (ip6_header_t *) vlib_buffer_get_current (c0);
  udp = (udp_header_t *) (ip + 1);

  u16 *elapsed_field = (u16 *) ((void *) ip + client_state->elapsed_pos);
  *elapsed_field =
    clib_host_to_net_u16 ((u16)
			  ((now - client_state->transaction_start) * 100));

  udp->checksum = 0;
  udp->checksum =
    ip6_tcp_udp_icmp_compute_checksum (vm, 0, ip, &bogus_length);

  f = vlib_get_frame_to_node (vm, next_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = ci0;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);

  if (params->mrc != 0 && --client_state->n_left == 0)
    stop_sending_client_message (vm, client_state);
  else
    {
      client_state->sleep_interval =
	(2 + random_f64_from_to (-0.1, 0.1)) * client_state->sleep_interval;
      if (client_state->sleep_interval > params->mrt)
	client_state->sleep_interval =
	  (1 + random_f64_from_to (-0.1, 0.1)) * params->mrt;

      client_state->due_time = current_time + client_state->sleep_interval;

      if (params->mrd != 0
	  && current_time > client_state->start_time + params->mrd)
	stop_sending_client_message (vm, client_state);
      else
	*due_time = client_state->due_time;
    }

  return client_state->keep_sending_client_message;
}

static uword
send_dhcp6_pd_client_message_process (vlib_main_t * vm,
				      vlib_node_runtime_t * rt,
				      vlib_frame_t * f0)
{
  dhcp6_pd_client_main_t *cm = &dhcp6_pd_client_main;
  dhcp6_pd_client_state_t *client_state;
  uword *event_data = 0;
  f64 sleep_time = 1e9;
  f64 current_time;
  f64 due_time;
  f64 dt = 0;
  int i;

  while (true)
    {
      vlib_process_wait_for_event_or_clock (vm, sleep_time);
      vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      current_time = vlib_time_now (vm);
      do
	{
	  due_time = current_time + 1e9;
	  for (i = 0; i < vec_len (cm->client_state_by_sw_if_index); i++)
	    {
	      client_state = &cm->client_state_by_sw_if_index[i];
	      if (!client_state->entry_valid)
		continue;
	      if (check_pd_send_client_message
		  (vm, client_state, current_time, &dt) && (dt < due_time))
		due_time = dt;
	    }
	  current_time = vlib_time_now (vm);
	}
      while (due_time < current_time);

      sleep_time = due_time - current_time;
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (send_dhcp6_pd_client_message_process_node) = {
    .function = send_dhcp6_pd_client_message_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "send-dhcp6-pd-client-message-process",
};
/* *INDENT-ON* */

void
dhcp6_pd_send_client_message (vlib_main_t * vm, u32 sw_if_index, u8 stop,
			      dhcp6_pd_send_client_message_params_t * params)
{
  dhcp6_pd_client_main_t *cm = &dhcp6_pd_client_main;
  dhcp6_pd_client_state_t *client_state = 0;
  dhcp6_pd_client_state_t empty_state = {
    0,
  };

  ASSERT (~0 != sw_if_index);

  vec_validate_init_empty (cm->client_state_by_sw_if_index, sw_if_index,
			   empty_state);
  client_state = &cm->client_state_by_sw_if_index[sw_if_index];
  if (!client_state->entry_valid)
    {
      client_state->entry_valid = 1;
      client_state->adj_index = ~0;
    }

  stop_sending_client_message (vm, client_state);

  if (!stop)
    {
      client_state->keep_sending_client_message = 1;
      vec_free (client_state->params.prefixes);
      client_state->params = *params;
      client_state->params.prefixes = vec_dup (params->prefixes);
      client_state->n_left = params->mrc;
      client_state->start_time = vlib_time_now (vm);
      client_state->sleep_interval =
	(1 + random_f64_from_to (-0.1, 0.1)) * params->irt;
      client_state->due_time = 0;	/* send first packet ASAP */
      client_state->transaction_id = random_u32 (&cm->seed) & 0x00ffffff;
      client_state->buffer =
	create_buffer_for_client_message (vm, sw_if_index, client_state,
					  params->msg_type);
      if (!client_state->buffer)
	client_state->keep_sending_client_message = 0;
      else
	vlib_process_signal_event (vm,
				   send_dhcp6_pd_client_message_process_node.index,
				   1, 0);
    }
}

void
  vl_api_dhcp6_pd_send_client_message_t_handler
  (vl_api_dhcp6_pd_send_client_message_t * mp)
{
  vl_api_dhcp6_pd_send_client_message_reply_t *rmp;
  dhcp6_pd_send_client_message_params_t params;
  vlib_main_t *vm = vlib_get_main ();
  u32 n_prefixes;
  u32 i;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE_REPLY);

  if (rv != 0)
    return;

  params.sw_if_index = ntohl (mp->sw_if_index);
  params.server_index = ntohl (mp->server_index);
  params.irt = ntohl (mp->irt);
  params.mrt = ntohl (mp->mrt);
  params.mrc = ntohl (mp->mrc);
  params.mrd = ntohl (mp->mrd);
  params.msg_type = mp->msg_type;
  params.T1 = ntohl (mp->T1);
  params.T2 = ntohl (mp->T2);
  n_prefixes = ntohl (mp->n_prefixes);
  params.prefixes = 0;
  if (n_prefixes > 0)
    vec_validate (params.prefixes, n_prefixes - 1);
  for (i = 0; i < n_prefixes; i++)
    {
      vl_api_dhcp6_pd_prefix_info_t *pi = &mp->prefixes[i];
      dhcp6_pd_send_client_message_params_prefix_t *pref =
	&params.prefixes[i];
      pref->preferred_lt = ntohl (pi->preferred_time);
      pref->valid_lt = ntohl (pi->valid_time);
      memcpy (pref->prefix.as_u8, pi->prefix, 16);
      pref->prefix_length = pi->prefix_length;
    }

  dhcp6_pd_send_client_message (vm, ntohl (mp->sw_if_index), mp->stop,
				&params);
}

static clib_error_t *
call_dhcp6_pd_reply_event_callbacks (void *data,
				     _vnet_dhcp6_pd_reply_event_function_list_elt_t
				     * elt)
{
  clib_error_t *error = 0;

  while (elt)
    {
      error = elt->fp (data);
      if (error)
	return error;
      elt = elt->next_dhcp6_pd_reply_event_function;
    }

  return error;
}

static uword
dhcp6_pd_reply_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
			vlib_frame_t * f)
{
  /* These cross the longjmp  boundry (vlib_process_wait_for_event)
   * and need to be volatile - to prevent them from being optimized into
   * a register - which could change during suspension */

  while (1)
    {
      vlib_process_wait_for_event (vm);
      uword event_type = DHCP6_PD_DP_REPLY_REPORT;
      void *event_data = vlib_process_get_event_data (vm, &event_type);

      int i;
      if (event_type == DHCP6_PD_DP_REPLY_REPORT)
	{
	  report_t *events = event_data;
	  for (i = 0; i < vec_len (events); i++)
	    {
	      u32 event_size =
		sizeof (vl_api_dhcp6_pd_reply_event_t) +
		vec_len (events[i].prefixes) *
		sizeof (vl_api_dhcp6_pd_prefix_info_t);
	      vl_api_dhcp6_pd_reply_event_t *event =
		clib_mem_alloc (event_size);
	      memset (event, 0, event_size);

	      event->sw_if_index = htonl (events[i].sw_if_index);
	      event->server_index = htonl (events[i].server_index);
	      event->msg_type = events[i].msg_type;
	      event->T1 = htonl (events[i].T1);
	      event->T2 = htonl (events[i].T2);
	      event->inner_status_code = htons (events[i].inner_status_code);
	      event->status_code = htons (events[i].status_code);
	      event->preference = events[i].preference;

	      event->n_prefixes = htonl (vec_len (events[i].prefixes));
	      vl_api_dhcp6_pd_prefix_info_t *prefix =
		(typeof (prefix)) event->prefixes;
	      u32 j;
	      for (j = 0; j < vec_len (events[i].prefixes); j++)
		{
		  prefix_info_t *info = &events[i].prefixes[j];
		  memcpy (prefix->prefix, &info->prefix, 16);
		  prefix->prefix_length = info->prefix_length;
		  prefix->valid_time = htonl (info->valid_time);
		  prefix->preferred_time = htonl (info->preferred_time);
		  prefix++;
		}

	      dhcp6_pd_client_public_main_t *dpcpm =
		&dhcp6_pd_client_public_main;
	      call_dhcp6_pd_reply_event_callbacks (event, dpcpm->functions);

	      vpe_client_registration_t *reg;
              /* *INDENT-OFF* */
              pool_foreach(reg, vpe_api_main.dhcp6_pd_reply_events_registrations,
              ({
                vl_api_registration_t *vl_reg;
                vl_reg =
                  vl_api_client_index_to_registration (reg->client_index);
                if (vl_reg && vl_api_can_send_msg (vl_reg))
                  {
                    vl_api_dhcp6_pd_reply_event_t *msg =
                      vl_msg_api_alloc (event_size);
                    clib_memcpy (msg, event, event_size);
                    msg->_vl_msg_id = htons (VL_API_DHCP6_PD_REPLY_EVENT);
                    msg->client_index = reg->client_index;
                    msg->pid = reg->client_pid;
                    vl_api_send_msg (vl_reg, (u8 *) msg);
                  }
              }));
              /* *INDENT-ON* */

	      clib_mem_free (event);
	    }
	}
      vlib_process_put_event_data (vm, event_data);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dhcp6_pd_reply_process_node, ) = {
  .function = dhcp6_pd_reply_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "dhcp6-pd-reply-publisher-process",
};
/* *INDENT-ON* */

void
  vl_api_want_dhcp6_pd_reply_events_t_handler
  (vl_api_want_dhcp6_pd_reply_events_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_want_dhcp6_pd_reply_events_reply_t *rmp;
  int rv = 0;

  uword *p =
    hash_get (am->dhcp6_pd_reply_events_registration_hash, mp->client_index);
  vpe_client_registration_t *rp;
  if (p)
    {
      if (mp->enable_disable)
	{
	  clib_warning ("pid %d: already enabled...", ntohl (mp->pid));
	  rv = VNET_API_ERROR_INVALID_REGISTRATION;
	  goto reply;
	}
      else
	{
	  rp =
	    pool_elt_at_index (am->dhcp6_pd_reply_events_registrations, p[0]);
	  pool_put (am->dhcp6_pd_reply_events_registrations, rp);
	  hash_unset (am->dhcp6_pd_reply_events_registration_hash,
		      mp->client_index);
	  if (pool_elts (am->dhcp6_pd_reply_events_registrations) == 0)
	    dhcp6_pd_set_publisher_node (~0, REPORT_MAX);
	  goto reply;
	}
    }
  if (mp->enable_disable == 0)
    {
      clib_warning ("pid %d: already disabled...", ntohl (mp->pid));
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto reply;
    }
  pool_get (am->dhcp6_pd_reply_events_registrations, rp);
  rp->client_index = mp->client_index;
  rp->client_pid = ntohl (mp->pid);
  hash_set (am->dhcp6_pd_reply_events_registration_hash, rp->client_index,
	    rp - am->dhcp6_pd_reply_events_registrations);
  dhcp6_pd_set_publisher_node (dhcp6_pd_reply_process_node.index,
			       DHCP6_PD_DP_REPLY_REPORT);

reply:
  REPLY_MACRO (VL_API_WANT_DHCP6_PD_REPLY_EVENTS_REPLY);
}

void
dhcp6_clients_enable_disable (u8 enable)
{
  vlib_main_t *vm = vlib_get_main ();

  if (enable)
    udp_register_dst_port (vm, UDP_DST_PORT_dhcpv6_to_client,
			   dhcpv6_pd_client_node.index, 0 /* is_ip6 */ );
  else
    udp_unregister_dst_port (vm, UDP_DST_PORT_dhcpv6_to_client,
			     0 /* is_ip6 */ );
}

void
  vl_api_dhcp6_clients_enable_disable_t_handler
  (vl_api_dhcp6_clients_enable_disable_t * mp)
{
  vl_api_dhcp6_clients_enable_disable_reply_t *rmp;
  int rv = 0;

  dhcp6_clients_enable_disable (mp->enable);

  REPLY_MACRO (VL_API_WANT_DHCP6_PD_REPLY_EVENTS_REPLY);
}

static void
genereate_client_duid (void)
{
  client_duid.duid_type = htons (DHCPV6_DUID_LLT);
  client_duid.hardware_type = htons (1);
  u32 time_since_2000 = (u32) time (0) - 946684800;
  client_duid.time = htonl (time_since_2000);

  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi;
  ethernet_interface_t *eth_if = 0;

  /* *INDENT-OFF* */
  pool_foreach (hi, im->hw_interfaces,
  ({
    eth_if = ethernet_get_interface (&ethernet_main, hi->hw_if_index);
    if (eth_if)
      break;
  }));
  /* *INDENT-ON* */

  if (eth_if)
    clib_memcpy (client_duid.lla, eth_if->address, 6);
  else
    {
      clib_warning ("Failed to find any Ethernet interface, "
		    "setting DHCPv6 DUID link-layer address to random value");
      u32 seed = random_default_seed ();
      random_u32 (&seed);
      client_duid.lla[0] = 0xc2;	/* locally administered unicast */
      client_duid.lla[1] = 0x18;
      client_duid.lla[2] = 0x44;
      client_duid.lla[3] = random_u32 (&seed);
      client_duid.lla[4] = random_u32 (&seed);
      client_duid.lla[5] = random_u32 (&seed);
    }
}

static clib_error_t *
dhcp6_pd_client_init (vlib_main_t * vm)
{
  dhcp6_pd_client_main_t *cm = &dhcp6_pd_client_main;

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main ();

  cm->publisher_node = ~0;

  cm->seed = 0xdeaddabe;

  // TODO: should be stored in non-volatile memory
  genereate_client_duid ();

  return 0;
}

VLIB_INIT_FUNCTION (dhcp6_pd_client_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
