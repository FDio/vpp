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

#include <vnet/dhcp/dhcp6_client_common_dp.h>
#include <vnet/dhcp/dhcp6_ia_na_client_dp.h>
#include <vnet/dhcp/dhcp6_pd_client_dp.h>
#include <vnet/dhcp/dhcp6_packet.h>
#include <vnet/udp/udp.h>

dhcp6_client_common_main_t dhcp6_client_common_main;
dhcpv6_duid_ll_string_t client_duid;

u32
server_index_get_or_create (u8 * data, u16 len)
{
  dhcp6_client_common_main_t *ccm = &dhcp6_client_common_main;
  u32 i;
  server_id_t *se;
  server_id_t new_se;

  for (i = 0; i < vec_len (ccm->server_ids); i++)
    {
      se = &ccm->server_ids[i];
      if (se->len == len && 0 == memcmp (se->data, data, len))
	return i;
    }

  new_se.len = len;
  new_se.data = 0;
  vec_validate (new_se.data, len - 1);
  memcpy (new_se.data, data, len);

  vec_add1 (ccm->server_ids, new_se);

  return vec_len (ccm->server_ids) - 1;
}

void
vl_api_dhcp6_duid_ll_set_t_handler (vl_api_dhcp6_duid_ll_set_t * mp)
{
  vl_api_dhcp6_duid_ll_set_reply_t *rmp;
  dhcpv6_duid_ll_string_t *duid;
  int rv = 0;

  duid = (dhcpv6_duid_ll_string_t *) mp->duid_ll;
  if (duid->duid_type != htonl (DHCPV6_DUID_LL))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }
  clib_memcpy (&client_duid, &duid, sizeof (client_duid));

reply:
  REPLY_MACRO (VL_API_DHCP6_DUID_LL_SET_REPLY);
}

static void
generate_client_duid (void)
{
  client_duid.duid_type = htons (DHCPV6_DUID_LL);
  client_duid.hardware_type = htons (1);

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

#define foreach_dhcpv6_client \
  _(DROP, "error-drop")       \
  _(LOOKUP, "ip6-lookup")

typedef enum
{
#define _(sym,str) DHCPV6_CLIENT_NEXT_##sym,
  foreach_dhcpv6_client
#undef _
    DHCPV6_CLIENT_N_NEXT,
} dhcpv6_client_next_t;

/**
 * per-packet trace data
 */
typedef struct dhcpv6_client_trace_t_
{
} dhcpv6_client_trace_t;

static u8 *
format_dhcpv6_client_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  //dhcpv6_client_trace_t *t = va_arg (*args, dhcpv6_client_trace_t *);

  s = format (s, "nothing");

  return s;
}

static uword
dhcpv6_client_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  dhcp6_ia_na_client_main_t *icm = &dhcp6_ia_na_client_main;
  dhcp6_pd_client_main_t *pcm = &dhcp6_pd_client_main;

  dhcpv6_client_next_t next_index;
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
	  dhcp6_report_common_t report;
	  dhcp6_address_info_t *addresses = 0;
	  dhcp6_prefix_info_t *prefixes = 0;
	  u32 next0 = DHCPV6_CLIENT_NEXT_DROP;
	  u32 bi0;
	  u32 xid;
	  u32 sw_if_index;
	  u32 iaid;
	  u8 client_id_present = 0;
	  u8 discard = 0;
	  u8 is_pd_packet = 0;

	  dhcp6_ia_na_client_state_t *ia_na_client_state = NULL;
	  dhcp6_pd_client_state_t *pd_client_state = NULL;

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

	  clib_memset (&report, 0, sizeof (report));

	  sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  if (sw_if_index >= vec_len (icm->client_state_by_sw_if_index))
	    ia_na_client_state = 0;
	  else
	    ia_na_client_state =
	      &icm->client_state_by_sw_if_index[sw_if_index];
	  if (sw_if_index >= vec_len (pcm->client_state_by_sw_if_index))
	    pd_client_state = 0;
	  else
	    pd_client_state = &pcm->client_state_by_sw_if_index[sw_if_index];

	  xid =
	    (dhcpv60->xid[0] << 16) + (dhcpv60->xid[1] << 8) +
	    dhcpv60->xid[2];
	  if (ia_na_client_state && ia_na_client_state->transaction_id == xid)
	    is_pd_packet = 0;
	  else if (pd_client_state && pd_client_state->transaction_id == xid)
	    is_pd_packet = 1;
	  else
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
		  if (oo == DHCPV6_OPTION_IA_NA || oo == DHCPV6_OPTION_IA_PD)
		    {
		      u8 discard_option = 0;
		      dhcpv6_ia_header_t *ia_header = (void *) option;
		      iaid = ntohl (ia_header->iaid);
		      u32 T1 = ntohl (ia_header->t1);
		      u32 T2 = ntohl (ia_header->t2);
		      if (iaid != DHCPV6_CLIENT_IAID)
			discard_option = 1;
		      if (T1 != 0 && T2 != 0 && T1 > T2)
			discard_option = 1;
		      if (!discard_option)
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
			  if (discard_option)
			    ;
			  else if (inner_oo == DHCPV6_OPTION_IAADDR)
			    {
			      dhcpv6_ia_opt_addr_t *iaaddr =
				(void *) inner_option;
			      u32 n_addresses = vec_len (addresses);
			      vec_validate (addresses, n_addresses);
			      dhcp6_address_info_t *address_info =
				&addresses[n_addresses];
			      address_info->preferred_time =
				ntohl (iaaddr->preferred);
			      address_info->valid_time =
				ntohl (iaaddr->valid);
			      address_info->address = iaaddr->addr;
			    }
			  else if (inner_oo == DHCPV6_OPTION_IAPREFIX)
			    {
			      dhcpv6_ia_opt_pd_t *iaprefix =
				(void *) inner_option;
			      u32 n_prefixes = vec_len (prefixes);
			      vec_validate (prefixes, n_prefixes);
			      dhcp6_prefix_info_t *prefix_info =
				&prefixes[n_prefixes];
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
			{
			  u16 ol = ntohs (option->length);
			  if (ol - 2 /* 2 byte DUID type code */  > 128)
			    {
			      clib_warning
				("Server DUID (without type code) is longer than 128 octets");
			      discard = 1;
			    }
			  else
			    {
			      report.server_index =
				server_index_get_or_create (option->data, ol);
			    }
			}
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
		{
		  if (!is_pd_packet)
		    {
		      address_report_t r;
		      r.body = report;
		      r.n_addresses = vec_len (addresses);
		      r.addresses = addresses;
		      dhcp6_publish_report (&r);
		      /* We just gave addresses to another process! */
		      addresses = 0;
		    }
		  else
		    {
		      prefix_report_t r;
		      r.body = report;
		      r.n_prefixes = vec_len (prefixes);
		      r.prefixes = prefixes;
		      dhcp6_pd_publish_report (&r);
		      /* We just gave prefixes to another process! */
		      prefixes = 0;
		    }
		}
	      vec_free (addresses);
	      vec_free (prefixes);

	      break;
	    default:
	      break;
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      dhcpv6_client_trace_t *t =
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
VLIB_REGISTER_NODE (dhcpv6_client_node, static) = {
    .function = dhcpv6_client_node_fn,
    .name = "dhcpv6-client",
    .vector_size = sizeof (u32),

    .n_errors = 0,

    .n_next_nodes = DHCPV6_CLIENT_N_NEXT,
    .next_nodes = {
  #define _(s,n) [DHCPV6_CLIENT_NEXT_##s] = n,
      foreach_dhcpv6_client
  #undef _
    },

    .format_trace = format_dhcpv6_client_trace,
};
/* *INDENT-ON* */

void
dhcp6_clients_enable_disable (u8 enable)
{
  vlib_main_t *vm = vlib_get_main ();

  if (enable)
    {
      if (client_duid.duid_type == 0)
	generate_client_duid ();
      udp_register_dst_port (vm, UDP_DST_PORT_dhcpv6_to_client,
			     dhcpv6_client_node.index, 0 /* is_ip6 */ );
    }
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

  REPLY_MACRO (VL_API_DHCP6_CLIENTS_ENABLE_DISABLE_REPLY);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
