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
#include <dhcp/dhcp6_packet.h>
#include <dhcp/dhcp_proxy.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/mfib/ip6_mfib.h>
#include <vnet/fib/fib.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/ip/ip6_link.h>
#include <dhcp/dhcp6_ia_na_client_dp.h>
#include <dhcp/dhcp6_client_common_dp.h>
#include <vnet/ip/ip_types_api.h>

dhcp6_ia_na_client_main_t dhcp6_ia_na_client_main;
dhcp6_ia_na_client_public_main_t dhcp6_ia_na_client_public_main;

static void
signal_report (address_report_t * r)
{
  vlib_main_t *vm = vlib_get_main ();
  dhcp6_ia_na_client_main_t *cm = &dhcp6_ia_na_client_main;
  uword ni = cm->publisher_node;
  uword et = cm->publisher_et;

  if (ni == (uword) ~ 0)
    return;
  address_report_t *q =
    vlib_process_signal_event_data (vm, ni, et, 1, sizeof *q);

  *q = *r;
}

int
dhcp6_publish_report (address_report_t * r)
{
  void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);
  vl_api_rpc_call_main_thread (signal_report, (u8 *) r, sizeof *r);
  return 0;
}

void
dhcp6_set_publisher_node (uword node_index, uword event_type)
{
  dhcp6_ia_na_client_main_t *cm = &dhcp6_ia_na_client_main;
  cm->publisher_node = node_index;
  cm->publisher_et = event_type;
}

static void
stop_sending_client_message (vlib_main_t * vm,
			     dhcp6_ia_na_client_state_t * client_state)
{
  u32 bi0;

  client_state->keep_sending_client_message = 0;
  vec_free (client_state->params.addresses);
  if (client_state->buffer)
    {
      bi0 = vlib_get_buffer_index (vm, client_state->buffer);
      vlib_buffer_free (vm, &bi0, 1);
      client_state->buffer = 0;
      adj_unlock (client_state->adj_index);
      client_state->adj_index = ~0;
    }
}

static vlib_buffer_t *
create_buffer_for_client_message (vlib_main_t * vm, u32 sw_if_index,
				  dhcp6_ia_na_client_state_t * client_state,
				  u32 type)
{
  dhcp6_client_common_main_t *ccm = &dhcp6_client_common_main;
  vlib_buffer_t *b;
  u32 bi;
  ip6_header_t *ip;
  udp_header_t *udp;
  dhcpv6_header_t *dhcp;
  const ip6_address_t *src_addr;
  u32 dhcp_opt_len = 0;
  client_state->transaction_start = vlib_time_now (vm);
  u32 n_addresses;
  u32 i;

  /* Get a link-local address */
  src_addr = ip6_get_link_local_address (sw_if_index);

  if (src_addr->as_u8[0] != 0xfe)
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
  vnet_buffer (b)->ip.adj_index = client_state->adj_index;
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  ip = (ip6_header_t *) vlib_buffer_get_current (b);
  udp = (udp_header_t *) (ip + 1);
  dhcp = (dhcpv6_header_t *) (udp + 1);

  ip->src_address = *src_addr;
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
  dhcpv6_ia_opt_addr_t *opt_addr;
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
	    &ccm->server_ids[client_state->params.server_index];

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
      ia_hdr->opt.option = clib_host_to_net_u16 (DHCPV6_OPTION_IA_NA);
      ia_hdr->iaid = clib_host_to_net_u32 (DHCPV6_CLIENT_IAID);
      ia_hdr->t1 = clib_host_to_net_u32 (client_state->params.T1);
      ia_hdr->t2 = clib_host_to_net_u32 (client_state->params.T2);
      d += sizeof (*ia_hdr);

      n_addresses = vec_len (client_state->params.addresses);

      ia_hdr->opt.length =
	clib_host_to_net_u16 (sizeof (*ia_hdr) +
			      n_addresses * sizeof (*opt_addr) -
			      sizeof (ia_hdr->opt));

      for (i = 0; i < n_addresses; i++)
	{
	  dhcp6_send_client_message_params_address_t *addr =
	    &client_state->params.addresses[i];
	  opt_addr = (dhcpv6_ia_opt_addr_t *) d;
	  opt_addr->opt.option = clib_host_to_net_u16 (DHCPV6_OPTION_IAADDR);
	  opt_addr->opt.length =
	    clib_host_to_net_u16 (sizeof (*opt_addr) -
				  sizeof (opt_addr->opt));
	  opt_addr->addr = addr->address;
	  opt_addr->valid = clib_host_to_net_u32 (addr->valid_lt);
	  opt_addr->preferred = clib_host_to_net_u32 (addr->preferred_lt);
	  d += sizeof (*opt_addr);
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
check_send_client_message (vlib_main_t * vm,
			   dhcp6_ia_na_client_state_t * client_state,
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

  dhcp6_send_client_message_params_t *params;

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
  if (c0 == NULL)
    return client_state->keep_sending_client_message;

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
send_dhcp6_client_message_process (vlib_main_t * vm,
				   vlib_node_runtime_t * rt,
				   vlib_frame_t * f0)
{
  dhcp6_ia_na_client_main_t *cm = &dhcp6_ia_na_client_main;
  dhcp6_ia_na_client_state_t *client_state;
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
	      if (check_send_client_message
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
VLIB_REGISTER_NODE (send_dhcp6_client_message_process_node, static) = {
    .function = send_dhcp6_client_message_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "send-dhcp6-client-message-process",
};
/* *INDENT-ON* */

void
dhcp6_send_client_message (vlib_main_t * vm, u32 sw_if_index, u8 stop,
			   dhcp6_send_client_message_params_t * params)
{
  dhcp6_ia_na_client_main_t *cm = &dhcp6_ia_na_client_main;
  dhcp6_ia_na_client_state_t *client_state = 0;
  dhcp6_ia_na_client_state_t empty_state = { 0, };

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
      vec_free (client_state->params.addresses);
      client_state->params = *params;
      client_state->params.addresses = vec_dup (params->addresses);
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
				   send_dhcp6_client_message_process_node.index,
				   1, 0);
    }
}

static clib_error_t *
dhcp6_client_init (vlib_main_t * vm)
{
  dhcp6_ia_na_client_main_t *cm = &dhcp6_ia_na_client_main;

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main ();

  cm->publisher_node = ~0;

  cm->seed = 0xdeaccabe;

  return 0;
}

VLIB_INIT_FUNCTION (dhcp6_client_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
