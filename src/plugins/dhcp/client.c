/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vlibmemory/api.h>
#include <dhcp/client.h>
#include <dhcp/dhcp_proxy.h>
#include <vnet/fib/fib_table.h>
#include <vnet/qos/qos_types.h>

vlib_log_class_t dhcp_logger;

dhcp_client_main_t dhcp_client_main;
static vlib_node_registration_t dhcp_client_process_node;

#define DHCP_DBG(...)                           \
    vlib_log_debug (dhcp_logger, __VA_ARGS__)

#define DHCP_INFO(...)                          \
    vlib_log_notice (dhcp_logger, __VA_ARGS__)

#define foreach_dhcp_sent_packet_stat           \
_(DISCOVER, "DHCP discover packets sent")       \
_(OFFER, "DHCP offer packets sent")             \
_(REQUEST, "DHCP request packets sent")         \
_(ACK, "DHCP ack packets sent")

#define foreach_dhcp_error_counter                                      \
_(NOT_FOR_US, "DHCP packets for other hosts, dropped")                  \
_(NAK, "DHCP nak packets received")                                     \
_(NON_OFFER_DISCOVER, "DHCP non-offer packets in discover state")       \
_(ODDBALL, "DHCP non-ack, non-offer packets received")                  \
_(BOUND, "DHCP bind success")

typedef enum
{
#define _(sym,str) DHCP_STAT_##sym,
  foreach_dhcp_sent_packet_stat foreach_dhcp_error_counter
#undef _
    DHCP_STAT_UNKNOWN,
  DHCP_STAT_N_STAT,
} sample_error_t;

static char *dhcp_client_process_stat_strings[] = {
#define _(sym,string) string,
  foreach_dhcp_sent_packet_stat foreach_dhcp_error_counter
#undef _
    "DHCP unknown packets sent",
};

static u8 *
format_dhcp_client_state (u8 * s, va_list * va)
{
  dhcp_client_state_t state = va_arg (*va, dhcp_client_state_t);
  char *str = "BOGUS!";

  switch (state)
    {
#define _(a)                                    \
    case a:                                     \
      str = #a;                                 \
        break;
      foreach_dhcp_client_state;
#undef _
    default:
      break;
    }

  s = format (s, "%s", str);
  return s;
}

static u8 *
format_dhcp_client (u8 * s, va_list * va)
{
  dhcp_client_main_t *dcm = va_arg (*va, dhcp_client_main_t *);
  dhcp_client_t *c = va_arg (*va, dhcp_client_t *);
  int verbose = va_arg (*va, int);
  ip4_address_t *addr;

  s = format (s, "[%d] %U state %U installed %d", c - dcm->clients,
	      format_vnet_sw_if_index_name, dcm->vnet_main, c->sw_if_index,
	      format_dhcp_client_state, c->state, c->addresses_installed);

  if (0 != c->dscp)
    s = format (s, " dscp %d", c->dscp);

  if (c->installed.leased_address.as_u32)
    {
      s = format (s, " addr %U/%d gw %U server %U",
		  format_ip4_address, &c->installed.leased_address,
		  c->installed.subnet_mask_width,
		  format_ip4_address, &c->installed.router_address,
		  format_ip4_address, &c->installed.dhcp_server);

      vec_foreach (addr, c->domain_server_address)
	s = format (s, " dns %U", format_ip4_address, addr);
    }
  else
    {
      s = format (s, " no address");
    }

  if (verbose)
    {
      s =
	format (s,
		"\n lease: lifetime:%d renewal-interval:%d expires:%.2f (now:%.2f)",
		c->lease_lifetime, c->lease_renewal_interval,
		c->lease_expires, vlib_time_now (dcm->vlib_main));
      s =
	format (s, "\n retry-count:%d, next-xmt:%.2f", c->retry_count,
		c->next_transmit);
      s = format (s, "\n broadcast adjacency:%d", c->ai_bcast);
    }
  return s;
}

static void
dhcp_client_acquire_address (dhcp_client_main_t * dcm, dhcp_client_t * c)
{
  /*
   * Install any/all info gleaned from dhcp, right here
   */
  if (!c->addresses_installed)
    {
      ip4_add_del_interface_address (dcm->vlib_main, c->sw_if_index,
				     (void *) &c->learned.leased_address,
				     c->learned.subnet_mask_width,
				     0 /*is_del */ );
      if (c->learned.router_address.as_u32)
	{
	  fib_prefix_t all_0s = {
	    .fp_len = 0,
	    .fp_proto = FIB_PROTOCOL_IP4,
	  };
	  ip46_address_t nh = {
	    .ip4 = c->learned.router_address,
	  };

          /* *INDENT-OFF* */
          fib_table_entry_path_add (
              fib_table_get_index_for_sw_if_index (
                  FIB_PROTOCOL_IP4,
                  c->sw_if_index),
              &all_0s,
              FIB_SOURCE_DHCP,
              FIB_ENTRY_FLAG_NONE,
              DPO_PROTO_IP4,
              &nh, c->sw_if_index,
              ~0, 1, NULL,	// no label stack
              FIB_ROUTE_PATH_FLAG_NONE);
          /* *INDENT-ON* */
	}
    }
  clib_memcpy (&c->installed, &c->learned, sizeof (c->installed));
  c->addresses_installed = 1;
}

static void
dhcp_client_release_address (dhcp_client_main_t * dcm, dhcp_client_t * c)
{
  /*
   * Remove any/all info gleaned from dhcp, right here. Caller(s)
   * have not wiped out the info yet.
   */
  if (c->addresses_installed)
    {
      ip4_add_del_interface_address (dcm->vlib_main, c->sw_if_index,
				     (void *) &c->installed.leased_address,
				     c->installed.subnet_mask_width,
				     1 /*is_del */ );

      /* Remove the default route */
      if (c->installed.router_address.as_u32)
	{
	  fib_prefix_t all_0s = {
	    .fp_len = 0,
	    .fp_proto = FIB_PROTOCOL_IP4,
	  };
	  ip46_address_t nh = {
	    .ip4 = c->installed.router_address,
	  };

	  fib_table_entry_path_remove (fib_table_get_index_for_sw_if_index
				       (FIB_PROTOCOL_IP4, c->sw_if_index),
				       &all_0s, FIB_SOURCE_DHCP,
				       DPO_PROTO_IP4, &nh, c->sw_if_index, ~0,
				       1, FIB_ROUTE_PATH_FLAG_NONE);
	}
    }
  clib_memset (&c->installed, 0, sizeof (c->installed));
  c->addresses_installed = 0;
}

static void
dhcp_client_proc_callback (uword * client_index)
{
  vlib_main_t *vm = vlib_get_main ();
  ASSERT (vlib_get_thread_index () == 0);
  vlib_process_signal_event (vm, dhcp_client_process_node.index,
			     EVENT_DHCP_CLIENT_WAKEUP, *client_index);
}

static void
dhcp_client_addr_callback (u32 * cindex)
{
  dhcp_client_main_t *dcm = &dhcp_client_main;
  dhcp_client_t *c;

  c = pool_elt_at_index (dcm->clients, *cindex);

  /* disable the feature */
  vnet_feature_enable_disable ("ip4-unicast",
			       "ip4-dhcp-client-detect",
			       c->sw_if_index, 0 /* disable */ , 0, 0);
  c->client_detect_feature_enabled = 0;

  /* add the address to the interface if they've changed since the last time */
  if (0 != clib_memcmp (&c->installed, &c->learned, sizeof (c->learned)))
    {
      dhcp_client_release_address (dcm, c);
      dhcp_client_acquire_address (dcm, c);
    }

  /*
   * Call the user's event callback to report DHCP information
   */
  if (c->event_callback)
    c->event_callback (c->client_index, c);

  DHCP_INFO ("update: %U", format_dhcp_client, dcm, c, 1 /* verbose */ );
}

static void
dhcp_client_reset (dhcp_client_main_t * dcm, dhcp_client_t * c)
{
  if (c->client_detect_feature_enabled == 1)
    {
      vnet_feature_enable_disable ("ip4-unicast",
				   "ip4-dhcp-client-detect",
				   c->sw_if_index, 0, 0, 0);
      c->client_detect_feature_enabled = 0;
    }

  dhcp_client_release_address (dcm, c);
  clib_memset (&c->learned, 0, sizeof (c->installed));
  c->state = DHCP_DISCOVER;
  c->next_transmit = vlib_time_now (dcm->vlib_main);
  c->retry_count = 0;
  c->lease_renewal_interval = 0;
  vec_free (c->domain_server_address);
}

/*
 * dhcp_client_for_us - server-to-client callback.
 * Called from proxy_node.c:dhcp_proxy_to_client_input().
 * This function first decides that the packet in question is
 * actually for the dhcp client code in case we're also acting as
 * a dhcp proxy. Ay caramba, what a folly!
 */
int
dhcp_client_for_us (u32 bi, vlib_buffer_t * b,
		    ip4_header_t * ip,
		    udp_header_t * udp, dhcp_header_t * dhcp)
{
  dhcp_client_main_t *dcm = &dhcp_client_main;
  vlib_main_t *vm = vlib_get_main ();
  dhcp_client_t *c;
  uword *p;
  f64 now = vlib_time_now (vm);
  u8 dhcp_message_type = 0;
  dhcp_option_t *o;

  /*
   * Doing dhcp client on this interface?
   * Presumably we will always receive dhcp clnt for-us pkts on
   * the interface that's asking for an address.
   */
  p = hash_get (dcm->client_by_sw_if_index,
		vnet_buffer (b)->sw_if_index[VLIB_RX]);
  if (p == 0)
    return 0;			/* no */

  c = pool_elt_at_index (dcm->clients, p[0]);

  /* Mixing dhcp relay and dhcp proxy? DGMS... */
  if (c->state == DHCP_BOUND && c->retry_count == 0)
    return 0;

  /* Packet not for us? Turf it... */
  if (memcmp (dhcp->client_hardware_address, c->client_hardware_address,
	      sizeof (c->client_hardware_address)))
    {
      vlib_node_increment_counter (vm, dhcp_client_process_node.index,
				   DHCP_STAT_NOT_FOR_US, 1);
      return 0;
    }

  /* parse through the packet, learn what we can */
  if (dhcp->your_ip_address.as_u32)
    c->learned.leased_address.as_u32 = dhcp->your_ip_address.as_u32;

  c->learned.dhcp_server.as_u32 = dhcp->server_ip_address.as_u32;

  o = (dhcp_option_t *) dhcp->options;

  while (o->option != 0xFF /* end of options */  &&
	 (u8 *) o < (b->data + b->current_data + b->current_length))
    {
      switch (o->option)
	{
	case 53:		/* dhcp message type */
	  dhcp_message_type = o->data[0];
	  break;

	case 51:		/* lease time */
	  {
	    u32 lease_time_in_seconds =
	      clib_host_to_net_u32 (o->data_as_u32[0]);
	    // for debug: lease_time_in_seconds = 20; /*$$$$*/
	    c->lease_expires = now + (f64) lease_time_in_seconds;
	    c->lease_lifetime = lease_time_in_seconds;
	    /* Set a sensible default, in case we don't get opt 58 */
	    c->lease_renewal_interval = lease_time_in_seconds / 2;
	  }
	  break;

	case 58:		/* lease renew time in seconds */
	  {
	    u32 lease_renew_time_in_seconds =
	      clib_host_to_net_u32 (o->data_as_u32[0]);
	    c->lease_renewal_interval = lease_renew_time_in_seconds;
	  }
	  break;

	case 54:		/* dhcp server address */
	  c->learned.dhcp_server.as_u32 = o->data_as_u32[0];
	  break;

	case 1:		/* subnet mask */
	  {
	    u32 subnet_mask = clib_host_to_net_u32 (o->data_as_u32[0]);
	    c->learned.subnet_mask_width = count_set_bits (subnet_mask);
	  }
	  break;
	case 3:		/* router address */
	  {
	    u32 router_address = o->data_as_u32[0];
	    c->learned.router_address.as_u32 = router_address;
	  }
	  break;
	case 6:		/* domain server address */
	  {
	    vec_free (c->domain_server_address);
	    vec_validate (c->domain_server_address,
			  o->length / sizeof (ip4_address_t) - 1);
	    clib_memcpy (c->domain_server_address, o->data, o->length);
	  }
	  break;
	case 12:		/* hostname */
	  {
	    /* Replace the existing hostname if necessary */
	    vec_free (c->hostname);
	    vec_validate (c->hostname, o->length - 1);
	    clib_memcpy (c->hostname, o->data, o->length);
	  }
	  break;

	  /* $$$$ Your message in this space, parse more options */
	default:
	  break;
	}

      o = (dhcp_option_t *) (((uword) o) + (o->length + 2));
    }

  switch (c->state)
    {
    case DHCP_DISCOVER:
      if (dhcp_message_type != DHCP_PACKET_OFFER)
	{
	  vlib_node_increment_counter (vm, dhcp_client_process_node.index,
				       DHCP_STAT_NON_OFFER_DISCOVER, 1);
	  c->next_transmit = now + 5.0;
	  break;
	}

      /* Received an offer, go send a request */
      c->state = DHCP_REQUEST;
      c->retry_count = 0;
      c->next_transmit = 0;	/* send right now... */
      /* Poke the client process, which will send the request */
      uword client_id = c - dcm->clients;
      vl_api_rpc_call_main_thread (dhcp_client_proc_callback,
				   (u8 *) & client_id, sizeof (uword));
      break;

    case DHCP_BOUND:
    case DHCP_REQUEST:
      if (dhcp_message_type == DHCP_PACKET_NAK)
	{
	  vlib_node_increment_counter (vm, dhcp_client_process_node.index,
				       DHCP_STAT_NAK, 1);
	  /* Probably never happens in bound state, but anyhow...
	     Wipe out any memory of the address we had... */
	  dhcp_client_reset (dcm, c);
	  break;
	}

      if (dhcp_message_type != DHCP_PACKET_ACK &&
	  dhcp_message_type != DHCP_PACKET_OFFER)
	{
	  vlib_node_increment_counter (vm, dhcp_client_process_node.index,
				       DHCP_STAT_NON_OFFER_DISCOVER, 1);
	  clib_warning ("sw_if_index %d state %U message type %d",
			c->sw_if_index, format_dhcp_client_state,
			c->state, dhcp_message_type);
	  c->next_transmit = now + 5.0;
	  break;
	}
      /* OK, we own the address (etc), add to the routing table(s) */
      {
	/* Send the index over to the main thread, where it can retrieve
	 * the original client */
	u32 cindex = c - dcm->clients;
	vl_api_force_rpc_call_main_thread (dhcp_client_addr_callback,
					   (u8 *) & cindex, sizeof (u32));
      }

      c->state = DHCP_BOUND;
      c->retry_count = 0;
      c->next_transmit = now + (f64) c->lease_renewal_interval;
      c->lease_expires = now + (f64) c->lease_lifetime;
      vlib_node_increment_counter (vm, dhcp_client_process_node.index,
				   DHCP_STAT_BOUND, 1);
      break;

    default:
      clib_warning ("client %d bogus state %d", c - dcm->clients, c->state);
      break;
    }

  /* return 1 so the call disposes of this packet */
  return 1;
}

static void
send_dhcp_pkt (dhcp_client_main_t * dcm, dhcp_client_t * c,
	       dhcp_packet_type_t type, int is_broadcast)
{
  vlib_main_t *vm = dcm->vlib_main;
  vnet_main_t *vnm = dcm->vnet_main;
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, c->sw_if_index);
  vnet_sw_interface_t *sup_sw
    = vnet_get_sup_sw_interface (vnm, c->sw_if_index);
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, c->sw_if_index);
  vlib_buffer_t *b;
  u32 bi;
  ip4_header_t *ip;
  udp_header_t *udp;
  dhcp_header_t *dhcp;
  u32 *to_next;
  vlib_frame_t *f;
  dhcp_option_t *o;
  u16 udp_length, ip_length;
  u32 counter_index, node_index;

  DHCP_INFO ("send: type:%U bcast:%d %U",
	     format_dhcp_packet_type, type,
	     is_broadcast, format_dhcp_client, dcm, c, 1 /* verbose */ );

  /* Interface(s) down? */
  if ((hw->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)
    return;
  if ((sup_sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    return;
  if ((sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    return;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("buffer allocation failure");
      c->next_transmit = 0;
      return;
    }

  /* Build a dhcpv4 pkt from whole cloth */
  b = vlib_get_buffer (vm, bi);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);

  ASSERT (b->current_data == 0);

  vnet_buffer (b)->sw_if_index[VLIB_RX] = c->sw_if_index;
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  if (is_broadcast)
    {
      node_index = ip4_rewrite_node.index;
      vnet_buffer (b)->ip.adj_index = c->ai_bcast;
    }
  else
    node_index = dcm->ip4_lookup_node_index;

  /* Enqueue the packet right now */
  f = vlib_get_frame_to_node (vm, node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, node_index, f);

  /* build the headers */
  ip = vlib_buffer_get_current (b);
  udp = (udp_header_t *) (ip + 1);
  dhcp = (dhcp_header_t *) (udp + 1);

  /* $$$ optimize, maybe */
  clib_memset (ip, 0, sizeof (*ip) + sizeof (*udp) + sizeof (*dhcp));

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 128;
  ip->protocol = IP_PROTOCOL_UDP;

  ip->tos = c->dscp;

  if (ip->tos)
    {
      /*
       * Setup the buffer's QoS settings so any QoS marker on the egress
       * interface, that might set VLAN CoS bits, based on this DSCP setting
       */
      vnet_buffer2 (b)->qos.source = QOS_SOURCE_IP;
      vnet_buffer2 (b)->qos.bits = ip->tos;
      b->flags |= VNET_BUFFER_F_QOS_DATA_VALID;
    }

  if (is_broadcast)
    {
      /* src = 0.0.0.0, dst = 255.255.255.255 */
      ip->dst_address.as_u32 = ~0;
    }
  else
    {
      /* Renewing an active lease, plain old ip4 src/dst */
      ip->src_address.as_u32 = c->learned.leased_address.as_u32;
      ip->dst_address.as_u32 = c->learned.dhcp_server.as_u32;
    }

  udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_dhcp_to_client);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_dhcp_to_server);

  /* Send the interface MAC address */
  clib_memcpy (dhcp->client_hardware_address,
	       vnet_sw_interface_get_hw_address (vnm, c->sw_if_index), 6);

  /* And remember it for rx-packet-for-us checking */
  clib_memcpy (c->client_hardware_address, dhcp->client_hardware_address,
	       sizeof (c->client_hardware_address));

  /* Lease renewal, set up client_ip_address */
  if (is_broadcast == 0)
    dhcp->client_ip_address.as_u32 = c->learned.leased_address.as_u32;

  dhcp->opcode = 1;		/* request, all we send */
  dhcp->hardware_type = 1;	/* ethernet */
  dhcp->hardware_address_length = 6;
  dhcp->transaction_identifier = c->transaction_id;
  dhcp->flags =
    clib_host_to_net_u16 (is_broadcast && c->set_broadcast_flag ?
			  DHCP_FLAG_BROADCAST : 0);
  dhcp->magic_cookie.as_u32 = DHCP_MAGIC;

  o = (dhcp_option_t *) dhcp->options;

  /* Send option 53, the DHCP message type */
  o->option = DHCP_PACKET_OPTION_MSG_TYPE;
  o->length = 1;
  o->data[0] = type;
  o = (dhcp_option_t *) (((uword) o) + (o->length + 2));

  /* Send option 57, max msg length */
  if (0 /* not needed, apparently */ )
    {
      o->option = 57;
      o->length = 2;
      {
	u16 *o2 = (u16 *) o->data;
	*o2 = clib_host_to_net_u16 (1152);
	o = (dhcp_option_t *) (((uword) o) + (o->length + 2));
      }
    }

  /*
   * If server ip address is available with non-zero value,
   * option 54 (DHCP Server Identifier) is sent.
   */
  if (c->learned.dhcp_server.as_u32)
    {
      o->option = 54;
      o->length = 4;
      clib_memcpy (o->data, &c->learned.dhcp_server.as_u32, 4);
      o = (dhcp_option_t *) (((uword) o) + (o->length + 2));
    }

  /* send option 50, requested IP address */
  if (c->learned.leased_address.as_u32)
    {
      o->option = 50;
      o->length = 4;
      clib_memcpy (o->data, &c->learned.leased_address.as_u32, 4);
      o = (dhcp_option_t *) (((uword) o) + (o->length + 2));
    }

  /* send option 12, host name */
  if (vec_len (c->hostname))
    {
      o->option = 12;
      o->length = vec_len (c->hostname);
      clib_memcpy (o->data, c->hostname, vec_len (c->hostname));
      o = (dhcp_option_t *) (((uword) o) + (o->length + 2));
    }

  /* send option 61, client_id */
  if (vec_len (c->client_identifier))
    {
      o->option = 61;
      o->length = vec_len (c->client_identifier) + 1;
      /* Set type to zero, apparently some dhcp servers care */
      o->data[0] = 0;
      clib_memcpy (o->data + 1, c->client_identifier,
		   vec_len (c->client_identifier));
      o = (dhcp_option_t *) (((uword) o) + (o->length + 2));
    }

  /* $$ maybe send the client s/w version if anyone cares */

  /*
   * send option 55, parameter request list
   * The current list - see below, matches the Linux dhcp client's list
   * Any specific dhcp server config and/or dhcp server may or may
   * not yield specific options.
   */
  o->option = 55;
  o->length = vec_len (c->option_55_data);
  clib_memcpy (o->data, c->option_55_data, vec_len (c->option_55_data));
  o = (dhcp_option_t *) (((uword) o) + (o->length + 2));

  /* End of list */
  o->option = 0xff;
  o->length = 0;
  o++;

  b->current_length = ((u8 *) o) - b->data;

  /* fix ip length, checksum and udp length */
  ip_length = vlib_buffer_length_in_chain (vm, b);

  ip->length = clib_host_to_net_u16 (ip_length);
  ip->checksum = ip4_header_checksum (ip);

  udp_length = ip_length - (sizeof (*ip));
  udp->length = clib_host_to_net_u16 (udp_length);

  switch (type)
    {
#define _(a,b) case DHCP_PACKET_##a: {counter_index = DHCP_STAT_##a; break;}
      foreach_dhcp_sent_packet_stat
#undef _
    default:
      counter_index = DHCP_STAT_UNKNOWN;
      break;
    }

  vlib_node_increment_counter (vm, dhcp_client_process_node.index,
			       counter_index, 1);
}

static int
dhcp_discover_state (dhcp_client_main_t * dcm, dhcp_client_t * c, f64 now)
{
  /*
   * State machine "DISCOVER" state. Send a dhcp discover packet,
   * eventually back off the retry rate.
   */
  /*
   * In order to accept any OFFER, whether broadcasted or unicasted, we
   * need to configure the dhcp-client-detect feature as an input feature
   * so the DHCP OFFER is sent to the ip4-local node. Without this a
   * broadcasted OFFER hits the 255.255.255.255/32 address and a unicast
   * hits 0.0.0.0/0 both of which default to drop and the latter may forward
   * of box - not what we want. Nor to we want to change these route for
   * all interfaces in this table
   */
  if (c->client_detect_feature_enabled == 0)
    {
      vnet_feature_enable_disable ("ip4-unicast",
				   "ip4-dhcp-client-detect",
				   c->sw_if_index, 1 /* enable */ , 0, 0);
      c->client_detect_feature_enabled = 1;
    }

  send_dhcp_pkt (dcm, c, DHCP_PACKET_DISCOVER, 1 /* is_broadcast */ );

  c->retry_count++;
  if (c->retry_count > 10)
    c->next_transmit = now + 5.0;
  else
    c->next_transmit = now + 1.0;
  return 0;
}

static int
dhcp_request_state (dhcp_client_main_t * dcm, dhcp_client_t * c, f64 now)
{
  /*
   * State machine "REQUEST" state. Send a dhcp request packet,
   * eventually drop back to the discover state.
   */
  DHCP_INFO ("enter request: %U", format_dhcp_client, dcm, c,
	     1 /*verbose */ );

  send_dhcp_pkt (dcm, c, DHCP_PACKET_REQUEST, 1 /* is_broadcast */ );

  c->retry_count++;
  if (c->retry_count > 7 /* lucky you */ )
    {
      c->state = DHCP_DISCOVER;
      c->next_transmit = now;
      c->retry_count = 0;
      return 1;
    }
  c->next_transmit = now + 1.0;
  return 0;
}

static int
dhcp_bound_state (dhcp_client_main_t * dcm, dhcp_client_t * c, f64 now)
{
  /*
   * We disable the client detect feature when we bind a
   * DHCP address. Turn it back on again on first renew attempt.
   * Otherwise, if the DHCP server replies we'll never see it.
   */
  if (c->client_detect_feature_enabled == 0)
    {
      vnet_feature_enable_disable ("ip4-unicast",
				   "ip4-dhcp-client-detect",
				   c->sw_if_index, 1 /* enable */ , 0, 0);
      c->client_detect_feature_enabled = 1;
    }

  /*
   * State machine "BOUND" state. Send a dhcp request packet to renew
   * the lease.
   * Eventually, when the lease expires, forget the dhcp data
   * and go back to the stone age.
   */
  if (now > c->lease_expires)
    {
      DHCP_INFO ("lease expired: %U", format_dhcp_client, dcm, c,
		 1 /*verbose */ );

      /* reset all data for the client. do not send any more messages
       * since the objects to do so have been lost */
      dhcp_client_reset (dcm, c);
      return 1;
    }

  DHCP_INFO ("enter bound: %U", format_dhcp_client, dcm, c, 1 /* verbose */ );
  send_dhcp_pkt (dcm, c, DHCP_PACKET_REQUEST, 0 /* is_broadcast */ );

  c->retry_count++;
  if (c->retry_count > 10)
    c->next_transmit = now + 5.0;
  else
    c->next_transmit = now + 1.0;

  return 0;
}

static f64
dhcp_client_sm (f64 now, f64 timeout, uword pool_index)
{
  dhcp_client_main_t *dcm = &dhcp_client_main;
  dhcp_client_t *c;

  /* deleted, pooched, yadda yadda yadda */
  if (pool_is_free_index (dcm->clients, pool_index))
    return timeout;

  c = pool_elt_at_index (dcm->clients, pool_index);

  /* Time for us to do something with this client? */
  if (now < c->next_transmit)
    return c->next_transmit;

  DHCP_INFO ("sm active session %d", c - dcm->clients);

again:
  switch (c->state)
    {
    case DHCP_DISCOVER:	/* send a discover */
      if (dhcp_discover_state (dcm, c, now))
	goto again;
      break;

    case DHCP_REQUEST:		/* send a request */
      if (dhcp_request_state (dcm, c, now))
	goto again;
      break;

    case DHCP_BOUND:		/* bound, renew needed? */
      if (dhcp_bound_state (dcm, c, now))
	goto again;
      break;

    default:
      clib_warning ("dhcp client %d bogus state %d",
		    c - dcm->clients, c->state);
      break;
    }

  return c->next_transmit;
}

static uword
dhcp_client_process (vlib_main_t * vm,
		     vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  f64 timeout = 1000.0;
  f64 next_expire_time, this_next_expire_time;
  f64 now;
  uword event_type;
  uword *event_data = 0;
  dhcp_client_main_t *dcm = &dhcp_client_main;
  dhcp_client_t *c;
  int i;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);

      event_type = vlib_process_get_events (vm, &event_data);

      now = vlib_time_now (vm);

      switch (event_type)
	{
	case EVENT_DHCP_CLIENT_WAKEUP:
	  for (i = 0; i < vec_len (event_data); i++)
	    (void) dhcp_client_sm (now, timeout, event_data[i]);
	  /* FALLTHROUGH */

	case ~0:
	  if (pool_elts (dcm->clients))
	    {
              /* *INDENT-OFF* */
              next_expire_time = 1e70;
              pool_foreach (c, dcm->clients,
              ({
                this_next_expire_time = dhcp_client_sm
                  (now, timeout, (uword) (c - dcm->clients));
                next_expire_time = this_next_expire_time < next_expire_time ?
                  this_next_expire_time : next_expire_time;
              }));
              if (next_expire_time > now)
                timeout = next_expire_time - now;
              else
                {
                  clib_warning ("BUG");
                  timeout = 1.13;
                }
              /* *INDENT-ON* */
	    }
	  else
	    timeout = 1000.0;
	  break;
	}

      vec_reset_length (event_data);
    }

  /* NOTREACHED */
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dhcp_client_process_node,static) = {
    .function = dhcp_client_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "dhcp-client-process",
    .process_log2_n_stack_bytes = 16,
    .n_errors = ARRAY_LEN(dhcp_client_process_stat_strings),
    .error_strings = dhcp_client_process_stat_strings,
};
/* *INDENT-ON* */

static clib_error_t *
show_dhcp_client_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  dhcp_client_main_t *dcm = &dhcp_client_main;
  dhcp_client_t *c;
  int verbose = 0;
  u32 sw_if_index = ~0;
  uword *p;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "intfc %U",
		    unformat_vnet_sw_interface, dcm->vnet_main, &sw_if_index))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else
	break;
    }

  if (sw_if_index != ~0)
    {
      p = hash_get (dcm->client_by_sw_if_index, sw_if_index);
      if (p == 0)
	return clib_error_return (0, "dhcp client not configured");
      c = pool_elt_at_index (dcm->clients, p[0]);
      vlib_cli_output (vm, "%U", format_dhcp_client, dcm, c, verbose);
      return 0;
    }

  /* *INDENT-OFF* */
  pool_foreach (c, dcm->clients,
  ({
    vlib_cli_output (vm, "%U",
                     format_dhcp_client, dcm,
                     c, verbose);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_dhcp_client_command, static) = {
  .path = "show dhcp client",
  .short_help = "show dhcp client [intfc <intfc>][verbose]",
  .function = show_dhcp_client_command_fn,
};
/* *INDENT-ON* */


int
dhcp_client_add_del (dhcp_client_add_del_args_t * a)
{
  dhcp_client_main_t *dcm = &dhcp_client_main;
  vlib_main_t *vm = dcm->vlib_main;
  dhcp_client_t *c;
  uword *p;

  p = hash_get (dcm->client_by_sw_if_index, a->sw_if_index);

  if ((p && a->is_add) || (!p && a->is_add == 0))
    return VNET_API_ERROR_INVALID_VALUE;

  if (a->is_add)
    {
      dhcp_maybe_register_udp_ports (DHCP_PORT_REG_CLIENT);
      pool_get (dcm->clients, c);
      clib_memset (c, 0, sizeof (*c));
      c->state = DHCP_DISCOVER;
      c->sw_if_index = a->sw_if_index;
      c->client_index = a->client_index;
      c->pid = a->pid;
      c->event_callback = a->event_callback;
      c->option_55_data = a->option_55_data;
      c->hostname = a->hostname;
      c->client_identifier = a->client_identifier;
      c->set_broadcast_flag = a->set_broadcast_flag;
      c->dscp = a->dscp;
      c->ai_bcast = adj_nbr_add_or_lock (FIB_PROTOCOL_IP4,
					 VNET_LINK_IP4,
					 &ADJ_BCAST_ADDR, c->sw_if_index);

      do
	{
	  c->transaction_id = random_u32 (&dcm->seed);
	}
      while (c->transaction_id == 0);

      hash_set (dcm->client_by_sw_if_index, a->sw_if_index, c - dcm->clients);

      vlib_process_signal_event (vm, dhcp_client_process_node.index,
				 EVENT_DHCP_CLIENT_WAKEUP, c - dcm->clients);

      DHCP_INFO ("create: %U", format_dhcp_client, dcm, c, 1 /* verbose */ );
    }
  else
    {
      c = pool_elt_at_index (dcm->clients, p[0]);

      dhcp_client_reset (dcm, c);

      adj_unlock (c->ai_bcast);

      vec_free (c->domain_server_address);
      vec_free (c->option_55_data);
      vec_free (c->hostname);
      vec_free (c->client_identifier);
      hash_unset (dcm->client_by_sw_if_index, c->sw_if_index);
      pool_put (dcm->clients, c);
    }
  return 0;
}

int
dhcp_client_config (u32 is_add,
		    u32 client_index,
		    vlib_main_t * vm,
		    u32 sw_if_index,
		    u8 * hostname,
		    u8 * client_id,
		    dhcp_event_cb_t event_callback,
		    u8 set_broadcast_flag, ip_dscp_t dscp, u32 pid)
{
  dhcp_client_add_del_args_t _a, *a = &_a;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->is_add = is_add;
  a->sw_if_index = sw_if_index;
  a->client_index = client_index;
  a->pid = pid;
  a->event_callback = event_callback;
  a->set_broadcast_flag = set_broadcast_flag;
  a->dscp = dscp;
  vec_validate (a->hostname, strlen ((char *) hostname) - 1);
  strncpy ((char *) a->hostname, (char *) hostname, vec_len (a->hostname));
  vec_validate (a->client_identifier, strlen ((char *) client_id) - 1);
  strncpy ((char *) a->client_identifier, (char *) client_id,
	   vec_len (a->client_identifier));

  /*
   * Option 55 request list. These data precisely match
   * the Ubuntu dhcp client. YMMV.
   */

  /* Subnet Mask */
  vec_add1 (a->option_55_data, 1);
  /* Broadcast address */
  vec_add1 (a->option_55_data, 28);
  /* time offset */
  vec_add1 (a->option_55_data, 2);
  /* Router */
  vec_add1 (a->option_55_data, 3);
  /* Domain Name */
  vec_add1 (a->option_55_data, 15);
  /* DNS */
  vec_add1 (a->option_55_data, 6);
  /* Domain search */
  vec_add1 (a->option_55_data, 119);
  /* Host name */
  vec_add1 (a->option_55_data, 12);
  /* NetBIOS name server */
  vec_add1 (a->option_55_data, 44);
  /* NetBIOS Scope */
  vec_add1 (a->option_55_data, 47);
  /* MTU */
  vec_add1 (a->option_55_data, 26);
  /* Classless static route */
  vec_add1 (a->option_55_data, 121);
  /* NTP servers */
  vec_add1 (a->option_55_data, 42);

  rv = dhcp_client_add_del (a);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_VALUE:

      vec_free (a->hostname);
      vec_free (a->client_identifier);
      vec_free (a->option_55_data);

      if (is_add)
	DHCP_INFO ("dhcp client already enabled on intf_idx %d", sw_if_index);
      else
	DHCP_INFO ("not enabled on on intf_idx %d", sw_if_index);
      break;

    default:
      DHCP_INFO ("dhcp_client_add_del returned %d", rv);
    }

  return rv;
}

void
dhcp_client_walk (dhcp_client_walk_cb_t cb, void *ctx)
{
  dhcp_client_main_t *dcm = &dhcp_client_main;
  dhcp_client_t *c;

  /* *INDENT-OFF* */
  pool_foreach (c, dcm->clients,
  ({
    if (!cb(c, ctx))
      break;
  }));
  /* *INDENT-ON* */

}

static clib_error_t *
dhcp_client_set_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{

  dhcp_client_main_t *dcm = &dhcp_client_main;
  u32 sw_if_index;
  u8 *hostname = 0;
  u8 sw_if_index_set = 0;
  u8 set_broadcast_flag = 1;
  int is_add = 1;
  dhcp_client_add_del_args_t _a, *a = &_a;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "intfc %U",
		    unformat_vnet_sw_interface, dcm->vnet_main, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (input, "hostname %v", &hostname))
	;
      else if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "broadcast", &set_broadcast_flag))
	is_add = 0;
      else
	break;
    }

  if (sw_if_index_set == 0)
    return clib_error_return (0, "interface not specified");

  clib_memset (a, 0, sizeof (*a));
  a->is_add = is_add;
  a->sw_if_index = sw_if_index;
  a->hostname = hostname;
  a->client_identifier = format (0, "vpp 1.1%c", 0);
  a->set_broadcast_flag = set_broadcast_flag;

  /*
   * Option 55 request list. These data precisely match
   * the Ubuntu dhcp client. YMMV.
   */

  /* Subnet Mask */
  vec_add1 (a->option_55_data, 1);
  /* Broadcast address */
  vec_add1 (a->option_55_data, 28);
  /* time offset */
  vec_add1 (a->option_55_data, 2);
  /* Router */
  vec_add1 (a->option_55_data, 3);
  /* Domain Name */
  vec_add1 (a->option_55_data, 15);
  /* DNS */
  vec_add1 (a->option_55_data, 6);
  /* Domain search */
  vec_add1 (a->option_55_data, 119);
  /* Host name */
  vec_add1 (a->option_55_data, 12);
  /* NetBIOS name server */
  vec_add1 (a->option_55_data, 44);
  /* NetBIOS Scope */
  vec_add1 (a->option_55_data, 47);
  /* MTU */
  vec_add1 (a->option_55_data, 26);
  /* Classless static route */
  vec_add1 (a->option_55_data, 121);
  /* NTP servers */
  vec_add1 (a->option_55_data, 42);

  rv = dhcp_client_add_del (a);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_VALUE:

      vec_free (a->hostname);
      vec_free (a->client_identifier);
      vec_free (a->option_55_data);
      if (is_add)
	return clib_error_return (0, "dhcp client already enabled on %U",
				  format_vnet_sw_if_index_name,
				  dcm->vnet_main, sw_if_index);
      else
	return clib_error_return (0, "dhcp client not enabled on %U",
				  format_vnet_sw_if_index_name,
				  dcm->vnet_main, sw_if_index);
      break;

    default:
      vlib_cli_output (vm, "dhcp_client_add_del returned %d", rv);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_client_set_command, static) = {
  .path = "set dhcp client",
  .short_help = "set dhcp client [del] intfc <interface> [hostname <name>]",
  .function = dhcp_client_set_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dhcp_client_init (vlib_main_t * vm)
{
  dhcp_client_main_t *dcm = &dhcp_client_main;
  vlib_node_t *ip4_lookup_node;

  ip4_lookup_node = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");

  /* Should never happen... */
  if (ip4_lookup_node == 0)
    return clib_error_return (0, "ip4-lookup node not found");

  dcm->ip4_lookup_node_index = ip4_lookup_node->index;
  dcm->vlib_main = vm;
  dcm->vnet_main = vnet_get_main ();
  dcm->seed = (u32) clib_cpu_time_now ();

  dhcp_logger = vlib_log_register_class ("dhcp", "client");
  DHCP_DBG ("plugin initialized");

  return 0;
}

VLIB_INIT_FUNCTION (dhcp_client_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
