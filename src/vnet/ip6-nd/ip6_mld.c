/*
 * ip/ip6_neighbor.c: IP6 neighbor handling
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#include <vnet/ip6-nd/ip6_nd.h>

#include <vnet/ip/ip.h>
#include <vnet/ip-neighbor/ip_neighbor_dp.h>

#include <vnet/ip/ip6_link.h>
#include <vnet/ip/ip6_ll_table.h>

#include <vnet/ethernet/ethernet.h>

/**
 * @file
 * @brief IPv6 Neighbor Adjacency and Neighbor Discovery.
 *
 * The files contains the API and CLI code for managing IPv6 neighbor
 * adjacency tables and neighbor discovery logic.
 */

/* *INDENT-OFF*/
/* multicast listener report packet format for ethernet. */
typedef CLIB_PACKED (struct
{
    ip6_hop_by_hop_ext_t ext_hdr;
    ip6_router_alert_option_t alert;
    ip6_padN_option_t pad;
    icmp46_header_t icmp;
    u16 rsvd;
    u16 num_addr_records;
    icmp6_multicast_address_record_t records[0];
}) icmp6_multicast_listener_report_header_t;

typedef CLIB_PACKED (struct
{
  ip6_header_t ip;
  icmp6_multicast_listener_report_header_t report_hdr;
}) icmp6_multicast_listener_report_packet_t;
/* *INDENT-ON*/

typedef struct
{
  /* group information */
  u16 num_sources;
  u8 type;
  ip6_address_t mcast_address;
  ip6_address_t *mcast_source_address_pool;
} ip6_mldp_group_t;

typedef struct ip6_nd_t_
{
  /* local information */
  u32 sw_if_index;
  int all_routers_mcast;

  /* MLDP  group information */
  ip6_mldp_group_t *mldp_group_pool;

  /* Hash table mapping address to index in mldp address pool. */
  mhash_t address_to_mldp_index;

} ip6_mld_t;


static ip6_link_delegate_id_t ip6_mld_delegate_id;
static ip6_mld_t *ip6_mld_pool;

/////

static inline ip6_mld_t *
ip6_mld_get_itf (u32 sw_if_index)
{
  index_t imi;

  imi = ip6_link_delegate_get (sw_if_index, ip6_mld_delegate_id);

  if (INDEX_INVALID != imi)
    return (pool_elt_at_index (ip6_mld_pool, imi));

  return (NULL);
}

/**
 * @brief Add a multicast Address to the advertised MLD set
 */
static void
ip6_neighbor_add_mld_prefix (ip6_mld_t * imd, ip6_address_t * addr)
{
  ip6_mldp_group_t *mcast_group_info;
  uword *p;

  /* lookup  mldp info for this interface */
  p = mhash_get (&imd->address_to_mldp_index, addr);
  mcast_group_info = p ? pool_elt_at_index (imd->mldp_group_pool, p[0]) : 0;

  /* add address */
  if (!mcast_group_info)
    {
      /* add */
      u32 mi;
      pool_get_zero (imd->mldp_group_pool, mcast_group_info);

      mi = mcast_group_info - imd->mldp_group_pool;
      mhash_set (&imd->address_to_mldp_index, addr, mi,	/* old_value */
		 0);

      mcast_group_info->type = 4;
      mcast_group_info->mcast_source_address_pool = 0;
      mcast_group_info->num_sources = 0;
      clib_memcpy (&mcast_group_info->mcast_address, addr,
		   sizeof (ip6_address_t));
    }
}

/**
 * @brief Delete a multicast Address from the advertised MLD set
 */
static void
ip6_neighbor_del_mld_prefix (ip6_mld_t * imd, ip6_address_t * addr)
{
  ip6_mldp_group_t *mcast_group_info;
  uword *p;

  p = mhash_get (&imd->address_to_mldp_index, addr);
  mcast_group_info = p ? pool_elt_at_index (imd->mldp_group_pool, p[0]) : 0;

  if (mcast_group_info)
    {
      mhash_unset (&imd->address_to_mldp_index, addr,
		   /* old_value */ 0);
      pool_put (imd->mldp_group_pool, mcast_group_info);
    }
}

/**
 * @brief Add a multicast Address to the advertised MLD set
 */
static void
ip6_neighbor_add_mld_grp (ip6_mld_t * a,
			  ip6_multicast_address_scope_t scope,
			  ip6_multicast_link_local_group_id_t group)
{
  ip6_address_t addr;

  ip6_set_reserved_multicast_address (&addr, scope, group);

  ip6_neighbor_add_mld_prefix (a, &addr);
}

static const ethernet_interface_t *
ip6_mld_get_eth_itf (u32 sw_if_index)
{
  const vnet_sw_interface_t *sw;

  /* lookup radv container  - ethernet interfaces only */
  sw = vnet_get_sup_sw_interface (vnet_get_main (), sw_if_index);
  if (sw->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
    return (ethernet_get_interface (&ethernet_main, sw->hw_if_index));

  return (NULL);
}

/**
 * @brief create and initialize router advertisement parameters with default
 * values for this intfc
 */
static void
ip6_mld_link_enable (u32 sw_if_index)
{
  const ethernet_interface_t *eth;
  ip6_mld_t *imd;

  eth = ip6_mld_get_eth_itf (sw_if_index);

  if (NULL == eth)
    return;

  ASSERT (INDEX_INVALID == ip6_link_delegate_get (sw_if_index,
						  ip6_mld_delegate_id));

  pool_get_zero (ip6_mld_pool, imd);

  imd->sw_if_index = sw_if_index;

  mhash_init (&imd->address_to_mldp_index, sizeof (uword),
	      sizeof (ip6_address_t));

  /* add multicast groups we will always be reporting  */
  ip6_neighbor_add_mld_grp (imd,
			    IP6_MULTICAST_SCOPE_link_local,
			    IP6_MULTICAST_GROUP_ID_all_hosts);
  ip6_neighbor_add_mld_grp (imd,
			    IP6_MULTICAST_SCOPE_link_local,
			    IP6_MULTICAST_GROUP_ID_all_routers);
  ip6_neighbor_add_mld_grp (imd,
			    IP6_MULTICAST_SCOPE_link_local,
			    IP6_MULTICAST_GROUP_ID_mldv2_routers);

  ip6_link_delegate_update (sw_if_index, ip6_mld_delegate_id,
			    imd - ip6_mld_pool);
}

static void
ip6_mld_delegate_disable (index_t imdi)
{
  ip6_mldp_group_t *m;
  ip6_mld_t *imd;

  imd = pool_elt_at_index (ip6_mld_pool, imdi);

  /* clean MLD pools */
  /* *INDENT-OFF* */
  pool_flush (m, imd->mldp_group_pool,
  ({
    mhash_unset (&imd->address_to_mldp_index, &m->mcast_address, 0);
  }));
  /* *INDENT-ON* */

  pool_free (imd->mldp_group_pool);

  mhash_free (&imd->address_to_mldp_index);

  pool_put (ip6_mld_pool, imd);
}

/* send an mldpv2 report  */
static void
ip6_neighbor_send_mldpv2_report (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vnm->vlib_main;
  int bogus_length;

  ip6_mld_t *imd;
  u16 payload_length;
  vlib_buffer_t *b0;
  ip6_header_t *ip0;
  u32 *to_next;
  vlib_frame_t *f;
  u32 bo0;
  u32 n_to_alloc = 1;

  icmp6_multicast_listener_report_header_t *rh0;
  icmp6_multicast_listener_report_packet_t *rp0;

  if (!vnet_sw_interface_is_admin_up (vnm, sw_if_index))
    return;

  imd = ip6_mld_get_itf (sw_if_index);

  if (NULL == imd)
    return;

  /* send report now - build a mldpv2 report packet  */
  if (0 == vlib_buffer_alloc (vm, &bo0, n_to_alloc))
    {
    alloc_fail:
      clib_warning ("buffer allocation failure");
      return;
    }

  b0 = vlib_get_buffer (vm, bo0);

  /* adjust the sizeof the buffer to just include the ipv6 header */
  b0->current_length = sizeof (icmp6_multicast_listener_report_packet_t);

  payload_length = sizeof (icmp6_multicast_listener_report_header_t);

  b0->error = ICMP6_ERROR_NONE;

  rp0 = vlib_buffer_get_current (b0);
  ip0 = (ip6_header_t *) & rp0->ip;
  rh0 = (icmp6_multicast_listener_report_header_t *) & rp0->report_hdr;

  clib_memset (rp0, 0x0, sizeof (icmp6_multicast_listener_report_packet_t));

  ip0->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x6 << 28);

  ip0->protocol = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS;
  /* for DEBUG - vnet driver won't seem to emit router alerts */
  /* ip0->protocol = IP_PROTOCOL_ICMP6; */
  ip0->hop_limit = 1;

  rh0->icmp.type = ICMP6_multicast_listener_report_v2;

  /* source address MUST be the link-local address */
  ip6_address_copy (&ip0->src_address,
		    ip6_get_link_local_address (sw_if_index));

  /* destination is all mldpv2 routers */
  ip6_set_reserved_multicast_address (&ip0->dst_address,
				      IP6_MULTICAST_SCOPE_link_local,
				      IP6_MULTICAST_GROUP_ID_mldv2_routers);

  /* add reports here */
  ip6_mldp_group_t *m;
  int num_addr_records = 0;
  icmp6_multicast_address_record_t rr;

  /* fill in the hop-by-hop extension header (router alert) info */
  rh0->ext_hdr.next_hdr = IP_PROTOCOL_ICMP6;
  rh0->ext_hdr.n_data_u64s = 0;

  rh0->alert.type = IP6_MLDP_ALERT_TYPE;
  rh0->alert.len = 2;
  rh0->alert.value = 0;

  rh0->pad.type = 1;
  rh0->pad.len = 0;

  rh0->icmp.checksum = 0;

  /* *INDENT-OFF* */
  pool_foreach (m, imd->mldp_group_pool,
  ({
    rr.type = m->type;
    rr.aux_data_len_u32s = 0;
    rr.num_sources = clib_host_to_net_u16 (m->num_sources);
    clib_memcpy(&rr.mcast_addr, &m->mcast_address, sizeof(ip6_address_t));

    num_addr_records++;

    if(vlib_buffer_add_data (vm, &bo0, (void *)&rr,
			     sizeof(icmp6_multicast_address_record_t)))
      {
        vlib_buffer_free (vm, &bo0, 1);
        goto alloc_fail;
      }

    payload_length += sizeof( icmp6_multicast_address_record_t);
  }));
  /* *INDENT-ON* */

  rh0->rsvd = 0;
  rh0->num_addr_records = clib_host_to_net_u16 (num_addr_records);

  /* update lengths */
  ip0->payload_length = clib_host_to_net_u16 (payload_length);

  rh0->icmp.checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip0,
							  &bogus_length);
  ASSERT (bogus_length == 0);

  /*
   * OK to override w/ no regard for actual FIB, because
   * ip6-rewrite only looks at the adjacency.
   */
  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
    vnet_main.local_interface_sw_if_index;

  vnet_buffer (b0)->ip.adj_index = ip6_link_get_mcast_adj (sw_if_index);
  b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "ip6-rewrite-mcast");

  f = vlib_get_frame_to_node (vm, node->index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bo0;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, node->index, f);
  return;
}

/* send a RA or update the timer info etc.. */
static uword
ip6_mld_timer_event (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_mld_t *imd;

  /* Interface ip6 radv info list */
  /* *INDENT-OFF* */
  pool_foreach (imd, ip6_mld_pool,
  ({
    if (!vnet_sw_interface_is_admin_up (vnm, imd->sw_if_index))
      {
        imd->all_routers_mcast = 0;
        continue;
      }

    /* Make sure that we've joined the all-routers multicast group */
    if (!imd->all_routers_mcast)
      {
        /* send MDLP_REPORT_EVENT message */
        ip6_neighbor_send_mldpv2_report(imd->sw_if_index);
        imd->all_routers_mcast = 1;
      }
  }));
  /* *INDENT-ON* */

  return 0;
}

static uword
ip6_mld_event_process (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  uword event_type;

  /* init code here */

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 1. /* seconds */ );

      if (!vlib_process_get_event_data (vm, &event_type))
	{
	  /* No events found: timer expired. */
	  /* process interface list and send RAs as appropriate, update timer info */
	  ip6_mld_timer_event (vm, node, frame);
	}
      /* else; no events */
    }
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_mld_event_process_node) = {
  .function = ip6_mld_event_process,
  .name = "ip6-mld-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};
/* *INDENT-ON* */

static u8 *
format_ip6_mld (u8 * s, va_list * args)
{
  index_t imi = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);
  ip6_mldp_group_t *m;
  ip6_mld_t *imd;

  imd = pool_elt_at_index (ip6_mld_pool, imi);

  s = format (s, "%UJoined group address(es):\n", format_white_space, indent);

  /* *INDENT-OFF* */
  pool_foreach (m, imd->mldp_group_pool,
  ({
    s = format (s, "%U%U\n",
                format_white_space, indent+2,
                format_ip6_address,
                &m->mcast_address);
  }));
  /* *INDENT-ON* */

  return (s);
}

/**
 * @brief callback when an interface address is added or deleted
 */
static void
ip6_mld_address_add (u32 imi,
		     const ip6_address_t * address, u8 address_oength)
{
  ip6_mld_t *imd;
  ip6_address_t a;

  imd = pool_elt_at_index (ip6_mld_pool, imi);

  /* create solicited node multicast address for this interface address */
  ip6_set_solicited_node_multicast_address (&a, 0);

  a.as_u8[0xd] = address->as_u8[0xd];
  a.as_u8[0xe] = address->as_u8[0xe];
  a.as_u8[0xf] = address->as_u8[0xf];

  ip6_neighbor_add_mld_prefix (imd, &a);
}

static void
ip6_mld_address_del (u32 imi,
		     const ip6_address_t * address, u8 address_oength)
{
  ip6_mld_t *imd;
  ip6_address_t a;

  imd = pool_elt_at_index (ip6_mld_pool, imi);

  /* create solicited node multicast address for this interface address */
  ip6_set_solicited_node_multicast_address (&a, 0);

  a.as_u8[0xd] = address->as_u8[0xd];
  a.as_u8[0xe] = address->as_u8[0xe];
  a.as_u8[0xf] = address->as_u8[0xf];

  ip6_neighbor_del_mld_prefix (imd, &a);
}

/**
 * VFT for registering as a delegate to an IP6 link
 */
const static ip6_link_delegate_vft_t ip6_mld_delegate_vft = {
  .ildv_disable = ip6_mld_delegate_disable,
  .ildv_enable = ip6_mld_link_enable,
  .ildv_format = format_ip6_mld,
  .ildv_addr_add = ip6_mld_address_add,
  .ildv_addr_del = ip6_mld_address_del,
};

static clib_error_t *
ip6_mld_init (vlib_main_t * vm)
{
  ip6_mld_delegate_id = ip6_link_delegate_register (&ip6_mld_delegate_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (ip6_mld_init) =
{
  .runs_after = VLIB_INITS("icmp6_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
