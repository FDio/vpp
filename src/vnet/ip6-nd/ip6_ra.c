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

#include <vnet/ip6-nd/ip6_ra.h>

#include <vnet/ip/ip.h>
#include <vnet/ip-neighbor/ip_neighbor_dp.h>

#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_link.h>

/**
 * @file
 * @brief IPv6 Router Advertisements.
 *
 * The files contains the API and CLI code for managing IPv6 RAs
 */

/* *INDENT-OFF* */
/* Router solicitation packet format for ethernet. */
typedef CLIB_PACKED (struct
{
    ip6_header_t ip;
    icmp6_neighbor_discovery_header_t neighbor;
    icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
    link_layer_option;
}) icmp6_router_solicitation_header_t;

/* router advertisement packet format for ethernet. */
typedef CLIB_PACKED (struct
{
  ip6_header_t ip;
  icmp6_router_advertisement_header_t router;
  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
  link_layer_option;
  icmp6_neighbor_discovery_mtu_option_t mtu_option;
  icmp6_neighbor_discovery_prefix_information_option_t
  prefix[0];
}) icmp6_router_advertisement_packet_t;
/* *INDENT-ON* */

#define DEF_MAX_RADV_INTERVAL 200
#define DEF_MIN_RADV_INTERVAL .75 * DEF_MAX_RADV_INTERVAL
#define DEF_CURR_HOP_LIMIT  64
#define DEF_DEF_RTR_LIFETIME   3 * DEF_MAX_RADV_INTERVAL
#define MAX_DEF_RTR_LIFETIME   9000

#define MAX_INITIAL_RTR_ADVERT_INTERVAL   16	/* seconds */
#define MAX_INITIAL_RTR_ADVERTISEMENTS        3	/*transmissions */
#define MIN_DELAY_BETWEEN_RAS                              3	/* seconds */
#define MAX_DELAY_BETWEEN_RAS                    1800	/* seconds */
#define MAX_RA_DELAY_TIME                                          .5	/* seconds */

/* advertised prefix option */
typedef struct
{
  /* basic advertised information */
  ip6_address_t prefix;
  u8 prefix_len;
  int adv_on_link_flag;
  int adv_autonomous_flag;
  u32 adv_valid_lifetime_in_secs;
  u32 adv_pref_lifetime_in_secs;

  /* advertised values are computed from these times if decrementing */
  f64 valid_lifetime_expires;
  f64 pref_lifetime_expires;

  /* local information */
  int enabled;
  int deprecated_prefix_flag;
  int decrement_lifetime_flag;

#define MIN_ADV_VALID_LIFETIME 7203	/* seconds */
#define DEF_ADV_VALID_LIFETIME  2592000
#define DEF_ADV_PREF_LIFETIME 604800

  /* extensions are added here, mobile, DNS etc.. */
} ip6_radv_prefix_t;

typedef struct ip6_ra_t_
{
  /* advertised config information, zero means unspecified  */
  u8 curr_hop_limit;
  int adv_managed_flag;
  int adv_other_flag;
  u16 adv_router_lifetime_in_sec;
  u32 adv_neighbor_reachable_time_in_msec;
  u32 adv_time_in_msec_between_retransmitted_neighbor_solicitations;

  /* mtu option */
  u32 adv_link_mtu;

  /* local information */
  u32 sw_if_index;
  int send_radv;		/* radv on/off on this interface -  set by config */
  int cease_radv;		/* we are ceasing  to send  - set byf config */
  int send_unicast;
  int adv_link_layer_address;
  int prefix_option;
  int failed_device_check;
  int ref_count;

  /* prefix option */
  ip6_radv_prefix_t *adv_prefixes_pool;

  /* Hash table mapping address to index in interface advertised  prefix pool. */
  mhash_t address_to_prefix_index;

  f64 max_radv_interval;
  f64 min_radv_interval;
  f64 min_delay_between_radv;
  f64 max_delay_between_radv;
  f64 max_rtr_default_lifetime;

  f64 last_radv_time;
  f64 last_multicast_time;
  f64 next_multicast_time;


  u32 initial_adverts_count;
  f64 initial_adverts_interval;
  u32 initial_adverts_sent;

  /* stats */
  u32 n_advertisements_sent;
  u32 n_solicitations_rcvd;
  u32 n_solicitations_dropped;

  /* router solicitations sending state */
  u8 keep_sending_rs;		/* when true then next fields are valid */
  icmp6_send_router_solicitation_params_t params;
  f64 sleep_interval;
  f64 due_time;
  u32 n_left;
  f64 start_time;
  vlib_buffer_t *buffer;

  u32 seed;

} ip6_ra_t;

static ip6_link_delegate_id_t ip6_ra_delegate_id;
static ip6_ra_t *ip6_ra_pool;


/* vector of registered RA report listeners */
static ip6_ra_report_notify_t *ip6_ra_listeners;

static int ip6_ra_publish (ip6_ra_report_t * r);

void
ip6_ra_report_register (ip6_ra_report_notify_t fn)
{
  ip6_ra_report_notify_t *listener;
  vec_foreach (listener, ip6_ra_listeners)
  {
    if (*listener == fn)
      return;
  }

  vec_add1 (ip6_ra_listeners, fn);
}

void
ip6_ra_report_unregister (ip6_ra_report_notify_t fn)
{
  u32 ii;

  vec_foreach_index (ii, ip6_ra_listeners)
  {
    if (ip6_ra_listeners[ii] == fn)
      {
	vec_del1 (ip6_ra_listeners, ii);
	break;
      }
  }
}

static inline ip6_ra_t *
ip6_ra_get_itf (u32 sw_if_index)
{
  index_t rai;

  rai = ip6_link_delegate_get (sw_if_index, ip6_ra_delegate_id);

  if (INDEX_INVALID != rai)
    return (pool_elt_at_index (ip6_ra_pool, rai));

  return (NULL);
}

/* for "syslogging" - use elog for now */
#define foreach_log_level	     \
  _ (DEBUG, "DEBUG")                 \
  _ (INFO, "INFORMATION")	     \
  _ (NOTICE, "NOTICE")		     \
  _ (WARNING, "WARNING")             \
  _ (ERR, "ERROR")	             \
  _ (CRIT, "CRITICAL")               \
  _ (ALERT, "ALERT")                 \
  _ (EMERG,  "EMERGENCY")

typedef enum
{
#define _(f,s) LOG_##f,
  foreach_log_level
#undef _
} log_level_t;

static char *log_level_strings[] = {
#define _(f,s) s,
  foreach_log_level
#undef _
};

static int logmask = 1 << LOG_DEBUG;

static void
ip6_neighbor_syslog (vlib_main_t * vm, int priority, char *fmt, ...)
{
  /* just use elog for now */
  u8 *what;
  va_list va;

  if ((priority > LOG_EMERG) || !(logmask & (1 << priority)))
    return;

  va_start (va, fmt);
  if (fmt)
    {
      what = va_format (0, fmt, &va);

      ELOG_TYPE_DECLARE (e) =
      {
      .format = "ip6 nd:  (%s): %s",.format_args = "T4T4",};
      struct
      {
	u32 s[2];
      } *ed;
      ed = ELOG_DATA (vlib_get_elog_main (), e);
      ed->s[0] =
	elog_string (vlib_get_elog_main (), log_level_strings[priority]);
      ed->s[1] = elog_string (vlib_get_elog_main (), (char *) what);
    }
  va_end (va);
  return;
}

/* ipv6 neighbor discovery - router advertisements */
typedef enum
{
  ICMP6_ROUTER_SOLICITATION_NEXT_DROP,
  ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_RW,
  ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_TX,
  ICMP6_ROUTER_SOLICITATION_N_NEXT,
} icmp6_router_solicitation_or_advertisement_next_t;

/*
 * Note: Both periodic RAs and solicited RS come through here.
 */
static_always_inline uword
icmp6_router_solicitation (vlib_main_t * vm,
			   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_main_t *im = &ip6_main;
  uword n_packets = frame->n_vectors;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next_index;
  u32 n_advertisements_sent = 0;
  int bogus_length;

  icmp6_neighbor_discovery_option_type_t option_type;

  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_icmp_input_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp6_input_trace_t));

  /* source may append his LL address */
  option_type = ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  ip6_ra_t *radv_info = NULL;

	  icmp6_neighbor_discovery_header_t *h0;
	  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *o0;

	  u32 bi0, options_len0, sw_if_index0, next0, error0;
	  u32 is_solicitation = 1, is_dropped = 0;
	  u32 is_unspecified, is_link_local;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  h0 = ip6_next_header (ip0);
	  options_len0 =
	    clib_net_to_host_u16 (ip0->payload_length) - sizeof (h0[0]);
	  is_unspecified = ip6_address_is_unspecified (&ip0->src_address);
	  is_link_local =
	    ip6_address_is_link_local_unicast (&ip0->src_address);

	  error0 = ICMP6_ERROR_NONE;
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  /* check if solicitation  (not from nd_timer node) */
	  if (ip6_address_is_unspecified (&ip0->dst_address))
	    is_solicitation = 0;

	  /* Check that source address is unspecified, link-local or else on-link. */
	  if (!is_unspecified && !is_link_local)
	    {
	      u32 src_adj_index0 = ip6_src_lookup_for_packet (im, p0, ip0);

	      if (ADJ_INDEX_INVALID != src_adj_index0)
		{
		  ip_adjacency_t *adj0 = adj_get (src_adj_index0);

		  error0 = (adj0->rewrite_header.sw_if_index != sw_if_index0
			    ?
			    ICMP6_ERROR_ROUTER_SOLICITATION_SOURCE_NOT_ON_LINK
			    : error0);
		}
	      else
		{
		  error0 = ICMP6_ERROR_ROUTER_SOLICITATION_SOURCE_NOT_ON_LINK;
		}
	    }

	  /* check for source LL option and process */
	  o0 = (void *) (h0 + 1);
	  o0 = ((options_len0 == 8
		 && o0->header.type == option_type
		 && o0->header.n_data_u64s == 1) ? o0 : 0);

	  /* if src address unspecified IGNORE any options */
	  if (PREDICT_TRUE (error0 == ICMP6_ERROR_NONE && o0 != 0 &&
			    !is_unspecified && !is_link_local))
	    {
              /* *INDENT-OFF* */
	      ip_neighbor_learn_t learn = {
		.sw_if_index = sw_if_index0,
		.ip = {
                  .ip.ip6 = ip0->src_address,
                  .version = AF_IP6,
                },
	      };
              /* *INDENT-ON* */
	      memcpy (&learn.mac, o0->ethernet_address, sizeof (learn.mac));
	      ip_neighbor_learn_dp (&learn);
	    }

	  /* default is to drop */
	  next0 = ICMP6_ROUTER_SOLICITATION_NEXT_DROP;

	  if (error0 == ICMP6_ERROR_NONE)
	    {
	      vnet_sw_interface_t *sw_if0;
	      ethernet_interface_t *eth_if0;
	      u32 adj_index0;

	      sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index0);
	      ASSERT (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
	      eth_if0 =
		ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);

	      /* only support ethernet interface type for now */
	      error0 =
		(!eth_if0) ? ICMP6_ERROR_ROUTER_SOLICITATION_UNSUPPORTED_INTF
		: error0;

	      if (error0 == ICMP6_ERROR_NONE)
		{
		  /* adjust the sizeof the buffer to just include the ipv6 header */
		  p0->current_length -=
		    (options_len0 +
		     sizeof (icmp6_neighbor_discovery_header_t));

		  radv_info = ip6_ra_get_itf (sw_if_index0);

		  error0 = ((!radv_info || 0 == radv_info->send_radv) ?
			      ICMP6_ERROR_ROUTER_SOLICITATION_RADV_NOT_CONFIG :
			      error0);
		  if (error0 == ICMP6_ERROR_NONE)
		    {
		      f64 now = vlib_time_now (vm);

		      /* for solicited adverts - need to rate limit */
		      if (is_solicitation)
			{
			  if (0 != radv_info->last_radv_time &&
			      (now - radv_info->last_radv_time) <
			      MIN_DELAY_BETWEEN_RAS)
			    is_dropped = 1;
			  else
			    radv_info->last_radv_time = now;
			}

		      /* send now  */
		      icmp6_router_advertisement_header_t rh;

		      rh.icmp.type = ICMP6_router_advertisement;
		      rh.icmp.code = 0;
		      rh.icmp.checksum = 0;

		      rh.current_hop_limit = radv_info->curr_hop_limit;
		      rh.router_lifetime_in_sec =
			clib_host_to_net_u16
			(radv_info->adv_router_lifetime_in_sec);
		      rh.
			time_in_msec_between_retransmitted_neighbor_solicitations
			=
			clib_host_to_net_u32 (radv_info->
					      adv_time_in_msec_between_retransmitted_neighbor_solicitations);
		      rh.neighbor_reachable_time_in_msec =
			clib_host_to_net_u32 (radv_info->
					      adv_neighbor_reachable_time_in_msec);

		      rh.flags =
			(radv_info->adv_managed_flag) ?
			ICMP6_ROUTER_DISCOVERY_FLAG_ADDRESS_CONFIG_VIA_DHCP :
			0;
		      rh.flags |=
			((radv_info->adv_other_flag) ?
			 ICMP6_ROUTER_DISCOVERY_FLAG_OTHER_CONFIG_VIA_DHCP :
			 0);


		      u16 payload_length =
			sizeof (icmp6_router_advertisement_header_t);

		      if (vlib_buffer_add_data
			  (vm, &bi0, (void *) &rh,
			   sizeof (icmp6_router_advertisement_header_t)))
			{
			  /* buffer allocation failed, drop the pkt */
			  error0 = ICMP6_ERROR_ALLOC_FAILURE;
			  goto drop0;
			}

		      if (radv_info->adv_link_layer_address)
			{
			  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
			    h;

			  h.header.type =
			    ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address;
			  h.header.n_data_u64s = 1;

			  /* copy ll address */
			  clib_memcpy (&h.ethernet_address[0],
				       &eth_if0->address, 6);

			  if (vlib_buffer_add_data
			      (vm, &bi0, (void *) &h,
			       sizeof
			       (icmp6_neighbor_discovery_ethernet_link_layer_address_option_t)))
			    {
			      error0 = ICMP6_ERROR_ALLOC_FAILURE;
			      goto drop0;
			    }

			  payload_length +=
			    sizeof
			    (icmp6_neighbor_discovery_ethernet_link_layer_address_option_t);
			}

		      /* add MTU option */
		      if (radv_info->adv_link_mtu)
			{
			  icmp6_neighbor_discovery_mtu_option_t h;

			  h.unused = 0;
			  h.mtu =
			    clib_host_to_net_u32 (radv_info->adv_link_mtu);
			  h.header.type = ICMP6_NEIGHBOR_DISCOVERY_OPTION_mtu;
			  h.header.n_data_u64s = 1;

			  payload_length +=
			    sizeof (icmp6_neighbor_discovery_mtu_option_t);

			  if (vlib_buffer_add_data
			      (vm, &bi0, (void *) &h,
			       sizeof
			       (icmp6_neighbor_discovery_mtu_option_t)))
			    {
			      error0 = ICMP6_ERROR_ALLOC_FAILURE;
			      goto drop0;
			    }
			}

		      /* add advertised prefix options  */
		      ip6_radv_prefix_t *pr_info;

		      /* *INDENT-OFF* */
		      pool_foreach (pr_info, radv_info->adv_prefixes_pool)
                       {
                        if(pr_info->enabled &&
                           (!pr_info->decrement_lifetime_flag
                            || (pr_info->pref_lifetime_expires >0)))
                          {
                            /* advertise this prefix */
                            icmp6_neighbor_discovery_prefix_information_option_t h;

                            h.header.type = ICMP6_NEIGHBOR_DISCOVERY_OPTION_prefix_information;
                            h.header.n_data_u64s  =  (sizeof(icmp6_neighbor_discovery_prefix_information_option_t) >> 3);

                            h.dst_address_length  = pr_info->prefix_len;

                            h.flags  = (pr_info->adv_on_link_flag) ? ICMP6_NEIGHBOR_DISCOVERY_PREFIX_INFORMATION_FLAG_ON_LINK : 0;
                            h.flags |= (pr_info->adv_autonomous_flag) ?  ICMP6_NEIGHBOR_DISCOVERY_PREFIX_INFORMATION_AUTO :  0;

                            if(radv_info->cease_radv && pr_info->deprecated_prefix_flag)
                              {
                                h.valid_time = clib_host_to_net_u32(MIN_ADV_VALID_LIFETIME);
                                h.preferred_time  = 0;
                              }
                            else
                              {
                                if(pr_info->decrement_lifetime_flag)
                                  {
                                    pr_info->adv_valid_lifetime_in_secs = ((pr_info->valid_lifetime_expires  > now)) ?
                                      (pr_info->valid_lifetime_expires  - now) : 0;

                                    pr_info->adv_pref_lifetime_in_secs = ((pr_info->pref_lifetime_expires  > now)) ?
                                      (pr_info->pref_lifetime_expires  - now) : 0;
                                  }

                                h.valid_time = clib_host_to_net_u32(pr_info->adv_valid_lifetime_in_secs);
                                h.preferred_time  = clib_host_to_net_u32(pr_info->adv_pref_lifetime_in_secs) ;
                              }
                            h.unused  = 0;

                            /* Handy for debugging, but too noisy... */
                            if (0 && CLIB_DEBUG > 0)
                              clib_warning
                                ("send RA for prefix %U/%d "
                                 "sw_if_index %d valid %u preferred %u",
                                 format_ip6_address, &pr_info->prefix,
                                 pr_info->prefix_len, sw_if_index0,
                                 clib_net_to_host_u32 (h.valid_time),
                                 clib_net_to_host_u32 (h.preferred_time));

                            if (h.valid_time == 0)
                              clib_warning ("BUG: send RA with valid_time 0");

                            clib_memcpy(&h.dst_address, &pr_info->prefix,  sizeof(ip6_address_t));

                            payload_length += sizeof( icmp6_neighbor_discovery_prefix_information_option_t);

                            if (vlib_buffer_add_data
				(vm, &bi0, (void *)&h,
				 sizeof(icmp6_neighbor_discovery_prefix_information_option_t)))
                              {
                                error0 = ICMP6_ERROR_ALLOC_FAILURE;
                                goto drop0;
                              }

                          }
                      }
		      /* *INDENT-ON* */

		      /* add additional options before here */

		      /* finish building the router advertisement... */
		      if (!is_unspecified && radv_info->send_unicast)
			{
			  ip0->dst_address = ip0->src_address;
			}
		      else
			{
			  /* target address is all-nodes mcast addr */
			  ip6_set_reserved_multicast_address
			    (&ip0->dst_address,
			     IP6_MULTICAST_SCOPE_link_local,
			     IP6_MULTICAST_GROUP_ID_all_hosts);
			}

		      /* source address MUST be the link-local address */
		      ip6_address_copy (&ip0->src_address,
					ip6_get_link_local_address
					(radv_info->sw_if_index));

		      ip0->hop_limit = 255;
		      ip0->payload_length =
			clib_host_to_net_u16 (payload_length);

		      icmp6_router_advertisement_header_t *rh0 =
			(icmp6_router_advertisement_header_t *) (ip0 + 1);
		      rh0->icmp.checksum =
			ip6_tcp_udp_icmp_compute_checksum (vm, p0, ip0,
							   &bogus_length);
		      ASSERT (bogus_length == 0);

		      /* setup output if and adjacency */
		      vnet_buffer (p0)->sw_if_index[VLIB_RX] =
			vnet_main.local_interface_sw_if_index;

		      if (is_solicitation)
			{
			  ethernet_header_t *eth0;
			  /* Reuse current MAC header, copy SMAC to DMAC and
			   * interface MAC to SMAC */
			  vlib_buffer_reset (p0);
			  eth0 = vlib_buffer_get_current (p0);
			  clib_memcpy (eth0->dst_address, eth0->src_address,
				       6);
			  clib_memcpy (eth0->src_address, &eth_if0->address,
				       6);
			  next0 =
			    is_dropped ? next0 :
			    ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_TX;
			  vnet_buffer (p0)->sw_if_index[VLIB_TX] =
			    sw_if_index0;
			}
		      else
			{
			  adj_index0 = ip6_link_get_mcast_adj (sw_if_index0);
			  if (adj_index0 == INDEX_INVALID)
			    error0 = ICMP6_ERROR_DST_LOOKUP_MISS;
			  else
			    {
			      next0 =
				is_dropped ? next0 :
				ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_RW;
			      vnet_buffer (p0)->ip.adj_index[VLIB_TX] =
				adj_index0;
			    }
			}
		      p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

		      radv_info->n_solicitations_dropped += is_dropped;
		      radv_info->n_solicitations_rcvd += is_solicitation;

		      if ((error0 == ICMP6_ERROR_NONE) && !is_dropped)
			{
			  radv_info->n_advertisements_sent++;
			  n_advertisements_sent++;
			}
		    }
		}
	    }

	drop0:
	  p0->error = error_node->errors[error0];

	  if (error0 != ICMP6_ERROR_NONE)
	    vlib_error_count (vm, error_node->node_index, error0, 1);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);

	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Account for router advertisements sent. */
  vlib_error_count (vm, error_node->node_index,
		    ICMP6_ERROR_ROUTER_ADVERTISEMENTS_TX,
		    n_advertisements_sent);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_icmp_router_solicitation_node,static) =
{
  .function = icmp6_router_solicitation,
  .name = "icmp6-router-solicitation",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = ICMP6_ROUTER_SOLICITATION_N_NEXT,
  .next_nodes = {
    [ICMP6_ROUTER_SOLICITATION_NEXT_DROP] = "ip6-drop",
    [ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_RW] = "ip6-rewrite-mcast",
    [ICMP6_ROUTER_SOLICITATION_NEXT_REPLY_TX] = "interface-output",
  },
};
/* *INDENT-ON* */

 /* validate advertised info for consistancy (see RFC-4861 section 6.2.7) - log any inconsistencies, packet will always  be dropped  */
static_always_inline uword
icmp6_router_advertisement (vlib_main_t * vm,
			    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  uword n_packets = frame->n_vectors;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next, next_index;
  u32 n_advertisements_rcvd = 0;

  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_icmp_input_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (icmp6_input_trace_t));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  ip6_ra_t *radv_info = 0;
	  icmp6_router_advertisement_header_t *h0;
	  u32 bi0, options_len0, sw_if_index0, next0, error0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  h0 = ip6_next_header (ip0);
	  options_len0 =
	    clib_net_to_host_u16 (ip0->payload_length) - sizeof (h0[0]);

	  error0 = ICMP6_ERROR_NONE;
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  /* Check that source address is link-local */
	  error0 = (!ip6_address_is_link_local_unicast (&ip0->src_address)) ?
	    ICMP6_ERROR_ROUTER_ADVERTISEMENT_SOURCE_NOT_LINK_LOCAL : error0;

	  /* default is to drop */
	  next0 = ICMP6_ROUTER_SOLICITATION_NEXT_DROP;

	  n_advertisements_rcvd++;

	  if (error0 == ICMP6_ERROR_NONE)
	    {
	      vnet_sw_interface_t *sw_if0;
	      ethernet_interface_t *eth_if0;

	      sw_if0 = vnet_get_sup_sw_interface (vnm, sw_if_index0);
	      ASSERT (sw_if0->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
	      eth_if0 =
		ethernet_get_interface (&ethernet_main, sw_if0->hw_if_index);

	      /* only support ethernet interface type for now */
	      error0 =
		(!eth_if0) ? ICMP6_ERROR_ROUTER_SOLICITATION_UNSUPPORTED_INTF
		: error0;

	      if (error0 == ICMP6_ERROR_NONE)
		{
		  /* look up the radv_t information for this interface */
		  radv_info = ip6_ra_get_itf (sw_if_index0);

		  error0 = ((!radv_info) ?
			    ICMP6_ERROR_ROUTER_SOLICITATION_RADV_NOT_CONFIG :
			    error0);

		  if (error0 == ICMP6_ERROR_NONE)
		    {
		      radv_info->keep_sending_rs = 0;

		      ip6_ra_report_t r;

		      r.sw_if_index = sw_if_index0;
		      memcpy (&r.router_address, &ip0->src_address, 16);
		      r.current_hop_limit = h0->current_hop_limit;
		      r.flags = h0->flags;
		      r.router_lifetime_in_sec =
			clib_net_to_host_u16 (h0->router_lifetime_in_sec);
		      r.neighbor_reachable_time_in_msec =
			clib_net_to_host_u32
			(h0->neighbor_reachable_time_in_msec);
		      r.time_in_msec_between_retransmitted_neighbor_solicitations = clib_net_to_host_u32 (h0->time_in_msec_between_retransmitted_neighbor_solicitations);
		      r.prefixes = 0;

		      /* validate advertised information */
		      if ((h0->current_hop_limit && radv_info->curr_hop_limit)
			  && (h0->current_hop_limit !=
			      radv_info->curr_hop_limit))
			{
			  ip6_neighbor_syslog (vm, LOG_WARNING,
					       "our AdvCurHopLimit on %U doesn't agree with %U",
					       format_vnet_sw_if_index_name,
					       vnm, sw_if_index0,
					       format_ip6_address,
					       &ip0->src_address);
			}

		      if ((h0->flags &
			   ICMP6_ROUTER_DISCOVERY_FLAG_ADDRESS_CONFIG_VIA_DHCP)
			  != radv_info->adv_managed_flag)
			{
			  ip6_neighbor_syslog (vm, LOG_WARNING,
					       "our AdvManagedFlag on %U doesn't agree with %U",
					       format_vnet_sw_if_index_name,
					       vnm, sw_if_index0,
					       format_ip6_address,
					       &ip0->src_address);
			}

		      if ((h0->flags &
			   ICMP6_ROUTER_DISCOVERY_FLAG_OTHER_CONFIG_VIA_DHCP)
			  != radv_info->adv_other_flag)
			{
			  ip6_neighbor_syslog (vm, LOG_WARNING,
					       "our AdvOtherConfigFlag on %U doesn't agree with %U",
					       format_vnet_sw_if_index_name,
					       vnm, sw_if_index0,
					       format_ip6_address,
					       &ip0->src_address);
			}

		      if ((h0->
			   time_in_msec_between_retransmitted_neighbor_solicitations
			   && radv_info->
			   adv_time_in_msec_between_retransmitted_neighbor_solicitations)
			  && (h0->
			      time_in_msec_between_retransmitted_neighbor_solicitations
			      !=
			      clib_host_to_net_u32 (radv_info->
						    adv_time_in_msec_between_retransmitted_neighbor_solicitations)))
			{
			  ip6_neighbor_syslog (vm, LOG_WARNING,
					       "our AdvRetransTimer on %U doesn't agree with %U",
					       format_vnet_sw_if_index_name,
					       vnm, sw_if_index0,
					       format_ip6_address,
					       &ip0->src_address);
			}

		      if ((h0->neighbor_reachable_time_in_msec &&
			   radv_info->adv_neighbor_reachable_time_in_msec) &&
			  (h0->neighbor_reachable_time_in_msec !=
			   clib_host_to_net_u32
			   (radv_info->adv_neighbor_reachable_time_in_msec)))
			{
			  ip6_neighbor_syslog (vm, LOG_WARNING,
					       "our AdvReachableTime on %U doesn't agree with %U",
					       format_vnet_sw_if_index_name,
					       vnm, sw_if_index0,
					       format_ip6_address,
					       &ip0->src_address);
			}

		      /* check for MTU or prefix options or .. */
		      u8 *opt_hdr = (u8 *) (h0 + 1);
		      while (options_len0 > 0)
			{
			  icmp6_neighbor_discovery_option_header_t *o0 =
			    (icmp6_neighbor_discovery_option_header_t *)
			    opt_hdr;
			  int opt_len = o0->n_data_u64s << 3;
			  icmp6_neighbor_discovery_option_type_t option_type =
			    o0->type;

			  if (options_len0 < 2)
			    {
			      ip6_neighbor_syslog (vm, LOG_ERR,
						   "malformed RA packet on %U from %U",
						   format_vnet_sw_if_index_name,
						   vnm, sw_if_index0,
						   format_ip6_address,
						   &ip0->src_address);
			      break;
			    }

			  if (opt_len == 0)
			    {
			      ip6_neighbor_syslog (vm, LOG_ERR,
						   " zero length option in RA on %U from %U",
						   format_vnet_sw_if_index_name,
						   vnm, sw_if_index0,
						   format_ip6_address,
						   &ip0->src_address);
			      break;
			    }
			  else if (opt_len > options_len0)
			    {
			      ip6_neighbor_syslog (vm, LOG_ERR,
						   "option length in RA packet  greater than total length on %U from %U",
						   format_vnet_sw_if_index_name,
						   vnm, sw_if_index0,
						   format_ip6_address,
						   &ip0->src_address);
			      break;
			    }

			  options_len0 -= opt_len;
			  opt_hdr += opt_len;

			  switch (option_type)
			    {
			    case ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address:
			      {
				icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
				  * h =
				  (icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
				   *) (o0);

				if (opt_len < sizeof (*h))
				  break;

				memcpy (r.slla, h->ethernet_address, 6);
			      }
			      break;

			    case ICMP6_NEIGHBOR_DISCOVERY_OPTION_mtu:
			      {
				icmp6_neighbor_discovery_mtu_option_t *h =
				  (icmp6_neighbor_discovery_mtu_option_t
				   *) (o0);

				if (opt_len < sizeof (*h))
				  break;

				r.mtu = clib_net_to_host_u32 (h->mtu);

				if ((h->mtu && radv_info->adv_link_mtu) &&
				    (h->mtu !=
				     clib_host_to_net_u32
				     (radv_info->adv_link_mtu)))
				  {
				    ip6_neighbor_syslog (vm, LOG_WARNING,
							 "our AdvLinkMTU on %U doesn't agree with %U",
							 format_vnet_sw_if_index_name,
							 vnm, sw_if_index0,
							 format_ip6_address,
							 &ip0->src_address);
				  }
			      }
			      break;

			    case ICMP6_NEIGHBOR_DISCOVERY_OPTION_prefix_information:
			      {
				icmp6_neighbor_discovery_prefix_information_option_t
				  * h =
				  (icmp6_neighbor_discovery_prefix_information_option_t
				   *) (o0);

				/* validate advertised prefix options  */
				ip6_radv_prefix_t *pr_info;
				u32 preferred, valid;

				if (opt_len < sizeof (*h))
				  break;

				vec_validate (r.prefixes,
					      vec_len (r.prefixes));
				ra_report_prefix_info_t *prefix =
				  vec_elt_at_index (r.prefixes,
						    vec_len (r.prefixes) - 1);

				preferred =
				  clib_net_to_host_u32 (h->preferred_time);
				valid = clib_net_to_host_u32 (h->valid_time);

				prefix->preferred_time = preferred;
				prefix->valid_time = valid;
				prefix->flags = h->flags & 0xc0;
				prefix->prefix.fp_len = h->dst_address_length;
				prefix->prefix.fp_addr.ip6 = h->dst_address;
				prefix->prefix.fp_proto = FIB_PROTOCOL_IP6;

				/* look for matching prefix - if we our advertising it, it better be consistant */
				/* *INDENT-OFF* */
				pool_foreach (pr_info, radv_info->adv_prefixes_pool)
                                 {

                                  ip6_address_t mask;
                                  ip6_address_mask_from_width(&mask, pr_info->prefix_len);

                                  if(pr_info->enabled &&
                                     (pr_info->prefix_len == h->dst_address_length) &&
                                     ip6_address_is_equal_masked (&pr_info->prefix,  &h->dst_address, &mask))
                                    {
                                      /* found it */
                                      if(!pr_info->decrement_lifetime_flag &&
                                         valid != pr_info->adv_valid_lifetime_in_secs)
                                        {
                                          ip6_neighbor_syslog(vm,  LOG_WARNING,
                                                              "our ADV validlifetime on  %U for %U does not  agree with %U",
                                                              format_vnet_sw_if_index_name, vnm, sw_if_index0,format_ip6_address, &pr_info->prefix,
                                                              format_ip6_address, &h->dst_address);
                                        }
                                      if(!pr_info->decrement_lifetime_flag &&
                                         preferred != pr_info->adv_pref_lifetime_in_secs)
                                        {
                                          ip6_neighbor_syslog(vm,  LOG_WARNING,
                                                              "our ADV preferredlifetime on  %U for %U does not  agree with %U",
                                                              format_vnet_sw_if_index_name, vnm, sw_if_index0,format_ip6_address, &pr_info->prefix,
                                                              format_ip6_address, &h->dst_address);
                                        }
                                    }
                                  break;
                                }
				/* *INDENT-ON* */
				break;
			      }
			    default:
			      /* skip this one */
			      break;
			    }
			}
		      ip6_ra_publish (&r);
		    }
		}
	    }

	  p0->error = error_node->errors[error0];

	  if (error0 != ICMP6_ERROR_NONE)
	    vlib_error_count (vm, error_node->node_index, error0, 1);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Account for router advertisements received. */
  vlib_error_count (vm, error_node->node_index,
		    ICMP6_ERROR_ROUTER_ADVERTISEMENTS_RX,
		    n_advertisements_rcvd);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_icmp_router_advertisement_node,static) =
{
  .function = icmp6_router_advertisement,
  .name = "icmp6-router-advertisement",

  .vector_size = sizeof (u32),

  .format_trace = format_icmp6_input_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip6-drop",
  },
};
/* *INDENT-ON* */

static inline f64
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

static inline u8
get_mac_address (u32 sw_if_index, u8 * address)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw_if = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (!hw_if->hw_address)
    return 1;
  clib_memcpy (address, hw_if->hw_address, 6);
  return 0;
}

static inline vlib_buffer_t *
create_buffer_for_rs (vlib_main_t * vm, ip6_ra_t * radv_info)
{
  u32 bi0;
  vlib_buffer_t *p0;
  icmp6_router_solicitation_header_t *rh;
  u16 payload_length;
  int bogus_length;
  u32 sw_if_index;

  sw_if_index = radv_info->sw_if_index;

  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    {
      clib_warning ("buffer allocation failure");
      return 0;
    }

  p0 = vlib_get_buffer (vm, bi0);
  p0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  vnet_buffer (p0)->sw_if_index[VLIB_RX] = sw_if_index;
  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index;

  vnet_buffer (p0)->ip.adj_index[VLIB_TX] =
    ip6_link_get_mcast_adj (sw_if_index);

  rh = vlib_buffer_get_current (p0);
  p0->current_length = sizeof (*rh);

  rh->neighbor.icmp.type = ICMP6_router_solicitation;
  rh->neighbor.icmp.code = 0;
  rh->neighbor.icmp.checksum = 0;
  rh->neighbor.reserved_must_be_zero = 0;

  rh->link_layer_option.header.type =
    ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address;
  if (0 != get_mac_address (sw_if_index,
			    rh->link_layer_option.ethernet_address))
    {
      clib_warning ("interface with sw_if_index %u has no mac address",
		    sw_if_index);
      vlib_buffer_free (vm, &bi0, 1);
      return 0;
    }
  rh->link_layer_option.header.n_data_u64s = 1;

  payload_length = sizeof (rh->neighbor) + sizeof (u64);

  rh->ip.ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x6 << 28);
  rh->ip.payload_length = clib_host_to_net_u16 (payload_length);
  rh->ip.protocol = IP_PROTOCOL_ICMP6;
  rh->ip.hop_limit = 255;
  ip6_address_copy (&rh->ip.src_address,
		    ip6_get_link_local_address (radv_info->sw_if_index));
  /* set address ff02::2 */
  rh->ip.dst_address.as_u64[0] = clib_host_to_net_u64 (0xff02ULL << 48);
  rh->ip.dst_address.as_u64[1] = clib_host_to_net_u64 (2);

  rh->neighbor.icmp.checksum = ip6_tcp_udp_icmp_compute_checksum (vm, p0,
								  &rh->ip,
								  &bogus_length);

  return p0;
}

static inline void
stop_sending_rs (vlib_main_t * vm, ip6_ra_t * ra)
{
  u32 bi0;

  ra->keep_sending_rs = 0;
  if (ra->buffer)
    {
      bi0 = vlib_get_buffer_index (vm, ra->buffer);
      vlib_buffer_free (vm, &bi0, 1);
      ra->buffer = 0;
    }
}

static inline bool
check_send_rs (vlib_main_t * vm, ip6_ra_t * radv_info, f64 current_time,
	       f64 * due_time)
{
  vlib_buffer_t *p0;
  vlib_frame_t *f;
  u32 *to_next;
  u32 next_index;
  vlib_buffer_t *c0;
  u32 ci0;

  icmp6_send_router_solicitation_params_t *params;

  if (!radv_info->keep_sending_rs)
    return false;

  params = &radv_info->params;

  if (radv_info->due_time > current_time)
    {
      *due_time = radv_info->due_time;
      return true;
    }

  p0 = radv_info->buffer;

  next_index = ip6_rewrite_mcast_node.index;

  c0 = vlib_buffer_copy (vm, p0);
  if (c0 == NULL)
    return radv_info->keep_sending_rs;

  ci0 = vlib_get_buffer_index (vm, c0);

  f = vlib_get_frame_to_node (vm, next_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = ci0;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);

  if (params->mrc != 0 && --radv_info->n_left == 0)
    stop_sending_rs (vm, radv_info);
  else
    {
      radv_info->sleep_interval =
	(2 + random_f64_from_to (-0.1, 0.1)) * radv_info->sleep_interval;
      if (radv_info->sleep_interval > params->mrt)
	radv_info->sleep_interval =
	  (1 + random_f64_from_to (-0.1, 0.1)) * params->mrt;

      radv_info->due_time = current_time + radv_info->sleep_interval;

      if (params->mrd != 0
	  && current_time > radv_info->start_time + params->mrd)
	stop_sending_rs (vm, radv_info);
      else
	*due_time = radv_info->due_time;
    }

  return radv_info->keep_sending_rs;
}

static uword
send_rs_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		 vlib_frame_t * f0)
{
  uword *event_data = NULL;
  f64 sleep_time = 1e9;
  ip6_ra_t *radv_info;
  f64 current_time;
  f64 due_time;
  f64 dt = 0;

  while (true)
    {
      vlib_process_wait_for_event_or_clock (vm, sleep_time);
      vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      current_time = vlib_time_now (vm);
      do
	{
	  due_time = current_time + 1e9;
        /* *INDENT-OFF* */
        pool_foreach (radv_info, ip6_ra_pool)
         {
	    if (check_send_rs (vm, radv_info, current_time, &dt)
		&& (dt < due_time))
	      due_time = dt;
        }
        /* *INDENT-ON* */
	  current_time = vlib_time_now (vm);
	}
      while (due_time < current_time);

      sleep_time = due_time - current_time;
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_rs_process_node) = {
    .function = send_rs_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "ip6-rs-process",
};
/* *INDENT-ON* */

void
icmp6_send_router_solicitation (vlib_main_t * vm, u32 sw_if_index, u8 stop,
				const icmp6_send_router_solicitation_params_t
				* params)
{
  ip6_ra_t *ra;

  ASSERT (~0 != sw_if_index);

  ra = ip6_ra_get_itf (sw_if_index);

  if (!ra)
    return;

  stop_sending_rs (vm, ra);

  if (!stop)
    {
      ra->keep_sending_rs = 1;
      ra->params = *params;
      ra->n_left = params->mrc;
      ra->start_time = vlib_time_now (vm);
      ra->sleep_interval = (1 + random_f64_from_to (-0.1, 0.1)) * params->irt;
      ra->due_time = 0;		/* send first packet ASAP */
      ra->buffer = create_buffer_for_rs (vm, ra);
      if (!ra->buffer)
	ra->keep_sending_rs = 0;
      else
	vlib_process_signal_event (vm, ip6_rs_process_node.index, 1, 0);
    }
}

static const ethernet_interface_t *
ip6_ra_get_eth_itf (u32 sw_if_index)
{
  const vnet_sw_interface_t *sw;

  /* lookup radv container  - ethernet interfaces only */
  sw = vnet_get_sup_sw_interface (vnet_get_main (), sw_if_index);
  if (sw->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
    return (ethernet_get_interface (&ethernet_main, sw->hw_if_index));

  return (NULL);
}

/**
 * @brief called when IP6 is enabled on an interface
 *create and initialize router advertisement parameters with default
 * values for this intfc
 */
static void
ip6_ra_link_enable (u32 sw_if_index)
{
  const ethernet_interface_t *eth;
  ip6_ra_t *radv_info;

  eth = ip6_ra_get_eth_itf (sw_if_index);

  if (NULL == eth)
    return;

  ASSERT (INDEX_INVALID == ip6_link_delegate_get (sw_if_index,
						  ip6_ra_delegate_id));

  pool_get_zero (ip6_ra_pool, radv_info);

  radv_info->seed = (u32) clib_cpu_time_now ();
  random_u32 (&radv_info->seed);

  radv_info->sw_if_index = sw_if_index;
  radv_info->max_radv_interval = DEF_MAX_RADV_INTERVAL;
  radv_info->min_radv_interval = DEF_MIN_RADV_INTERVAL;
  radv_info->curr_hop_limit = DEF_CURR_HOP_LIMIT;
  radv_info->adv_router_lifetime_in_sec = DEF_DEF_RTR_LIFETIME;

  /* send ll address source address option */
  radv_info->adv_link_layer_address = 1;

  radv_info->min_delay_between_radv = MIN_DELAY_BETWEEN_RAS;
  radv_info->max_delay_between_radv = MAX_DELAY_BETWEEN_RAS;
  radv_info->max_rtr_default_lifetime = MAX_DEF_RTR_LIFETIME;

  radv_info->initial_adverts_count = MAX_INITIAL_RTR_ADVERTISEMENTS;
  radv_info->initial_adverts_sent = radv_info->initial_adverts_count - 1;
  radv_info->initial_adverts_interval = MAX_INITIAL_RTR_ADVERT_INTERVAL;

  /* deafult is to send */
  radv_info->send_radv = 1;

  /* fill in delegate for this interface that will be needed later */
  radv_info->adv_link_mtu =
    vnet_sw_interface_get_mtu (vnet_get_main (), sw_if_index, VNET_MTU_IP6);

  mhash_init (&radv_info->address_to_prefix_index, sizeof (uword),
	      sizeof (ip6_address_t));

  ip6_link_delegate_update (sw_if_index, ip6_ra_delegate_id,
			    radv_info - ip6_ra_pool);
}

static void
ip6_ra_delegate_disable (index_t rai)
{
  ip6_radv_prefix_t *p;
  ip6_ra_t *radv_info;

  radv_info = pool_elt_at_index (ip6_ra_pool, rai);

  /* clean up prefix and MDP pools */
  /* *INDENT-OFF* */
  pool_flush(p, radv_info->adv_prefixes_pool,
  ({
    mhash_unset (&radv_info->address_to_prefix_index, &p->prefix, 0);
  }));
  /* *INDENT-ON* */

  pool_free (radv_info->adv_prefixes_pool);

  mhash_free (&radv_info->address_to_prefix_index);

  pool_put (ip6_ra_pool, radv_info);
}

void
ip6_ra_update_secondary_radv_info (ip6_address_t * address, u8 prefix_len,
				   u32 primary_sw_if_index,
				   u32 valid_time, u32 preferred_time)
{
  vlib_main_t *vm = vlib_get_main ();
  static u32 *radv_indices;
  ip6_ra_t *radv_info;
  int i;
  ip6_address_t mask;
  ip6_address_mask_from_width (&mask, prefix_len);

  vec_reset_length (radv_indices);
  /* *INDENT-OFF* */
  pool_foreach (radv_info, ip6_ra_pool)
   {
    vec_add1 (radv_indices, radv_info - ip6_ra_pool);
  }
  /* *INDENT-ON* */

  /*
   * If we have another customer for this prefix,
   * tell the RA code about it...
   */
  for (i = 0; i < vec_len (radv_indices); i++)
    {
      ip6_radv_prefix_t *this_prefix;
      radv_info = pool_elt_at_index (ip6_ra_pool, radv_indices[i]);

      /* We already took care of these timers... */
      if (radv_info->sw_if_index == primary_sw_if_index)
	continue;

      /* *INDENT-OFF* */
      pool_foreach (this_prefix, radv_info->adv_prefixes_pool)
       {
        if (this_prefix->prefix_len == prefix_len
            && ip6_address_is_equal_masked (&this_prefix->prefix, address,
                                            &mask))
          {
            int rv = ip6_ra_prefix (vm,
                                    radv_info->sw_if_index,
                                    address,
                                    prefix_len,
                                    0 /* use_default */,
                                    valid_time,
                                    preferred_time,
                                    0 /* no_advertise */,
                                    0 /* off_link */,
                                    0 /* no_autoconfig */,
                                    0 /* no_onlink */,
                                    0 /* is_no */);
            if (rv != 0)
              clib_warning ("ip6_neighbor_ra_prefix returned %d", rv);
          }
      }
      /* *INDENT-ON*/
    }
}

/* send a RA or update the timer info etc.. */
static uword
ip6_ra_process_timer_event (vlib_main_t * vm,
			    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_ra_t *radv_info;
  vlib_frame_t *f = 0;
  u32 n_this_frame = 0;
  u32 n_left_to_next = 0;
  u32 *to_next = 0;
  u32 bo0;
  icmp6_router_solicitation_header_t *h0;
  vlib_buffer_t *b0;
  f64 now = vlib_time_now (vm);

  /* Interface ip6 radv info list */
  /* *INDENT-OFF* */
  pool_foreach (radv_info, ip6_ra_pool)
   {
    if( !vnet_sw_interface_is_admin_up (vnm, radv_info->sw_if_index))
      {
        radv_info->initial_adverts_sent = radv_info->initial_adverts_count-1;
        radv_info->next_multicast_time = now;
        radv_info->last_multicast_time = now;
        radv_info->last_radv_time = 0;
        continue;
      }

    /* is it time to send a multicast  RA on this interface? */
    if(radv_info->send_radv && (now >=  radv_info->next_multicast_time))
      {
        u32 n_to_alloc = 1;
        u32 n_allocated;

        f64 rfn = (radv_info->max_radv_interval - radv_info->min_radv_interval) *
          random_f64 (&radv_info->seed) + radv_info->min_radv_interval;

        /* multicast send - compute next multicast send time */
        if( radv_info->initial_adverts_sent > 0)
          {
            radv_info->initial_adverts_sent--;
            if(rfn > radv_info->initial_adverts_interval)
              rfn =  radv_info->initial_adverts_interval;

            /* check to see if we are ceasing to send */
            if( radv_info->initial_adverts_sent  == 0)
              if(radv_info->cease_radv)
                radv_info->send_radv = 0;
          }

        radv_info->next_multicast_time =  rfn + now;
        radv_info->last_multicast_time = now;

        /* send advert now - build a "solicted" router advert with unspecified source address */
        n_allocated = vlib_buffer_alloc (vm, &bo0, n_to_alloc);

        if (PREDICT_FALSE(n_allocated == 0))
          {
            clib_warning ("buffer allocation failure");
            continue;
          }
        b0 = vlib_get_buffer (vm, bo0);
        b0->current_length = sizeof( icmp6_router_solicitation_header_t);
        b0->error = ICMP6_ERROR_NONE;
        vnet_buffer (b0)->sw_if_index[VLIB_RX] = radv_info->sw_if_index;

        h0 =  vlib_buffer_get_current (b0);

        clib_memset (h0, 0, sizeof (icmp6_router_solicitation_header_t));

        h0->ip.ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (0x6 << 28);
        h0->ip.payload_length = clib_host_to_net_u16 (sizeof (icmp6_router_solicitation_header_t)
                                                      - STRUCT_OFFSET_OF (icmp6_router_solicitation_header_t, neighbor));
        h0->ip.protocol = IP_PROTOCOL_ICMP6;
        h0->ip.hop_limit = 255;

        /* set src/dst address as "unspecified" this marks this packet as internally generated rather than recieved */
        h0->ip.src_address.as_u64[0] = 0;
        h0->ip.src_address.as_u64[1] = 0;

        h0->ip.dst_address.as_u64[0] = 0;
        h0->ip.dst_address.as_u64[1] = 0;

        h0->neighbor.icmp.type = ICMP6_router_solicitation;

        if (PREDICT_FALSE(f == 0))
          {
            f = vlib_get_frame_to_node (vm, ip6_icmp_router_solicitation_node.index);
            to_next = vlib_frame_vector_args (f);
            n_left_to_next = VLIB_FRAME_SIZE;
            n_this_frame = 0;
          }

        n_this_frame++;
        n_left_to_next--;
        to_next[0] = bo0;
        to_next += 1;

        if (PREDICT_FALSE(n_left_to_next == 0))
          {
            f->n_vectors = n_this_frame;
            vlib_put_frame_to_node (vm, ip6_icmp_router_solicitation_node.index, f);
            f = 0;
          }
      }
  }
  /* *INDENT-ON* */

  if (f)
    {
      ASSERT (n_this_frame);
      f->n_vectors = n_this_frame;
      vlib_put_frame_to_node (vm, ip6_icmp_router_solicitation_node.index, f);
    }
  return 0;
}

static void
ip6_ra_handle_report (ip6_ra_report_t * rap)
{
  u32 ii;

  vec_foreach_index (ii, ip6_ra_listeners) ip6_ra_listeners[ii] (rap);
  vec_free (rap->prefixes);
  clib_mem_free (rap);
}

static uword
ip6_ra_event_process (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip6_ra_report_t *r;
  uword event_type;
  uword *event_data = 0;
  int i;

  /* init code here */

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 1. /* seconds */ );

      event_type = vlib_process_get_events (vm, &event_data);

      if (event_type == ~0)
	{
	  /* No events found: timer expired. */
	  /* process interface list and send RAs as appropriate, update timer info */
	  ip6_ra_process_timer_event (vm, node, frame);
	}
      else
	{
	  for (i = 0; i < vec_len (event_data); i++)
	    {
	      r = (void *) (event_data[i]);
	      ip6_ra_handle_report (r);
	    }
	  vec_reset_length (event_data);
	}
    }
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_ra_process_node) =
{
 .function = ip6_ra_event_process,
 .name = "ip6-ra-process",
 .type = VLIB_NODE_TYPE_PROCESS,
};
/* *INDENT-ON* */

static void
ip6_ra_signal_report (ip6_ra_report_t * r)
{
  vlib_main_t *vm = vlib_get_main ();
  ip6_ra_report_t *q;

  if (!vec_len (ip6_ra_listeners))
    return;

  q = clib_mem_alloc (sizeof (*q));
  *q = *r;

  vlib_process_signal_event (vm, ip6_ra_process_node.index, 0, (uword) q);
}

static int
ip6_ra_publish (ip6_ra_report_t * r)
{
  void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);
  vl_api_rpc_call_main_thread (ip6_ra_signal_report, (u8 *) r, sizeof *r);
  return 0;
}

/* API support functions */
int
ip6_ra_config (vlib_main_t * vm, u32 sw_if_index,
	       u8 suppress, u8 managed, u8 other,
	       u8 ll_option, u8 send_unicast, u8 cease,
	       u8 use_lifetime, u32 lifetime,
	       u32 initial_count, u32 initial_interval,
	       u32 max_interval, u32 min_interval, u8 is_no)
{
  ip6_ra_t *radv_info;

  /* look up the radv_t  information for this interface */
  radv_info = ip6_ra_get_itf (sw_if_index);

  if (!radv_info)
    return (VNET_API_ERROR_IP6_NOT_ENABLED);

  if ((max_interval != 0) && (min_interval == 0))
    min_interval = .75 * max_interval;

  max_interval =
    (max_interval !=
     0) ? ((is_no) ? DEF_MAX_RADV_INTERVAL : max_interval) :
    radv_info->max_radv_interval;
  min_interval =
    (min_interval !=
     0) ? ((is_no) ? DEF_MIN_RADV_INTERVAL : min_interval) :
    radv_info->min_radv_interval;
  lifetime =
    (use_lifetime !=
     0) ? ((is_no) ? DEF_DEF_RTR_LIFETIME : lifetime) :
    radv_info->adv_router_lifetime_in_sec;

  if (lifetime)
    {
      if (lifetime > MAX_DEF_RTR_LIFETIME)
	lifetime = MAX_DEF_RTR_LIFETIME;

      if (lifetime <= max_interval)
	return VNET_API_ERROR_INVALID_VALUE;
    }

  if (min_interval != 0)
    {
      if ((min_interval > .75 * max_interval) || (min_interval < 3))
	return VNET_API_ERROR_INVALID_VALUE;
    }

  if ((initial_count > MAX_INITIAL_RTR_ADVERTISEMENTS) ||
      (initial_interval > MAX_INITIAL_RTR_ADVERT_INTERVAL))
    return VNET_API_ERROR_INVALID_VALUE;

  /*
     if "flag" is set and is_no is true then restore default value else set value corresponding to "flag"
     if "flag" is clear  don't change corresponding value
   */
  radv_info->send_radv =
    (suppress != 0) ? ((is_no != 0) ? 1 : 0) : radv_info->send_radv;
  radv_info->adv_managed_flag =
    (managed != 0) ? ((is_no) ? 0 : 1) : radv_info->adv_managed_flag;
  radv_info->adv_other_flag =
    (other != 0) ? ((is_no) ? 0 : 1) : radv_info->adv_other_flag;
  radv_info->adv_link_layer_address =
    (ll_option != 0) ? ((is_no) ? 1 : 0) : radv_info->adv_link_layer_address;
  radv_info->send_unicast =
    (send_unicast != 0) ? ((is_no) ? 0 : 1) : radv_info->send_unicast;
  radv_info->cease_radv =
    (cease != 0) ? ((is_no) ? 0 : 1) : radv_info->cease_radv;

  radv_info->min_radv_interval = min_interval;
  radv_info->max_radv_interval = max_interval;
  radv_info->adv_router_lifetime_in_sec = lifetime;

  radv_info->initial_adverts_count =
    (initial_count !=
     0) ? ((is_no) ? MAX_INITIAL_RTR_ADVERTISEMENTS : initial_count) :
    radv_info->initial_adverts_count;
  radv_info->initial_adverts_interval =
    (initial_interval !=
     0) ? ((is_no) ? MAX_INITIAL_RTR_ADVERT_INTERVAL : initial_interval) :
    radv_info->initial_adverts_interval;

  /* restart */
  if ((cease != 0) && (is_no))
    radv_info->send_radv = 1;

  radv_info->initial_adverts_sent = radv_info->initial_adverts_count - 1;
  radv_info->next_multicast_time = vlib_time_now (vm);
  radv_info->last_multicast_time = vlib_time_now (vm);
  radv_info->last_radv_time = 0;

  return (0);
}


int
ip6_ra_prefix (vlib_main_t * vm, u32 sw_if_index,
	       ip6_address_t * prefix_addr, u8 prefix_len,
	       u8 use_default, u32 val_lifetime, u32 pref_lifetime,
	       u8 no_advertise, u8 off_link, u8 no_autoconfig,
	       u8 no_onlink, u8 is_no)
{
  ip6_ra_t *radv_info;

  /* look up the radv_t  information for this interface */
  radv_info = ip6_ra_get_itf (sw_if_index);

  if (!radv_info)
    return (VNET_API_ERROR_IP6_NOT_ENABLED);

  f64 now = vlib_time_now (vm);

  /* prefix info add, delete or update */
  ip6_radv_prefix_t *prefix;

  /* lookup  prefix info for this  address on this interface */
  uword *p = mhash_get (&radv_info->address_to_prefix_index, prefix_addr);

  prefix = p ? pool_elt_at_index (radv_info->adv_prefixes_pool, p[0]) : 0;

  if (is_no)
    {
      /* delete */
      if (!prefix)
	return VNET_API_ERROR_INVALID_VALUE;	/* invalid prefix */

      if (prefix->prefix_len != prefix_len)
	return VNET_API_ERROR_INVALID_VALUE_2;

      /* FIXME - Should the DP do this or the CP ? */
      /* do specific delete processing here before returning */
      /* try to remove from routing table */

      mhash_unset (&radv_info->address_to_prefix_index, prefix_addr,
		   /* old_value */ 0);
      pool_put (radv_info->adv_prefixes_pool, prefix);

      radv_info->initial_adverts_sent = radv_info->initial_adverts_count - 1;
      radv_info->next_multicast_time = vlib_time_now (vm);
      radv_info->last_multicast_time = vlib_time_now (vm);
      radv_info->last_radv_time = 0;
      return (0);
    }

  /* adding or changing */
  if (!prefix)
    {
      /* add */
      u32 pi;
      pool_get_zero (radv_info->adv_prefixes_pool, prefix);
      pi = prefix - radv_info->adv_prefixes_pool;
      mhash_set (&radv_info->address_to_prefix_index, prefix_addr, pi,
		 /* old_value */ 0);

      clib_memset (prefix, 0x0, sizeof (ip6_radv_prefix_t));

      prefix->prefix_len = prefix_len;
      clib_memcpy (&prefix->prefix, prefix_addr, sizeof (ip6_address_t));

      /* initialize default values */
      prefix->adv_on_link_flag = 1;	/* L bit set */
      prefix->adv_autonomous_flag = 1;	/* A bit set */
      prefix->adv_valid_lifetime_in_secs = DEF_ADV_VALID_LIFETIME;
      prefix->adv_pref_lifetime_in_secs = DEF_ADV_PREF_LIFETIME;
      prefix->enabled = 1;
      prefix->decrement_lifetime_flag = 1;
      prefix->deprecated_prefix_flag = 1;

      if (off_link == 0)
	{
	  /* FIXME - Should the DP do this or the CP ? */
	  /* insert prefix into routing table as a connected prefix */
	}

      if (use_default)
	goto restart;
    }
  else
    {

      if (prefix->prefix_len != prefix_len)
	return VNET_API_ERROR_INVALID_VALUE_2;

      if (off_link != 0)
	{
	  /* FIXME - Should the DP do this or the CP ? */
	  /* remove from routing table if already there */
	}
    }

  if ((val_lifetime == ~0) || (pref_lifetime == ~0))
    {
      prefix->adv_valid_lifetime_in_secs = ~0;
      prefix->adv_pref_lifetime_in_secs = ~0;
      prefix->decrement_lifetime_flag = 0;
    }
  else
    {
      prefix->adv_valid_lifetime_in_secs = val_lifetime;;
      prefix->adv_pref_lifetime_in_secs = pref_lifetime;
    }

  /* copy  remaining */
  prefix->enabled = !(no_advertise != 0);
  prefix->adv_on_link_flag = !((off_link != 0) || (no_onlink != 0));
  prefix->adv_autonomous_flag = !(no_autoconfig != 0);

restart:
  /* restart */
  /* fill in the expiration times  */
  prefix->valid_lifetime_expires = now + prefix->adv_valid_lifetime_in_secs;
  prefix->pref_lifetime_expires = now + prefix->adv_pref_lifetime_in_secs;

  radv_info->initial_adverts_sent = radv_info->initial_adverts_count - 1;
  radv_info->next_multicast_time = vlib_time_now (vm);
  radv_info->last_multicast_time = vlib_time_now (vm);
  radv_info->last_radv_time = 0;

  return (0);
}

clib_error_t *
ip6_ra_cmd (vlib_main_t * vm,
	    unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u8 is_no = 0;
  u8 suppress = 0, managed = 0, other = 0;
  u8 suppress_ll_option = 0, send_unicast = 0, cease = 0;
  u8 use_lifetime = 0;
  u32 sw_if_index, ra_lifetime = 0, ra_initial_count =
    0, ra_initial_interval = 0;
  u32 ra_max_interval = 0, ra_min_interval = 0;

  unformat_input_t _line_input, *line_input = &_line_input;

  int add_radv_info = 1;
  ip6_address_t ip6_addr;
  u32 addr_len;


  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  /* get basic radv info for this interface */
  if (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {

      if (unformat_user (line_input,
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  if (!ip6_ra_get_eth_itf (sw_if_index))
	    {
	      error =
		clib_error_return (0, "Interface must be of ethernet type");
	      goto done;
	    }

	  if (!ip6_link_is_enabled (sw_if_index))
	    {
	      error = clib_error_return (0, "IP6 nt enabler interface %U'",
					 format_unformat_error, line_input);
	      goto done;
	    }
	}
      else
	{
	  error = clib_error_return (0, "invalid interface name %U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  /* get the rest of the command */
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "no"))
	is_no = 1;
      else if (unformat (line_input, "prefix %U/%d",
			 unformat_ip6_address, &ip6_addr, &addr_len))
	{
	  add_radv_info = 0;
	}
      else if (unformat (line_input, "ra-managed-config-flag"))
	{
	  managed = 1;
	}
      else if (unformat (line_input, "ra-other-config-flag"))
	{
	  other = 1;
	}
      else if (unformat (line_input, "ra-suppress") ||
	       unformat (line_input, "ra-surpress"))
	{
	  suppress = 1;
	}
      else if (unformat (line_input, "ra-suppress-link-layer") ||
	       unformat (line_input, "ra-surpress-link-layer"))
	{
	  suppress_ll_option = 1;
	}
      else if (unformat (line_input, "ra-send-unicast"))
	{
	  send_unicast = 1;
	}
      else if (unformat (line_input, "ra-lifetime"))
	{
	  if (!unformat (line_input, "%d", &ra_lifetime))
	    {
	      error = unformat_parse_error (line_input);
	      goto done;
	    }
	  use_lifetime = 1;
	}
      else if (unformat (line_input, "ra-initial"))
	{
	  if (!unformat
	      (line_input, "%d %d", &ra_initial_count, &ra_initial_interval))
	    {
	      error = unformat_parse_error (line_input);
	      goto done;
	    }
	}
      else if (unformat (line_input, "ra-interval"))
	{
	  if (!unformat (line_input, "%d", &ra_max_interval))
	    {
	      error = unformat_parse_error (line_input);
	      goto done;
	    }

	  if (!unformat (line_input, "%d", &ra_min_interval))
	    ra_min_interval = 0;
	}
      else if (unformat (line_input, "ra-cease"))
	{
	  cease = 1;
	}
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (add_radv_info)
    {
      ip6_ra_config (vm, sw_if_index,
		     suppress, managed, other,
		     suppress_ll_option, send_unicast, cease,
		     use_lifetime, ra_lifetime,
		     ra_initial_count, ra_initial_interval,
		     ra_max_interval, ra_min_interval, is_no);
    }
  else
    {
      u32 valid_lifetime_in_secs = 0;
      u32 pref_lifetime_in_secs = 0;
      u8 use_prefix_default_values = 0;
      u8 no_advertise = 0;
      u8 off_link = 0;
      u8 no_autoconfig = 0;
      u8 no_onlink = 0;

      /* get the rest of the command */
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "default"))
	    {
	      use_prefix_default_values = 1;
	      break;
	    }
	  else if (unformat (line_input, "infinite"))
	    {
	      valid_lifetime_in_secs = ~0;
	      pref_lifetime_in_secs = ~0;
	      break;
	    }
	  else if (unformat (line_input, "%d %d", &valid_lifetime_in_secs,
			     &pref_lifetime_in_secs))
	    break;
	  else
	    break;
	}


      /* get the rest of the command */
      while (!use_prefix_default_values &&
	     unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "no-advertise"))
	    no_advertise = 1;
	  else if (unformat (line_input, "off-link"))
	    off_link = 1;
	  else if (unformat (line_input, "no-autoconfig"))
	    no_autoconfig = 1;
	  else if (unformat (line_input, "no-onlink"))
	    no_onlink = 1;
	  else
	    {
	      error = unformat_parse_error (line_input);
	      goto done;
	    }
	}

      ip6_ra_prefix (vm, sw_if_index,
		     &ip6_addr, addr_len,
		     use_prefix_default_values,
		     valid_lifetime_in_secs,
		     pref_lifetime_in_secs,
		     no_advertise, off_link, no_autoconfig, no_onlink, is_no);
    }

done:
  unformat_free (line_input);

  return error;
}

static u8 *
format_ip6_ra (u8 * s, va_list * args)
{
  index_t rai = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);
  ip6_radv_prefix_t *p;
  ip6_ra_t *radv_info;

  radv_info = pool_elt_at_index (ip6_ra_pool, rai);

  s = format (s, "%UAdvertised Prefixes:\n", format_white_space, indent);

  indent += 2;

  /* *INDENT-OFF* */
  pool_foreach (p, radv_info->adv_prefixes_pool)
   {
    s = format (s, "%Uprefix %U, length %d\n",
                format_white_space, indent+2,
                format_ip6_address, &p->prefix, p->prefix_len);
  }
  /* *INDENT-ON* */

  s = format (s, "%UMTU is %d\n",
	      format_white_space, indent, radv_info->adv_link_mtu);
  s = format (s, "%UICMP error messages are unlimited\n",
	      format_white_space, indent);
  s = format (s, "%UICMP redirects are disabled\n",
	      format_white_space, indent);
  s = format (s, "%UICMP unreachables are not sent\n",
	      format_white_space, indent);
  s = format (s, "%UND DAD is disabled\n", format_white_space, indent);
  //s = format (s, "%UND reachable time is %d milliseconds\n",);
  s = format (s, "%UND advertised reachable time is %d\n",
	      format_white_space, indent,
	      radv_info->adv_neighbor_reachable_time_in_msec);
  s = format (s,
	      "%UND advertised retransmit interval is %d (msec)\n",
	      format_white_space, indent,
	      radv_info->
	      adv_time_in_msec_between_retransmitted_neighbor_solicitations);
  s =
    format (s,
	    "%UND router advertisements are sent every %0.1f seconds (min interval is %0.1f)\n",
	    format_white_space, indent, radv_info->max_radv_interval,
	    radv_info->min_radv_interval);
  s =
    format (s, "%UND router advertisements live for %d seconds\n",
	    format_white_space, indent,
	    radv_info->adv_router_lifetime_in_sec);
  s =
    format (s, "%UHosts %s stateless autoconfig for addresses\n",
	    format_white_space, indent,
	    (radv_info->adv_managed_flag) ? "use" : " don't use");
  s =
    format (s, "%UND router advertisements sent %d\n", format_white_space,
	    indent, radv_info->n_advertisements_sent);
  s =
    format (s, "%UND router solicitations received %d\n", format_white_space,
	    indent, radv_info->n_solicitations_rcvd);
  s =
    format (s, "%UND router solicitations dropped %d\n", format_white_space,
	    indent, radv_info->n_solicitations_dropped);

  return (s);
}

/*?
 * This command is used to configure the neighbor discovery
 * parameters on a given interface. Use the '<em>show ip6 interface</em>'
 * command to display some of the current neighbor discovery parameters
 * on a given interface. This command has three formats:
 *
 *
 * <b>Format 1 - Router Advertisement Options:</b> (Only one can be entered in
 * a single command)
 *
 * @clistart
 * ip6 nd <interface> [no] [ra-managed-config-flag] |
 *   [ra-other-config-flag] | [ra-suppress] | [ra-suppress-link-layer] |
 *   [ra-send-unicast] | [ra-lifetime <lifetime>] |
 *   [ra-initial <cnt> <interval>] |
 *   [ra-interval <max-interval> [<min-interval>]] | [ra-cease]
 * @cliend
 *
 * Where:
 *
 * <em>[no] ra-managed-config-flag</em> - Advertises in ICMPv6
 * router-advertisement messages to use stateful address
 * auto-configuration to obtain address information (sets the M-bit).
 * Default is the M-bit is not set and the '<em>no</em>' option
 * returns it to this default state.
 *
 * <em>[no] ra-other-config-flag</em> - Indicates in ICMPv6
 * router-advertisement messages that hosts use stateful auto
 * configuration to obtain nonaddress related information (sets
 * the O-bit). Default is the O-bit is not set and the '<em>no</em>'
 * option returns it to this default state.
 *
 * <em>[no] ra-suppress</em> - Disables sending ICMPv6 router-advertisement
 * messages. The '<em>no</em>' option implies to enable sending ICMPv6
 * router-advertisement messages.
 *
 * <em>[no] ra-suppress-link-layer</em> - Indicates not to include the
 * optional source link-layer address in the ICMPv6 router-advertisement
 * messages. Default is to include the optional source link-layer address
 * and the '<em>no</em>' option returns it to this default state.
 *
 * <em>[no] ra-send-unicast</em> - Use the source address of the
 * router-solicitation message if available. The default is to use
 * multicast address of all nodes, and the '<em>no</em>' option returns
 * it to this default state.
 *
 * <em>[no] ra-lifetime <lifetime></em> - Advertises the lifetime of a
 * default router in ICMPv6 router-advertisement messages. The range is
 * from 0 to 9000 seconds. '<em><lifetime></em>' must be greater than
 * '<em><max-interval></em>'. The default value is 600 seconds and the
 * '<em>no</em>' option returns it to this default value.
 *
 * <em>[no] ra-initial <cnt> <interval></em> - Number of initial ICMPv6
 * router-advertisement messages sent and the interval between each
 * message. Range for count is 1 - 3 and default is 3. Range for interval
 * is 1 to 16 seconds, and default is 16 seconds. The '<em>no</em>' option
 * returns both to their default value.
 *
 * <em>[no] ra-interval <max-interval> [<min-interval>]</em> - Configures the
 * interval between sending ICMPv6 router-advertisement messages. The
 * range for max-interval is from 4 to 200 seconds. min-interval can not
 * be more than 75% of max-interval. If not set, min-interval will be
 * set to 75% of max-interval. The range for min-interval is from 3 to
 * 150 seconds.  The '<em>no</em>' option returns both to their default
 * value.
 *
 * <em>[no] ra-cease</em> - Cease sending ICMPv6 router-advertisement messages.
 * The '<em>no</em>' options implies to start (or restart) sending
 * ICMPv6 router-advertisement messages.
 *
 *
 * <b>Format 2 - Prefix Options:</b>
 *
 * @clistart
 * ip6 nd <interface> [no] prefix <ip6-address>/<width>
 *   [<valid-lifetime> <pref-lifetime> | infinite] [no-advertise] [off-link]
 *   [no-autoconfig] [no-onlink]
 * @cliend
 *
 * Where:
 *
 * <em>no</em> - All additional flags are ignored and the prefix is deleted.
 *
 * <em><valid-lifetime> <pref-lifetime></em> - '<em><valid-lifetime></em>' is
 * the length of time in seconds during what the prefix is valid for the
 * purpose of on-link determination. Range is 7203 to 2592000 seconds and
 * default is 2592000 seconds (30 days). '<em><pref-lifetime></em>' is the
 * preferred-lifetime and is the length of time in seconds during what
 * addresses generated from the prefix remain preferred. Range is 0 to 604800
 * seconds and default is 604800 seconds (7 days).
 *
 * <em>infinite</em> - Both '<em><valid-lifetime></em>' and
 * '<em><pref-lifetime></em>' are infinite, no timeout.
 *
 * <em>no-advertise</em> - Do not send full router address in prefix
 * advertisement. Default is to advertise (i.e. - This flag is off by default).
 *
 * <em>off-link</em> - Prefix is off-link, clear L-bit in packet. Default is
 * on-link (i.e. - This flag is off and L-bit in packet is set by default
 * and this prefix can be used for on-link determination). '<em>no-onlink</em>'
 * also controls the L-bit.
 *
 * <em>no-autoconfig</em> - Do not use prefix for autoconfiguration, clear
 * A-bit in packet. Default is autoconfig (i.e. - This flag is off and A-bit
 * in packet is set by default.
 *
 * <em>no-onlink</em> - Do not use prefix for onlink determination, clear L-bit
 * in packet. Default is on-link (i.e. - This flag is off and L-bit in packet
 * is set by default and this prefix can be used for on-link determination).
 * '<em>off-link</em>' also controls the L-bit.
 *
 *
 * <b>Format 3: - Default of Prefix:</b>
 *
 * @cliexcmd{ip6 nd <interface> [no] prefix <ip6-address>/<width> default}
 *
 * When a new prefix is added (or existing one is being overwritten)
 * <em>default</em> uses default values for the prefix. If <em>no</em> is
 * used, the <em>default</em> is ignored and the prefix is deleted.
 *
 *
 * @cliexpar
 * Example of how set a router advertisement option:
 * @cliexcmd{ip6 nd GigabitEthernet2/0/0 ra-interval 100 20}
 * Example of how to add a prefix:
 * @cliexcmd{ip6 nd GigabitEthernet2/0/0 prefix fe80::fe:28ff:fe9c:75b3/64
 * infinite no-advertise}
 * Example of how to delete a prefix:
 * @cliexcmd{ip6 nd GigabitEthernet2/0/0 no prefix fe80::fe:28ff:fe9c:75b3/64}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_nd_command, static) =
{
  .path = "ip6 nd",
  .short_help = "ip6 nd <interface> ...",
  .function = ip6_ra_cmd,
};
/* *INDENT-ON* */

/**
 * VFT for registering as a delegate to an IP6 link
 */
const static ip6_link_delegate_vft_t ip6_ra_delegate_vft = {
  .ildv_disable = ip6_ra_delegate_disable,
  .ildv_enable = ip6_ra_link_enable,
  .ildv_format = format_ip6_ra,
};

static clib_error_t *
ip6_ra_init (vlib_main_t * vm)
{
  vlib_call_init_function (vm, icmp6_init);

  icmp6_register_type (vm, ICMP6_router_solicitation,
		       ip6_icmp_router_solicitation_node.index);
  icmp6_register_type (vm, ICMP6_router_advertisement,
		       ip6_icmp_router_advertisement_node.index);

  ip6_ra_delegate_id = ip6_link_delegate_register (&ip6_ra_delegate_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (ip6_ra_init) =
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
