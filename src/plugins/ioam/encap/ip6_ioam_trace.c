/*
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vpp/app/version.h>

#include <vnet/ip/ip6.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/ip/ip6_hop_by_hop_packet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>
#include <vnet/plugin/plugin.h>

#include <ioam/lib-trace/trace_util.h>
#include <ioam/lib-trace/trace_config.h>
#include <ioam/encap/ip6_ioam_trace.h>
#include <ioam/udp-ping/udp_ping.h>
#include <ioam/udp-ping/udp_ping_packet.h>
#include <ioam/udp-ping/udp_ping_util.h>

// For transit delay
#include <timestamp/timestamp.h>
// For queue depth
#include <linux/if_packet.h>
#include <vnet/devices/af_packet/af_packet.h>
/* Timestamp precision multipliers for seconds, milliseconds, microseconds
 * and nanoseconds respectively.
 */
static f64 trace_tsp_mul[IOAM_TSP_OPTION_SIZE] = { 1, 1e3, 1e6, 1e9 };

typedef union
{
  u64 as_u64;
  u32 as_u32[2];
} time_u64_t;

extern ip6_hop_by_hop_ioam_main_t ip6_hop_by_hop_ioam_main;
extern ip6_main_t ip6_main;

#define foreach_ip6_hop_by_hop_ioam_trace_stats                                \
  _(PROCESSED, "Pkts with ip6 hop-by-hop trace options")                        \
  _(PROFILE_MISS, "Pkts with ip6 hop-by-hop trace options but no profile set") \
  _(UPDATED, "Pkts with trace updated")                                        \
  _(FULL, "Pkts with trace options but no space")                              \
  _(LOOPBACK, "Pkts with trace options Loopback")                              \
  _(LOOPBACK_REPLY, "Pkts with trace options Loopback Reply")

static char *ip6_hop_by_hop_ioam_trace_stats_strings[] = {
#define _(sym,string) string,
  foreach_ip6_hop_by_hop_ioam_trace_stats
#undef _
};

typedef enum
{
#define _(sym,str) IP6_IOAM_TRACE_##sym,
  foreach_ip6_hop_by_hop_ioam_trace_stats
#undef _
    IP6_IOAM_TRACE_N_STATS,
} ip6_ioam_trace_stats_t;


typedef struct
{
  /* stats */
  u64 counters[ARRAY_LEN (ip6_hop_by_hop_ioam_trace_stats_strings)];

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} ip6_hop_by_hop_ioam_trace_main_t;

ip6_hop_by_hop_ioam_trace_main_t ip6_hop_by_hop_ioam_trace_main;

always_inline void
ip6_ioam_trace_stats_increment_counter (u32 counter_index, u64 increment)
{
  ip6_hop_by_hop_ioam_trace_main_t *hm = &ip6_hop_by_hop_ioam_trace_main;

  hm->counters[counter_index] += increment;
}

static u8 *
format_ioam_data_list_element (u8 * s, va_list * args)
{
  u32 *elt = va_arg (*args, u32 *);
  u32 *trace_type_p = va_arg (*args, u32 *);
  u32 trace_type = *trace_type_p;

  if (trace_type & IOAM_BIT_TTL_NODEID_SHORT)
    {
      u32 ttl_node_id_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, ", ttl: 0x%x, node id short: 0x%x",
		  ttl_node_id_host_byte_order >> 24,
		  ttl_node_id_host_byte_order & IOAM_EMPTY_FIELD_U24);

      elt++;
    }
  if (trace_type & IOAM_BIT_ING_EGR_INT_SHORT)
    {
      u32 ingress_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, ", ingress sw: %d, egress sw: %d",
		  ingress_host_byte_order >> 16,
		  ingress_host_byte_order & IOAM_EMPTY_FIELD_U16);
      elt++;
    }
  if (trace_type & IOAM_BIT_TIMESTAMP_SEC)
    {
      u32 ts_in_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, ", timestamp (s): 0x%x", ts_in_host_byte_order);
      elt++;
    }

  if (trace_type & IOAM_BIT_TIMESTAMP_SUB_SEC)
    {
      u32 ts_sub_in_host_byte_order = clib_net_to_host_u32 (*elt);
      s =
	format (s, ", timestamp (sub-sec): 0x%x", ts_sub_in_host_byte_order);
      elt++;
    }

  if (trace_type & IOAM_BIT_TRANSIT_DELAY)
    {
      u32 transit_delay_in_host_byte_order = clib_net_to_host_u32 (*elt);
      s =
	format (s, ", transit delay (ns): 0x%x",
		transit_delay_in_host_byte_order);
      elt++;
    }

  if (trace_type & IOAM_BIT_APPDATA_SHORT_DATA)
    {
      u32 appdata_in_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, ", appdata: 0x%x", appdata_in_host_byte_order);
      elt++;
    }

  if (trace_type & IOAM_BIT_QUEUE_DEPTH)
    {
      u32 queue_in_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, ", queue depth: 0x%x", queue_in_host_byte_order);
      elt++;
    }

  if (trace_type & IOAM_BIT_CHECKSUM_COMPLEMENT)
    {
      u32 cc_in_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, ", checksum complement: 0x%x", cc_in_host_byte_order);
      elt++;
    }

  if (trace_type & IOAM_BIT_TTL_NODEID_WIDE)
    {
      u64 *ttl_node_id_p = (u64 *) elt;
      u64 ttl_node_id = clib_net_to_host_u64 (*ttl_node_id_p);
      elt += 2;

      s = format (s, ", ttl: 0x%x, node id wide: 0x%Lx",
		  ttl_node_id >> 56, (ttl_node_id & IOAM_EMPTY_FIELD_U56));

    }

  if (trace_type & IOAM_BIT_ING_EGR_INT_WIDE)
    {
      u32 ingress_wide_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, ", ingress hw: %d", ingress_wide_host_byte_order);
      elt++;

      u32 egress_wide_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, ", egress hw: %d", egress_wide_host_byte_order);
      elt++;
    }

  if (trace_type & IOAM_BIT_APPDATA_WIDE_DATA)
    {
      u64 *app_data_wide_host_byte_order_p = (u64 *) elt;
      u64 app_data_wide_host_byte_order =
	clib_net_to_host_u64 (*app_data_wide_host_byte_order_p);
      s = format (s, ", appdata wide: 0x%x", app_data_wide_host_byte_order);
      elt += 2;
    }

  if (trace_type & IOAM_BIT_BUFFER_OCCUPANCY)
    {
      u32 buffer_occ_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, ", buffers available: %d", buffer_occ_host_byte_order);
      elt++;
    }

  if (trace_type & IOAM_BIT_VAR_LEN_OP_ST_SNSH)
    {
      u32 opaque_len_id_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, ", opaque len: %d , opaque id: 0x%x",
		  IOAM_GET_OPAQUE_LEN (opaque_len_id_host_byte_order),
		  IOAM_OPAQUE_SCHEMEID_MASK & opaque_len_id_host_byte_order);
      elt++;
    }
  return s;
}

int
ip6_ioam_trace_get_sizeof_handler (u32 * result)
{
  u32 size = 0;
  u32 trace_data_size = 0;
  trace_profile *profile = NULL;

  *result = 0;

  profile = trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      ip6_ioam_trace_stats_increment_counter (IP6_IOAM_TRACE_PROFILE_MISS, 1);
      return (-1);
    }

  trace_data_size = fetch_trace_data_size (profile);
  if (PREDICT_FALSE (trace_data_size == 0))
    {
      return VNET_API_ERROR_INVALID_VALUE;
    }

  if (PREDICT_FALSE (profile->num_elts * trace_data_size > 254))
    {
      return VNET_API_ERROR_INVALID_VALUE;
    }
  size +=
    sizeof (ioam_trace_option_t) + (profile->num_elts * trace_data_size);
  *result = size;

  return 0;
}

int
ip6_hop_by_hop_ioam_trace_rewrite_handler (u8 * rewrite_string,
					   u8 * rewrite_size)
{
  ioam_trace_option_t *trace_option = NULL;
  u32 trace_data_size = 0;
  u8 trace_option_elts = 0;
  trace_profile *profile = NULL;

  profile = trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      ip6_ioam_trace_stats_increment_counter (IP6_IOAM_TRACE_PROFILE_MISS, 1);
      return (-1);
    }

  if (PREDICT_FALSE (!rewrite_string))
    {
      return -1;
    }

  trace_option_elts = profile->num_elts;
  trace_data_size = fetch_trace_data_size (profile);
  trace_option = (ioam_trace_option_t *) rewrite_string;

  trace_option->hdr.type =
    HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST |
    HBH_OPTION_TYPE_DATA_CHANGE_ENROUTE;
  // LENGTH
  trace_option->hdr.length = sizeof (ioam_trace_hdr_t) + (trace_option_elts * trace_data_size) + 2;	/* ip6_hop_by_hop_option_t: reserved and ioam_type */
  trace_option->hdr.ioam_type = profile->option_type;
  // ioam_trace_hdr_t things
  trace_option->trace_hdr.namespace_id =
    clib_host_to_net_u16 (profile->namespace_id);
  u16 node_len = trace_data_size >> 2;	// In 4-octets
  if (IOAM_GET_OPAQUE_LEN (profile->opaque.len_schemeid))
    {
      node_len += IOAM_GET_OPAQUE_LEN (profile->opaque.len_schemeid);	// Should already be in 4 octets
    }
  u16 nlfrl = IOAM_SET_NODE_LEN (node_len);
  nlfrl |= (IOAM_REMAIN_LEN_MASK & trace_option_elts);
  trace_option->trace_hdr.node_len_flags_remaining_len =
    clib_host_to_net_u16 (nlfrl);
  trace_option->trace_hdr.trace_type =
    IOAM_SET_TRACETYPE (profile->trace_type);
  // LENGTH
  *rewrite_size =
    sizeof (ioam_trace_option_t) + (trace_option_elts * trace_data_size);
  return 0;
}

always_inline void
ip6_hbh_ioam_loopback_handler (vlib_buffer_t * b, ip6_header_t * ip,
			       ioam_trace_option_t * trace)
{
  u32 buf_index;
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  vlib_buffer_t *b0;
  vlib_frame_t *nf = 0;
  u32 *to_next;
  vlib_node_t *next_node;
  ip6_header_t *ip6;
  ip6_hop_by_hop_header_t *hbh;
  ioam_trace_option_t *opt;
  udp_ping_t *udp;

  b0 = vlib_buffer_copy (hm->vlib_main, b);
  if (b0 == NULL)
    return;

  buf_index = vlib_get_buffer_index (hm->vlib_main, b0);
  next_node = vlib_get_node_by_name (hm->vlib_main, (u8 *) "ip6-lookup");
  nf = vlib_get_frame_to_node (hm->vlib_main, next_node->index);
  nf->n_vectors = 0;
  to_next = vlib_frame_vector_args (nf);

  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;

  ip6 = vlib_buffer_get_current (b0);
  hbh = (ip6_hop_by_hop_header_t *) (ip6 + 1);
  opt =
    (ioam_trace_option_t *) ip6_hbh_get_option (hbh,
						HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST);

  udp = (udp_ping_t *) ((u8 *) hbh + ((hbh->length + 1) << 3));
  udp_ping_create_reply_from_probe_ip6 (ip6, hbh, udp);
  ip6_hbh_ioam_trace_set_flag_bit (opt, IOAM_BIT_FLAG_LOOPBACK_REPLY);

  *to_next = buf_index;
  nf->n_vectors++;
  to_next++;

  vlib_put_frame_to_node (hm->vlib_main, next_node->index, nf);
  ip6_ioam_trace_stats_increment_counter (IP6_IOAM_TRACE_LOOPBACK, 1);
}

int
ip6_hbh_ioam_trace_data_list_handler (vlib_buffer_t * b, ip6_header_t * ip,
				      ip6_hop_by_hop_option_t * opt)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;
  u8 elt_index = 0;
  ioam_trace_option_t *trace = (ioam_trace_option_t *) opt;
  u32 adj_index = vnet_buffer (b)->ip.adj_index[VLIB_TX];
  ip_adjacency_t *adj = adj_get (adj_index);
  u32 *elt;
  int rv = 0;
  trace_profile *profile = NULL;

  profile = trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      ip6_ioam_trace_stats_increment_counter (IP6_IOAM_TRACE_PROFILE_MISS, 1);
      return (-1);
    }

  // Ignore if namespace ID is different
  if (clib_net_to_host_u16 (trace->trace_hdr.namespace_id) !=
      profile->namespace_id)
    {
      return rv;
    }

  /* Don't trace loopback reply packets */
  u16 nlfrl_host =
    clib_net_to_host_u16 (trace->trace_hdr.node_len_flags_remaining_len);
  if ((IOAM_FLAGS_MASK & nlfrl_host) & IOAM_BIT_FLAG_LOOPBACK_REPLY)
    {
      ip6_ioam_trace_stats_increment_counter (IP6_IOAM_TRACE_LOOPBACK_REPLY,
					      1);
      return rv;
    }

  u32 data_list_elts_left = IOAM_REMAIN_LEN_MASK & nlfrl_host;

  if (PREDICT_TRUE (data_list_elts_left))
    {
      data_list_elts_left--;
      nlfrl_host &= (~IOAM_REMAIN_LEN_MASK);
      nlfrl_host |= data_list_elts_left;
      trace->trace_hdr.node_len_flags_remaining_len =
	clib_host_to_net_u16 (nlfrl_host);
      /* fetch_trace_data_size returns in bytes. Convert it to 4-bytes
       * to skip to this node's location.
       */
      elt_index = data_list_elts_left * fetch_trace_data_size (profile) / 4;
      elt = &trace->trace_hdr.data_list[elt_index];

      // START writing the telemtry info
      u32 trace_type = IOAM_GET_TRACETYPE (trace->trace_hdr.trace_type);

      time_u64_t time_u64;
      // reports TTL and user defined node-id-short, different from -wide
      if (trace_type & IOAM_BIT_TTL_NODEID_SHORT)
	{
	  u32 node_id = profile->node_id_short;
	  if (!node_id)
	    {
	      node_id = IOAM_EMPTY_FIELD_U24;
	    }
	  *elt = clib_host_to_net_u32 ((ip->hop_limit << 24) | node_id);
	  elt++;
	}
      // reports software interface index
      if (trace_type & IOAM_BIT_ING_EGR_INT_SHORT)
	{
	  u32 rxid = (vnet_buffer (b)->sw_if_index[VLIB_RX] & 0xFFFF);
	  u32 txid = (adj->rewrite_header.sw_if_index & 0xFFFF);
	  if (!rxid)
	    {
	      rxid = IOAM_EMPTY_FIELD_U16;
	    }
	  if (!txid)
	    {
	      txid = IOAM_EMPTY_FIELD_U16;
	    }
	  *elt = clib_host_to_net_u32 ((rxid << 16) | txid);
	  elt++;
	}
      // time stamp in secs
      if (trace_type & IOAM_BIT_TIMESTAMP_SEC)
	{
	  /* Send least significant 32 bits */
	  f64 time_f64 =
	    (f64) (((f64) hm->unix_time_0) +
		   (vlib_time_now (hm->vlib_main) - hm->vlib_time_0));
	  time_u64.as_u64 = time_f64 * trace_tsp_mul[IOAM_TSP_SECONDS];
	  if (!time_u64.as_u32[0])
	    {
	      time_u64.as_u32[0] = IOAM_EMPTY_FIELD_U32;
	    }
	  *elt = clib_host_to_net_u32 (time_u64.as_u32[0]);
	  elt++;
	}
      // time stamp in user defined ts-format
      if (trace_type & IOAM_BIT_TIMESTAMP_SUB_SEC)
	{
	  /* Send least significant 32 bits */
	  f64 time_sub_f64 =
	    (f64) (((f64) hm->unix_time_0) +
		   (vlib_time_now (hm->vlib_main) - hm->vlib_time_0));
	  time_u64.as_u64 = time_sub_f64 * trace_tsp_mul[profile->ts_format];
	  if (!time_u64.as_u32[0])
	    {
	      time_u64.as_u32[0] = IOAM_EMPTY_FIELD_U32;
	    }
	  *elt = clib_host_to_net_u32 (time_u64.as_u32[0]);
	  elt++;
	}
      // reports hop delay from ingress (uses timestamp plugin) to here, though
      // not exactly the 'egress' time, but close to it and provides good insight in nano secs
      if (trace_type & IOAM_BIT_TRANSIT_DELAY)
	{
	  /* Ingress timestamp meta in buffer2->unused data */
	  timestamp_meta_t *time_meta = (void *) &vnet_buffer2 (b)->unused[0];
	  // Copy the ptr to the location it needs to be stored in the packet, egress timestamp node will handle the rest
	  time_meta->ptr_to_ioam_transit_delay = elt;
	  // could mean CLIB_UNIX not defined, always added in case it's not possible to add stamp
	  *elt = clib_host_to_net_u32 (IOAM_EMPTY_FIELD_U32);
	  elt++;
	}
      // user defined app data, different from app-data-wide
      if (trace_type & IOAM_BIT_APPDATA_SHORT_DATA)
	{
	  *elt = clib_host_to_net_u32 (profile->app_data_short);
	  elt++;
	}
      /*
       * Reporting is dependent on what device is selected, see device_driver_info.c
       */
      if (trace_type & IOAM_BIT_QUEUE_DEPTH)
	{
	  u32 depth = IOAM_EMPTY_FIELD_U32;
	  if (profile->queue_depth_type & QUEUE_DEPTH_AF_PACKET)
	    {
	      // Get TX hardware interface index
	      u32 txid = adj->rewrite_header.sw_if_index;
	      txid =
		(vnet_get_sup_hw_interface
		 (hm->vnet_main, txid))->hw_if_index;
	      af_packet_main_t *am = &af_packet_main;
	      /* Maybe there's a better way to obtain apif from hw_if_index */
	      vnet_hw_interface_t *hw =
		vnet_get_hw_interface (hm->vnet_main, txid);
	      af_packet_if_t *apif =
		pool_elt_at_index (am->interfaces, hw->dev_instance);
	      u8 *tx_block_start = apif->tx_ring;
	      struct tpacket2_hdr *tph_tx =
		(struct tpacket2_hdr *) tx_block_start;
	      u32 frame_size = apif->tx_req->tp_frame_size;
	      u32 frame_num = apif->tx_req->tp_frame_nr;
	      do
		{
		  if (tph_tx->tp_status == TP_STATUS_AVAILABLE)
		    {
		      depth++;
		    }
		  tph_tx =
		    (struct tpacket2_hdr *) (((u8 *) tph_tx) + frame_size);
		}
	      while (--frame_num);
	    }
	  // Trick here is similar to transit delay except, the queue depth is saved in unused[7]
	  else if (profile->queue_depth_type & QUEUE_DEPTH_DPDK)
	    {
	      u32 *queueSize_queueDepth = &vnet_buffer2 (b)->unused[7];
	      // Upper bytes is the total queue size, we only intrested in lower
	      depth =
		0x0000FFFF & clib_net_to_host_u32 (*queueSize_queueDepth);
	    }
	  *elt = clib_host_to_net_u32 (depth);
	  elt++;
	}
      /* TODO */
      if (trace_type & IOAM_BIT_CHECKSUM_COMPLEMENT)
	{
	  *elt = IOAM_EMPTY_FIELD_U32;
	  elt++;
	}
      // reports TTL and user defined node id (different from node-id-short)
      if (trace_type & IOAM_BIT_TTL_NODEID_WIDE)
	{
	  u64 *elt_tmp = (u64 *) elt;
	  u64 node_id = profile->node_id_wide;
	  if (!node_id)
	    {
	      node_id = IOAM_EMPTY_FIELD_U56;
	    }
	  *elt_tmp =
	    clib_host_to_net_u64 ((((u64) ip->hop_limit) << 56) | node_id);
	  elt += 2;
	}
      // reports hardware interface index
      if (trace_type & IOAM_BIT_ING_EGR_INT_WIDE)
	{
	  ip6_hop_by_hop_ioam_trace_main_t *hm =
	    &ip6_hop_by_hop_ioam_trace_main;
	  u32 rxid = vnet_buffer (b)->sw_if_index[VLIB_RX];
	  u32 txid = adj->rewrite_header.sw_if_index;
	  rxid =
	    (vnet_get_sup_hw_interface (hm->vnet_main, rxid))->hw_if_index;
	  txid =
	    (vnet_get_sup_hw_interface (hm->vnet_main, txid))->hw_if_index;
	  if (!rxid)
	    {
	      rxid = IOAM_EMPTY_FIELD_U32;
	    }
	  if (!txid)
	    {
	      txid = IOAM_EMPTY_FIELD_U32;
	    }
	  *elt = clib_host_to_net_u32 (rxid);
	  elt++;
	  *elt = clib_host_to_net_u32 (txid);
	  elt++;
	}
      // user defined app data, different from -short
      if (trace_type & IOAM_BIT_APPDATA_WIDE_DATA)
	{
	  u64 *elt_tmp = (u64 *) elt;
	  *elt_tmp = clib_host_to_net_u64 (profile->app_data_wide);
	  elt += 2;
	}
      // reports the number of buffer available in this packet's mem pool
      if (trace_type & IOAM_BIT_BUFFER_OCCUPANCY)
	{
	  vlib_buffer_pool_t *bp =
	    vlib_get_buffer_pool (vlib_get_main (), b->buffer_pool_index);
	  u32 buff_avail = IOAM_EMPTY_FIELD_U32;
	  if (bp)
	    {
	      buff_avail = bp->n_avail;
	    }
	  *elt = clib_host_to_net_u32 (buff_avail);
	  elt++;
	}
      // user defined opaque data
      if (trace_type & IOAM_BIT_VAR_LEN_OP_ST_SNSH)
	{
	  u32 schema =
	    profile->opaque.len_schemeid & IOAM_OPAQUE_SCHEMEID_MASK;
	  u32 len = IOAM_GET_OPAQUE_LEN (profile->opaque.len_schemeid);
	  opaque_scheme_t *opq = (opaque_scheme_t *) elt;
	  if (!schema || !len)
	    {
	      opq->len_schemeid = IOAM_EMPTY_FIELD_U32;
	    }
	  else
	    {
	      opq->len_schemeid =
		clib_host_to_net_u32 (profile->opaque.len_schemeid);
	      // Endianess taken care in trace_profile_create
	      clib_memcpy_fast (opq->data, profile->opaque.data, len << 2);
	      // (1+) for opaque header and len is in 4 octet multipes
	      elt += 1 + len;
	    }
	}

      if (PREDICT_FALSE
	  ((nlfrl_host & IOAM_FLAGS_MASK) & IOAM_BIT_FLAG_LOOPBACK))
	{
	  /* if loopback flag set then copy the packet
	   * and send it back to source */
	  ip6_hbh_ioam_loopback_handler (b, ip, trace);
	}

      ip6_ioam_trace_stats_increment_counter (IP6_IOAM_TRACE_UPDATED, 1);
    }
  else
    {
      ip6_ioam_trace_stats_increment_counter (IP6_IOAM_TRACE_FULL, 1);
    }
  return (rv);
}

u8 *
ip6_hbh_ioam_trace_data_list_trace_handler (u8 * s,
					    ip6_hop_by_hop_option_t * opt)
{
  ioam_trace_option_t *trace;
  u8 trace_data_size_in_words = 0;
  u32 *elt;
  int elt_index = 0;

  trace = (ioam_trace_option_t *) opt;

  s =
    format (s,
	    " namespace id %d, trace type 0x%x, %d elts left, %d bytes per node\n",
	    clib_net_to_host_u16 (trace->trace_hdr.namespace_id),
	    IOAM_GET_TRACETYPE (trace->trace_hdr.trace_type),
	    clib_net_to_host_u16 (trace->
				  trace_hdr.node_len_flags_remaining_len) &
	    IOAM_REMAIN_LEN_MASK,
	    IOAM_GET_NODE_LEN (clib_net_to_host_u16
			       (trace->
				trace_hdr.node_len_flags_remaining_len)) <<
	    2);
  trace_data_size_in_words =
    fetch_trace_data_size (trace_profile_find ()) / 4;
  elt = &trace->trace_hdr.data_list[0];
  u32 trace_type = IOAM_GET_TRACETYPE (trace->trace_hdr.trace_type);
  while ((u8 *) elt < ((u8 *) (&trace->trace_hdr.data_list[0]) + trace->hdr.length - sizeof (ioam_trace_hdr_t) - 2))	/* ip6_hop_by_hop_option_t: reserved and ioam_type */
    {
      s =
	format (s, "    [%d]%U\n", elt_index, format_ioam_data_list_element,
		elt, &trace_type);
      elt_index++;
      elt += trace_data_size_in_words;
    }
  return (s);
}


static clib_error_t *
ip6_show_ioam_trace_cmd_fn (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  ip6_hop_by_hop_ioam_trace_main_t *hm = &ip6_hop_by_hop_ioam_trace_main;
  u8 *s = 0;
  int i = 0;

  for (i = 0; i < IP6_IOAM_TRACE_N_STATS; i++)
    {
      s =
	format (s, " %s - %lu\n", ip6_hop_by_hop_ioam_trace_stats_strings[i],
		hm->counters[i]);
    }

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_show_ioam_trace_cmd, static) = {
  .path = "show ioam trace",
  .short_help = "iOAM trace statistics",
  .function = ip6_show_ioam_trace_cmd_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Inbound Operations, Administration, and Maintenance (OAM)",
};
/* *INDENT-ON* */

static clib_error_t *
ip6_hop_by_hop_ioam_trace_init (vlib_main_t * vm)
{
  ip6_hop_by_hop_ioam_trace_main_t *hm = &ip6_hop_by_hop_ioam_trace_main;

  hm->vlib_main = vm;
  hm->vnet_main = vnet_get_main ();
  clib_memset (hm->counters, 0, sizeof (hm->counters));

  if (ip6_hbh_register_option
      (HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST,
       ip6_hbh_ioam_trace_data_list_handler,
       ip6_hbh_ioam_trace_data_list_trace_handler) < 0)
    return (clib_error_create
	    ("registration of HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST failed"));

  if (ip6_hbh_add_register_option (HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST,
				   sizeof (ioam_trace_option_t),
				   ip6_hop_by_hop_ioam_trace_rewrite_handler)
      < 0)
    return (clib_error_create
	    ("registration of HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST for rewrite failed"));

  return (0);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (ip6_hop_by_hop_ioam_trace_init) =
{
  .runs_after = VLIB_INITS ("ip_main_init", "ip6_lookup_init",
                            "ip6_hop_by_hop_ioam_init"),
};
/* *INDENT-ON* */

int
ip6_trace_profile_cleanup (void)
{
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  hm->options_size[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST] = 0;
  return 0;

}

int
ip6_trace_profile_setup (void)
{
  u32 trace_size = 0;
  ip6_hop_by_hop_ioam_main_t *hm = &ip6_hop_by_hop_ioam_main;

  trace_profile *profile = NULL;

  profile = trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      ip6_ioam_trace_stats_increment_counter (IP6_IOAM_TRACE_PROFILE_MISS, 1);
      return (-1);
    }

  if (ip6_ioam_trace_get_sizeof_handler (&trace_size) < 0)
    {
      return (-1);
    }
  // rewrite size for rewrite handler is set here
  // LENGTH
  hm->options_size[HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST] = trace_size;
  return (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
