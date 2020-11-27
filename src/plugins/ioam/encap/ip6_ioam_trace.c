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

/* Timestamp precision multipliers for seconds, milliseconds, microseconds
 * and nanoseconds respectively.
 */
static f64 trace_tsp_mul[4] = { 1, 1e3, 1e6, 1e9 };

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
  u8 *trace_type_p = va_arg (*args, u8 *);
  u8 trace_type = *trace_type_p;


  if (trace_type & BIT_TTL_NODEID)
    {
      u32 ttl_node_id_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, "ttl 0x%x node id 0x%x ",
		  ttl_node_id_host_byte_order >> 24,
		  ttl_node_id_host_byte_order & 0x00FFFFFF);

      elt++;
    }

  if (trace_type & BIT_ING_INTERFACE && trace_type & BIT_ING_INTERFACE)
    {
      u32 ingress_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, "ingress 0x%x egress 0x%x ",
		  ingress_host_byte_order >> 16,
		  ingress_host_byte_order & 0xFFFF);
      elt++;
    }

  if (trace_type & BIT_TIMESTAMP)
    {
      u32 ts_in_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, "ts 0x%x \n", ts_in_host_byte_order);
      elt++;
    }

  if (trace_type & BIT_APPDATA)
    {
      u32 appdata_in_host_byte_order = clib_net_to_host_u32 (*elt);
      s = format (s, "app 0x%x ", appdata_in_host_byte_order);
      elt++;
    }

  return s;
}


int
ip6_ioam_trace_get_sizeof_handler (u32 * result)
{
  u16 size = 0;
  u8 trace_data_size = 0;
  trace_profile *profile = NULL;

  *result = 0;

  profile = trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      ip6_ioam_trace_stats_increment_counter (IP6_IOAM_TRACE_PROFILE_MISS, 1);
      return (-1);
    }

  trace_data_size = fetch_trace_data_size (profile->trace_type);
  if (PREDICT_FALSE (trace_data_size == 0))
    return VNET_API_ERROR_INVALID_VALUE;

  if (PREDICT_FALSE (profile->num_elts * trace_data_size > 254))
    return VNET_API_ERROR_INVALID_VALUE;

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
  u8 trace_data_size = 0;
  u8 trace_option_elts = 0;
  trace_profile *profile = NULL;


  profile = trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      ip6_ioam_trace_stats_increment_counter (IP6_IOAM_TRACE_PROFILE_MISS, 1);
      return (-1);
    }

  if (PREDICT_FALSE (!rewrite_string))
    return -1;

  trace_option_elts = profile->num_elts;
  trace_data_size = fetch_trace_data_size (profile->trace_type);
  trace_option = (ioam_trace_option_t *) rewrite_string;
  trace_option->hdr.type = HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST |
    HBH_OPTION_TYPE_DATA_CHANGE_ENROUTE;
  trace_option->hdr.length = 2 /*ioam_trace_type,data_list_elts_left */  +
    trace_option_elts * trace_data_size;
  trace_option->trace_hdr.ioam_trace_type =
    profile->trace_type & TRACE_TYPE_MASK;
  trace_option->trace_hdr.data_list_elts_left = trace_option_elts;
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
  opt = (ioam_trace_option_t *)
    ip6_hbh_get_option (hbh, HBH_OPTION_TYPE_IOAM_TRACE_DATA_LIST);

  udp = (udp_ping_t *) ((u8 *) hbh + ((hbh->length + 1) << 3));
  udp_ping_create_reply_from_probe_ip6 (ip6, hbh, udp);
  ip6_hbh_ioam_trace_set_bit (opt, BIT_LOOPBACK_REPLY);

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
  u32 adj_index = vnet_buffer (b)->ip.adj_index;
  ip_adjacency_t *adj = adj_get (adj_index);
  time_u64_t time_u64;
  u32 *elt;
  int rv = 0;
  trace_profile *profile = NULL;


  profile = trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      ip6_ioam_trace_stats_increment_counter (IP6_IOAM_TRACE_PROFILE_MISS, 1);
      return (-1);
    }

  /* Don't trace loopback reply packets */
  if (trace->trace_hdr.ioam_trace_type & BIT_LOOPBACK_REPLY)
    {
      ip6_ioam_trace_stats_increment_counter (IP6_IOAM_TRACE_LOOPBACK_REPLY,
					      1);
      return rv;
    }

  time_u64.as_u64 = 0;

  if (PREDICT_TRUE (trace->trace_hdr.data_list_elts_left))
    {
      trace->trace_hdr.data_list_elts_left--;
      /* fetch_trace_data_size returns in bytes. Convert it to 4-bytes
       * to skip to this node's location.
       */
      elt_index =
	trace->trace_hdr.data_list_elts_left *
	fetch_trace_data_size (trace->trace_hdr.ioam_trace_type) / 4;
      elt = &trace->trace_hdr.elts[elt_index];
      if (trace->trace_hdr.ioam_trace_type & BIT_TTL_NODEID)
	{
	  *elt =
	    clib_host_to_net_u32 ((ip->hop_limit << 24) | profile->node_id);
	  elt++;
	}

      if (trace->trace_hdr.ioam_trace_type & BIT_ING_INTERFACE)
	{
	  *elt =
	    (vnet_buffer (b)->sw_if_index[VLIB_RX] & 0xFFFF) << 16 |
	    (adj->rewrite_header.sw_if_index & 0xFFFF);
	  *elt = clib_host_to_net_u32 (*elt);
	  elt++;
	}

      if (trace->trace_hdr.ioam_trace_type & BIT_TIMESTAMP)
	{
	  /* Send least significant 32 bits */
	  f64 time_f64 =
	    (f64) (((f64) hm->unix_time_0) +
		   (vlib_time_now (hm->vlib_main) - hm->vlib_time_0));

	  time_u64.as_u64 = time_f64 * trace_tsp_mul[profile->trace_tsp];
	  *elt = clib_host_to_net_u32 (time_u64.as_u32[0]);
	  elt++;
	}

      if (trace->trace_hdr.ioam_trace_type & BIT_APPDATA)
	{
	  /* $$$ set elt0->app_data */
	  *elt = clib_host_to_net_u32 (profile->app_data);
	  elt++;
	}


      if (PREDICT_FALSE (trace->trace_hdr.ioam_trace_type & BIT_LOOPBACK))
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
    format (s, "  Trace Type 0x%x , %d elts left\n",
	    trace->trace_hdr.ioam_trace_type,
	    trace->trace_hdr.data_list_elts_left);
  trace_data_size_in_words =
    fetch_trace_data_size (trace->trace_hdr.ioam_trace_type) / 4;
  elt = &trace->trace_hdr.elts[0];
  while ((u8 *) elt <
	 ((u8 *) (&trace->trace_hdr.elts[0]) + trace->hdr.length - 2
	  /* -2 accounts for ioam_trace_type,elts_left */ ))
    {
      s = format (s, "    [%d] %U\n", elt_index,
		  format_ioam_data_list_element,
		  elt, &trace->trace_hdr.ioam_trace_type);
      elt_index++;
      elt += trace_data_size_in_words;
    }
  return (s);
}


static clib_error_t *
ip6_show_ioam_trace_cmd_fn (vlib_main_t * vm,
			    unformat_input_t * input,
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
    return (-1);

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
