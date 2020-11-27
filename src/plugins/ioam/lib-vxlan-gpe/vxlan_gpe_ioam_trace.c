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

#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/vxlan-gpe/vxlan_gpe_packet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <ioam/lib-trace/trace_util.h>
#include <ioam/lib-trace/trace_config.h>
#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam.h>

/* Timestamp precision multipliers for seconds, milliseconds, microseconds
 * and nanoseconds respectively.
 */
static f64 trace_tsp_mul[4] = { 1, 1e3, 1e6, 1e9 };

typedef union
{
  u64 as_u64;
  u32 as_u32[2];
} time_u64_t;


/* *INDENT-OFF* */
typedef CLIB_PACKED(struct {
  vxlan_gpe_ioam_option_t hdr;
  u8 ioam_trace_type;
  u8 data_list_elts_left;
  u32 elts[0]; /* Variable type. So keep it generic */
}) vxlan_gpe_ioam_trace_option_t;
/* *INDENT-ON* */


#define foreach_vxlan_gpe_ioam_trace_stats				\
  _(SUCCESS, "Pkts updated with TRACE records")					\
  _(FAILED, "Errors in TRACE due to lack of TRACE records")

static char *vxlan_gpe_ioam_trace_stats_strings[] = {
#define _(sym,string) string,
  foreach_vxlan_gpe_ioam_trace_stats
#undef _
};

typedef enum
{
#define _(sym,str) VXLAN_GPE_IOAM_TRACE_##sym,
  foreach_vxlan_gpe_ioam_trace_stats
#undef _
    VXLAN_GPE_IOAM_TRACE_N_STATS,
} vxlan_gpe_ioam_trace_stats_t;


typedef struct
{
  /* stats */
  u64 counters[ARRAY_LEN (vxlan_gpe_ioam_trace_stats_strings)];

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} vxlan_gpe_ioam_trace_main_t;

vxlan_gpe_ioam_trace_main_t vxlan_gpe_ioam_trace_main;

int
vxlan_gpe_ioam_add_register_option (u8 option,
				    u8 size,
				    int rewrite_options (u8 * rewrite_string,
							 u8 * rewrite_size))
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->add_options));

  /* Already registered */
  if (hm->add_options[option])
    return (-1);

  hm->add_options[option] = rewrite_options;
  hm->options_size[option] = size;

  return (0);
}

int
vxlan_gpe_add_unregister_option (u8 option)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->add_options));

  /* Not registered */
  if (!hm->add_options[option])
    return (-1);

  hm->add_options[option] = NULL;
  hm->options_size[option] = 0;
  return (0);
}


int
vxlan_gpe_ioam_register_option (u8 option,
				int options (vlib_buffer_t * b,
					     vxlan_gpe_ioam_option_t * opt,
					     u8 is_ipv4, u8 use_adj),
				u8 * trace (u8 * s,
					    vxlan_gpe_ioam_option_t * opt))
{
  vxlan_gpe_ioam_main_t *im = &vxlan_gpe_ioam_main;

  ASSERT ((u32) option < ARRAY_LEN (im->options));

  /* Already registered */
  if (im->options[option])
    return (-1);

  im->options[option] = options;
  im->trace[option] = trace;

  return (0);
}

int
vxlan_gpe_ioam_unregister_option (u8 option)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->options));

  /* Not registered */
  if (!hm->options[option])
    return (-1);

  hm->options[option] = NULL;
  hm->trace[option] = NULL;

  return (0);
}


always_inline void
vxlan_gpe_ioam_trace_stats_increment_counter (u32 counter_index,
					      u64 increment)
{
  vxlan_gpe_ioam_trace_main_t *hm = &vxlan_gpe_ioam_trace_main;

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
vxlan_gpe_ioam_trace_rewrite_handler (u8 * rewrite_string, u8 * rewrite_size)
{
  vxlan_gpe_ioam_trace_option_t *trace_option = NULL;
  u8 trace_data_size = 0;
  u8 trace_option_elts = 0;
  trace_profile *profile = NULL;


  profile = trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      return (-1);
    }

  if (PREDICT_FALSE (!rewrite_string))
    return -1;

  trace_option_elts = profile->num_elts;
  trace_data_size = fetch_trace_data_size (profile->trace_type);
  trace_option = (vxlan_gpe_ioam_trace_option_t *) rewrite_string;
  trace_option->hdr.type = VXLAN_GPE_OPTION_TYPE_IOAM_TRACE;
  trace_option->hdr.length = 2 /*ioam_trace_type,data_list_elts_left */  +
    trace_option_elts * trace_data_size;
  trace_option->ioam_trace_type = profile->trace_type & TRACE_TYPE_MASK;
  trace_option->data_list_elts_left = trace_option_elts;
  *rewrite_size =
    sizeof (vxlan_gpe_ioam_trace_option_t) +
    (trace_option_elts * trace_data_size);

  return 0;
}


int
vxlan_gpe_ioam_trace_data_list_handler (vlib_buffer_t * b,
					vxlan_gpe_ioam_option_t * opt,
					u8 is_ipv4, u8 use_adj)
{
  u8 elt_index = 0;
  vxlan_gpe_ioam_trace_option_t *trace =
    (vxlan_gpe_ioam_trace_option_t *) opt;
  time_u64_t time_u64;
  u32 *elt;
  int rv = 0;
  trace_profile *profile = NULL;
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;


  profile = trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      return (-1);
    }


  time_u64.as_u64 = 0;

  if (PREDICT_TRUE (trace->data_list_elts_left))
    {
      trace->data_list_elts_left--;
      /* fetch_trace_data_size returns in bytes. Convert it to 4-bytes
       * to skip to this node's location.
       */
      elt_index =
	trace->data_list_elts_left *
	fetch_trace_data_size (trace->ioam_trace_type) / 4;
      elt = &trace->elts[elt_index];
      if (is_ipv4)
	{
	  if (trace->ioam_trace_type & BIT_TTL_NODEID)
	    {
	      ip4_header_t *ip0 = vlib_buffer_get_current (b);
	      /* The transit case is the only case where the TTL decrement happens
	       * before iOAM processing. For now, use the use_adj flag as an overload.
	       * We can probably use a separate flag instead of overloading the use_adj flag.
	       */
	      *elt = clib_host_to_net_u32 (((ip0->ttl - 1 + use_adj) << 24) |
					   profile->node_id);
	      elt++;
	    }

	  if (trace->ioam_trace_type & BIT_ING_INTERFACE)
	    {
	      u16 tx_if = 0;
	      u32 adj_index = vnet_buffer (b)->ip.adj_index;

	      if (use_adj)
		{
		  ip_adjacency_t *adj = adj_get (adj_index);
		  tx_if = adj->rewrite_header.sw_if_index & 0xFFFF;
		}

	      *elt =
		(vnet_buffer (b)->sw_if_index[VLIB_RX] & 0xFFFF) << 16 |
		tx_if;
	      *elt = clib_host_to_net_u32 (*elt);
	      elt++;
	    }
	}
      else
	{
	  if (trace->ioam_trace_type & BIT_TTL_NODEID)
	    {
	      ip6_header_t *ip0 = vlib_buffer_get_current (b);
	      *elt = clib_host_to_net_u32 ((ip0->hop_limit << 24) |
					   profile->node_id);
	      elt++;
	    }
	  if (trace->ioam_trace_type & BIT_ING_INTERFACE)
	    {
	      u16 tx_if = 0;
	      u32 adj_index = vnet_buffer (b)->ip.adj_index;

	      if (use_adj)
		{
		  ip_adjacency_t *adj = adj_get (adj_index);
		  tx_if = adj->rewrite_header.sw_if_index & 0xFFFF;
		}

	      *elt =
		(vnet_buffer (b)->sw_if_index[VLIB_RX] & 0xFFFF) << 16 |
		tx_if;
	      *elt = clib_host_to_net_u32 (*elt);
	      elt++;
	    }
	}

      if (trace->ioam_trace_type & BIT_TIMESTAMP)
	{
	  /* Send least significant 32 bits */
	  f64 time_f64 =
	    (f64) (((f64) hm->unix_time_0) +
		   (vlib_time_now (hm->vlib_main) - hm->vlib_time_0));

	  time_u64.as_u64 = time_f64 * trace_tsp_mul[profile->trace_tsp];
	  *elt = clib_host_to_net_u32 (time_u64.as_u32[0]);
	  elt++;
	}

      if (trace->ioam_trace_type & BIT_APPDATA)
	{
	  /* $$$ set elt0->app_data */
	  *elt = clib_host_to_net_u32 (profile->app_data);
	  elt++;
	}
      vxlan_gpe_ioam_trace_stats_increment_counter
	(VXLAN_GPE_IOAM_TRACE_SUCCESS, 1);
    }
  else
    {
      vxlan_gpe_ioam_trace_stats_increment_counter
	(VXLAN_GPE_IOAM_TRACE_FAILED, 1);
    }
  return (rv);
}

u8 *
vxlan_gpe_ioam_trace_data_list_trace_handler (u8 * s,
					      vxlan_gpe_ioam_option_t * opt)
{
  vxlan_gpe_ioam_trace_option_t *trace;
  u8 trace_data_size_in_words = 0;
  u32 *elt;
  int elt_index = 0;

  trace = (vxlan_gpe_ioam_trace_option_t *) opt;
  s =
    format (s, "  Trace Type 0x%x , %d elts left\n", trace->ioam_trace_type,
	    trace->data_list_elts_left);
  trace_data_size_in_words =
    fetch_trace_data_size (trace->ioam_trace_type) / 4;
  elt = &trace->elts[0];
  while ((u8 *) elt < ((u8 *) (&trace->elts[0]) + trace->hdr.length - 2
		       /* -2 accounts for ioam_trace_type,elts_left */ ))
    {
      s = format (s, "    [%d] %U\n", elt_index,
		  format_ioam_data_list_element,
		  elt, &trace->ioam_trace_type);
      elt_index++;
      elt += trace_data_size_in_words;
    }
  return (s);
}


static clib_error_t *
vxlan_gpe_show_ioam_trace_cmd_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  vxlan_gpe_ioam_trace_main_t *hm = &vxlan_gpe_ioam_trace_main;
  u8 *s = 0;
  int i = 0;

  for (i = 0; i < VXLAN_GPE_IOAM_TRACE_N_STATS; i++)
    {
      s = format (s, " %s - %lu\n", vxlan_gpe_ioam_trace_stats_strings[i],
		  hm->counters[i]);
    }

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vxlan_gpe_show_ioam_trace_cmd, static) = {
  .path = "show ioam vxlan-gpe trace",
  .short_help = "iOAM trace statistics",
  .function = vxlan_gpe_show_ioam_trace_cmd_fn,
};
/* *INDENT-ON* */


static clib_error_t *
vxlan_gpe_ioam_trace_init (vlib_main_t * vm)
{
  vxlan_gpe_ioam_trace_main_t *hm = &vxlan_gpe_ioam_trace_main;

  hm->vlib_main = vm;
  hm->vnet_main = vnet_get_main ();
  clib_memset (hm->counters, 0, sizeof (hm->counters));

  if (vxlan_gpe_ioam_register_option
      (VXLAN_GPE_OPTION_TYPE_IOAM_TRACE,
       vxlan_gpe_ioam_trace_data_list_handler,
       vxlan_gpe_ioam_trace_data_list_trace_handler) < 0)
    return (clib_error_create
	    ("registration of VXLAN_GPE_OPTION_TYPE_IOAM_TRACE failed"));


  if (vxlan_gpe_ioam_add_register_option
      (VXLAN_GPE_OPTION_TYPE_IOAM_TRACE,
       sizeof (vxlan_gpe_ioam_trace_option_t),
       vxlan_gpe_ioam_trace_rewrite_handler) < 0)
    return (clib_error_create
	    ("registration of VXLAN_GPE_OPTION_TYPE_IOAM_TRACE for rewrite failed"));


  return (0);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (vxlan_gpe_ioam_trace_init) =
{
  .runs_after = VLIB_INITS("ip_main_init", "ip6_lookup_init",
                           "vxlan_gpe_init"),
};
/* *INDENT-ON* */


int
vxlan_gpe_trace_profile_cleanup (void)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;

  hm->options_size[VXLAN_GPE_OPTION_TYPE_IOAM_TRACE] = 0;

  return 0;

}

static int
vxlan_gpe_ioam_trace_get_sizeof_handler (u32 * result)
{
  u16 size = 0;
  u8 trace_data_size = 0;
  trace_profile *profile = NULL;

  *result = 0;

  profile = trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      return (-1);
    }

  trace_data_size = fetch_trace_data_size (profile->trace_type);
  if (PREDICT_FALSE (trace_data_size == 0))
    return VNET_API_ERROR_INVALID_VALUE;

  if (PREDICT_FALSE (profile->num_elts * trace_data_size > 254))
    return VNET_API_ERROR_INVALID_VALUE;

  size +=
    sizeof (vxlan_gpe_ioam_trace_option_t) +
    profile->num_elts * trace_data_size;
  *result = size;

  return 0;
}


int
vxlan_gpe_trace_profile_setup (void)
{
  u32 trace_size = 0;
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;

  trace_profile *profile = NULL;


  profile = trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      return (-1);
    }


  if (vxlan_gpe_ioam_trace_get_sizeof_handler (&trace_size) < 0)
    return (-1);

  hm->options_size[VXLAN_GPE_OPTION_TYPE_IOAM_TRACE] = trace_size;

  return (0);
}



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
