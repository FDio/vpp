/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <ioam/lib-trace/trace_util.h>
#include <nsh/nsh-md2-ioam/nsh_md2_ioam.h>
#include <nsh/nsh_packet.h>

/* Timestamp precision multipliers for seconds, milliseconds, microseconds
 * and nanoseconds respectively.
 */
static f64 trace_tsp_mul[4] = { 1, 1e3, 1e6, 1e9 };

#define NSH_MD2_IOAM_TRACE_SIZE_DUMMY 20

typedef union
{
  u64 as_u64;
  u32 as_u32[2];
} time_u64_t;


/* *INDENT-OFF* */
typedef CLIB_PACKED(struct {
  u16 class;
  u8 type;
  u8 length;
  u8 data_list_elts_left;
  u16 ioam_trace_type;
  u8 reserve;
  u32 elts[0]; /* Variable type. So keep it generic */
}) nsh_md2_ioam_trace_option_t;
/* *INDENT-ON* */


#define foreach_nsh_md2_ioam_trace_stats				\
  _(SUCCESS, "Pkts updated with TRACE records")					\
  _(FAILED, "Errors in TRACE due to lack of TRACE records")

static char *nsh_md2_ioam_trace_stats_strings[] = {
#define _(sym,string) string,
  foreach_nsh_md2_ioam_trace_stats
#undef _
};

typedef enum
{
#define _(sym,str) NSH_MD2_IOAM_TRACE_##sym,
  foreach_nsh_md2_ioam_trace_stats
#undef _
    NSH_MD2_IOAM_TRACE_N_STATS,
} nsh_md2_ioam_trace_stats_t;


typedef struct
{
  /* stats */
  u64 counters[ARRAY_LEN (nsh_md2_ioam_trace_stats_strings)];

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} nsh_md2_ioam_trace_main_t;

nsh_md2_ioam_trace_main_t nsh_md2_ioam_trace_main;

/*
 * Find a trace profile
 */

extern u8 *nsh_trace_main;
always_inline trace_profile *
nsh_trace_profile_find (void)
{
  trace_main_t *sm = (trace_main_t *) nsh_trace_main;

  return (&(sm->profile));
}


always_inline void
nsh_md2_ioam_trace_stats_increment_counter (u32 counter_index, u64 increment)
{
  nsh_md2_ioam_trace_main_t *hm = &nsh_md2_ioam_trace_main;

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
nsh_md2_ioam_trace_rewrite_handler (u8 * rewrite_string, u8 * rewrite_size)
{
  nsh_md2_ioam_trace_option_t *trace_option = NULL;
  u8 trace_data_size = 0;
  u8 trace_option_elts = 0;
  trace_profile *profile = NULL;

  profile = nsh_trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      return (-1);
    }

  if (PREDICT_FALSE (!rewrite_string))
    return -1;

  trace_option_elts = profile->num_elts;
  trace_data_size = fetch_trace_data_size (profile->trace_type);

  trace_option = (nsh_md2_ioam_trace_option_t *) rewrite_string;
  trace_option->class = clib_host_to_net_u16 (0x9);
  trace_option->type = NSH_MD2_IOAM_OPTION_TYPE_TRACE;
  trace_option->length = (trace_option_elts * trace_data_size) + 4;
  trace_option->data_list_elts_left = trace_option_elts;
  trace_option->ioam_trace_type =
    clib_host_to_net_u16 (profile->trace_type & TRACE_TYPE_MASK);

  *rewrite_size =
    sizeof (nsh_md2_ioam_trace_option_t) +
    (trace_option_elts * trace_data_size);

  return 0;
}


int
nsh_md2_ioam_trace_data_list_handler (vlib_buffer_t * b,
				      nsh_tlv_header_t * opt)
{
  u8 elt_index = 0;
  nsh_md2_ioam_trace_option_t *trace =
    (nsh_md2_ioam_trace_option_t *) ((u8 *) opt);
  time_u64_t time_u64;
  u32 *elt;
  int rv = 0;
  trace_profile *profile = NULL;
  nsh_md2_ioam_main_t *hm = &nsh_md2_ioam_main;
  nsh_main_t *gm = &nsh_main;
  u16 ioam_trace_type = 0;

  profile = nsh_trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      return (-1);
    }


  ioam_trace_type = profile->trace_type & TRACE_TYPE_MASK;
  time_u64.as_u64 = 0;

  if (PREDICT_TRUE (trace->data_list_elts_left))
    {
      trace->data_list_elts_left--;
      /* fetch_trace_data_size returns in bytes. Convert it to 4-bytes
       * to skip to this node's location.
       */
      elt_index =
	trace->data_list_elts_left *
	fetch_trace_data_size (ioam_trace_type) / 4;
      elt = &trace->elts[elt_index];
      if (ioam_trace_type & BIT_TTL_NODEID)
	{
	  ip4_header_t *ip0 = vlib_buffer_get_current (b);
	  *elt = clib_host_to_net_u32 (((ip0->ttl - 1) << 24) |
				       profile->node_id);
	  elt++;
	}

      if (ioam_trace_type & BIT_ING_INTERFACE)
	{
	  u16 tx_if = vnet_buffer (b)->sw_if_index[VLIB_TX];

	  *elt =
	    (vnet_buffer (b)->sw_if_index[VLIB_RX] & 0xFFFF) << 16 | tx_if;
	  *elt = clib_host_to_net_u32 (*elt);
	  elt++;
	}


      if (ioam_trace_type & BIT_TIMESTAMP)
	{
	  /* Send least significant 32 bits */
	  f64 time_f64 =
	    (f64) (((f64) hm->unix_time_0) +
		   (vlib_time_now (gm->vlib_main) - hm->vlib_time_0));

	  time_u64.as_u64 = time_f64 * trace_tsp_mul[profile->trace_tsp];
	  *elt = clib_host_to_net_u32 (time_u64.as_u32[0]);
	  elt++;
	}

      if (ioam_trace_type & BIT_APPDATA)
	{
	  /* $$$ set elt0->app_data */
	  *elt = clib_host_to_net_u32 (profile->app_data);
	  elt++;
	}
      nsh_md2_ioam_trace_stats_increment_counter
	(NSH_MD2_IOAM_TRACE_SUCCESS, 1);
    }
  else
    {
      nsh_md2_ioam_trace_stats_increment_counter
	(NSH_MD2_IOAM_TRACE_FAILED, 1);
    }
  return (rv);
}



u8 *
nsh_md2_ioam_trace_data_list_trace_handler (u8 * s, nsh_tlv_header_t * opt)
{
  nsh_md2_ioam_trace_option_t *trace;
  u8 trace_data_size_in_words = 0;
  u32 *elt;
  int elt_index = 0;
  u16 ioam_trace_type = 0;

  trace = (nsh_md2_ioam_trace_option_t *) ((u8 *) opt);
  ioam_trace_type = clib_net_to_host_u16 (trace->ioam_trace_type);
  trace_data_size_in_words = fetch_trace_data_size (ioam_trace_type) / 4;
  elt = &trace->elts[0];
  s =
    format (s, "  Trace Type 0x%x , %d elts left\n", ioam_trace_type,
	    trace->data_list_elts_left);
  while ((u8 *) elt < ((u8 *) (&trace->elts[0]) + trace->length - 4
		       /* -2 accounts for ioam_trace_type,elts_left */ ))
    {
      s = format (s, "    [%d] %U\n", elt_index,
		  format_ioam_data_list_element, elt, &ioam_trace_type);
      elt_index++;
      elt += trace_data_size_in_words;
    }
  return (s);
}

int
nsh_md2_ioam_trace_swap_handler (vlib_buffer_t * b,
				 nsh_tlv_header_t * old_opt,
				 nsh_tlv_header_t * new_opt)
{

  clib_memcpy (new_opt, old_opt, new_opt->length + sizeof (nsh_tlv_header_t));
  return nsh_md2_ioam_trace_data_list_handler (b, new_opt);
}

static clib_error_t *
nsh_md2_ioam_show_ioam_trace_cmd_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  nsh_md2_ioam_trace_main_t *hm = &nsh_md2_ioam_trace_main;
  u8 *s = 0;
  int i = 0;

  for (i = 0; i < NSH_MD2_IOAM_TRACE_N_STATS; i++)
    {
      s = format (s, " %s - %lu\n", nsh_md2_ioam_trace_stats_strings[i],
		  hm->counters[i]);
    }

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (nsh_md2_ioam_show_ioam_trace_cmd, static) = {
  .path = "show ioam nsh-lisp-gpe trace",
  .short_help = "iOAM trace statistics",
  .function = nsh_md2_ioam_show_ioam_trace_cmd_fn,
};
/* *INDENT-ON* */


int
nsh_md2_ioam_trace_pop_handler (vlib_buffer_t * b, nsh_tlv_header_t * opt)
{
  return nsh_md2_ioam_trace_data_list_handler (b, opt);
}

static clib_error_t *
nsh_md2_ioam_trace_init (vlib_main_t * vm)
{
  nsh_md2_ioam_trace_main_t *hm = &nsh_md2_ioam_trace_main;
  nsh_md2_ioam_main_t *gm = &nsh_md2_ioam_main;
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, nsh_init)))
    return (error);

  if ((error = vlib_call_init_function (vm, nsh_md2_ioam_init)))
    return (error);

  hm->vlib_main = vm;
  hm->vnet_main = vnet_get_main ();
  gm->unix_time_0 = (u32) time (0);	/* Store starting time */
  gm->vlib_time_0 = vlib_time_now (vm);

  memset (hm->counters, 0, sizeof (hm->counters));

  if (nsh_md2_register_option
      (clib_host_to_net_u16 (0x9),
       NSH_MD2_IOAM_OPTION_TYPE_TRACE,
       NSH_MD2_IOAM_TRACE_SIZE_DUMMY,
       nsh_md2_ioam_trace_rewrite_handler,
       nsh_md2_ioam_trace_data_list_handler,
       nsh_md2_ioam_trace_swap_handler,
       nsh_md2_ioam_trace_pop_handler,
       nsh_md2_ioam_trace_data_list_trace_handler) < 0)
    return (clib_error_create
	    ("registration of NSH_MD2_IOAM_OPTION_TYPE_TRACE failed"));

  return (0);
}

VLIB_INIT_FUNCTION (nsh_md2_ioam_trace_init);

int
nsh_md2_ioam_trace_profile_cleanup (void)
{
  nsh_main_t *hm = &nsh_main;

  hm->options_size[NSH_MD2_IOAM_OPTION_TYPE_TRACE] = 0;

  return 0;

}

static int
nsh_md2_ioam_trace_get_sizeof_handler (u32 * result)
{
  u16 size = 0;
  u8 trace_data_size = 0;
  trace_profile *profile = NULL;

  *result = 0;

  profile = nsh_trace_profile_find ();

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
    sizeof (nsh_md2_ioam_trace_option_t) +
    profile->num_elts * trace_data_size;
  *result = size;

  return 0;
}


int
nsh_md2_ioam_trace_profile_setup (void)
{
  u32 trace_size = 0;
  nsh_main_t *hm = &nsh_main;

  trace_profile *profile = NULL;


  profile = nsh_trace_profile_find ();

  if (PREDICT_FALSE (!profile))
    {
      return (-1);
    }


  if (nsh_md2_ioam_trace_get_sizeof_handler (&trace_size) < 0)
    return (-1);

  hm->options_size[NSH_MD2_IOAM_OPTION_TYPE_TRACE] = trace_size;

  return (0);
}



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
