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
/*
 *------------------------------------------------------------------
 * ioam_cache.c - ioam ip6 API / debug CLI handling
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ioam/ip6/ioam_cache.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip6_hop_by_hop.h>

#include "ioam_cache.h"

/* define message IDs */
#include <ioam/ip6/ioam_cache_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ioam/ip6/ioam_cache_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ioam/ip6/ioam_cache_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ioam/ip6/ioam_cache_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ioam/ip6/ioam_cache_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE cm->msg_id_base
#include <vlibapi/api_helper_macros.h>

ioam_cache_main_t ioam_cache_main;

/* List of message types that this plugin understands */
#define foreach_ioam_cache_plugin_api_msg                        \
_(IOAM_CACHE_IP6_ENABLE_DISABLE, ioam_cache_ip6_enable_disable)

static u8 *
ioam_e2e_id_trace_handler (u8 * s, ip6_hop_by_hop_option_t * opt)
{
  ioam_e2e_id_option_t *e2e = (ioam_e2e_id_option_t *) opt;

  if (e2e)
    {
      s =
	format (s, "IP6_HOP_BY_HOP E2E ID = %U\n", format_ip6_address,
		&(e2e->id));
    }


  return s;
}

static u8 *
ioam_e2e_cache_trace_handler (u8 * s, ip6_hop_by_hop_option_t * opt)
{
  ioam_e2e_cache_option_t *e2e = (ioam_e2e_cache_option_t *) opt;

  if (e2e)
    {
      s =
	format (s, "IP6_HOP_BY_HOP E2E CACHE = pool:%d idx:%d\n",
		e2e->pool_id, e2e->pool_index);
    }


  return s;
}

/* Action function shared between message handler and debug CLI */
int
ioam_cache_ip6_enable_disable (ioam_cache_main_t * em,
			       ip6_address_t * sr_localsid, u8 is_disable)
{
  vlib_main_t *vm = em->vlib_main;

  if (is_disable == 0)
    {
      ioam_cache_table_init (vm);
      em->sr_localsid_cache.as_u64[0] = sr_localsid->as_u64[0];
      em->sr_localsid_cache.as_u64[1] = sr_localsid->as_u64[1];
      ip6_hbh_set_next_override (em->cache_hbh_slot);
      ip6_hbh_register_option (HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE_ID,
			       0, ioam_e2e_id_trace_handler);
      ip6_hbh_register_option (HBH_OPTION_TYPE_IOAM_E2E_CACHE_ID,
			       0, ioam_e2e_cache_trace_handler);

    }
  else
    {
      ip6_hbh_set_next_override (IP6_LOOKUP_NEXT_POP_HOP_BY_HOP);
      ioam_cache_table_destroy (vm);
      em->sr_localsid_cache.as_u64[0] = 0;
      em->sr_localsid_cache.as_u64[1] = 0;
      ip6_hbh_unregister_option (HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE_ID);
      ip6_hbh_unregister_option (HBH_OPTION_TYPE_IOAM_E2E_CACHE_ID);
    }

  return 0;
}

/* Action function shared between message handler and debug CLI */
int
ioam_tunnel_select_ip6_enable_disable (ioam_cache_main_t * em,
				       u8 criteria,
				       u8 no_of_responses,
				       ip6_address_t * sr_localsid,
				       u8 is_disable)
{
  vlib_main_t *vm = em->vlib_main;

  if (is_disable == 0)
    {
      ioam_cache_ts_table_init (vm);
      em->criteria_oneway = criteria;
      em->wait_for_responses = no_of_responses;
      em->sr_localsid_ts.as_u64[0] = sr_localsid->as_u64[0];
      em->sr_localsid_ts.as_u64[1] = sr_localsid->as_u64[1];
      ip6_hbh_set_next_override (em->ts_hbh_slot);
      ip6_ioam_ts_cache_set_rewrite ();
      ip6_hbh_register_option (HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE_ID,
			       0, ioam_e2e_id_trace_handler);
      ip6_hbh_register_option (HBH_OPTION_TYPE_IOAM_E2E_CACHE_ID,
			       0, ioam_e2e_cache_trace_handler);

      /* Turn on the cleanup process */
      //      vlib_process_signal_event (vm, em->cleanup_process_node_index, 1, 0);
    }
  else
    {
      ioam_cache_ts_timer_node_enable (vm, 0);
      ip6_hbh_set_next_override (IP6_LOOKUP_NEXT_POP_HOP_BY_HOP);
      em->sr_localsid_ts.as_u64[0] = 0;
      em->sr_localsid_ts.as_u64[1] = 0;
      ioam_cache_ts_table_destroy (vm);
      ip6_ioam_ts_cache_cleanup_rewrite ();
      ip6_hbh_unregister_option (HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE_ID);
      ip6_hbh_unregister_option (HBH_OPTION_TYPE_IOAM_E2E_CACHE_ID);
    }

  return 0;
}

/* API message handler */
static void vl_api_ioam_cache_ip6_enable_disable_t_handler
  (vl_api_ioam_cache_ip6_enable_disable_t * mp)
{
  vl_api_ioam_cache_ip6_enable_disable_reply_t *rmp;
  ioam_cache_main_t *cm = &ioam_cache_main;
  ip6_address_t sr_localsid;
  int rv;

  sr_localsid.as_u64[0] = 0;
  sr_localsid.as_u64[1] = 0;
  rv =
    ioam_cache_ip6_enable_disable (cm, &sr_localsid, (int) (mp->is_disable));
  REPLY_MACRO (VL_API_IOAM_CACHE_IP6_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
ioam_cache_plugin_api_hookup (vlib_main_t * vm)
{
  ioam_cache_main_t *sm = &ioam_cache_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_ioam_cache_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <ioam/ip6/ioam_cache_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (ioam_cache_main_t * sm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_ioam_cache;
#undef _
}

static clib_error_t *
set_ioam_cache_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ioam_cache_main_t *em = &ioam_cache_main;
  u8 is_disable = 0;
  ip6_address_t sr_localsid;
  u8 address_set = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	is_disable = 1;
      else if (!address_set
	       && unformat (input, "sr_localsid %U", unformat_ip6_address,
			    &sr_localsid))
	address_set = 1;
      else
	break;
    }

  if (is_disable == 0 && !address_set)
    return clib_error_return (0, "Error: SRv6 LocalSID address is mandatory");

  ioam_cache_ip6_enable_disable (em, &sr_localsid, is_disable);

  return 0;
}

/* *INDENT_OFF* */
VLIB_CLI_COMMAND (set_ioam_cache_command, static) =
{
.path = "set ioam ip6 cache",.short_help =
    "set ioam ip6 cache sr_localsid <ip6 address> [disable]",.function =
    set_ioam_cache_command_fn};
/* *INDENT_ON* */

#define IOAM_TS_WAIT_FOR_RESPONSES 3
static clib_error_t *
set_ioam_tunnel_select_command_fn (vlib_main_t * vm,
				   unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  ioam_cache_main_t *em = &ioam_cache_main;
  u8 is_disable = 0;
  u8 one_way = 0;
  ip6_address_t sr_localsid;
  u8 address_set = 0;
  u8 no_of_responses = IOAM_TS_WAIT_FOR_RESPONSES;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	is_disable = 1;
      else if (unformat (input, "rtt"))
	one_way = 0;
      else if (unformat (input, "oneway"))
	one_way = 1;
      else if (unformat (input, "wait_for_responses %d", &no_of_responses))
	;
      else if (!address_set
	       && unformat (input, "sr_localsid %U", unformat_ip6_address,
			    &sr_localsid))
	address_set = 1;
      else
	break;
    }
  if (is_disable == 0 && !address_set)
    return clib_error_return (0,
			      "Error: SRv6 LocalSID address is mandatory to receive response.");

  ioam_tunnel_select_ip6_enable_disable (em, one_way, no_of_responses,
					 &sr_localsid, is_disable);

  return 0;
}

/* *INDENT_OFF* */
VLIB_CLI_COMMAND (set_ioam_cache_ts_command, static) =
{
.path = "set ioam ip6 sr-tunnel-select",.short_help =
    "set ioam ip6 sr-tunnel-select [disable] [oneway|rtt] [wait_for_responses <n|default 3>] \
  [sr_localsid <ip6 address>]",.function = set_ioam_tunnel_select_command_fn};
/* *INDENT_ON* */

static void
ioam_cache_table_print (vlib_main_t * vm, u8 verbose)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  ioam_cache_entry_t *entry = 0;
  ioam_cache_ts_entry_t *ts_entry = 0;
  int no_of_threads = vec_len (vlib_worker_threads);
  int i;

  pool_foreach (entry, cm->ioam_rewrite_pool, (
						{
						vlib_cli_output (vm, "%U",
								 format_ioam_cache_entry,
								 entry);
						}));

  if (cm->ts_stats)
    for (i = 0; i < no_of_threads; i++)
      {
	vlib_cli_output (vm, "Number of entries in thread-%d selection pool: %lu\n \
                          (pool found to be full: %lu times)", i,
			 cm->ts_stats[i].inuse, cm->ts_stats[i].add_failed);

	if (verbose == 1)
	  vlib_worker_thread_barrier_sync (vm);
	pool_foreach (ts_entry, cm->ioam_ts_pool[i], (
						       {
						       vlib_cli_output (vm,
									"%U",
									format_ioam_cache_ts_entry,
									ts_entry,
									(u32)
									i);
						       }
		      ));
	vlib_worker_thread_barrier_release (vm);
      }

}

static clib_error_t *
show_ioam_cache_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  u8 verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
    }
  ioam_cache_table_print (vm, verbose);


  return 0;
}

/* *INDENT_OFF* */
VLIB_CLI_COMMAND (show_ioam_cache_command, static) =
{
.path = "show ioam ip6 cache",.short_help =
    "show ioam ip6 cache [verbose]",.function = show_ioam_cache_command_fn};
/* *INDENT_ON* */

static clib_error_t *
ioam_cache_init (vlib_main_t * vm)
{
  ioam_cache_main_t *em = &ioam_cache_main;
  clib_error_t *error = 0;
  u8 *name;
  u32 cache_node_index = ioam_cache_node.index;
  u32 ts_node_index = ioam_cache_ts_node.index;
  vlib_node_t *ip6_hbyh_node = NULL, *ip6_hbh_pop_node = NULL, *error_node =
    NULL;

  name = format (0, "ioam_cache_%08x%c", api_version, 0);

  memset (&ioam_cache_main, 0, sizeof (ioam_cache_main));
  /* Ask for a correctly-sized block of API message decode slots */
  em->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = ioam_cache_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (em, &api_main);

  /* Hook this node to ip6-hop-by-hop */
  ip6_hbyh_node = vlib_get_node_by_name (vm, (u8 *) "ip6-hop-by-hop");
  em->cache_hbh_slot =
    vlib_node_add_next (vm, ip6_hbyh_node->index, cache_node_index);
  em->ts_hbh_slot =
    vlib_node_add_next (vm, ip6_hbyh_node->index, ts_node_index);

  ip6_hbh_pop_node = vlib_get_node_by_name (vm, (u8 *) "ip6-pop-hop-by-hop");
  em->ip6_hbh_pop_node_index = ip6_hbh_pop_node->index;

  error_node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  em->error_node_index = error_node->index;
  em->vlib_main = vm;

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (ioam_cache_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
