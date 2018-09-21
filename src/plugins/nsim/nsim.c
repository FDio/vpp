/*
 * nsim.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <nsim/nsim.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <nsim/nsim_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <nsim/nsim_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <nsim/nsim_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <nsim/nsim_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <nsim/nsim_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE nsm->msg_id_base
#include <vlibapi/api_helper_macros.h>

nsim_main_t nsim_main;

/* List of message types that this plugin understands */

#define foreach_nsim_plugin_api_msg                           \
_(NSIM_ENABLE_DISABLE, nsim_enable_disable)

/* Action function shared between message handler and debug CLI */

int
nsim_enable_disable (nsim_main_t * nsm, u32 sw_if_index0,
		     u32 sw_if_index1, int enable_disable)
{
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;
  int rv = 0;

  if (nsm->is_configured == 0)
    return VNET_API_ERROR_CANNOT_ENABLE_DISABLE_FEATURE;

  /* Utterly wrong? */
  if (pool_is_free_index (nsm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index0))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (pool_is_free_index (nsm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index1))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (nsm->vnet_main, sw_if_index0);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  sw = vnet_get_sw_interface (nsm->vnet_main, sw_if_index1);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Add graph arcs for the input / wheel scraper node */
  hw = vnet_get_hw_interface (nsm->vnet_main, sw_if_index0);
  nsm->output_next_index0 =
    vlib_node_add_next (nsm->vlib_main,
			nsim_input_node.index, hw->output_node_index);

  hw = vnet_get_hw_interface (nsm->vnet_main, sw_if_index1);
  nsm->output_next_index1 =
    vlib_node_add_next (nsm->vlib_main,
			nsim_input_node.index, hw->output_node_index);

  vnet_feature_enable_disable ("device-input", "nsim",
			       sw_if_index0, enable_disable, 0, 0);
  vnet_feature_enable_disable ("device-input", "nsim",
			       sw_if_index1, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
nsim_enable_disable_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  nsim_main_t *nsm = &nsim_main;
  u32 sw_if_index0 = ~0;
  u32 sw_if_index1 = ~0;
  int enable_disable = 1;
  u32 tmp;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 nsm->vnet_main, &tmp))
	{
	  if (sw_if_index0 == ~0)
	    sw_if_index0 = tmp;
	  else
	    sw_if_index1 = tmp;
	}
      else
	break;
    }

  if (sw_if_index0 == ~0 || sw_if_index1 == ~0)
    return clib_error_return (0, "Please specify two interfaces...");

  rv = nsim_enable_disable (nsm, sw_if_index0, sw_if_index1, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_CANNOT_ENABLE_DISABLE_FEATURE:
      return clib_error_return (0, "Not configured, please 'set nsim' first");

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "nsim_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (nsim_enable_disable_command, static) =
{
  .path = "nsim enable-disable",
  .short_help =
  "nsim enable-disable <interface-name-1> <interface-name-2> [disable]",
  .function = nsim_enable_disable_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_nsim_enable_disable_t_handler
  (vl_api_nsim_enable_disable_t * mp)
{
  vl_api_nsim_enable_disable_reply_t *rmp;
  nsim_main_t *nsm = &nsim_main;
  int rv;

  rv = nsim_enable_disable (nsm, ntohl (mp->sw_if_index0),
			    ntohl (mp->sw_if_index1),
			    (int) (mp->enable_disable));

  REPLY_MACRO (VL_API_NSIM_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
nsim_plugin_api_hookup (vlib_main_t * vm)
{
  nsim_main_t *nsm = &nsim_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + nsm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_nsim_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <nsim/nsim_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (nsim_main_t * nsm, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n  #crc, id + nsm->msg_id_base);
  foreach_vl_msg_name_crc_nsim;
#undef _
}

static clib_error_t *
nsim_init (vlib_main_t * vm)
{
  nsim_main_t *nsm = &nsim_main;
  clib_error_t *error = 0;
  u8 *name;

  nsm->vlib_main = vm;
  nsm->vnet_main = vnet_get_main ();

  name = format (0, "nsim_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  nsm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = nsim_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (nsm, &api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (nsim_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (nsim, static) =
{
  .arc_name = "device-input",
  .node_name = "nsim",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "network delay simulator plugin",
};
/* *INDENT-ON* */

static uword
unformat_delay (unformat_input_t * input, va_list * args)
{
  f64 *result = va_arg (*args, f64 *);
  f64 tmp;

  if (unformat (input, "%f usec", &tmp))
    *result = tmp * 1e-6;
  else if (unformat (input, "%f msec", &tmp))
    *result = tmp * 1e-3;
  else if (unformat (input, "%f sec", &tmp))
    *result = tmp;
  else
    return 0;

  return 1;
}

static uword
unformat_bandwidth (unformat_input_t * input, va_list * args)
{
  f64 *result = va_arg (*args, f64 *);
  f64 tmp;

  if (unformat (input, "%f gbit", &tmp))
    *result = tmp * 1e9;
  else if (unformat (input, "%f gbyte", &tmp))
    *result = tmp * 8e9;
  else
    return 0;
  return 1;
}

static clib_error_t *
set_nsim_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  nsim_main_t *nsm = &nsim_main;
  u64 total_buffer_size_in_bytes, per_worker_buffer_size;
  u64 wheel_slots_per_worker;
  int i;
  f64 delay, bandwidth;
  int num_workers = vlib_num_workers ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "delay %U", unformat_delay, &delay))
	;
      else if (unformat (input, "bandwidth %U", unformat_bandwidth,
			 &bandwidth))
	;
      else
	break;
    }

  if (nsm->is_configured)
    {
      for (i = 0; i < vec_len (nsm->wheel_by_thread); i++)
	{
	  nsim_wheel_t *wp = nsm->wheel_by_thread[i];
	  munmap (wp, nsm->mmap_size);
	  nsm->wheel_by_thread[i] = 0;
	}
    }

  nsm->delay = delay;

  /* delay in seconds, bandwidth in bits/sec */
  total_buffer_size_in_bytes = (u32) ((delay * bandwidth) / 8.0) + 0.5;

  if (num_workers)
    per_worker_buffer_size = total_buffer_size_in_bytes / num_workers;
  else
    per_worker_buffer_size = total_buffer_size_in_bytes;

  wheel_slots_per_worker = per_worker_buffer_size / WHEEL_ENTRY_DATA_SIZE;
  wheel_slots_per_worker++;

  vlib_cli_output (vm, "Total buffer: %lld bytes, per worker %lld bytes",
		   total_buffer_size_in_bytes, per_worker_buffer_size);
  vlib_cli_output (vm, "%lld wheel slots per worker", wheel_slots_per_worker);

  vec_validate (nsm->wheel_by_thread, num_workers);
  vec_validate (nsm->buffer_indices_by_thread, num_workers);

  for (i = num_workers ? 1 : 0; i < num_workers + 1; i++)
    {
      nsim_wheel_t *wp;

      nsm->mmap_size = sizeof (nsim_wheel_t)
	+ wheel_slots_per_worker * sizeof (nsim_wheel_entry_t);

      wp = clib_mem_vm_map (0, nsm->mmap_size);
      ASSERT (wp != 0);
      wp->wheel_size = wheel_slots_per_worker;
      wp->cursize = 0;
      wp->head = 0;
      wp->tail = 0;
      wp->entries = (void *) (wp + 1);
      nsm->wheel_by_thread[i] = wp;
      vec_validate (nsm->buffer_indices_by_thread[i], VLIB_FRAME_SIZE - 1);
      _vec_len (nsm->buffer_indices_by_thread[i]) = 0;
    }

  vlib_worker_thread_barrier_sync (vm);

  /* turn on the ring scrapers */
  for (i = num_workers ? 1 : 0; i < num_workers + 1; i++)
    {
      vlib_main_t *this_vm = vlib_mains[i];

      vlib_node_set_state (this_vm, nsim_input_node.index,
			   VLIB_NODE_STATE_POLLING);
    }

  vlib_worker_thread_barrier_release (vm);

  nsm->is_configured = 1;

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_nsim_command, static) =
{
  .path = "set nsim",
  .short_help = "set nsim delay <time> bandwidth <bps>",
  .function = set_nsim_command_fn,
};
/* *INDENT-ON*/


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
