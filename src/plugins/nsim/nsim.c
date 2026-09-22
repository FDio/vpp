/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) <current-year> <your-organization>
 */

/* nsim.c - skeleton vpp engine plug-in */

/**
 * @file
 * @brief Network Delay Simulator
 */
/*? %%clicmd:group_label Network Delay Simulator %% ?*/

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <nsim/nsim.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <nsim/nsim.api_enum.h>
#include <nsim/nsim.api_types.h>

#define REPLY_MSG_ID_BASE nsm->msg_id_base
#include <vlibapi/api_helper_macros.h>

nsim_main_t nsim_main;

/* Action functions shared between message handlers and debug CLI */

int
nsim_cross_connect_enable_disable (nsim_main_t * nsm, u32 sw_if_index0,
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

  if (enable_disable)
    {
      /* Add graph arcs for the input / wheel scraper node */
      hw = vnet_get_hw_interface (nsm->vnet_main, sw_if_index0);
      nsm->output_next_index0 =
	vlib_node_add_next (nsm->vlib_main, nsim_input_node.index, hw->output_node_index);

      hw = vnet_get_hw_interface (nsm->vnet_main, sw_if_index1);
      nsm->output_next_index1 =
	vlib_node_add_next (nsm->vlib_main, nsim_input_node.index, hw->output_node_index);

      nsm->sw_if_index0 = sw_if_index0;
      nsm->sw_if_index1 = sw_if_index1;
      nsm->cross_connect_enabled = 1;
    }

  vnet_feature_enable_disable ("device-input", "nsim",
			       sw_if_index0, enable_disable, 0, 0);
  vnet_feature_enable_disable ("device-input", "nsim", sw_if_index1, enable_disable, 0, 0);

  if (!enable_disable)
    {
      nsm->cross_connect_enabled = 0;
      nsm->sw_if_index0 = nsm->sw_if_index1 = ~0;
    }

  return rv;
}

int
nsim_output_feature_enable_disable (nsim_main_t * nsm, u32 sw_if_index,
				    int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  if (nsm->is_configured == 0)
    return VNET_API_ERROR_CANNOT_ENABLE_DISABLE_FEATURE;

  /* Utterly wrong? */
  if (pool_is_free_index (nsm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (nsm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Add a graph arc from the wheel scraper to "interface-output-arc-end". The
   * delayed packet has already traversed "<ifname>-output" (the arc start node,
   * where TX offload ran and the pcap TX hook fired) on its way into nsim, so we
   * reinject past it, straight to the arc-end node that does the per-buffer TX
   * demux and populates the driver tx-frame scalar. This avoids re-running the
   * output arc -- in particular the pcap TX hook, which would otherwise capture
   * every shaped packet a second time. */
  vec_validate_init_empty (nsm->output_next_index_by_sw_if_index, sw_if_index, ~0);
  if (enable_disable && nsm->output_next_index_by_sw_if_index[sw_if_index] == ~0)
    {
      nsm->output_next_index_by_sw_if_index[sw_if_index] = vlib_node_add_next (
	nsm->vlib_main, nsim_input_node.index,
	vlib_get_node_by_name (nsm->vlib_main, (u8 *) "interface-output-arc-end")->index);
      nsm->n_output_features++;
    }

  vnet_feature_enable_disable ("interface-output", "nsim-output-feature", sw_if_index,
			       enable_disable, 0, 0);
  if (!enable_disable && nsm->output_next_index_by_sw_if_index[sw_if_index] != ~0)
    {
      nsm->output_next_index_by_sw_if_index[sw_if_index] = ~0;
      nsm->n_output_features--;
    }
  return rv;
}

static nsim_wheel_t *
nsim_wheel_alloc (u32 wheel_slots, u64 mmap_size)
{
  nsim_wheel_t *wp;

  wp = clib_mem_vm_alloc (mmap_size);
  ASSERT (wp != 0);
  wp->wheel_size = wheel_slots;
  wp->cursize = 0;
  wp->head = 0;
  wp->tail = 0;
  wp->last_tx_time = 0.0;
  wp->entries = (void *) (wp + 1);

  return wp;
}

static_always_inline u32
nsim_worker_seed (u32 seed, u32 thread_index, u32 stream)
{
  u32 x = seed ^ (thread_index * 0x9e3779b9) ^ stream;

  x ^= x >> 16;
  x *= 0x7feb352d;
  x ^= x >> 15;
  x *= 0x846ca68b;
  x ^= x >> 16;
  return x ? x : 1;
}

static void
nsim_worker_models_init (nsim_main_t *nsm)
{
  nsim_worker_t *nsw;
  u32 i;

  vec_foreach_index (i, nsm->workers)
    {
      nsw = vec_elt_at_index (nsm->workers, i);
      if (!nsw->wheel)
	continue;
      nsw->loss = nsm->loss_config;
      nsw->rate = nsm->rate_config;
      nsw->loss_seed = nsim_worker_seed (nsm->seed, i, 0x6c6f7373);
      nsw->reorder_seed = nsim_worker_seed (nsm->seed, i, 0x72656f72);
      nsw->rate_seed = nsim_worker_seed (nsm->seed, i, 0x72617465);
      nsw->batch_seed = nsim_worker_seed (nsm->seed, i, 0x62617463);
    }
}

static void
nsim_workers_free (nsim_worker_t *workers, u64 mmap_size)
{
  nsim_worker_t *nsw;

  vec_foreach (nsw, workers)
    {
      if (nsw->wheel)
	clib_mem_vm_free (nsw->wheel, mmap_size);
      if (nsw->reorder_wheel)
	clib_mem_vm_free (nsw->reorder_wheel, mmap_size);
    }
  vec_free (workers);
}

static u8
nsim_is_enabled (nsim_main_t *nsm)
{
  return nsm->cross_connect_enabled || nsm->n_output_features;
}

static u8
nsim_wheels_busy (nsim_main_t *nsm)
{
  nsim_worker_t *nsw;

  vec_foreach (nsw, nsm->workers)
    if ((nsw->wheel && nsw->wheel->cursize) || (nsw->reorder_wheel && nsw->reorder_wheel->cursize))
      return 1;
  return 0;
}

static int
nsim_configure (nsim_main_t *nsm, f64 bandwidth, f64 delay, u32 packet_size, f64 drop_fraction,
		f64 reorder_fraction, f64 reorder_delay, f64 buffer, f64 batch_interval,
		u32 batch_packets, nsim_batch_gap_t *batch_gaps, u8 n_batch_gaps, u32 seed)
{
  nsim_worker_t *new_workers = 0, *old_workers;
  u64 total_buffer_size_in_bytes, wheel_slots_per_wrk, mmap_size, old_mmap_size;
  f64 holding_interval;
  u32 pagesize = getpagesize ();
  int i, num_workers = vlib_num_workers ();
  vlib_main_t *vm = nsm->vlib_main;

  if (bandwidth == 0.0)
    return VNET_API_ERROR_INVALID_VALUE;

  if (delay == 0.0)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (packet_size < 64 || packet_size > 9000)
    return VNET_API_ERROR_INVALID_VALUE_3;

  if (reorder_fraction > 0.0 && delay == 0.0)
    return VNET_API_ERROR_INVALID_VALUE_4;

  if (nsim_is_enabled (nsm))
    return VNET_API_ERROR_INSTANCE_IN_USE;

  /* Disabling the feature stops new enqueues, but packets already scheduled
   * are allowed to drain. Do not orphan their buffers on reconfiguration. */
  if (nsm->is_configured)
    {
      vlib_worker_thread_barrier_sync (vm);
      if (nsim_wheels_busy (nsm))
	{
	  vlib_worker_thread_barrier_release (vm);
	  return VNET_API_ERROR_BUSY;
	}
      vlib_worker_thread_barrier_release (vm);
    }

  nsm->delay = delay;
  /* Uniform drop is the default loss model; the CLI may override it with a
   * richer model (burst/one-shot/targeted) after nsim_configure returns. */
  nsim_loss_model_uniform (&nsm->loss_config, drop_fraction);
  nsm->reorder_fraction = reorder_fraction;
  nsm->reorder_delay = reorder_delay;
  nsm->seed = seed;
  nsm->buffer_time = buffer;
  nsm->batch_interval = batch_interval;
  nsm->batch_packets = batch_packets;
  nsm->n_batch_gaps = n_batch_gaps;
  nsm->batch_max_gap = batch_interval;
  for (i = 0; i < n_batch_gaps; i++)
    {
      nsm->batch_gaps[i] = batch_gaps[i];
      nsm->batch_max_gap = clib_max (nsm->batch_max_gap, batch_gaps[i].interval);
    }
  /* Per-packet serialization time at the bottleneck rate. Only used by the
   * queued model (buffer > 0). bandwidth is bits/sec. */
  nsm->serialization_time = (f64) (packet_size * 8) / bandwidth;
  /* Constant rate by default; the CLI may install a time-varying rate model
   * after nsim_configure returns (queued model only). */
  nsim_rate_model_reset (&nsm->rate_config);

  /* Size every worker's wheel to hold the configured backlog. Workers model
   * independent links; a single flow must not lose queue capacity merely
   * because more workers are configured. In the default fixed-delay
   * model that backlog is one bandwidth-delay product; in the queued
   * (bufferbloat) model it is the configured buffer depth, which is decoupled
   * from the BDP so cwnd can grow well past it before the buffer overflows. */
  if (buffer > 0.0)
    total_buffer_size_in_bytes = ((buffer * bandwidth) / 8.0) + 0.5;
  else
    total_buffer_size_in_bytes = ((delay * bandwidth) / 8.0) + 0.5;
  holding_interval = nsm->batch_max_gap;
  total_buffer_size_in_bytes += ((holding_interval * bandwidth) / 8.0) + 0.5;

  wheel_slots_per_wrk = total_buffer_size_in_bytes / packet_size;
  wheel_slots_per_wrk++;

  /* Save these for the show command */
  nsm->bandwidth = bandwidth;
  nsm->packet_size = packet_size;
  nsm->wheel_slots_per_wrk = wheel_slots_per_wrk;

  mmap_size = sizeof (nsim_wheel_t) + wheel_slots_per_wrk * sizeof (nsim_wheel_entry_t);
  mmap_size = (mmap_size + pagesize - 1) & ~(pagesize - 1);
  vec_validate (new_workers, num_workers);

  /* Initialize the output scheduler wheels */
  i = (!nsm->poll_main_thread && num_workers) ? 1 : 0;
  for (; i < num_workers + 1; i++)
    {
      new_workers[i].wheel = nsim_wheel_alloc (wheel_slots_per_wrk, mmap_size);
      /* Side wheel for late-reordered packets, same geometry */
      if (reorder_fraction > 0.0)
	new_workers[i].reorder_wheel = nsim_wheel_alloc (wheel_slots_per_wrk, mmap_size);
    }

  vlib_worker_thread_barrier_sync (vm);

  old_workers = nsm->workers;
  old_mmap_size = nsm->mmap_size;
  nsm->workers = new_workers;
  nsm->mmap_size = mmap_size;
  nsim_worker_models_init (nsm);

  /* turn on the ring scrapers */
  i = (!nsm->poll_main_thread && num_workers) ? 1 : 0;
  for (; i < num_workers + 1; i++)
    {
      vlib_main_t *this_vm = vlib_get_main_by_index (i);

      vlib_node_set_state (this_vm, nsim_input_node.index,
			   VLIB_NODE_STATE_POLLING);
    }

  vlib_worker_thread_barrier_release (vm);

  nsim_workers_free (old_workers, old_mmap_size);

  nsm->is_configured = 1;
  return 0;
}

/*
 * enable or disable the cross-connect
 */
static clib_error_t *
nsim_cross_connect_enable_disable_command_fn (vlib_main_t * vm,
					      unformat_input_t * input,
					      vlib_cli_command_t * cmd)
{
  nsim_main_t *nsm = &nsim_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index0 = ~0;
  u32 sw_if_index1 = ~0;
  int enable_disable = 1;
  u32 tmp;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "disable"))
	enable_disable = 0;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
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

  unformat_free (line_input);

  if (sw_if_index0 == ~0 || sw_if_index1 == ~0)
    return clib_error_return (0, "Please specify two interfaces...");

  rv = nsim_cross_connect_enable_disable (nsm, sw_if_index0,
					  sw_if_index1, enable_disable);

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

static clib_error_t *
nsim_config (vlib_main_t * vm, unformat_input_t * input)
{
  nsim_main_t *nsm = &nsim_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "poll-main-thread"))
	{
	  nsm->poll_main_thread = 1;
	}
      else
	{
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (nsim_config, "nsim");

/*?
 * Enable or disable network simulation cross-connect on two interfaces
 * The network simulator must have already been configured, see
 * the "nsim_configure" command.
 *
 * Place the interfaces into a bridge group, to ensure that
 * interfaces are in promiscuous mode.
 *
 * @cliexpar
 * To enable or disable network simulation cross-connect
 * @clistart
 * nsim cross-connect enable-disable TenGigabitEthernet2/0/0 TenGigabitEthernet2/0
 * nsim cross-connect enable-disable TenGigabitEthernet2/0/0 TenGigabitEthernet2/0 disable
 * @cliend
 * @cliexcmd{nsim enable-disable <intfc> <intfc> [disable]}
?*/
VLIB_CLI_COMMAND (nsim_enable_disable_command, static) =
{
  .path = "nsim cross-connect enable-disable",
  .short_help =
  "nsim cross-connect enable-disable <interface-name-1> "
  "<interface-name-2> [disable]",
  .function = nsim_cross_connect_enable_disable_command_fn,
};

/* API message handler */
static void vl_api_nsim_cross_connect_enable_disable_t_handler
  (vl_api_nsim_cross_connect_enable_disable_t * mp)
{
  vl_api_nsim_cross_connect_enable_disable_reply_t *rmp;
  nsim_main_t *nsm = &nsim_main;
  int rv;
  u32 sw_if_index0, sw_if_index1;

  sw_if_index0 = clib_net_to_host_u32 (mp->sw_if_index0);
  sw_if_index1 = clib_net_to_host_u32 (mp->sw_if_index1);

  if (!vnet_sw_if_index_is_api_valid (sw_if_index0))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto bad_sw_if_index;
    }
  if (!vnet_sw_if_index_is_api_valid (sw_if_index1))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX_2;
      goto bad_sw_if_index;
    }

  rv = nsim_cross_connect_enable_disable (nsm, sw_if_index0, sw_if_index1,
					  (int) (mp->enable_disable));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_NSIM_CROSS_CONNECT_ENABLE_DISABLE_REPLY);
}

/* API message handler */
static void vl_api_nsim_output_feature_enable_disable_t_handler
  (vl_api_nsim_output_feature_enable_disable_t * mp)
{
  vl_api_nsim_output_feature_enable_disable_reply_t *rmp;
  nsim_main_t *nsm = &nsim_main;
  int rv;
  VALIDATE_SW_IF_INDEX (mp);

  rv = nsim_output_feature_enable_disable (nsm, ntohl (mp->sw_if_index),
					   (int) (mp->enable_disable));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_NSIM_OUTPUT_FEATURE_ENABLE_DISABLE_REPLY);
}

/* API message handler */
static void
vl_api_nsim_configure_t_handler (vl_api_nsim_configure_t * mp)
{
  vl_api_nsim_configure_reply_t *rmp;
  nsim_main_t *nsm = &nsim_main;
  f64 delay, bandwidth, packet_size, drop_fraction = 0.0, reorder_rate = 0.0;
  u32 packets_per_drop;
  int rv;

  delay = ((f64) (ntohl (mp->delay_in_usec))) * 1e-6;
  bandwidth = (f64) (clib_net_to_host_u64 (mp->bandwidth_in_bits_per_second));
  packet_size = (f64) (ntohl (mp->average_packet_size));

  packets_per_drop = ntohl (mp->packets_per_drop);
  if (packets_per_drop > 0)
    drop_fraction = 1.0 / (f64) (packets_per_drop);

  rv = nsim_configure (nsm, bandwidth, delay, packet_size, drop_fraction, reorder_rate,
		       reorder_rate > 0.0 ? delay : 0.0 /* reorder_delay */,
		       0.0 /* buffer: fixed-delay model */, 0.0 /* batch interval */,
		       0 /* batch packets: unlimited */, 0 /* batch gaps */, 0 /* number of gaps */,
		       nsm->seed);

  REPLY_MACRO (VL_API_NSIM_CONFIGURE_REPLY);
}

static void
vl_api_nsim_configure2_t_handler (vl_api_nsim_configure2_t * mp)
{
  vl_api_nsim_configure_reply_t *rmp;
  nsim_main_t *nsm = &nsim_main;
  f64 delay, bandwidth, packet_size, drop_fraction = 0.0, reorder_rate = 0.0;
  u32 packets_per_drop, packets_per_reorder;
  int rv;

  delay = ((f64) (ntohl (mp->delay_in_usec))) * 1e-6;
  bandwidth = (f64) (clib_net_to_host_u64 (mp->bandwidth_in_bits_per_second));
  packet_size = (f64) (ntohl (mp->average_packet_size));

  packets_per_drop = ntohl (mp->packets_per_drop);
  if (packets_per_drop > 0)
    drop_fraction = 1.0 / (f64) (packets_per_drop);

  packets_per_reorder = ntohl (mp->packets_per_reorder);
  if (packets_per_reorder > 0)
    reorder_rate = 1.0 / (f64) packets_per_reorder;

  rv = nsim_configure (nsm, bandwidth, delay, packet_size, drop_fraction, reorder_rate,
		       reorder_rate > 0.0 ? delay : 0.0 /* reorder_delay */,
		       0.0 /* buffer: fixed-delay model */, 0.0 /* batch interval */,
		       0 /* batch packets: unlimited */, 0 /* batch gaps */, 0 /* number of gaps */,
		       nsm->seed);

  REPLY_MACRO (VL_API_NSIM_CONFIGURE2_REPLY);
}


/*
 * enable or disable the output_feature
 */
static clib_error_t *
nsim_output_feature_enable_disable_command_fn (vlib_main_t * vm,
					       unformat_input_t * input,
					       vlib_cli_command_t * cmd)
{
  nsim_main_t *nsm = &nsim_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  int enable_disable = 1;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "disable"))
	enable_disable = 0;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 nsm->vnet_main, &sw_if_index))
	;
      else
	{
	  clib_error_t *error = clib_error_return (0, "unknown input `%U'",
						   format_unformat_error,
						   line_input);
	  unformat_free (line_input);
	  return error;
	}
    }

  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify one interface...");

  rv = nsim_output_feature_enable_disable (nsm, sw_if_index, enable_disable);

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
      return clib_error_return
	(0, "nsim_output_feature_enable_disable returned %d", rv);
    }
  return 0;
}

/*?
 * Enable or disable network simulation output feature on an interface
 * The network simulator must have already been configured, see
 * the "nsim_configure" command.
 *
 * @cliexpar
 * To enable or disable network simulation output feature
 * @clistart
 * nsim output-feature enable-disable TenGigabitEthernet2/0/0
 * nsim output-feature enable-disable TenGigabitEthernet2/0/0 disable
 * @cliend
 * @cliexcmd{nsim output-feature enable-disable <intfc> [disable]}
?*/
VLIB_CLI_COMMAND (nsim_output_feature_enable_disable_command, static) =
{
  .path = "nsim output-feature enable-disable",
  .short_help =
  "nsim output-feature enable-disable <interface-name> [disable]",
  .function = nsim_output_feature_enable_disable_command_fn,
};

#include <nsim/nsim.api.c>
static clib_error_t *
nsim_init (vlib_main_t * vm)
{
  nsim_main_t *nsm = &nsim_main;

  nsm->vlib_main = vm;
  nsm->vnet_main = vnet_get_main ();
  nsm->seed = 0x6e73696d;
  nsm->sw_if_index0 = nsm->sw_if_index1 = ~0;

  /* Ask for a correctly-sized block of API message decode slots */
  nsm->msg_id_base = setup_message_id_table ();
  nsm->arc_index = nsm->vnet_main->interface_main.output_feature_arc_index;
  return 0;
}

VLIB_INIT_FUNCTION (nsim_init);

VNET_FEATURE_INIT (nsim, static) =
{
  .arc_name = "device-input",
  .node_name = "nsim",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (nsim_feature, static) = {
  .arc_name = "interface-output",
  .node_name = "nsim-output-feature",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};

VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Network Delay Simulator",
};

static uword
unformat_delay (unformat_input_t * input, va_list * args)
{
  f64 *result = va_arg (*args, f64 *);
  f64 tmp;

  if (unformat (input, "%f us", &tmp))
    *result = tmp * 1e-6;
  else if (unformat (input, "%f ms", &tmp))
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
  else if (unformat (input, "%f gbps", &tmp))
    *result = tmp * 1e9;
  else if (unformat (input, "%f mbps", &tmp))
    *result = tmp * 1e6;
  else if (unformat (input, "%f kbps", &tmp))
    *result = tmp * 1e3;
  else if (unformat (input, "%f bps", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static u8 *
format_delay (u8 *s, va_list *args)
{
  f64 delay = va_arg (*args, f64);

  if (delay < 1e-3)
    s = format (s, "%.1f us", delay * 1e6);
  else if (delay < 1)
    s = format (s, "%.1f ms", delay * 1e3);
  else
    s = format (s, "%f sec", delay);

  return s;
}

static u8 *
format_bandwidth (u8 *s, va_list *args)
{
  f64 bandwidth = va_arg (*args, f64);

  if (bandwidth >= 1e9)
    s = format (s, "%.1f gbps", bandwidth / 1e9);
  else if (bandwidth >= 1e6)
    s = format (s, "%.1f mbps", bandwidth / 1e6);
  else if (bandwidth >= 1e3)
    s = format (s, "%.1f kbps", bandwidth / 1e3);
  else
    s = format (s, "%f bps", bandwidth);

  return s;
}

static u8 *
format_nsim_config (u8 * s, va_list * args)
{
  int verbose = va_arg (*args, int);
  nsim_main_t *nsm = &nsim_main;
  nsim_worker_t *nsw;
  u32 i;

  s = format (s, "configuration\n");
  s = format (s, " delay: %U\n", format_delay, nsm->delay);
  if (nsm->buffer_time > 0.0)
    s = format (s, " buffer: %U (queued/bufferbloat model)\n", format_delay, nsm->buffer_time);
  else
    s = format (s, " buffer: 1 bdp (fixed-delay model)\n");
  s = format (s, " loss model: %U\n", format_nsim_loss_model, &nsm->loss_config);
  if (nsm->rate_config.type != NSIM_RATE_NONE)
    s =
      format (s, " rate model: %U\n", format_nsim_rate_config, &nsm->rate_config, nsm->packet_size);
  if (nsm->reorder_fraction)
    s = format (s, " reorder fraction: %.5f delay up to %U\n", nsm->reorder_fraction, format_delay,
		nsm->reorder_delay);
  else
    s = format (s, " reorder fraction: 0\n");
  if (nsm->batch_interval > 0.0)
    {
      s = format (s, " batch interval: %U\n", format_delay, nsm->batch_interval);
      if (nsm->batch_packets)
	s = format (s, " batch packet budget: %u\n", nsm->batch_packets);
    }
  if (nsm->n_batch_gaps)
    {
      f64 probability = 0.0;

      s = format (s, " batch gap distribution:");
      for (i = 0; i < nsm->n_batch_gaps; i++)
	{
	  probability += nsm->batch_gaps[i].probability;
	  s = format (s, " %U %.5f", format_delay, nsm->batch_gaps[i].interval,
		      nsm->batch_gaps[i].probability);
	}
      s = format (s, " base %.5f\n", clib_max (1.0 - probability, 0.0));
    }
  s = format (s, " packet size: %u\n", nsm->packet_size);
  s = format (s, " worker wheel size: %u\n", nsm->wheel_slots_per_wrk);
  s = format (s, " throughput: %U\n", format_bandwidth, nsm->bandwidth);

  if (verbose)
    {
      f64 now = vlib_time_now (nsm->vlib_main);
      u64 total_memory = 0;

      s = format (s, " poll main thread: %u\n", nsm->poll_main_thread);
      s = format (s, " base seed: %u\n", nsm->seed);
      vec_foreach (nsw, nsm->workers)
	{
	  total_memory += nsw->wheel ? nsm->mmap_size : 0;
	  total_memory += nsw->reorder_wheel ? nsm->mmap_size : 0;
	}
      s = format (s, " memory: %U per wheel, %U total\n", format_memory_size, nsm->mmap_size,
		  format_memory_size, total_memory);
      vec_foreach_index (i, nsm->workers)
	{
	  nsw = vec_elt_at_index (nsm->workers, i);
	  if (!nsw->wheel)
	    continue;
	  s = format (s,
		      " worker %u: queue %u/%u service backlog %.3f ms reorder %u/%u seeds "
		      "loss %u reorder %u rate %u batch %u\n",
		      i, nsw->wheel->cursize, nsw->wheel->wheel_size,
		      clib_max (nsw->wheel->last_tx_time - now, 0.0) * 1e3,
		      nsw->reorder_wheel ? nsw->reorder_wheel->cursize : 0,
		      nsw->reorder_wheel ? nsw->reorder_wheel->wheel_size : 0, nsw->loss_seed,
		      nsw->reorder_seed, nsw->rate_seed, nsw->batch_seed);
	  s = format (s, "  counters: packets %llu drops %llu queue-full %llu reordered %llu\n",
		      nsw->packets, nsw->drops, nsw->queue_drops, nsw->reordered);
	  s = format (s, "  loss: %U\n", format_nsim_loss_model, &nsw->loss);
	  if (nsw->rate.type != NSIM_RATE_NONE)
	    s = format (s, "  rate: %U next transition %.6f\n", format_nsim_rate_model, &nsw->rate,
			nsm->packet_size, nsw->rate.next_transition);
	  if (nsm->batch_interval > 0.0)
	    s = format (s,
			"  batching: delayed %llu batches %llu extended %llu max gap %U "
			"max batch %u next %.6f\n",
			nsw->batch.delayed_packets + nsw->reorder_batch.delayed_packets,
			nsw->batch.batches + nsw->reorder_batch.batches,
			nsw->batch.extended_batches + nsw->reorder_batch.extended_batches,
			format_delay, clib_max (nsw->batch.max_gap, nsw->reorder_batch.max_gap),
			clib_max (nsw->batch.max_batch_size, nsw->reorder_batch.max_batch_size),
			clib_max (nsw->batch.next_boundary, nsw->reorder_batch.next_boundary));
	}
    }

  s = format (s, "\n");

  if (nsm->cross_connect_enabled)
    {
      s = format (s, "cross-connect\n %U and %U\n",
		  format_vnet_sw_if_index_name, nsm->vnet_main,
		  nsm->sw_if_index0, format_vnet_sw_if_index_name,
		  nsm->vnet_main, nsm->sw_if_index1);
    }
  else if (nsm->n_output_features)
    {
      int i;
      s = format (s, "output feature arcs to:\n");
      for (i = 0; i < vec_len (nsm->output_next_index_by_sw_if_index); i++)
	{
	  if (nsm->output_next_index_by_sw_if_index[i] != ~0)
	    s = format (s, " %U %u\n", format_vnet_sw_if_index_name,
			nsm->vnet_main, i, i);
	}
    }
  else
    {
      s = format (s, " nsim not enabled\n");
    }

  return s;
}

static clib_error_t *
set_nsim_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  f64 drop_fraction = 0.0, reorder_fraction = 0.0, reorder_delay = 0.0;
  f64 delay = 0.0, bandwidth = 0.0, buffer = 0.0, batch_interval = 0.0;
  nsim_batch_gap_t batch_gaps[NSIM_MAX_BATCH_GAPS] = {};
  f64 batch_gap_interval, batch_gap_probability = 0.0, batch_gap_weight;
  f64 burst_prob = 0.0, burst_dur = 0.0, drop_once_at = 0.0, drop_once_dur = 0.0;
  f64 rate_stall_bw = 0.0, rate_good_dwell = 0.0, rate_stall_dwell = 0.0;
  f64 rate_cycle_bw = 0.0, rate_cycle_good = 0.0, rate_cycle_bad = 0.0;
  u32 packets_per_drop, packets_per_reorder, packet_size = 1500, batch_packets = 0;
  u32 drop_seq_offset = 0, drop_seq_rxt = 0;
  u8 drop_seq_set = 0, wifi_preset = 0, rate_cycle_set = 0, n_batch_gaps = 0;
  nsim_main_t *nsm = &nsim_main;
  u32 seed = nsm->seed;
  int rv;

  if (nsim_is_enabled (nsm))
    return clib_error_return (0, "disable nsim before reconfiguring it");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "delay %U", unformat_delay, &delay))
	;
      else if (unformat (input, "bandwidth %U", unformat_bandwidth,
			 &bandwidth))
	;
      else if (unformat (input, "buffer %U", unformat_delay, &buffer))
	;
      else if (unformat (input, "batch-interval %U", unformat_delay, &batch_interval))
	;
      else if (unformat (input, "batch-packets %u", &batch_packets))
	;
      else if (unformat (input, "batch-gap %U probability %f", unformat_delay, &batch_gap_interval,
			 &batch_gap_weight))
	{
	  if (n_batch_gaps == NSIM_MAX_BATCH_GAPS)
	    return clib_error_return (0, "at most %u batch gaps may be configured",
				      NSIM_MAX_BATCH_GAPS);
	  batch_gaps[n_batch_gaps].interval = batch_gap_interval;
	  batch_gaps[n_batch_gaps].probability = batch_gap_weight;
	  n_batch_gaps++;
	}
      else if (unformat (input, "packet-size %u", &packet_size))
	;
      else if (unformat (input, "packets-per-drop %d", &packets_per_drop))
	{
	  if (packets_per_drop > 0)
	    drop_fraction = 1.0 / ((f64) packets_per_drop);
	}
      else if (unformat (input, "packets-per-reorder %d",
			 &packets_per_reorder))
	{
	  if (packets_per_reorder > 0)
	    reorder_fraction = 1.0 / ((f64) packets_per_reorder);
	}
      else if (unformat (input, "drop-fraction %f", &drop_fraction))
	{
	  if (drop_fraction < 0.0 || drop_fraction > 1.0)
	    return clib_error_return
	      (0, "drop fraction must be between zero and 1");
	}
      else if (unformat (input, "reorder-fraction %f", &reorder_fraction))
	{
	  if (reorder_fraction < 0.0 || reorder_fraction > 1.0)
	    return clib_error_return
	      (0, "reorder fraction must be between zero and 1");
	}
      else if (unformat (input, "reorder-delay %U", unformat_delay, &reorder_delay))
	;
      else if (unformat (input, "burst-loss-prob %f", &burst_prob))
	{
	  if (burst_prob < 0.0 || burst_prob > 1.0)
	    return clib_error_return (0, "burst loss probability must be between zero and 1");
	}
      else if (unformat (input, "burst-duration %U", unformat_delay, &burst_dur))
	;
      else if (unformat (input, "drop-once after %U for %U", unformat_delay, &drop_once_at,
			 unformat_delay, &drop_once_dur))
	;
      else if (unformat (input, "drop-seq %u retransmits %u", &drop_seq_offset, &drop_seq_rxt))
	drop_seq_set = 1;
      else if (unformat (input, "drop-seq %u", &drop_seq_offset))
	drop_seq_set = 1;
      else if (unformat (input, "rate-stall bandwidth %U every %U for %U", unformat_bandwidth,
			 &rate_stall_bw, unformat_delay, &rate_good_dwell, unformat_delay,
			 &rate_stall_dwell))
	;
      else if (unformat (input, "rate-cycle bandwidth %U good %U bad %U", unformat_bandwidth,
			 &rate_cycle_bw, unformat_delay, &rate_cycle_good, unformat_delay,
			 &rate_cycle_bad))
	rate_cycle_set = 1;
      else if (unformat (input, "seed %u", &seed))
	;
      else if (unformat (input, "wifi"))
	wifi_preset = 1;
      else if (unformat (input, "poll-main-thread"))
	nsm->poll_main_thread = 1;
      else
	break;
    }

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);

  /* Default the reorder displacement to the base delay if reorder is on but no
   * explicit reorder-delay was given */
  if (reorder_fraction > 0.0 && reorder_delay == 0.0)
    reorder_delay = delay;
  if (batch_interval < 0.0)
    return clib_error_return (0, "batch interval must not be negative");
  if (n_batch_gaps && batch_interval <= 0.0)
    return clib_error_return (0, "batch gaps require 'batch-interval <time>'");
  if (batch_packets && batch_interval <= 0.0)
    return clib_error_return (0, "batch packet budget requires 'batch-interval <time>'");
  for (u32 i = 0; i < n_batch_gaps; i++)
    {
      if (batch_gaps[i].interval < batch_interval)
	return clib_error_return (0, "batch gaps must not be shorter than the batch interval");
      if (batch_gaps[i].probability <= 0.0 || batch_gaps[i].probability > 1.0)
	return clib_error_return (0, "batch gap probability must be between zero and 1");
      batch_gap_probability += batch_gaps[i].probability;
    }
  if (batch_gap_probability > 1.0 + 1e-9)
    return clib_error_return (0, "batch gap probabilities exceed 1");
  if (rate_cycle_set && (wifi_preset || rate_stall_bw > 0.0))
    return clib_error_return (0, "configure only one rate model");
  if ((rate_cycle_set || wifi_preset || rate_stall_bw > 0.0) && buffer <= 0.0)
    return clib_error_return (0, "rate model requires the queued model; set 'buffer <time>'");
  if (rate_cycle_set && (rate_cycle_bw <= 0.0 || rate_cycle_bw >= bandwidth ||
			 rate_cycle_good <= 0.0 || rate_cycle_bad <= 0.0))
    return clib_error_return (0, "rate cycle requires a lower bad-state bandwidth and positive "
				 "good/bad durations");
  if ((wifi_preset || rate_stall_bw > 0.0) && bandwidth > 0.0 &&
      (rate_stall_bw > 0.0 ? rate_stall_bw : 6e6) >= bandwidth)
    return clib_error_return (0, "stall bandwidth must be below link bandwidth");

  rv = nsim_configure (nsm, bandwidth, delay, packet_size, drop_fraction, reorder_fraction,
		       reorder_delay, buffer, batch_interval, batch_packets, batch_gaps,
		       n_batch_gaps, seed);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "invalid bandwidth %.2f", bandwidth);

    case VNET_API_ERROR_INVALID_VALUE_2:
      return clib_error_return (0, "invalid delay %.2f", delay);

    case VNET_API_ERROR_INVALID_VALUE_3:
      return clib_error_return (0, "invalid packet size %.2f", packet_size);

    case VNET_API_ERROR_INVALID_VALUE_4:
      return clib_error_return (0, "invalid reorder fraction %.3f for "
				"delay %.2f", reorder_fraction, delay);

    case VNET_API_ERROR_INSTANCE_IN_USE:
      return clib_error_return (0, "disable nsim before reconfiguring it");

    case VNET_API_ERROR_BUSY:
      return clib_error_return (0, "nsim still has scheduled packets");

    default:
      return clib_error_return (0, "error %d", rv);

    case 0:
      break;
    }

  /* Select the loss model. nsim_configure already installed uniform drop from
   * drop_fraction; a richer model specified on the same line overrides it. Only
   * one model is active; pick the most specific requested. */
  if (drop_seq_set)
    nsim_loss_model_target_seq (&nsm->loss_config, drop_seq_offset, drop_seq_rxt);
  else if (drop_once_dur > 0.0)
    nsim_loss_model_once (&nsm->loss_config, drop_once_at, drop_once_dur);
  else if (burst_prob > 0.0)
    nsim_loss_model_burst (&nsm->loss_config, burst_prob, burst_dur);
  /* else: keep the uniform model from nsim_configure. */

  /* Time-varying bottleneck rate (queued model only). The `wifi` alias fills
   * defaults characteristic of a wireless link -- long good stretches broken by
   * occasional multi-hundred-ms rate collapses -- which an explicit rate-stall
   * spec then overrides. */
  if (rate_cycle_set)
    nsim_rate_model_cycle (&nsm->rate_config, nsm->serialization_time,
			   (f64) (packet_size * 8) / rate_cycle_bw, rate_cycle_good,
			   rate_cycle_bad);
  else if (wifi_preset || rate_stall_bw > 0.0)
    {
      /* wifi preset: mostly at full rate (~8 s good stretches) with brief
       * (~250 ms) collapses to a low MCS / heavy-retransmit rate (6 mbps) --
       * ~3% stalled. A stall bottoms out at a few mbps, not ~0, so the queue
       * still drains and the induced RTT spike stays bounded to a few seconds
       * for a typical window. Any field may be overridden on the same line. */
      f64 good_dwell = rate_good_dwell > 0.0 ? rate_good_dwell : 8.0;
      f64 stall_dwell = rate_stall_dwell > 0.0 ? rate_stall_dwell : 0.25;
      f64 stall_bw = rate_stall_bw > 0.0 ? rate_stall_bw : 6e6;

      nsim_rate_model_markov (&nsm->rate_config, nsm->serialization_time,
			      (f64) (packet_size * 8) / stall_bw, good_dwell, stall_dwell);
    }

  /* Publish the final CLI-selected model templates atomically. */
  vlib_worker_thread_barrier_sync (vm);
  nsim_worker_models_init (nsm);
  vlib_worker_thread_barrier_release (vm);

  vlib_cli_output (vm, "%U", format_nsim_config, 1);

  return 0;
}

/*?
 * Configure the network simulation cross-connect
 * Once the simulator is configured, use the "nsim enable-disable" command
 * to set up a cross-connect with the supplied delay characteristics.
 *
 * The cross connect configuration may be changed without restarting vpp
 * but it is good practice to shut down the interfaces.
 *
 * @cliexpar
 * To configure the network delay simulator:
 * @clistart
 * set nsim delay 10.0 ms bandwidth 5.5 gbit packet-size 128
 *
 * @cliend
 * @cliexcmd{set nsim delay <nn> bandwidth <bb> packet-size <nn>}
?*/
VLIB_CLI_COMMAND (set_nsim_command, static) = {
  .path = "set nsim",
  .short_help = "set nsim delay <time> bandwidth <bps> packet-size <nbytes>\n"
		"    [buffer <time>] [batch-interval <time>] [batch-packets <count>]\n"
		"    [batch-gap <time> probability <f64>]\n"
		"    [packets-per-drop <nn>] "
		"[drop-fraction <f64: 0.0 - 1.0>]\n"
		"    [seed <u32>]\n"
		"    [wifi | rate-stall bandwidth <bps> every <time> for <time> |\n"
		"     rate-cycle bandwidth <bad-bps> good <time> bad <time>]",
  .function = set_nsim_command_fn,
};

static clib_error_t *
show_nsim_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  nsim_main_t *nsm = &nsim_main;
  int verbose = 0;

  if (nsm->is_configured == 0)
    return clib_error_return (0, "Network simulator not configured");

  if (unformat (input, "verbose"))
    verbose = 1;

  vlib_cli_output (vm, "%U", format_nsim_config, verbose);

  return 0;
}

/*?
 * Display state info for the network delay simulator.
 *
 * @cliexpar
 * To display the state of the network simulator
 * @clistart
 * show nsim verbose
 * Network simulator cross-connects TenGigabitEthernet2/0/0 and TenGigabitEthernet2/0/1
 * ...inserting link delay of 10.00 ms, 20.00 ms round-trip
 *  Configured bandwidth: 10.10 gbit/sec
 *  Configured packet size: 128
 *  Sim uses 157814784 bytes total
 * @cliend
 * @cliexcmd{show nsim}
?*/

VLIB_CLI_COMMAND (show_nsim_command, static) = {
  .path = "show nsim",
  .short_help = "Display network delay simulator configuration",
  .function = show_nsim_command_fn,
};
