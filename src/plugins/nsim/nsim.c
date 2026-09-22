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

  enable_disable = !!enable_disable;
  if (nsm->sw_if_index0 != ~0 &&
      !((sw_if_index0 == nsm->sw_if_index0 && sw_if_index1 == nsm->sw_if_index1) ||
	(sw_if_index0 == nsm->sw_if_index1 && sw_if_index1 == nsm->sw_if_index0)))
    return VNET_API_ERROR_INSTANCE_IN_USE;
  if (enable_disable == (nsm->sw_if_index0 != ~0))
    return 0;

  if (enable_disable)
    {
      /* Add graph arcs for the input / wheel scraper node */
      hw = vnet_get_hw_interface (nsm->vnet_main, sw_if_index0);
      nsm->output_next_index0 =
	vlib_node_add_next (nsm->vlib_main, nsim_input_node.index, hw->output_node_index);

      hw = vnet_get_hw_interface (nsm->vnet_main, sw_if_index1);
      nsm->output_next_index1 =
	vlib_node_add_next (nsm->vlib_main, nsim_input_node.index, hw->output_node_index);

      /* Forwarding state must be visible before the features are enabled. */
      nsm->sw_if_index0 = sw_if_index0;
      nsm->sw_if_index1 = sw_if_index1;
    }
  else
    {
      sw_if_index0 = nsm->sw_if_index0;
      sw_if_index1 = nsm->sw_if_index1;
    }

  rv = vnet_feature_enable_disable ("device-input", "nsim", sw_if_index0, enable_disable, 0, 0);
  if (rv)
    goto done;
  rv = vnet_feature_enable_disable ("device-input", "nsim", sw_if_index1, enable_disable, 0, 0);
  if (rv)
    {
      vnet_feature_enable_disable ("device-input", "nsim", sw_if_index0, !enable_disable, 0, 0);
      goto done;
    }

  if (!enable_disable)
    {
      nsm->sw_if_index0 = nsm->sw_if_index1 = ~0;
    }

done:
  if (rv && enable_disable)
    nsm->sw_if_index0 = nsm->sw_if_index1 = ~0;
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
  enable_disable = !!enable_disable;
  if (enable_disable == (nsm->output_next_index_by_sw_if_index[sw_if_index] != ~0))
    return 0;

  if (enable_disable)
    nsm->output_next_index_by_sw_if_index[sw_if_index] = vlib_node_add_next (
      nsm->vlib_main, nsim_input_node.index,
      vlib_get_node_by_name (nsm->vlib_main, (u8 *) "interface-output-arc-end")->index);

  rv = vnet_feature_enable_disable ("interface-output", "nsim-output-feature", sw_if_index,
				    enable_disable, 0, 0);
  if (rv)
    {
      if (enable_disable)
	nsm->output_next_index_by_sw_if_index[sw_if_index] = ~0;
      return rv;
    }
  if (!enable_disable)
    nsm->output_next_index_by_sw_if_index[sw_if_index] = ~0;
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
      clib_memset (&nsw->model, 0, sizeof (nsw->model));
      nsw->loss_seed = nsim_worker_seed (nsm->seed, i, 0x6c6f7373);
      nsw->reorder_seed = nsim_worker_seed (nsm->seed, i, 0x72656f72);
      nsw->reorder_delay_seed = nsim_worker_seed (nsm->seed, i, 0x72646c79);
      nsw->model.rate_seed = nsim_worker_seed (nsm->seed, i, 0x72617465);
      nsw->model.batch_seed = nsim_worker_seed (nsm->seed, i, 0x62617463);
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
      vec_free (nsw->service_departures);
    }
  vec_free (workers);
}

static u8
nsim_is_enabled (nsim_main_t *nsm)
{
  u32 *next;

  if (nsm->sw_if_index0 != ~0)
    return 1;
  vec_foreach (next, nsm->output_next_index_by_sw_if_index)
    if (*next != ~0)
      return 1;
  return 0;
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
nsim_configure (nsim_main_t *nsm, f64 bandwidth, f64 delay, u32 packet_size,
		const nsim_loss_model_t *loss, f64 reorder_fraction, f64 reorder_delay,
		const nsim_model_config_t *model, u32 seed, u32 poll_main_thread)
{
  nsim_worker_t *new_workers = 0, *old_workers;
  u64 queue_slots_per_wrk, wheel_slots_per_wrk, mmap_size, old_mmap_size;
  u32 pagesize = getpagesize ();
  int i, num_workers = vlib_num_workers ();
  vlib_main_t *vm = nsm->vlib_main;

  if (bandwidth <= 0.0)
    return VNET_API_ERROR_INVALID_VALUE;

  if (delay <= 0.0)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (packet_size < 64 || packet_size > 9000)
    return VNET_API_ERROR_INVALID_VALUE_3;

  if (reorder_fraction < 0.0 || reorder_fraction > 1.0 || reorder_delay < 0.0)
    return VNET_API_ERROR_INVALID_VALUE_4;

  if (reorder_fraction > 0.0 && model->batch.interval > 0.0)
    return VNET_API_ERROR_UNSUPPORTED;

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

  queue_slots_per_wrk = nsim_model_queue_slots (model, bandwidth, packet_size);
  wheel_slots_per_wrk = nsim_model_wheel_slots (
    model, bandwidth, delay, reorder_fraction > 0.0 ? reorder_delay : 0.0, packet_size);
  if (queue_slots_per_wrk > CLIB_U32_MAX || wheel_slots_per_wrk > CLIB_U32_MAX)
    return VNET_API_ERROR_INVALID_MEMORY_SIZE;

  nsm->delay = delay;
  nsm->loss_config = *loss;
  nsm->reorder_fraction = reorder_fraction;
  nsm->reorder_delay = reorder_delay;
  nsm->seed = seed;
  nsm->model = *model;

  /* Save these for the show command */
  nsm->bandwidth = bandwidth;
  nsm->packet_size = packet_size;
  nsm->queue_slots_per_wrk = queue_slots_per_wrk;
  nsm->wheel_slots_per_wrk = wheel_slots_per_wrk;

  mmap_size = sizeof (nsim_wheel_t) + wheel_slots_per_wrk * sizeof (nsim_wheel_entry_t);
  mmap_size = (mmap_size + pagesize - 1) & ~(pagesize - 1);
  vec_validate (new_workers, num_workers);

  /* Initialize the output scheduler wheels */
  i = (!poll_main_thread && num_workers) ? 1 : 0;
  for (; i < num_workers + 1; i++)
    {
      new_workers[i].wheel = nsim_wheel_alloc (wheel_slots_per_wrk, mmap_size);
      if (queue_slots_per_wrk)
	vec_validate (new_workers[i].service_departures, queue_slots_per_wrk - 1);
      /* Side wheel for late-reordered packets, same geometry */
      if (reorder_fraction > 0.0)
	new_workers[i].reorder_wheel = nsim_wheel_alloc (wheel_slots_per_wrk, mmap_size);
    }

  vlib_worker_thread_barrier_sync (vm);

  old_workers = nsm->workers;
  old_mmap_size = nsm->mmap_size;
  nsm->workers = new_workers;
  nsm->mmap_size = mmap_size;
  nsm->poll_main_thread = poll_main_thread;
  nsim_worker_models_init (nsm);

  /* Match each scraper's state to the newly installed worker context. */
  for (i = 0; i < num_workers + 1; i++)
    {
      vlib_main_t *this_vm = vlib_get_main_by_index (i);

      vlib_node_set_state (this_vm, nsim_input_node.index,
			   new_workers[i].wheel ? VLIB_NODE_STATE_POLLING :
						  VLIB_NODE_STATE_DISABLED);
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
vl_api_nsim_configure_t_handler (vl_api_nsim_configure_t *mp)
{
  vl_api_nsim_configure_reply_t *rmp;
  nsim_main_t *nsm = &nsim_main;
  nsim_model_spec_t model_spec = {};
  nsim_model_config_t model;
  nsim_loss_model_t loss;
  f64 delay, bandwidth, drop_fraction = 0.0, reorder_rate = 0.0;
  u32 packet_size, packets_per_drop;
  int rv;

  delay = ((f64) (ntohl (mp->delay_in_usec))) * 1e-6;
  bandwidth = (f64) (clib_net_to_host_u64 (mp->bandwidth_in_bits_per_second));
  packet_size = ntohl (mp->average_packet_size);

  packets_per_drop = ntohl (mp->packets_per_drop);
  if (packets_per_drop > 0)
    drop_fraction = 1.0 / (f64) (packets_per_drop);

  nsim_loss_model_uniform (&loss, drop_fraction);
  nsim_model_configure (&model, &model_spec, bandwidth, packet_size);
  rv = nsim_configure (nsm, bandwidth, delay, packet_size, &loss, reorder_rate,
		       reorder_rate > 0.0 ? delay : 0.0, &model, nsm->seed, nsm->poll_main_thread);

  REPLY_MACRO (VL_API_NSIM_CONFIGURE_REPLY);
}

static void
vl_api_nsim_configure2_t_handler (vl_api_nsim_configure2_t *mp)
{
  vl_api_nsim_configure_reply_t *rmp;
  nsim_main_t *nsm = &nsim_main;
  nsim_model_spec_t model_spec = {};
  nsim_model_config_t model;
  nsim_loss_model_t loss;
  f64 delay, bandwidth, drop_fraction = 0.0, reorder_rate = 0.0;
  u32 packet_size, packets_per_drop, packets_per_reorder;
  int rv;

  delay = ((f64) (ntohl (mp->delay_in_usec))) * 1e-6;
  bandwidth = (f64) (clib_net_to_host_u64 (mp->bandwidth_in_bits_per_second));
  packet_size = ntohl (mp->average_packet_size);

  packets_per_drop = ntohl (mp->packets_per_drop);
  if (packets_per_drop > 0)
    drop_fraction = 1.0 / (f64) (packets_per_drop);

  packets_per_reorder = ntohl (mp->packets_per_reorder);
  if (packets_per_reorder > 0)
    reorder_rate = 1.0 / (f64) packets_per_reorder;

  nsim_loss_model_uniform (&loss, drop_fraction);
  nsim_model_configure (&model, &model_spec, bandwidth, packet_size);
  rv = nsim_configure (nsm, bandwidth, delay, packet_size, &loss, reorder_rate,
		       reorder_rate > 0.0 ? delay : 0.0, &model, nsm->seed, nsm->poll_main_thread);

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
nsim_init (vlib_main_t *vm)
{
  nsim_main_t *nsm = &nsim_main;

  nsm->vlib_main = vm;
  nsm->vnet_main = vnet_get_main ();
  nsm->seed = 0x6e73696d;
  nsm->sw_if_index0 = nsm->sw_if_index1 = ~0;

  /* Ask for a correctly-sized block of API message decode slots */
  nsm->msg_id_base = setup_message_id_table ();
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

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Network Delay Simulator",
};

uword
unformat_nsim_delay (unformat_input_t *input, va_list *args)
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

uword
unformat_nsim_bandwidth (unformat_input_t *input, va_list *args)
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

static u32
nsim_service_queue_occupancy (const nsim_worker_t *nsw, f64 now)
{
  u32 head = nsw->service_head, count = nsw->service_cursize;

  /* Verbose diagnostics are a best-effort live snapshot. Do not stop workers
   * merely to make queue and wheel counters mutually atomic. */
  while (count && nsw->service_departures[head] <= now)
    {
      if (++head == vec_len (nsw->service_departures))
	head = 0;
      count--;
    }
  return count;
}

static u8 *
format_nsim_config (u8 *s, va_list *args)
{
  int verbose = va_arg (*args, int);
  nsim_main_t *nsm = &nsim_main;
  nsim_worker_t *nsw;
  u32 i;

  s = format (s, "configuration\n");
  s = format (s, " delay: %U\n", format_delay, nsm->delay);
  s = format (s, "%U", format_nsim_model_config, &nsm->model, nsm->packet_size);
  s = format (s, " loss model: %U\n", format_nsim_loss_config, &nsm->loss_config);
  if (nsm->reorder_fraction)
    s = format (s, " reorder fraction: %.5f delay up to %U\n", nsm->reorder_fraction, format_delay,
		nsm->reorder_delay);
  else
    s = format (s, " reorder fraction: 0\n");
  s = format (s, " packet size: %u\n", nsm->packet_size);
  if (nsm->queue_slots_per_wrk)
    {
      f64 good_time = nsm->queue_slots_per_wrk * nsm->model.serialization_time;

      s = format (s, " worker bottleneck queue size: %u packets (%llu nominal bytes, %U",
		  nsm->queue_slots_per_wrk, (u64) nsm->queue_slots_per_wrk * nsm->packet_size,
		  format_delay, good_time);
      if (nsm->model.rate.type != NSIM_RATE_NONE)
	s = format (s, " good / %U bad", format_delay,
		    nsm->queue_slots_per_wrk * nsm->model.rate.bad_ser);
      s = format (s, ")\n");
    }
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
	  total_memory += nsw->service_departures ? vec_mem_size (nsw->service_departures) : 0;
	}
      s = format (s, " memory: %U per wheel, %U total\n", format_memory_size, nsm->mmap_size,
		  format_memory_size, total_memory);
      vec_foreach_index (i, nsm->workers)
	{
	  nsw = vec_elt_at_index (nsm->workers, i);
	  if (!nsw->wheel)
	    continue;
	  s = format (s,
		      " worker %u: queue %u/%u service backlog %.3f ms storage %u/%u reorder %u/%u "
		      "seeds loss %u reorder %u reorder-delay %u rate %u batch %u\n",
		      i, nsim_service_queue_occupancy (nsw, now), nsm->queue_slots_per_wrk,
		      clib_max (nsw->wheel->last_tx_time - now, 0.0) * 1e3, nsw->wheel->cursize,
		      nsw->wheel->wheel_size, nsw->reorder_wheel ? nsw->reorder_wheel->cursize : 0,
		      nsw->reorder_wheel ? nsw->reorder_wheel->wheel_size : 0, nsw->loss_seed,
		      nsw->reorder_seed, nsw->reorder_delay_seed, nsw->model.rate_seed,
		      nsw->model.batch_seed);
	  s = format (
	    s,
	    "  counters: packets %llu drops %llu queue-full %llu reordered %llu transmitted %llu\n",
	    nsw->packets, nsw->drops, nsw->queue_drops, nsw->reordered, nsw->transmitted);
	  s = format (s, "  peaks: queue %u/%u service backlog %.3f ms storage %u/%u\n",
		      nsw->max_service_cursize, nsm->queue_slots_per_wrk,
		      nsw->max_service_backlog * 1e3, nsw->max_storage_cursize,
		      nsw->wheel->wheel_size);
	  s = format (s, "  loss: %U\n", format_nsim_loss_model, &nsw->loss);
	  s = format (s, "%U", format_nsim_model_state, &nsm->model, &nsw->model, nsm->packet_size);
	}
    }

  s = format (s, "\n");

  if (nsm->sw_if_index0 != ~0)
    {
      s =
	format (s, "cross-connect\n %U and %U\n", format_vnet_sw_if_index_name, nsm->vnet_main,
		nsm->sw_if_index0, format_vnet_sw_if_index_name, nsm->vnet_main, nsm->sw_if_index1);
    }
  else if (nsim_is_enabled (nsm))
    {
      int i;
      s = format (s, "output feature arcs to:\n");
      for (i = 0; i < vec_len (nsm->output_next_index_by_sw_if_index); i++)
	{
	  if (nsm->output_next_index_by_sw_if_index[i] != ~0)
	    s = format (s, " %U %u\n", format_vnet_sw_if_index_name, nsm->vnet_main, i, i);
	}
    }
  else
    {
      s = format (s, " nsim not enabled\n");
    }

  return s;
}

static clib_error_t *
set_nsim_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  f64 reorder_fraction = 0.0, reorder_delay = 0.0;
  f64 delay = 0.0, bandwidth = 0.0;
  nsim_model_spec_t model_spec = {};
  nsim_model_config_t model;
  nsim_loss_spec_t loss_spec = {};
  nsim_loss_model_t loss;
  i32 packets_per_reorder;
  u32 packet_size = 1500;
  nsim_main_t *nsm = &nsim_main;
  clib_error_t *error;
  u32 seed = nsm->seed;
  u32 poll_main_thread = nsm->poll_main_thread;
  int rv;

  if (nsim_is_enabled (nsm))
    return clib_error_return (0, "disable nsim before reconfiguring it");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "delay %U", unformat_nsim_delay, &delay))
	;
      else if (unformat (input, "bandwidth %U", unformat_nsim_bandwidth, &bandwidth))
	;
      else if (unformat (input, "%U", unformat_nsim_model_spec, &model_spec))
	;
      else if (unformat (input, "%U", unformat_nsim_loss_spec, &loss_spec))
	;
      else if (unformat (input, "packet-size %u", &packet_size))
	;
      else if (unformat (input, "packets-per-reorder %d", &packets_per_reorder))
	{
	  if (packets_per_reorder < 0)
	    return clib_error_return (0, "packets per reorder must not be negative");
	  if (packets_per_reorder > 0)
	    reorder_fraction = 1.0 / ((f64) packets_per_reorder);
	}
      else if (unformat (input, "reorder-fraction %f", &reorder_fraction))
	{
	  if (reorder_fraction < 0.0 || reorder_fraction > 1.0)
	    return clib_error_return (0, "reorder fraction must be between zero and 1");
	}
      else if (unformat (input, "reorder-delay %U", unformat_nsim_delay, &reorder_delay))
	;
      else if (unformat (input, "seed %u", &seed))
	;
      else if (unformat (input, "poll-main-thread"))
	poll_main_thread = 1;
      else
	break;
    }

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);

  /* Default the reorder displacement to the base delay if reorder is on but no
   * explicit reorder-delay was given */
  if (reorder_fraction > 0.0 && reorder_delay == 0.0)
    reorder_delay = delay;
  if ((error = nsim_loss_validate (&loss_spec)))
    return error;
  if ((error = nsim_model_validate (&model_spec, bandwidth)))
    return error;
  if (reorder_fraction > 0.0 && model_spec.batch_interval > 0.0)
    return clib_error_return (0, "release batching cannot be combined with packet reordering");

  nsim_loss_configure (&loss, &loss_spec);
  nsim_model_configure (&model, &model_spec, bandwidth, packet_size);

  rv = nsim_configure (nsm, bandwidth, delay, packet_size, &loss, reorder_fraction, reorder_delay,
		       &model, seed, poll_main_thread);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "invalid bandwidth %.2f", bandwidth);

    case VNET_API_ERROR_INVALID_VALUE_2:
      return clib_error_return (0, "invalid delay %.2f", delay);

    case VNET_API_ERROR_INVALID_VALUE_3:
      return clib_error_return (0, "invalid packet size %u", packet_size);

    case VNET_API_ERROR_INVALID_VALUE_4:
      return clib_error_return (0,
				"invalid reorder fraction %.3f for "
				"delay %.2f",
				reorder_fraction, delay);

    case VNET_API_ERROR_INSTANCE_IN_USE:
      return clib_error_return (0, "disable nsim before reconfiguring it");

    case VNET_API_ERROR_BUSY:
      return clib_error_return (0, "nsim still has scheduled packets");

    case VNET_API_ERROR_INVALID_MEMORY_SIZE:
      return clib_error_return (0, "nsim wheel is too large");

    case VNET_API_ERROR_UNSUPPORTED:
      return clib_error_return (0, "release batching cannot be combined with packet reordering");

    default:
      return clib_error_return (0, "error %d", rv);

    case 0:
      break;
    }

  vlib_cli_output (vm, "%U", format_nsim_config, 1);

  return 0;
}

/*?
 * Configure the network simulation cross-connect
 * Once the simulator is configured, use the "nsim enable-disable" command
 * to set up a cross-connect with the supplied delay characteristics.
 *
 * Disable nsim before changing its configuration or cross-connect interfaces.
 * Restarting VPP is not required.
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
