/*
 * src/vnet/ip/ip_neighboor.c: ip neighbor generic handling
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_neighbor.h>
#include <vnet/ip/ip_neighbor.h>
#include <vnet/ethernet/arp.h>

/*
 * IP neighbor scan parameter defaults are as follows:
 *   - Scan interval                       : 60 sec
 *   - Max processing allowed per run      : 20 usec
 *   - Max probe/delete operations per run : 10
 *   - Scan interrupt delay to resume scan : 1 msec
 *   - Neighbor stale threashold           : 4 x scan-interval
 */
#define IP_NEIGHBOR_DEF_SCAN_INTERVAL (60.0)
#define IP_NEIGHBOR_DEF_MAX_PROC_TIME (20e-6)
#define IP_NEIGHBOR_DEF_SCAN_INT_DELAY (1e-3)
#define IP_NEIGHBOR_DEF_STALE (4*IP_NEIGHBOR_DEF_SCAN_INTERVAL)
#define IP_NEIGHBOR_DEF_MAX_UPDATE 10

typedef struct
{
  f64 scan_interval;		/* Periodic scan interval */
  f64 max_proc_time;		/* Max processing time allowed per run */
  f64 scan_int_delay;		/* Scan interrupt delay to resume scan */
  f64 stale_threshold;		/* IP neighbor stale threshod */
  u8 max_update;		/* Max probe/delete actions allowed per run */
  u8 mode;			/* IP neighbor scan mode */
} ip_neighbor_scan_config_t;

static ip_neighbor_scan_config_t ip_neighbor_scan_conf;

int
ip_neighbor_add (const ip46_address_t * ip,
		 u8 is_ip6,
		 const u8 * mac,
		 u32 sw_if_index,
		 ip_neighbor_flags_t flags, u32 * stats_index)
{
  fib_protocol_t fproto;
  vnet_link_t linkt;
  int rv;

  /*
   * there's no validation here of the ND/ARP entry being added.
   * The expectation is that the FIB will ensure that nothing bad
   * will come of adding bogus entries.
   */
  if (is_ip6)
    {
      rv = vnet_set_ip6_ethernet_neighbor (vlib_get_main (),
					   sw_if_index, &ip->ip6, mac, 6,
					   (flags & IP_NEIGHBOR_FLAG_STATIC),
					   (flags &
					    IP_NEIGHBOR_FLAG_NO_ADJ_FIB));
      fproto = FIB_PROTOCOL_IP6;
      linkt = VNET_LINK_IP6;
    }
  else
    {
      ethernet_arp_ip4_over_ethernet_address_t a = {
	.ip4 = ip->ip4,
      };

      clib_memcpy (&a.ethernet, mac, 6);

      rv = vnet_arp_set_ip4_over_ethernet (vnet_get_main (),
					   sw_if_index,
					   &a,
					   (flags & IP_NEIGHBOR_FLAG_STATIC),
					   (flags &
					    IP_NEIGHBOR_FLAG_NO_ADJ_FIB));
      fproto = FIB_PROTOCOL_IP4;
      linkt = VNET_LINK_IP4;
    }

  if (0 == rv && stats_index)
    *stats_index = adj_nbr_find (fproto, linkt, ip, sw_if_index);

  return (rv);
}

int
ip_neighbor_del (const ip46_address_t * ip, u8 is_ip6, u32 sw_if_index)
{
  int rv;

  if (is_ip6)
    {
      rv = vnet_unset_ip6_ethernet_neighbor (vlib_get_main (),
					     sw_if_index, &ip->ip6);
    }
  else
    {
      ethernet_arp_ip4_over_ethernet_address_t a = {
	.ip4 = ip->ip4,
      };

      rv =
	vnet_arp_unset_ip4_over_ethernet (vnet_get_main (), sw_if_index, &a);
    }

  return (rv);
}

void
ip_neighbor_scan_enable_disable (ip_neighbor_scan_arg_t * arg)
{
  ip_neighbor_scan_config_t *cfg = &ip_neighbor_scan_conf;

  cfg->mode = arg->mode;

  if (arg->mode)
    {
      cfg->scan_interval = arg->scan_interval ?
	arg->scan_interval * 60.0 : IP_NEIGHBOR_DEF_SCAN_INTERVAL;
      cfg->max_proc_time = arg->max_proc_time ?
	arg->max_proc_time * 1e-6 : IP_NEIGHBOR_DEF_MAX_PROC_TIME;
      cfg->scan_int_delay = arg->scan_int_delay ?
	arg->scan_int_delay * 1e-3 : IP_NEIGHBOR_DEF_SCAN_INT_DELAY;
      cfg->stale_threshold = arg->stale_threshold ?
	arg->stale_threshold * 60.0 : cfg->scan_interval * 4;
      cfg->max_update = arg->max_update ?
	cfg->max_update : IP_NEIGHBOR_DEF_MAX_UPDATE;
    }
  else
    cfg->scan_interval = IP_NEIGHBOR_DEF_SCAN_INTERVAL;
}

static_always_inline u32
ip_neighbor_scan (vlib_main_t * vm, f64 start_time, u32 start_idx,
		  u8 is_ip6, u8 delete_stale, u8 * update_count)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip_neighbor_scan_config_t *cfg = &ip_neighbor_scan_conf;
  ethernet_arp_ip4_entry_t *np4 = ip4_neighbors_pool ();
  ip6_neighbor_t *np6 = ip6_neighbors_pool ();
  ethernet_arp_ip4_entry_t *n4;
  ip6_neighbor_t *n6;
  u32 curr_idx = start_idx;
  u32 loop_count = 0;
  f64 delta, update_time;

  if (!is_ip6)
    {
      if (pool_is_free_index (np4, start_idx))
	curr_idx = pool_next_index (np4, start_idx);
    }
  else
    {
      if (pool_is_free_index (np6, start_idx))
	curr_idx = pool_next_index (np6, start_idx);
    }

  while (curr_idx != ~0)
    {
      /* allow no more than 10 neighbor updates or 20 usec of scan */
      if ((update_count[0] >= cfg->max_update) ||
	  (((loop_count % 100) == 0) &&
	   ((vlib_time_now (vm) - start_time) > cfg->max_proc_time)))
	break;

      if (!is_ip6)
	{
	  n4 = pool_elt_at_index (np4, curr_idx);
	  if (n4->flags & ETHERNET_ARP_IP4_ENTRY_FLAG_STATIC)
	    goto next_neighbor;
	  update_time = n4->time_last_updated;
	}
      else
	{
	  n6 = pool_elt_at_index (np6, curr_idx);
	  if (n6->flags & IP6_NEIGHBOR_FLAG_STATIC)
	    goto next_neighbor;
	  update_time = n6->time_last_updated;
	}

      delta = start_time - update_time;
      if (delete_stale && (delta >= cfg->stale_threshold))
	{
	  update_count[0]++;
	  /* delete stale neighbor */
	  if (!is_ip6)
	    {
	      ethernet_arp_ip4_over_ethernet_address_t delme;
	      clib_memcpy (&delme.ethernet, n4->ethernet_address, 6);
	      delme.ip4.as_u32 = n4->ip4_address.as_u32;
	      vnet_arp_unset_ip4_over_ethernet (vnm, n4->sw_if_index, &delme);
	    }
	  else
	    {
	      vnet_unset_ip6_ethernet_neighbor
		(vm, n6->key.sw_if_index, &n6->key.ip6_address);
	    }
	}
      else if (delta >= cfg->scan_interval)
	{
	  update_count[0]++;
	  /* probe neighbor */
	  if (!is_ip6)
	    ip4_probe_neighbor (vm, &n4->ip4_address, n4->sw_if_index, 1);
	  else
	    ip6_probe_neighbor (vm, &n6->key.ip6_address,
				n6->key.sw_if_index, 1);
	}

    next_neighbor:
      loop_count++;

      if (!is_ip6)
	curr_idx = pool_next_index (np4, curr_idx);
      else
	curr_idx = pool_next_index (np6, curr_idx);
    }

  return curr_idx;
}

static uword
neighbor_scan_process (vlib_main_t * vm,
		       vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  ip_neighbor_scan_config_t *cfg = &ip_neighbor_scan_conf;
  f64 timeout = IP_NEIGHBOR_DEF_SCAN_INTERVAL;
  f64 start, next_scan = CLIB_TIME_MAX;
  u32 ip4_nidx = 0;		/* ip4 neighbor pool index */
  u32 ip6_nidx = 0;		/* ip6 neighbor pool index */
  uword *event_data = 0;
  u8 purge4 = 0, purge6 = 0;	/* flags to purge stale entry during scan */
  u8 update;

  cfg->mode = IP_SCAN_DISABLED;
  cfg->scan_interval = IP_NEIGHBOR_DEF_SCAN_INTERVAL;
  cfg->scan_int_delay = IP_NEIGHBOR_DEF_SCAN_INTERVAL;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      start = vlib_time_now (vm);
      update = 0;

      if ((ip4_nidx == 0) && (ip6_nidx == 0))	/* starting a fresh scan */
	next_scan = start + cfg->scan_interval;

      if ((cfg->mode & IP_SCAN_V4_NEIGHBORS) == 0)
	ip4_nidx = ~0;		/* disable ip4 neighbor scan */

      if ((cfg->mode & IP_SCAN_V6_NEIGHBORS) == 0)
	ip6_nidx = ~0;		/* disable ip6 neighbor scan */

      if (ip4_nidx != ~0)	/* scan ip4 neighbors */
	ip4_nidx = ip_neighbor_scan (vm, start, ip4_nidx, /* ip4 */ 0,
				     purge4, &update);

      if (ip6_nidx != ~0)	/* scan ip6 neighbors */
	ip6_nidx = ip_neighbor_scan (vm, start, ip6_nidx, /* ip6 */ 1,
				     purge6, &update);

      if ((ip4_nidx == ~0) && (ip6_nidx == ~0))
	{			/* scan complete */
	  timeout = next_scan - vlib_time_now (vm);
	  ip4_nidx = ip6_nidx = 0;
	  purge4 = cfg->mode & IP_SCAN_V4_NEIGHBORS;
	  purge6 = cfg->mode & IP_SCAN_V6_NEIGHBORS;
	}
      else			/* scan incomplete */
	timeout = cfg->scan_int_delay;

      if (timeout > cfg->scan_interval)
	timeout = cfg->scan_interval;
      else if (timeout < cfg->scan_int_delay)
	timeout = cfg->scan_int_delay;

    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (neighbor_scan_process_node,static) = {
  .function = neighbor_scan_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ip-neighbor-scan-process",
};
/* *INDENT-ON* */

static clib_error_t *
ip_neighbor_scan_cli (vlib_main_t * vm, unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 interval = 0, time = 0, update = 0, delay = 0, stale = 0;
  ip_neighbor_scan_arg_t arg;

  clib_memset (&arg, 0, sizeof (arg));
  arg.mode = IP_SCAN_V46_NEIGHBORS;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      ip_neighbor_scan_enable_disable (&arg);
      return error;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "ip4"))
	arg.mode = IP_SCAN_V4_NEIGHBORS;

      else if (unformat (line_input, "ip6"))
	arg.mode = IP_SCAN_V6_NEIGHBORS;

      else if (unformat (line_input, "both"))
	arg.mode = IP_SCAN_V46_NEIGHBORS;

      else if (unformat (line_input, "disable"))
	arg.mode = IP_SCAN_DISABLED;

      else if (unformat (line_input, "interval %d", &interval))
	arg.scan_interval = interval;

      else if (unformat (line_input, "max-time %d", &time))
	arg.max_proc_time = time;

      else if (unformat (line_input, "max-update %d", &update))
	arg.max_update = update;

      else if (unformat (line_input, "delay %d", &delay))
	arg.scan_int_delay = delay;

      else if (unformat (line_input, "stale %d", &stale))
	arg.stale_threshold = stale;

      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (interval > 255)
    {
      error = clib_error_return (0, "interval cannot exceed 255 minutes.");
      goto done;
    }
  if (time > 255)
    {
      error = clib_error_return (0, "max-time cannot exceed 255 usec.");
      goto done;
    }
  if (update > 255)
    {
      error = clib_error_return (0, "max-update cannot exceed 255.");
      goto done;
    }
  if (delay > 255)
    {
      error = clib_error_return (0, "delay cannot exceed 255 msec.");
      goto done;
    }
  if (stale > 255)
    {
      error = clib_error_return (0, "stale cannot exceed 255 minutes.");
      goto done;
    }

  ip_neighbor_scan_enable_disable (&arg);

done:
  unformat_free (line_input);

  return error;
}

/*?
 * The '<em>ip scan-neighbor</em>' command can be used to enable and disable
 * periodic IP neighbor scan and change various scan parameneters.
 *
 * @note The default parameters used for IP neighbor scan should work fine
 * under normal conditions. They should not be changed from the default unless
 * properly tested to work as desied.
 *
 * @cliexpar
 * Example of enabling IP neighbor scan:
 * @cliexcmd{ip neighbor-scan enable}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip_scan_neighbor_command, static) = {
  .path = "ip scan-neighbor",
  .function = ip_neighbor_scan_cli,
  .short_help = "ip scan-neighbor [ip4|ip6|both|disable] [interval <n-min>] [max-time <n-usec>] [max-update <n>] [delay <n-msec>] [stale <n-min>]",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static u8 *
format_ip_scan_mode (u8 * s, va_list * args)
{
  u8 mode = va_arg (*args, u32);
  switch (mode)
    {
    case IP_SCAN_V4_NEIGHBORS:
      return format (s, "IPv4");
    case IP_SCAN_V6_NEIGHBORS:
      return format (s, "IPv6");
    case IP_SCAN_V46_NEIGHBORS:
      return format (s, "IPv4 and IPv6");
    }
  return format (s, "unknown");
}

static clib_error_t *
show_ip_neighbor_scan (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  ip_neighbor_scan_config_t *cfg = &ip_neighbor_scan_conf;

  if (cfg->mode == 0)
    vlib_cli_output (vm,
		     "IP neighbor scan disabled - current time is %.4f sec",
		     vlib_time_now (vm));
  else
    vlib_cli_output (vm, "IP neighbor scan enabled for %U neighbors - "
		     "current time is %.4f sec\n   "
		     "Full_scan_interval: %f min  "
		     "Stale_purge_threshod: %f min\n   "
		     "Max_process_time: %f usec  Max_updates %d  "
		     "Delay_to_resume_after_max_limit: %f msec",
		     format_ip_scan_mode, cfg->mode,
		     vlib_time_now (vm), cfg->scan_interval / 60.0,
		     cfg->stale_threshold / 60.0, cfg->max_proc_time / 1e-6,
		     cfg->max_update, cfg->scan_int_delay / 1e-3);
  return 0;
}

/*?
 * The '<em>show ip scan-neighbor</em>' command can be used to show the current
 * periodic IP neighbor scan parameters
 *
 * @cliexpar
 * Example of showing IP neighbor scan current parameters:
 * @cliexcmd{show ip neighbor-scan}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip_scan_neighbor_command, static) = {
  .path = "show ip scan-neighbor",
  .function = show_ip_neighbor_scan,
  .short_help = "show ip scan-neighbor",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
