/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief IPv6 Duplicate Address Detection (DAD) - RFC 4862 Implementation
 */

#include <vnet/ip6-nd/ip6_dad.h>
#include <vnet/ip6-nd/ip6_nd.h>
#include <vnet/ip/ip6_forward.h>
#include <vnet/ip-neighbor/ip6_neighbor.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_table.h>

/* Global DAD main */
ip6_dad_main_t ip6_dad_main;

/* IP6 link delegate ID for DAD */
static ip6_link_delegate_id_t ip6_dad_delegate_id;

/**
 * DAD delegate structure - one per interface with IPv6 enabled
 */
typedef struct ip6_dad_delegate_t_
{
  u32 sw_if_index;
} ip6_dad_delegate_t;

static ip6_dad_delegate_t *ip6_dad_delegate_pool;

/* Logging */
#define DAD_DBG(...)  vlib_log_debug (ip6_dad_main.log_class, __VA_ARGS__)
#define DAD_INFO(...) vlib_log_notice (ip6_dad_main.log_class, __VA_ARGS__)
#define DAD_ERR(...)  vlib_log_err (ip6_dad_main.log_class, __VA_ARGS__)

/* Forward declarations */

/**
 * Send DAD event to registered clients
 * This is a weak symbol that will be overridden by ip6_dad_api.c
 */
void __attribute__ ((weak))
ip6_dad_send_event (u32 sw_if_index, const ip6_address_t *address, ip6_dad_state_e state,
		    u8 dad_count, u8 dad_transmits)
{
  /* Stub implementation - will be overridden by API layer */
  DAD_DBG ("DAD Event: %U on sw_if_index %u, state=%U, count=%u/%u", format_ip6_address, address,
	   sw_if_index, format_ip6_dad_state, state, dad_count, dad_transmits);
}

/**
 * Helper function to find a DAD entry by interface and address
 */
static ip6_dad_entry_t *
find_dad_entry (u32 sw_if_index, const ip6_address_t *address)
{
  ip6_dad_main_t *dm = &ip6_dad_main;
  ip6_dad_entry_t *entry;

  pool_foreach (entry, dm->dad_entries)
    {
      if (entry->sw_if_index == sw_if_index && ip6_address_is_equal (&entry->address, address))
	return entry;
    }
  return NULL;
}

/**
 * Create a DAD Neighbor Solicitation packet
 */
static u32
create_dad_ns_buffer (vlib_main_t *vm, ip6_dad_entry_t *entry)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_buffer_t *b;
  icmp6_neighbor_solicitation_header_t *h;
  ip6_address_t dst_mcast;
  u8 dst_mac[6];
  u8 *rewrite;
  u8 rewrite_len;
  u32 bi;
  int bogus_length;

  /* Get NS packet template */
  extern vlib_packet_template_t ip6_neighbor_packet_template;
  h = vlib_packet_template_get_packet (vm, &ip6_neighbor_packet_template, &bi);
  if (!h)
    return ~0;

  b = vlib_get_buffer (vm, bi);

  /* Calculate solicited-node multicast address */
  u32 id = clib_net_to_host_u32 (entry->address.as_u32[3]) & 0x00FFFFFF;
  ip6_set_solicited_node_multicast_address (&dst_mcast, id);

  /* Build IPv6 header */
  h->ip.ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (0x6 << 28);
  h->ip.payload_length =
    clib_host_to_net_u16 (sizeof (icmp6_neighbor_solicitation_or_advertisement_header_t));
  h->ip.protocol = IP_PROTOCOL_ICMP6;
  h->ip.hop_limit = 255;

  /* DAD NS: Source = :: (unspecified) */
  ip6_address_set_zero (&h->ip.src_address);

  /* Destination = solicited-node multicast */
  h->ip.dst_address = dst_mcast;

  /* ICMPv6 NS */
  h->neighbor.icmp.type = ICMP6_neighbor_solicitation;
  h->neighbor.icmp.code = 0;
  h->neighbor.target_address = entry->address;

  /* RFC 4861: NO Source Link-Layer option when src is :: */
  h->link_layer_option.header.type = 0;
  h->link_layer_option.header.n_data_u64s = 0;

  /* Compute checksum */
  h->neighbor.icmp.checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, &h->ip, &bogus_length);
  ASSERT (bogus_length == 0);

  /* Ethernet header: multicast destination */
  ip6_multicast_ethernet_address (dst_mac, id | (0xff << 24));
  rewrite = ethernet_build_rewrite (vnm, entry->sw_if_index, VNET_LINK_IP6, dst_mac);
  rewrite_len = vec_len (rewrite);
  vlib_buffer_advance (b, -rewrite_len);
  ethernet_header_t *e = vlib_buffer_get_current (b);
  clib_memcpy (e, rewrite, rewrite_len);
  vec_free (rewrite);

  /* Mark buffer for TX on specific interface */
  vnet_buffer (b)->sw_if_index[VLIB_RX] = entry->sw_if_index;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = entry->sw_if_index;

  return bi;
}

/**
 * Send DAD NS from main thread
 */
static void
send_dad_ns (vlib_main_t *vm, ip6_dad_entry_t *entry)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;
  vlib_frame_t *f;
  u32 *to_next;
  u32 bi;

  ASSERT (vm->thread_index == 0); /* Main thread only */

  hi = vnet_get_sup_hw_interface (vnm, entry->sw_if_index);

  /* Create a fresh NS buffer */
  bi = create_dad_ns_buffer (vm, entry);
  if (bi == ~0)
    {
      DAD_ERR ("Failed to create DAD NS buffer for %U", format_ip6_address, &entry->address);
      return;
    }

  /* Send to interface output node */
  f = vlib_get_frame_to_node (vm, hi->output_node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, hi->output_node_index, f);

  DAD_DBG ("DAD NS sent for %U on sw_if_index %u (attempt %u/%u)", format_ip6_address,
	   &entry->address, entry->sw_if_index, entry->dad_count + 1, entry->dad_transmits);

  /* Send TENTATIVE notification after sending NS */
  ip6_dad_send_event (entry->sw_if_index, &entry->address, IP6_DAD_STATE_TENTATIVE,
		      entry->dad_count + 1, entry->dad_transmits);
}

/**
 * Complete DAD successfully
 */
static void
complete_dad_success (vlib_main_t *vm, ip6_dad_entry_t *entry)
{
  entry->state = IP6_DAD_STATE_PREFERRED;

  DAD_INFO ("DAD SUCCESS: %U on sw_if_index %u is now PREFERRED", format_ip6_address,
	    &entry->address, entry->sw_if_index);

  /* Send PREFERRED notification */
  ip6_dad_send_event (entry->sw_if_index, &entry->address, IP6_DAD_STATE_PREFERRED,
		      entry->dad_count, entry->dad_transmits);

  /* Address is already in FIB, just update state if needed */
}

/**
 * Handle DAD conflict (called from main thread via RPC)
 */
static void
handle_dad_conflict (vlib_main_t *vm, u32 sw_if_index, const ip6_address_t *address)
{
  ip6_dad_entry_t *entry;

  ASSERT (vm->thread_index == 0); /* Main thread only */

  /* Find the DAD entry */
  entry = find_dad_entry (sw_if_index, address);
  if (!entry || entry->state != IP6_DAD_STATE_TENTATIVE)
    return;

  /* CONFLICT DETECTED */
  entry->state = IP6_DAD_STATE_DUPLICATE;

  DAD_ERR ("DAD FAILED: Duplicate address %U on sw_if_index %u - IP REMAINS CONFIGURED",
	   format_ip6_address, address, sw_if_index);

  /* Send DUPLICATE notification */
  ip6_dad_send_event (sw_if_index, address, IP6_DAD_STATE_DUPLICATE, entry->dad_count,
		      entry->dad_transmits);

  /* IMPORTANT CHANGE: Do NOT remove the IP address
   * The IP remains configured but in DUPLICATE state
   * Applications are notified via the event system
   */

  /* Free the DAD entry */
  pool_put (ip6_dad_main.dad_entries, entry);
}

/**
 * RPC callback for NA received (called on main thread)
 */
static void
ip6_dad_na_received_main (ip6_dad_na_event_t *event)
{
  vlib_main_t *vm = vlib_get_main ();
  handle_dad_conflict (vm, event->sw_if_index, &event->address);
}

/**
 * DAD process node - runs on main thread only
 */
static uword
ip6_dad_process (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ip6_dad_main_t *dm = &ip6_dad_main;
  ip6_dad_entry_t *entry;
  f64 now, next_timeout, due_time;
  uword event_type;
  uword *event_data = 0;

  ASSERT (vm->thread_index == 0); /* Main thread only */

  /* Initialize */
  next_timeout = 1e70; /* Far in the future */

  while (1)
    {
      /* Wait for event or timeout */
      vlib_process_wait_for_event_or_clock (vm, next_timeout);

      /* Get events */
      event_type = vlib_process_get_events (vm, &event_data);

      /* Current time */
      now = vlib_time_now (vm);
      next_timeout = 1e70;

      /* Process events */
      if (event_type == IP6_DAD_EVENT_START)
	{
	  DAD_DBG ("DAD process: START event received");
	}
      else if (event_type == IP6_DAD_EVENT_NA_RECEIVED)
	{
	  DAD_DBG ("DAD process: NA_RECEIVED event");
	}

      pool_foreach (entry, dm->dad_entries)
	{
	  if (entry->state != IP6_DAD_STATE_TENTATIVE)
	    continue;

	  /* Time to send NS? */
	  if (now >= entry->dad_next_send_time)
	    {
	      if (entry->dad_count < entry->dad_transmits)
		{
		  /* Send NS (this will also send TENTATIVE event) */
		  send_dad_ns (vm, entry);
		  entry->dad_count++;

		  /* Schedule next transmission */
		  entry->dad_next_send_time = now + entry->dad_retransmit_delay;
		}
	      else
		{
		  /* DAD completed successfully */
		  complete_dad_success (vm, entry);
		  pool_put (dm->dad_entries, entry);
		  continue;
		}
	    }

	  /* Update next timeout */
	  due_time = entry->dad_next_send_time;
	  if (due_time < next_timeout)
	    next_timeout = due_time;
	}

      /* Calculate sleep time */
      if (next_timeout > now)
	next_timeout = next_timeout - now;
      else
	next_timeout = 0.001; /* Wake up soon */

      vec_reset_length (event_data);
    }

  return 0;
}

VLIB_REGISTER_NODE (ip6_dad_process_node) = {
  .function = ip6_dad_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ip6-dad-process",
};

/**
 * Start DAD for an address
 */
clib_error_t *
ip6_dad_start (u32 sw_if_index, const ip6_address_t *address, u8 address_length)
{
  vlib_main_t *vm = vlib_get_main ();
  ip6_dad_main_t *dm = &ip6_dad_main;
  ip6_dad_entry_t *entry;
  f64 now;

  /* Check if DAD is enabled */
  DAD_DBG (" ip6_dad_start called, dad_enabled=%d", dm->dad_enabled);
  if (!dm->dad_enabled)
    {
      DAD_DBG (" DAD disabled, returning NULL");
      return NULL; /* DAD disabled - success */
    }
  DAD_DBG (" DAD enabled, proceeding with DAD start");

  /* Skip DAD for certain address types */
  if (ip6_address_is_loopback (address) || ip6_address_is_multicast (address))
    {
      DAD_DBG ("Skipping DAD for special address %U", format_ip6_address, address);
      return NULL;
    }

  /* Check if DAD already in progress for this address */
  if (find_dad_entry (sw_if_index, address))
    return clib_error_return (0, "DAD already in progress for %U", format_ip6_address, address);

  /* Allocate new DAD entry */
  pool_get_zero (dm->dad_entries, entry);

  entry->sw_if_index = sw_if_index;
  entry->address = *address;
  entry->address_length = address_length;
  entry->state = IP6_DAD_STATE_TENTATIVE;

  /* Timer configuration */
  now = vlib_time_now (vm);
  entry->dad_start_time = now;
  entry->dad_transmits = dm->dad_transmits_default;
  entry->dad_count = 0;
  entry->dad_retransmit_delay = dm->dad_retransmit_delay_default;

  /* Send first NS ASAP */
  entry->dad_next_send_time = now;

  DAD_INFO ("DAD started for %U on sw_if_index %u (%u transmits)", format_ip6_address, address,
	    sw_if_index, entry->dad_transmits);

  /* Send initial TENTATIVE notification (count=0, before first NS) */
  ip6_dad_send_event (sw_if_index, address, IP6_DAD_STATE_TENTATIVE, 0, entry->dad_transmits);

  /* Signal process node to wake up */
  vlib_process_signal_event (vm, ip6_dad_process_node.index, IP6_DAD_EVENT_START,
			     entry - dm->dad_entries);

  return NULL;
}

/**
 * NA received from data plane (called from worker thread)
 */
void
ip6_dad_na_received_dp (u32 sw_if_index, const ip6_address_t *address)
{
  ip6_dad_na_event_t event = {
    .sw_if_index = sw_if_index,
    .address = *address,
  };

  /* RPC to main thread */
  vlib_rpc_call_main_thread (ip6_dad_na_received_main, (u8 *) &event, sizeof (event));
}

/**
 * Stop DAD for an address
 */
void
ip6_dad_stop (u32 sw_if_index, const ip6_address_t *address)
{
  ip6_dad_entry_t *entry = find_dad_entry (sw_if_index, address);

  if (entry)
    {
      DAD_INFO ("DAD stopped for %U on sw_if_index %u", format_ip6_address, address, sw_if_index);

      /* Free DAD entry */
      pool_put (ip6_dad_main.dad_entries, entry);
    }
}

/**
 * Enable/disable DAD
 */
void
ip6_dad_enable_disable (bool enable)
{
  ip6_dad_main_t *dm = &ip6_dad_main;

  DAD_DBG (" ip6_dad_enable_disable called with enable=%d", enable);

  /* If disabling, clear all active DAD sessions before changing flag */
  if (!enable)
    {
      ip6_dad_entry_t *entry;

      /* Free all active DAD entries immediately */
    restart:
      pool_foreach (entry, dm->dad_entries)
	{
	  if (entry->state == IP6_DAD_STATE_TENTATIVE)
	    {
	      DAD_INFO ("Stopping DAD for %U on sw_if_index %u (disabled)", format_ip6_address,
			&entry->address, entry->sw_if_index);
	      pool_put (dm->dad_entries, entry);
	      goto restart; /* Restart iteration after pool modification */
	    }
	}
    }

  dm->dad_enabled = enable;
  DAD_DBG (" dad_enabled is now %d", dm->dad_enabled);
  DAD_INFO ("DAD %s", enable ? "enabled" : "disabled");
}
/**
 * Configure DAD parameters
 */
clib_error_t *
ip6_dad_config (u8 transmits, f64 delay)
{
  if (transmits < 1 || transmits > 10)
    return clib_error_return (0, "transmits must be 1-10");

  if (delay < 0.1 || delay > 10.0)
    return clib_error_return (0, "delay must be 0.1-10.0 seconds");

  ip6_dad_main.dad_transmits_default = transmits;
  ip6_dad_main.dad_retransmit_delay_default = delay;

  DAD_INFO ("DAD configured: transmits=%u, delay=%.1fs", transmits, delay);
  return NULL;
}

/**
 * Get DAD configuration
 */
void
ip6_dad_get_config (bool *enabled, u8 *transmits, f64 *delay)
{
  *enabled = ip6_dad_main.dad_enabled;
  *transmits = ip6_dad_main.dad_transmits_default;
  *delay = ip6_dad_main.dad_retransmit_delay_default;
}

/**
 * Format DAD state
 */
u8 *
format_ip6_dad_state (u8 *s, va_list *args)
{
  ip6_dad_state_e state = va_arg (*args, ip6_dad_state_e);

  switch (state)
    {
    case IP6_DAD_STATE_IDLE:
      s = format (s, "IDLE");
      break;
    case IP6_DAD_STATE_TENTATIVE:
      s = format (s, "TENTATIVE");
      break;
    case IP6_DAD_STATE_PREFERRED:
      s = format (s, "PREFERRED");
      break;
    case IP6_DAD_STATE_DUPLICATE:
      s = format (s, "DUPLICATE");
      break;
    default:
      s = format (s, "UNKNOWN");
      break;
    }

  return s;
}

/**
 * Format DAD entry
 */
u8 *
format_ip6_dad_entry (u8 *s, va_list *args)
{
  vlib_main_t *vm = vlib_get_main ();
  ip6_dad_entry_t *entry = va_arg (*args, ip6_dad_entry_t *);
  f64 now = vlib_time_now (vm);
  f64 next_in = entry->dad_next_send_time - now;

  s = format (s, "%U/%u on sw_if_index %u: state=%U, count=%u/%u", format_ip6_address,
	      &entry->address, entry->address_length, entry->sw_if_index, format_ip6_dad_state,
	      entry->state, entry->dad_count, entry->dad_transmits);

  if (entry->state == IP6_DAD_STATE_TENTATIVE)
    s = format (s, ", next in %.3fs", next_in);

  return s;
}

/**
 * CLI: set ip6 dad
 */
static clib_error_t *
ip6_dad_enable_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u8 transmits = 0;
  f64 delay = 0;
  bool has_transmits = false;
  bool has_delay = false;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "transmits %u", &transmits))
	has_transmits = true;
      else if (unformat (input, "delay %f", &delay))
	has_delay = true;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  DAD_DBG (" enable command, has_transmits=%d", has_transmits);

  /* Enable DAD */
  DAD_DBG (" About to call ip6_dad_enable_disable(true)");
  ip6_dad_enable_disable (true);

  /* Configure parameters if specified */
  if (has_transmits || has_delay)
    {
      bool enabled;
      u8 cur_transmits;
      f64 cur_delay;

      ip6_dad_get_config (&enabled, &cur_transmits, &cur_delay);

      if (!has_transmits)
	transmits = cur_transmits;
      if (!has_delay)
	delay = cur_delay;

      return ip6_dad_config (transmits, delay);
    }

  return NULL;
}

static clib_error_t *
ip6_dad_disable_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  DAD_DBG (" disable command");
  ip6_dad_enable_disable (false);
  return NULL;
}

VLIB_CLI_COMMAND (ip6_dad_enable_command, static) = {
  .path = "set ip6 dad enable",
  .short_help = "set ip6 dad enable [transmits <1-10>] [delay <seconds>]",
  .function = ip6_dad_enable_command_fn,
};

VLIB_CLI_COMMAND (ip6_dad_disable_command, static) = {
  .path = "set ip6 dad disable",
  .short_help = "set ip6 dad disable",
  .function = ip6_dad_disable_command_fn,
};

/**
 * CLI: show ip6 dad
 */
static clib_error_t *
ip6_dad_show_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  ip6_dad_main_t *dm = &ip6_dad_main;
  ip6_dad_entry_t *entry;

  vlib_cli_output (vm, "DAD Configuration:");
  vlib_cli_output (vm, "  Enabled: %s", dm->dad_enabled ? "yes" : "no");
  vlib_cli_output (vm, "  Transmits: %u", dm->dad_transmits_default);
  vlib_cli_output (vm, "  Delay: %.1f seconds", dm->dad_retransmit_delay_default);
  vlib_cli_output (vm, "");

  vlib_cli_output (vm, "Active DAD entries: %u", pool_elts (dm->dad_entries));

  if (pool_elts (dm->dad_entries) > 0)
    {
      vlib_cli_output (vm, "");
      pool_foreach (entry, dm->dad_entries)
	{
	  vlib_cli_output (vm, "  %U", format_ip6_dad_entry, entry);
	}
    }
  return NULL;
}

/**
 * @brief Callback when IPv6 is enabled on an interface
 */
static void
ip6_dad_link_enable (u32 sw_if_index)
{
  ip6_dad_delegate_t *idd;

  /* Ensure no existing delegate for this interface */
  ASSERT (INDEX_INVALID == ip6_link_delegate_get (sw_if_index, ip6_dad_delegate_id));

  /* Allocate new delegate instance */
  pool_get_zero (ip6_dad_delegate_pool, idd);

  /* Store the interface index */
  idd->sw_if_index = sw_if_index;

  /* Register this delegate instance with the IP6 link layer */
  ip6_link_delegate_update (sw_if_index, ip6_dad_delegate_id, idd - ip6_dad_delegate_pool);

  DAD_DBG ("DAD delegate enabled for sw_if_index %u", sw_if_index);
}

/**
 * @brief Callback when IPv6 is disabled on an interface
 */
static void
ip6_dad_delegate_disable (index_t iddi)
{
  ip6_dad_main_t *dm = &ip6_dad_main;
  ip6_dad_delegate_t *idd;
  ip6_dad_entry_t *entry;
  u32 sw_if_index;

  /* Get delegate instance from pool using the delegate index */
  idd = pool_elt_at_index (ip6_dad_delegate_pool, iddi);
  sw_if_index = idd->sw_if_index;

  DAD_DBG ("DAD delegate disable for sw_if_index %u", sw_if_index);

  /* Stop all DAD entries for this interface */
restart:
  pool_foreach (entry, dm->dad_entries)
    {
      if (entry->sw_if_index == sw_if_index)
	{
	  DAD_INFO ("Stopping DAD for %U on sw_if_index %u (interface disabled)",
		    format_ip6_address, &entry->address, sw_if_index);
	  pool_put (dm->dad_entries, entry);
	  goto restart; /* Restart iteration after pool modification */
	}
    }

  /* Free the delegate instance */
  pool_put (ip6_dad_delegate_pool, idd);
}

/**
 * @brief Callback when link-local address changes on an interface
 */
static void
ip6_dad_delegate_ll_change (u32 iddi, const ip6_address_t *address)
{
  ip6_dad_delegate_t *idd;
  u32 sw_if_index;
  clib_error_t *dad_err;

  /* Get delegate instance to extract sw_if_index */
  idd = pool_elt_at_index (ip6_dad_delegate_pool, iddi);
  sw_if_index = idd->sw_if_index;

  DAD_DBG ("DAD link-local change for sw_if_index %u, address %U", sw_if_index, format_ip6_address,
	   address);

  /* Start DAD for the new link-local address (always /128) */
  dad_err = ip6_dad_start (sw_if_index, address, 128);
  if (dad_err)
    {
      DAD_INFO ("DAD start failed for link-local %U: %v", format_ip6_address, address, dad_err);
      clib_error_free (dad_err);
    }
}

/**
 * @brief Callback when an address is added to an interface
 */
static void
ip6_dad_delegate_addr_add (u32 iddi, const ip6_address_t *address, u8 address_length)
{
  ip6_dad_delegate_t *idd;
  u32 sw_if_index;
  clib_error_t *dad_err;

  /* Get delegate instance to extract sw_if_index */
  idd = pool_elt_at_index (ip6_dad_delegate_pool, iddi);
  sw_if_index = idd->sw_if_index;

  DAD_DBG ("DAD address add for sw_if_index %u, address %U/%u", sw_if_index, format_ip6_address,
	   address, address_length);

  /* Start DAD for the new address */
  dad_err = ip6_dad_start (sw_if_index, address, address_length);
  if (dad_err)
    {
      DAD_INFO ("DAD start failed for %U: %v", format_ip6_address, address, dad_err);
      clib_error_free (dad_err);
    }
}

/**
 * @brief Callback when an address is deleted from an interface
 */
static void
ip6_dad_delegate_addr_del (u32 iddi, const ip6_address_t *address, u8 address_length)
{
  ip6_dad_delegate_t *idd;
  u32 sw_if_index;

  /* Get delegate instance to extract sw_if_index */
  idd = pool_elt_at_index (ip6_dad_delegate_pool, iddi);
  sw_if_index = idd->sw_if_index;

  DAD_DBG ("DAD address del for sw_if_index %u, address %U", sw_if_index, format_ip6_address,
	   address);

  /* Stop DAD if in progress */
  ip6_dad_stop (sw_if_index, address);
}

/**
 * @brief Format delegate for display
 */
static u8 *
ip6_dad_delegate_format (u8 *s, va_list *args)
{
  index_t iddi = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);
  ip6_dad_delegate_t *idd;
  ip6_dad_main_t *dm = &ip6_dad_main;
  ip6_dad_entry_t *entry;
  u32 count = 0;

  idd = pool_elt_at_index (ip6_dad_delegate_pool, iddi);

  /* Count active DAD sessions for this interface */
  pool_foreach (entry, dm->dad_entries)
    {
      if (entry->sw_if_index == idd->sw_if_index)
	count++;
    }

  if (count > 0 || dm->dad_enabled)
    {
      s = format (s, "%UDAD: %s\n", format_white_space, indent,
		  dm->dad_enabled ? "enabled" : "disabled");

      /* Show active DAD sessions */
      pool_foreach (entry, dm->dad_entries)
	{
	  if (entry->sw_if_index == idd->sw_if_index)
	    s =
	      format (s, "%U  %U (transmits: %u/%u)\n", format_white_space, indent,
		      format_ip6_address, &entry->address, entry->dad_count, entry->dad_transmits);
	}
    }

  return s;
}

static const ip6_link_delegate_vft_t ip6_dad_delegate_vft = {
  .ildv_enable = ip6_dad_link_enable,
  .ildv_disable = ip6_dad_delegate_disable,
  .ildv_addr_add = ip6_dad_delegate_addr_add,
  .ildv_addr_del = ip6_dad_delegate_addr_del,
  .ildv_ll_change = ip6_dad_delegate_ll_change,
  .ildv_format = ip6_dad_delegate_format,
};

VLIB_CLI_COMMAND (ip6_dad_show_command, static) = {
  .path = "show ip6 dad",
  .short_help = "show ip6 dad",
  .function = ip6_dad_show_command_fn,
};

/**
 * DAD initialization
 */
static clib_error_t *
ip6_dad_init (vlib_main_t *vm)
{
  ip6_dad_main_t *dm = &ip6_dad_main;

  /* Initialize */
  clib_memset (dm, 0, sizeof (*dm));

  /* Default configuration */
  dm->dad_enabled = false;
  dm->dad_transmits_default = 1;
  dm->dad_retransmit_delay_default = 1.0;

  /* Initialize event registrations pool */
  dm->dad_event_registrations = NULL;

  /* Logging */
  dm->log_class = vlib_log_register_class ("ip6", "dad");

  /* Store process node index */
  dm->dad_process_node_index = ip6_dad_process_node.index;

  /* Register as an IP6 link delegate */
  ip6_dad_delegate_id = ip6_link_delegate_register (&ip6_dad_delegate_vft);

  DAD_INFO ("IPv6 DAD initialized (disabled by default)");

  return NULL;
}

VLIB_INIT_FUNCTION (ip6_dad_init);
