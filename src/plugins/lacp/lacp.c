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

#include <stdint.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vppinfra/hash.h>
#include <vnet/bonding/node.h>
#include <lacp/node.h>

lacp_main_t lacp_main;

/*
 * Generate lacp pdu
 */
static void
lacp_fill_pdu (lacp_pdu_t * lacpdu, slave_if_t * sif)
{
  /* Actor TLV */
  lacpdu->actor.port_info = sif->actor;

  /* Partner TLV */
  lacpdu->partner.port_info = sif->partner;
}

/*
 * send a lacp pkt on an ethernet interface
 */
static void
lacp_send_ethernet_lacp_pdu (slave_if_t * sif)
{
  lacp_main_t *lm = &lacp_main;
  u32 *to_next;
  ethernet_lacp_pdu_t *h0;
  vnet_hw_interface_t *hw;
  u32 bi0;
  vlib_buffer_t *b0;
  vlib_frame_t *f;
  vlib_main_t *vm = lm->vlib_main;
  vnet_main_t *vnm = lm->vnet_main;

  /*
   * see lacp_periodic_init() to understand what's already painted
   * into the buffer by the packet template mechanism
   */
  h0 = vlib_packet_template_get_packet
    (vm, &lm->packet_templates[sif->packet_template_index], &bi0);

  if (!h0)
    return;

  /* Add the interface's ethernet source address */
  hw = vnet_get_sup_hw_interface (vnm, sif->sw_if_index);

  clib_memcpy (h0->ethernet.src_address, hw->hw_address,
	       vec_len (hw->hw_address));

  lacp_fill_pdu (&h0->lacp, sif);

  /* Set the outbound packet length */
  b0 = vlib_get_buffer (vm, bi0);
  b0->current_length = sizeof (ethernet_lacp_pdu_t);
  b0->current_data = 0;
  b0->total_length_not_including_first_buffer = 0;

  /* And the outbound interface */
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = hw->sw_if_index;

  /* And output the packet on the correct interface */
  f = vlib_get_frame_to_node (vm, hw->output_node_index);

  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi0;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, hw->output_node_index, f);

  sif->last_lacpdu_time = vlib_time_now (lm->vlib_main);
}

/*
 * Decide which lacp packet template to use
 */
static int
lacp_pick_packet_template (slave_if_t * sif)
{
  sif->packet_template_index = LACP_PACKET_TEMPLATE_ETHERNET;

  return 0;
}

void
lacp_send_lacp_pdu (vlib_main_t * vm, slave_if_t * sif)
{
  if (sif->mode != BOND_MODE_LACP)
    {
      lacp_stop_timer (&sif->periodic_timer);
      return;
    }

  if (sif->packet_template_index == (u8) ~ 0)
    {
      /* If we don't know how to talk to this peer, don't try again */
      if (lacp_pick_packet_template (sif))
	{
	  lacp_stop_timer (&sif->periodic_timer);
	  return;
	}
    }

  switch (sif->packet_template_index)
    {
    case LACP_PACKET_TEMPLATE_ETHERNET:
      lacp_send_ethernet_lacp_pdu (sif);
      break;

    default:
      ASSERT (0);
    }
}

void
lacp_periodic (vlib_main_t * vm)
{
  bond_main_t *bm = &bond_main;
  lacp_main_t *lm = &lacp_main;
  slave_if_t *sif;

  /* *INDENT-OFF* */
  pool_foreach (sif, bm->neighbors,
  ({
    if (sif->port_enabled == 0)
      continue;

    if (lacp_timer_is_running (sif->current_while_timer) &&
	lacp_timer_is_expired (lm->vlib_main, sif->current_while_timer))
      {
        lacp_machine_dispatch (&lacp_rx_machine, vm, sif,
			       LACP_RX_EVENT_TIMER_EXPIRED, &sif->rx_state);
      }

    if (lacp_timer_is_running (sif->periodic_timer) &&
	lacp_timer_is_expired (lm->vlib_main, sif->periodic_timer))
      {
        lacp_machine_dispatch (&lacp_ptx_machine, vm, sif,
			       LACP_PTX_EVENT_TIMER_EXPIRED, &sif->ptx_state);
      }
    if (lacp_timer_is_running (sif->wait_while_timer) &&
	lacp_timer_is_expired (lm->vlib_main, sif->wait_while_timer))
      {
	sif->ready_n = 1;
        lacp_stop_timer (&sif->wait_while_timer);
        lacp_selection_logic (vm, sif);
      }
  }));
  /* *INDENT-ON* */
}

static void
lacp_interface_enable_disable (vlib_main_t * vm, bond_if_t * bif,
			       slave_if_t * sif, u8 enable)
{
  lacp_main_t *lm = &lacp_main;
  uword port_number;

  if (enable)
    {
      port_number = clib_bitmap_first_clear (bif->port_number_bitmap);
      bif->port_number_bitmap = clib_bitmap_set (bif->port_number_bitmap,
						 port_number, 1);
      // bitmap starts at 0. Our port number starts at 1.
      lacp_init_neighbor (sif, bif->hw_address, port_number + 1, sif->group);
      lacp_init_state_machines (vm, sif);
      lm->lacp_int++;
      if (lm->lacp_int == 1)
	{
	  vlib_process_signal_event (vm, lm->lacp_process_node_index,
				     LACP_PROCESS_EVENT_START, 0);
	}
    }
  else
    {
      lm->lacp_int--;
      if (lm->lacp_int == 0)
	{
	  vlib_process_signal_event (vm, lm->lacp_process_node_index,
				     LACP_PROCESS_EVENT_STOP, 0);
	}
    }
}

static clib_error_t *
lacp_periodic_init (vlib_main_t * vm)
{
  lacp_main_t *lm = &lacp_main;
  ethernet_lacp_pdu_t h;
  ethernet_marker_pdu_t m;
  u8 dst[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x02 };

  /* initialize binary API */
  lacp_plugin_api_hookup (vm);

  /* Create the ethernet lacp packet template */

  clib_memset (&h, 0, sizeof (h));

  memcpy (h.ethernet.dst_address, dst, sizeof (h.ethernet.dst_address));

  /* leave src address blank (fill in at send time) */

  h.ethernet.type = htons (ETHERNET_TYPE_SLOW_PROTOCOLS);

  h.lacp.subtype = LACP_SUBTYPE;
  h.lacp.version_number = LACP_ACTOR_LACP_VERSION;

  /* Actor TLV */
  h.lacp.actor.tlv_type = LACP_ACTOR_INFORMATION;
  h.lacp.actor.tlv_length = sizeof (lacp_actor_partner_t);

  /* Partner TLV */
  h.lacp.partner.tlv_type = LACP_PARTNER_INFORMATION;
  h.lacp.partner.tlv_length = sizeof (lacp_actor_partner_t);

  /* Collector TLV */
  h.lacp.collector.tlv_type = LACP_COLLECTOR_INFORMATION;
  h.lacp.collector.tlv_length = sizeof (lacp_collector_t);
  h.lacp.collector.max_delay = 0;

  /* Terminator TLV */
  h.lacp.terminator.tlv_type = LACP_TERMINATOR_INFORMATION;
  h.lacp.terminator.tlv_length = 0;

  vlib_packet_template_init
    (vm, &lm->packet_templates[LACP_PACKET_TEMPLATE_ETHERNET],
     /* data */ &h,
     sizeof (h),
     /* alloc chunk size */ 8,
     "lacp-ethernet");

  /* Create the ethernet marker protocol packet template */

  clib_memset (&m, 0, sizeof (m));

  memcpy (m.ethernet.dst_address, dst, sizeof (m.ethernet.dst_address));

  /* leave src address blank (fill in at send time) */

  m.ethernet.type = htons (ETHERNET_TYPE_SLOW_PROTOCOLS);

  m.marker.subtype = MARKER_SUBTYPE;
  m.marker.version_number = MARKER_PROTOCOL_VERSION;

  m.marker.marker_info.tlv_length = sizeof (marker_information_t);

  /* Terminator TLV */
  m.marker.terminator.tlv_type = MARKER_TERMINATOR_INFORMATION;
  m.marker.terminator.tlv_length = 0;

  vlib_packet_template_init
    (vm, &lm->marker_packet_templates[MARKER_PACKET_TEMPLATE_ETHERNET],
     /* data */ &m,
     sizeof (m),
     /* alloc chunk size */ 8,
     "marker-ethernet");

  bond_register_callback (lacp_interface_enable_disable);

  return 0;
}

int
lacp_machine_dispatch (lacp_machine_t * machine, vlib_main_t * vm,
		       slave_if_t * sif, int event, int *state)
{
  lacp_fsm_state_t *transition;
  int rc = 0;

  transition = &machine->tables[*state].state_table[event];
  LACP_DBG2 (sif, event, *state, machine, transition);
  *state = transition->next_state;
  if (transition->action)
    rc = (*transition->action) ((void *) vm, (void *) sif);

  return rc;
}

void
lacp_init_neighbor (slave_if_t * sif, u8 * hw_address, u16 port_number,
		    u32 group)
{
  lacp_stop_timer (&sif->wait_while_timer);
  lacp_stop_timer (&sif->current_while_timer);
  lacp_stop_timer (&sif->actor_churn_timer);
  lacp_stop_timer (&sif->partner_churn_timer);
  lacp_stop_timer (&sif->periodic_timer);
  lacp_stop_timer (&sif->last_lacpdu_time);
  sif->lacp_enabled = 1;
  sif->loopback_port = 0;
  sif->ready = 0;
  sif->ready_n = 0;
  sif->port_moved = 0;
  sif->ntt = 0;
  sif->selected = LACP_PORT_UNSELECTED;
  sif->actor.state = LACP_STATE_AGGREGATION;
  if (sif->ttl_in_seconds == LACP_SHORT_TIMOUT_TIME)
    sif->actor.state |= LACP_STATE_LACP_TIMEOUT;
  if (sif->is_passive == 0)
    sif->actor.state |= LACP_STATE_LACP_ACTIVITY;
  clib_memcpy (sif->actor.system, hw_address, 6);
  sif->actor.system_priority = htons (LACP_DEFAULT_SYSTEM_PRIORITY);
  sif->actor.key = htons (group);
  sif->actor.port_number = htons (port_number);
  sif->actor.port_priority = htons (LACP_DEFAULT_PORT_PRIORITY);

  sif->partner.system_priority = htons (LACP_DEFAULT_SYSTEM_PRIORITY);
  sif->partner.key = htons (group);
  sif->partner.port_number = htons (port_number);
  sif->partner.port_priority = htons (LACP_DEFAULT_PORT_PRIORITY);
  sif->partner.key = htons (group);
  sif->partner.state = LACP_STATE_LACP_ACTIVITY;

  sif->actor_admin = sif->actor;
  sif->partner_admin = sif->partner;
}

void
lacp_init_state_machines (vlib_main_t * vm, slave_if_t * sif)
{
  lacp_init_tx_machine (vm, sif);
  lacp_init_mux_machine (vm, sif);
  lacp_init_ptx_machine (vm, sif);
  lacp_init_rx_machine (vm, sif);
}

VLIB_INIT_FUNCTION (lacp_periodic_init);

static clib_error_t *
lacp_sw_interface_up_down (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  lacp_main_t *lm = &lacp_main;
  slave_if_t *sif;
  vlib_main_t *vm = lm->vlib_main;

  sif = bond_get_slave_by_sw_if_index (sw_if_index);
  if (sif)
    {
      sif->port_enabled = flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP;
      if (sif->port_enabled == 0)
	{
	  if (sif->lacp_enabled)
	    {
	      lacp_init_neighbor (sif, sif->actor_admin.system,
				  ntohs (sif->actor_admin.port_number),
				  ntohs (sif->actor_admin.key));
	      lacp_init_state_machines (vm, sif);
	    }
	}
    }

  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (lacp_sw_interface_up_down);

static clib_error_t *
lacp_hw_interface_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  lacp_main_t *lm = &lacp_main;
  slave_if_t *sif;
  vnet_sw_interface_t *sw;
  vlib_main_t *vm = lm->vlib_main;

  sw = vnet_get_hw_sw_interface (vnm, hw_if_index);
  sif = bond_get_slave_by_sw_if_index (sw->sw_if_index);
  if (sif)
    {
      if (!(flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
	{
	  if (sif->lacp_enabled)
	    {
	      lacp_init_neighbor (sif, sif->actor_admin.system,
				  ntohs (sif->actor_admin.port_number),
				  ntohs (sif->actor_admin.key));
	      lacp_init_state_machines (vm, sif);
	    }
	}
    }

  return 0;
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (lacp_hw_interface_up_down);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Link Aggregation Control Protocol",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
