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
#include <vpp/stats/stat_segment.h>

lacp_main_t lacp_main;

/*
 * Generate lacp pdu
 */
static void
lacp_fill_pdu (lacp_pdu_t * lacpdu, member_if_t * mif)
{
  /* Actor TLV */
  lacpdu->actor.port_info = mif->actor;

  /* Partner TLV */
  lacpdu->partner.port_info = mif->partner;
}

/*
 * send a lacp pkt on an ethernet interface
 */
static void
lacp_send_ethernet_lacp_pdu (vlib_main_t * vm, member_if_t * mif)
{
  lacp_main_t *lm = &lacp_main;
  u32 *to_next;
  ethernet_lacp_pdu_t *h0;
  vnet_hw_interface_t *hw;
  u32 bi0;
  vlib_buffer_t *b0;
  vlib_frame_t *f;
  vnet_main_t *vnm = lm->vnet_main;

  /*
   * see lacp_periodic_init() to understand what's already painted
   * into the buffer by the packet template mechanism
   */
  h0 = vlib_packet_template_get_packet
    (vm, &lm->packet_templates[mif->packet_template_index], &bi0);

  if (!h0)
    return;

  /* Add the interface's ethernet source address */
  hw = vnet_get_sup_hw_interface (vnm, mif->sw_if_index);

  clib_memcpy (h0->ethernet.src_address, hw->hw_address,
	       vec_len (hw->hw_address));

  lacp_fill_pdu (&h0->lacp, mif);

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

  mif->last_lacpdu_sent_time = vlib_time_now (vm);
  mif->pdu_sent++;
}

/*
 * Decide which lacp packet template to use
 */
static int
lacp_pick_packet_template (member_if_t * mif)
{
  mif->packet_template_index = LACP_PACKET_TEMPLATE_ETHERNET;

  return 0;
}

void
lacp_send_lacp_pdu (vlib_main_t * vm, member_if_t * mif)
{
  if ((mif->mode != BOND_MODE_LACP) || (mif->port_enabled == 0))
    {
      lacp_stop_timer (&mif->periodic_timer);
      return;
    }

  if (mif->packet_template_index == (u8) ~ 0)
    {
      /* If we don't know how to talk to this peer, don't try again */
      if (lacp_pick_packet_template (mif))
	{
	  lacp_stop_timer (&mif->periodic_timer);
	  return;
	}
    }

  switch (mif->packet_template_index)
    {
    case LACP_PACKET_TEMPLATE_ETHERNET:
      lacp_send_ethernet_lacp_pdu (vm, mif);
      break;

    default:
      ASSERT (0);
    }
}

void
lacp_periodic (vlib_main_t * vm)
{
  bond_main_t *bm = &bond_main;
  member_if_t *mif;
  bond_if_t *bif;
  u8 actor_state, partner_state;

  /* *INDENT-OFF* */
  pool_foreach (mif, bm->neighbors)
   {
    if (mif->port_enabled == 0)
      continue;

    actor_state = mif->actor.state;
    partner_state = mif->partner.state;
    if (lacp_timer_is_running (mif->current_while_timer) &&
	lacp_timer_is_expired (vm, mif->current_while_timer))
      {
        lacp_machine_dispatch (&lacp_rx_machine, vm, mif,
			       LACP_RX_EVENT_TIMER_EXPIRED, &mif->rx_state);
      }

    if (lacp_timer_is_running (mif->periodic_timer) &&
	lacp_timer_is_expired (vm, mif->periodic_timer))
      {
        lacp_machine_dispatch (&lacp_ptx_machine, vm, mif,
			       LACP_PTX_EVENT_TIMER_EXPIRED, &mif->ptx_state);
      }
    if (lacp_timer_is_running (mif->wait_while_timer) &&
	lacp_timer_is_expired (vm, mif->wait_while_timer))
      {
	mif->ready_n = 1;
        lacp_stop_timer (&mif->wait_while_timer);
        lacp_selection_logic (vm, mif);
      }
    if (actor_state != mif->actor.state)
      {
	bif = bond_get_bond_if_by_dev_instance (mif->bif_dev_instance);
	stat_segment_set_state_counter (bm->stats[bif->sw_if_index]
					[mif->sw_if_index].actor_state,
					mif->actor.state);
      }
    if (partner_state != mif->partner.state)
      {
	bif = bond_get_bond_if_by_dev_instance (mif->bif_dev_instance);
	stat_segment_set_state_counter (bm->stats[bif->sw_if_index]
					[mif->sw_if_index].partner_state,
					mif->partner.state);
      }
  }
  /* *INDENT-ON* */
}

static void
lacp_interface_enable_disable (vlib_main_t * vm, bond_if_t * bif,
			       member_if_t * mif, u8 enable)
{
  lacp_main_t *lm = &lacp_main;
  uword port_number;

  if (enable)
    {
      lacp_create_periodic_process ();
      port_number = clib_bitmap_first_clear (bif->port_number_bitmap);
      bif->port_number_bitmap = clib_bitmap_set (bif->port_number_bitmap,
						 port_number, 1);
      // bitmap starts at 0. Our port number starts at 1.
      lacp_init_neighbor (mif, bif->hw_address, port_number + 1, mif->group);
      lacp_init_state_machines (vm, mif);
      lm->lacp_int++;
      if (lm->lacp_int == 1)
	{
	  vlib_process_signal_event (vm, lm->lacp_process_node_index,
				     LACP_PROCESS_EVENT_START, 0);
	}
    }
  else
    {
      ASSERT (lm->lacp_int >= 1);
      if (lm->lacp_int == 0)
	{
	  /* *INDENT-OFF* */
	  ELOG_TYPE_DECLARE (e) =
	    {
	      .format = "lacp-int-en-dis: BUG lacp_int == 0",
	    };
	  /* *INDENT-ON* */
	  ELOG_DATA (&vlib_global_main.elog_main, e);
	}
      else
	{
	  lm->lacp_int--;
	  if (lm->lacp_int == 0)
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
		       member_if_t * mif, int event, int *state)
{
  lacp_fsm_state_t *transition;
  int rc = 0;

  transition = &machine->tables[*state].state_table[event];
  LACP_DBG2 (mif, event, *state, machine, transition);
  *state = transition->next_state;
  if (transition->action)
    rc = (*transition->action) ((void *) vm, (void *) mif);

  return rc;
}

void
lacp_init_neighbor (member_if_t * mif, u8 * hw_address, u16 port_number,
		    u32 group)
{
  lacp_stop_timer (&mif->wait_while_timer);
  lacp_stop_timer (&mif->current_while_timer);
  lacp_stop_timer (&mif->actor_churn_timer);
  lacp_stop_timer (&mif->partner_churn_timer);
  lacp_stop_timer (&mif->periodic_timer);
  lacp_stop_timer (&mif->last_lacpdu_sent_time);
  lacp_stop_timer (&mif->last_lacpdu_recd_time);
  lacp_stop_timer (&mif->last_marker_pdu_sent_time);
  lacp_stop_timer (&mif->last_marker_pdu_recd_time);
  mif->lacp_enabled = 1;
  mif->loopback_port = 0;
  mif->ready = 0;
  mif->ready_n = 0;
  mif->port_moved = 0;
  mif->ntt = 0;
  mif->selected = LACP_PORT_UNSELECTED;
  mif->actor.state = LACP_STATE_AGGREGATION;
  if (mif->ttl_in_seconds == LACP_SHORT_TIMOUT_TIME)
    mif->actor.state |= LACP_STATE_LACP_TIMEOUT;
  if (mif->is_passive == 0)
    mif->actor.state |= LACP_STATE_LACP_ACTIVITY;
  clib_memcpy (mif->actor.system, hw_address, 6);
  mif->actor.system_priority = htons (LACP_DEFAULT_SYSTEM_PRIORITY);
  mif->actor.key = htons (group);
  mif->actor.port_number = htons (port_number);
  mif->actor.port_priority = htons (LACP_DEFAULT_PORT_PRIORITY);

  mif->partner.system_priority = htons (LACP_DEFAULT_SYSTEM_PRIORITY);
  mif->partner.key = htons (group);
  mif->partner.port_number = htons (port_number);
  mif->partner.port_priority = htons (LACP_DEFAULT_PORT_PRIORITY);
  mif->partner.state = 0;

  mif->actor_admin = mif->actor;
  mif->partner_admin = mif->partner;
}

void
lacp_init_state_machines (vlib_main_t * vm, member_if_t * mif)
{
  bond_main_t *bm = &bond_main;
  bond_if_t *bif = bond_get_bond_if_by_dev_instance (mif->bif_dev_instance);

  lacp_init_tx_machine (vm, mif);
  lacp_init_mux_machine (vm, mif);
  lacp_init_ptx_machine (vm, mif);
  lacp_init_rx_machine (vm, mif);
  stat_segment_set_state_counter (bm->stats[bif->sw_if_index]
				  [mif->sw_if_index].actor_state,
				  mif->actor.state);
  stat_segment_set_state_counter (bm->stats[bif->sw_if_index]
				  [mif->sw_if_index].partner_state,
				  mif->partner.state);
}

VLIB_INIT_FUNCTION (lacp_periodic_init);

static clib_error_t *
lacp_sw_interface_up_down (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  lacp_main_t *lm = &lacp_main;
  member_if_t *mif;
  vlib_main_t *vm = lm->vlib_main;

  mif = bond_get_member_by_sw_if_index (sw_if_index);
  if (mif)
    {
      if (mif->lacp_enabled == 0)
	return 0;

      /* port_enabled is both admin up and hw link up */
      mif->port_enabled = ((flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) &&
			   vnet_sw_interface_is_link_up (vnm, sw_if_index));
      if (mif->port_enabled == 0)
	{
	  lacp_init_neighbor (mif, mif->actor_admin.system,
			      ntohs (mif->actor_admin.port_number),
			      ntohs (mif->actor_admin.key));
	  lacp_init_state_machines (vm, mif);
	}
    }

  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (lacp_sw_interface_up_down);

static clib_error_t *
lacp_hw_interface_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  lacp_main_t *lm = &lacp_main;
  member_if_t *mif;
  vnet_sw_interface_t *sw;
  vlib_main_t *vm = lm->vlib_main;

  sw = vnet_get_hw_sw_interface (vnm, hw_if_index);
  mif = bond_get_member_by_sw_if_index (sw->sw_if_index);
  if (mif)
    {
      if (mif->lacp_enabled == 0)
	return 0;

      /* port_enabled is both admin up and hw link up */
      mif->port_enabled = ((flags & VNET_HW_INTERFACE_FLAG_LINK_UP) &&
			   vnet_sw_interface_is_admin_up (vnm,
							  sw->sw_if_index));
      if (mif->port_enabled == 0)
	{
	  lacp_init_neighbor (mif, mif->actor_admin.system,
			      ntohs (mif->actor_admin.port_number),
			      ntohs (mif->actor_admin.key));
	  lacp_init_state_machines (vm, mif);
	}
    }

  return 0;
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (lacp_hw_interface_up_down);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Link Aggregation Control Protocol (LACP)",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
