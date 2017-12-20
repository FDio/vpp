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
#include <vppinfra/hash.h>
#include <vnet/bonding/node.h>
#include <vnet/bonding/lacp/node.h>
#include <vnet/bonding/lacp/machine.h>
#include <vnet/bonding/lacp/rx_machine.h>
#include <vnet/bonding/lacp/ptx_machine.h>
#include <vnet/bonding/lacp/mux_machine.h>

/*
 * Generate lacp pdu
 */
static void
lacp_fill_pdu (bond_main_t * bm, vnet_hw_interface_t * hw,
	       lacp_pdu_t * lacpdu, lacp_neighbor_t * n)
{
  /* Actor TLV */
  lacpdu->actor.tlv_type = LACP_ACTOR_INFORMATION;
  lacpdu->actor.tlv_length = sizeof (lacp_actor_partner_t);
  lacpdu->actor.port_info = n->actor;

  /* Partner TLV */
  lacpdu->partner.tlv_type = LACP_PARTNER_INFORMATION;
  lacpdu->partner.tlv_length = sizeof (lacp_actor_partner_t);
  lacpdu->partner.port_info = n->partner;

  /* Collector TLV */
  lacpdu->collector.tlv_type = LACP_COLLECTOR_INFORMATION;
  lacpdu->collector.tlv_length = sizeof (lacp_collector_t);
  lacpdu->collector.max_delay = 0;

  /* Terminator TLV */
  lacpdu->terminator.tlv_type = LACP_TERMINATOR_INFORMATION;
  lacpdu->terminator.tlv_length = 0;
}

/*
 * send a lacp pkt on an ethernet interface
 */
static void
lacp_send_ethernet_lacp_pdu (bond_main_t * bm, lacp_neighbor_t * n, int count)
{
  u32 *to_next;
  ethernet_lacp_pdu_t *h0;
  vnet_hw_interface_t *hw;
  u32 bi0;
  vlib_buffer_t *b0;
  int i;
  vlib_frame_t *f;
  vlib_main_t *vm = bm->vlib_main;
  vnet_main_t *vnm = bm->vnet_main;

  for (i = 0; i < count; i++)
    {
      /*
       * see lacp_periodic_init() to understand what's already painted
       * into the buffer by the packet template mechanism
       */
      h0 = vlib_packet_template_get_packet
	(vm, &bm->packet_templates[n->packet_template_index], &bi0);

      if (!h0)
	break;

      /* Add the interface's ethernet source address */
      hw = vnet_get_sup_hw_interface (vnm, n->sw_if_index);

      clib_memcpy (h0->ethernet.src_address, hw->hw_address,
		   vec_len (hw->hw_address));

      lacp_fill_pdu (bm, hw, &h0->lacp, n);

      /* Set the outbound packet length */
      b0 = vlib_get_buffer (vm, bi0);
      b0->current_length = sizeof (ethernet_lacp_pdu_t);

      /* And the outbound interface */
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = hw->sw_if_index;

      /* And output the packet on the correct interface */
      f = vlib_get_frame_to_node (vm, hw->output_node_index);

      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi0;
      f->n_vectors = 1;

      vlib_put_frame_to_node (vm, hw->output_node_index, f);

      n->periodic_timer = vlib_time_now (vm);
    }
}

/*
 * Decide which lacp packet template to use
 */
static int
pick_packet_template (bond_main_t * bm, lacp_neighbor_t * n)
{
  n->packet_template_index = LACP_PACKET_TEMPLATE_ETHERNET;

  return 0;
}

void
lacp_send_lacp_pdu (bond_main_t * bm, lacp_neighbor_t * n, int count)
{
  if (n->packet_template_index == (u8) ~ 0)
    {
      /* If we don't know how to talk to this peer, don't try again */
      if (pick_packet_template (bm, n))
	{
	  n->periodic_timer = 1e70;
	  return;
	}
    }

  switch (n->packet_template_index)
    {
    case LACP_PACKET_TEMPLATE_ETHERNET:
      lacp_send_ethernet_lacp_pdu (bm, n, count);
      break;

    default:
      ASSERT (0);
    }
  n->periodic_timer = vlib_time_now (bm->vlib_main);
}

void
lacp_delete_neighbor (bond_main_t * bm, lacp_neighbor_t * n,
		      int want_broadcast)
{
  hash_unset (bm->neighbor_by_sw_if_index, n->sw_if_index);
  vec_free (n->last_rx_pkt);
  pool_put (bm->neighbors, n);
}

void
lacp_periodic (vlib_main_t * vm)
{
  bond_main_t *bm = &bond_main;
  lacp_neighbor_t *n;
  f64 now = vlib_time_now (vm);
  vnet_sw_interface_t *sw;

  /* *INDENT-OFF* */
  pool_foreach (n, bm->neighbors,
  ({    
    if (n->disabled == 1)
      continue;

    sw = vnet_get_sw_interface (bm->vnet_main, n->sw_if_index);

    /* Interface shutdown */
    if (!(sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
      continue;

    if (now >= n->periodic_timer + LACP_FAST_PERIODIC_TIMER)
      lacp_machine_dispatch (&lacp_ptx_machine, vm, n,
			     LACP_PTX_EVENT_TIMER_EXPIRED, &n->ptx_state);
    if (now >= n->current_while_timer + (f64) n->ttl_in_seconds)
      lacp_machine_dispatch (&lacp_rx_machine, vm, n,
			     LACP_RX_EVENT_TIMER_EXPIRED, &n->rx_state);
    if ((n->wait_while_timer != 0.0) &&
	(now >= n->wait_while_timer + LACP_AGGREGATE_WAIT_TIME))
      {
        n->ready = 1;
	n->wait_while_timer = 0.0;
        lacp_machine_dispatch (&lacp_mux_machine, vm, n,
			       LACP_MUX_EVENT_READY, &n->mux_state);
      }
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
lacp_periodic_init (vlib_main_t * vm)
{
  bond_main_t *bm = &bond_main;
  ethernet_lacp_pdu_t h;
  u8 dst[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x02 };

  /* Create the ethernet lacp packet template */

  memset (&h, 0, sizeof (h));

  memcpy (h.ethernet.dst_address, dst, sizeof (h.ethernet.dst_address));

  /* leave src address blank (fill in at send time) */

  h.ethernet.type = htons (ETHERNET_TYPE_SLOW_PROTOCOLS);

  h.lacp.subtype = LACP_SUBTYPE;
  h.lacp.version_number = LACP_ACTOR_LACP_VERSION;
  vlib_packet_template_init
    (vm, &bm->packet_templates[LACP_PACKET_TEMPLATE_ETHERNET],
     /* data */ &h,
     sizeof (h),
     /* alloc chunk size */ 8,
     "lacp-ethernet");

  return 0;
}

int
lacp_machine_dispatch (lacp_machine_t * machine, vlib_main_t * vm,
		       lacp_neighbor_t * n, int event, int *state)
{
  lacp_fsm_state_t *transition;
  int rc = 0;

  transition = &machine->tables[*state].state_table[event];
  LACP_DBG2 (n, event, *state, machine, transition);
  *state = transition->next_state;
  if (transition->action)
    rc = (*transition->action) ((void *) vm, (void *) n);

  return rc;
}

void
lacp_init_neighbor (lacp_neighbor_t * n, u32 sw_if_index, int port_number,
		    u32 group)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw;

  n->wait_while_timer = 0.0;
  n->current_while_timer = 0.0;
  n->actor_churn_timer = 0.0;
  n->partner_churn_timer = 0.0;
  n->periodic_timer = 0.0;
  n->begin = 1;
  n->lacp_enabled = 1;
  n->actor.state = LACP_STATE_AGGREGATION;
  if (n->ttl_in_seconds == LACP_SHORT_TIMOUT_TIME)
    n->actor.state |= LACP_STATE_LACP_TIMEOUT;
  if (n->is_passive == 0)
    n->actor.state |= LACP_STATE_LACP_ACTIVITY;
  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  clib_memcpy (n->actor.system, hw->hw_address, 6);
  n->actor.system_priority = htons (LACP_DEFAULT_SYSTEM_PRIORITY);
  n->actor.key = htons (group);
  n->actor.port_number = htons (port_number);
  n->actor.port_priority = htons (LACP_DEFAULT_PORT_PRIORITY);

  n->partner.system_priority = htons (LACP_DEFAULT_SYSTEM_PRIORITY);
  n->partner.key = htons (group);
  n->partner.port_number = htons (port_number);
  n->partner.port_priority = htons (LACP_DEFAULT_PORT_PRIORITY);
  n->partner.key = htons (group);
  n->partner.state = LACP_STATE_LACP_ACTIVITY;

  n->actor_admin = n->actor;
  n->partner_admin = n->partner;
}

void
lacp_init_state_machines (vlib_main_t * vm, lacp_neighbor_t * n)
{
  lacp_init_tx_machine (vm, n);
  lacp_init_mux_machine (vm, n);
  lacp_init_ptx_machine (vm, n);
  lacp_init_rx_machine (vm, n);
}

VLIB_INIT_FUNCTION (lacp_periodic_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
