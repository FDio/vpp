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

#define _GNU_SOURCE
#include <vnet/bonding/node.h>
#include <vnet/bonding/lacp/node.h>
#include <vnet/bonding/lacp/rx_machine.h>

static int
lacp_packet_scan (vlib_main_t * vm, bond_main_t * bm, lacp_neighbor_t * n)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) n->last_rx_pkt;

  if (lacpdu->subtype != LACP_SUBTYPE)
    return LACP_ERROR_UNSUPPORTED;

  /*
   * According to the spec, no checking on the version number and tlv types.
   * But we may check the tlv lengths.
   */
  if ((lacpdu->actor.tlv_length != sizeof (lacp_actor_partner_t)) ||
      (lacpdu->partner.tlv_length != sizeof (lacp_actor_partner_t)) ||
      (lacpdu->collector.tlv_length != sizeof (lacp_collector_t)) ||
      (lacpdu->terminator.tlv_length != 0))
    return (LACP_ERROR_BAD_TLV);

  lacp_machine_dispatch (&lacp_rx_machine, vm, n, LACP_RX_EVENT_PDU_RECEIVED,
			 &n->rx_state);

  return LACP_ERROR_NONE;
}

/*
 * lacp input routine
 */
lacp_error_t
lacp_input (vlib_main_t * vm, vlib_buffer_t * b0, u32 bi0)
{
  bond_main_t *bm = &bond_main;
  lacp_neighbor_t *n;
  uword *p, nbytes;
  lacp_error_t e;

  /* find or create a neighbor pool entry for the (sw) interface
     upon which we received this pkt */

  p = hash_get (bm->neighbor_by_sw_if_index,
		vnet_buffer (b0)->sw_if_index[VLIB_RX]);

  if (p == 0)
    {
      return LACP_ERROR_DISABLED;
    }
  else
    {
      n = pool_elt_at_index (bm->neighbors, p[0]);
    }

  /*
   * typical clib idiom. Don't repeatedly allocate and free
   * the per-neighbor rx buffer. Reset its apparent length to zero
   * and reuse it.
   */

  if (n->last_rx_pkt)
    _vec_len (n->last_rx_pkt) = 0;

  /* lacp disabled on this interface, we're done */
  if (n->disabled)
    return LACP_ERROR_DISABLED;

  /*
   * Make sure the per-neighbor rx buffer is big enough to hold
   * the data we're about to copy
   */
  vec_validate (n->last_rx_pkt, vlib_buffer_length_in_chain (vm, b0) - 1);

  /*
   * Coalesce / copy e the buffer chain into the per-neighbor
   * rx buffer
   */
  nbytes = vlib_buffer_contents (vm, bi0, n->last_rx_pkt);
  ASSERT (nbytes <= vec_len (n->last_rx_pkt));

  if (nbytes < sizeof (lacp_pdu_t))
    return LACP_ERROR_TOO_SMALL;

  /* Actually scan the packet */
  e = lacp_packet_scan (vm, bm, n);

  if (e == LACP_ERROR_NONE)
    {
      n->last_heard = vlib_time_now (vm);
    }

  return e;
}

/*
 * setup neighbor hash table
 */
static clib_error_t *
lacp_init (vlib_main_t * vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, lacp_periodic_init)))
    return error;

  return 0;
}

VLIB_INIT_FUNCTION (lacp_init);

/*
 * packet trace format function, very similar to
 * lacp_packet_scan except that we call the per TLV format
 * functions instead of the per TLV processing functions
 */
u8 *
lacp_input_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lacp_input_trace_t *t = va_arg (*args, lacp_input_trace_t *);
  lacp_pdu_t *lacpdu = &t->lacpdu;
  int i, len;
  u8 *p;
  lacp_state_struct *state_entry;

  s = format (s, "Length: %d\n", t->len);
  if (t->len >= sizeof (lacp_pdu_t))
    {
      if ((lacpdu->subtype == LACP_SUBTYPE) && (lacpdu->version_number == 1))
	s = format (s, "  LACPv1\n");
      else
	s = format (s, "  Subtype %u, Version %u\n", lacpdu->subtype,
		    lacpdu->version_number);
      s = format (s, "  Actor Information TLV: length %u\n",
		  lacpdu->actor.tlv_length);
      s = format (s, "    System %U\n", format_ethernet_address,
		  lacpdu->actor.port_info.system);
      s = format (s, "    System priority %u\n",
		  ntohs (lacpdu->actor.port_info.system_priority));
      s = format (s, "    Key %u\n", ntohs (lacpdu->actor.port_info.key));
      s = format (s, "    Port priority %u\n",
		  ntohs (lacpdu->actor.port_info.port_priority));
      s = format (s, "    Port number %u\n",
		  ntohs (lacpdu->actor.port_info.port_number));
      s = format (s, "    State 0x%x\n", lacpdu->actor.port_info.state);
      state_entry = (lacp_state_struct *) & lacp_state_array;
      while (state_entry->str)
	{
	  if (lacpdu->actor.port_info.state & (1 << state_entry->bit))
	    s = format (s, "      %s (%d)\n", state_entry->str,
			state_entry->bit);
	  state_entry++;
	}

      s = format (s, "  Partner Information TLV: length %u\n",
		  lacpdu->partner.tlv_length);
      s = format (s, "    System %U\n", format_ethernet_address,
		  lacpdu->partner.port_info.system);
      s = format (s, "    System priority %u\n",
		  ntohs (lacpdu->partner.port_info.system_priority));
      s = format (s, "    Key %u\n", ntohs (lacpdu->partner.port_info.key));
      s = format (s, "    Port priority %u\n",
		  ntohs (lacpdu->partner.port_info.port_priority));
      s = format (s, "    Port number %u\n",
		  ntohs (lacpdu->partner.port_info.port_number));
      s = format (s, "    State 0x%x\n", lacpdu->partner.port_info.state);
      state_entry = (lacp_state_struct *) & lacp_state_array;
      while (state_entry->str)
	{
	  if (lacpdu->partner.port_info.state & (1 << state_entry->bit))
	    s = format (s, "      %s (%d)\n", state_entry->str,
			state_entry->bit);
	  state_entry++;
	}
    }

  if (t->len > sizeof (lacp_pdu_t))
    len = sizeof (lacp_pdu_t);
  else
    len = t->len;
  p = (u8 *) lacpdu;
  for (i = 0; i < len; i++)
    {
      if ((i % 16) == 0)
	{
	  if (i)
	    s = format (s, "\n");
	  s = format (s, "  0x%04x: ", i);
	}
      if ((i % 2) == 0)
	s = format (s, " ");
      s = format (s, "%02x", p[i]);
    }

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
