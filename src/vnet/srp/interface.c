/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 * srp_interface.c: srp interfaces
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/srp/srp.h>

static u8*
srp_build_rewrite (vnet_main_t * vnm,
		   u32 sw_if_index,
		   vnet_link_t link_type,
		   const void * dst_address)
{
  vnet_hw_interface_t * hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  srp_main_t * sm = &srp_main;
  srp_and_ethernet_header_t * h;
  u8* rewrite = NULL;
  u16 type;
  uword n_bytes = sizeof (h[0]);

  switch (link_type) {
#define _(a,b) case VNET_LINK_##a: type = ETHERNET_TYPE_##b; break
    _ (IP4, IP4);
    _ (IP6, IP6);
    _ (MPLS, MPLS);
    _ (ARP, ARP);
#undef _
  default:
      return (NULL);
  }

  vec_validate(rewrite, n_bytes-1);
  h = (srp_and_ethernet_header_t *)rewrite;

  clib_memcpy (h->ethernet.src_address, hw->hw_address, sizeof (h->ethernet.src_address));
  if (dst_address)
    clib_memcpy (h->ethernet.dst_address, dst_address, sizeof (h->ethernet.dst_address));
  else
    memset (h->ethernet.dst_address, ~0, sizeof (h->ethernet.dst_address)); /* broadcast */

  h->ethernet.type = clib_host_to_net_u16 (type);

  h->srp.as_u16 = 0;
  h->srp.mode = SRP_MODE_data;
  h->srp.ttl = sm->default_data_ttl;
  srp_header_compute_parity (&h->srp);

  return (rewrite);
}

static void srp_register_interface_helper (u32 * hw_if_indices_by_side, u32 redistribute);

void serialize_srp_main (serialize_main_t * m, va_list * va)
{
  srp_main_t * sm = &srp_main;
  srp_interface_t * si;

  serialize_integer (m, pool_elts (sm->interface_pool), sizeof (u32));
  pool_foreach (si, sm->interface_pool, ({
    serialize_integer (m, si->rings[SRP_RING_OUTER].hw_if_index, sizeof (u32));
    serialize_integer (m, si->rings[SRP_RING_INNER].hw_if_index, sizeof (u32));
  }));
}

void unserialize_srp_main (serialize_main_t * m, va_list * va)
{
  u32 i, n_ifs, hw_if_indices[SRP_N_RING];

  unserialize_integer (m, &n_ifs, sizeof (u32));
  for (i = 0; i < n_ifs; i++)
    {
      unserialize_integer (m, &hw_if_indices[SRP_RING_OUTER], sizeof (u32));
      unserialize_integer (m, &hw_if_indices[SRP_RING_INNER], sizeof (u32));
      srp_register_interface_helper (hw_if_indices, /* redistribute */ 0);
    }
}

static void serialize_srp_register_interface_msg (serialize_main_t * m, va_list * va)
{
  u32 * hw_if_indices = va_arg (*va, u32 *);
  serialize_integer (m, hw_if_indices[SRP_SIDE_A], sizeof (hw_if_indices[SRP_SIDE_A]));
  serialize_integer (m, hw_if_indices[SRP_SIDE_B], sizeof (hw_if_indices[SRP_SIDE_B]));
}

static void unserialize_srp_register_interface_msg (serialize_main_t * m, va_list * va)
{
  CLIB_UNUSED (mc_main_t * mcm) = va_arg (*va, mc_main_t *);
  u32 hw_if_indices[SRP_N_SIDE];
  srp_main_t * sm = &srp_main;
  uword * p;

  unserialize_integer (m, &hw_if_indices[SRP_SIDE_A], sizeof (hw_if_indices[SRP_SIDE_A]));
  unserialize_integer (m, &hw_if_indices[SRP_SIDE_B], sizeof (hw_if_indices[SRP_SIDE_B]));

  p = hash_get (sm->srp_register_interface_waiting_process_pool_index_by_hw_if_index,
		hw_if_indices[0]);
  if (p)
    {
      vlib_one_time_waiting_process_t * wp = pool_elt_at_index (sm->srp_register_interface_waiting_process_pool, p[0]);
      vlib_signal_one_time_waiting_process (mcm->vlib_main, wp);
      pool_put (sm->srp_register_interface_waiting_process_pool, wp);
      hash_unset (sm->srp_register_interface_waiting_process_pool_index_by_hw_if_index,
		  hw_if_indices[0]);
    }
  else
    srp_register_interface_helper (hw_if_indices, /* redistribute */ 0);
}

MC_SERIALIZE_MSG (srp_register_interface_msg, static) = {
  .name = "vnet_srp_register_interface",
  .serialize = serialize_srp_register_interface_msg,
  .unserialize = unserialize_srp_register_interface_msg,
};

static void srp_register_interface_helper (u32 * hw_if_indices_by_side, u32 redistribute)
{
  vnet_main_t * vnm = vnet_get_main();
  srp_main_t * sm = &srp_main;
  vlib_main_t * vm = sm->vlib_main;
  srp_interface_t * si;
  vnet_hw_interface_t * hws[SRP_N_RING];
  uword s, * p;

  if (vm->mc_main && redistribute)
    {
      vlib_one_time_waiting_process_t * wp;
      mc_serialize (vm->mc_main, &srp_register_interface_msg, hw_if_indices_by_side);
      pool_get (sm->srp_register_interface_waiting_process_pool, wp);
      hash_set (sm->srp_register_interface_waiting_process_pool_index_by_hw_if_index,
		hw_if_indices_by_side[0],
		wp - sm->srp_register_interface_waiting_process_pool);
      vlib_current_process_wait_for_one_time_event (vm, wp);
    }

  /* Check if interface has already been registered. */
  p = hash_get (sm->interface_index_by_hw_if_index, hw_if_indices_by_side[0]);
  if (p)
    {
      si = pool_elt_at_index (sm->interface_pool, p[0]);
    }
  else
    {
      pool_get (sm->interface_pool, si);
      memset (si, 0, sizeof (si[0]));
    }
  for (s = 0; s < SRP_N_SIDE; s++)
    {
      hws[s] = vnet_get_hw_interface (vnm, hw_if_indices_by_side[s]);
      si->rings[s].ring = s;
      si->rings[s].hw_if_index = hw_if_indices_by_side[s];
      si->rings[s].sw_if_index = hws[s]->sw_if_index;
      hash_set (sm->interface_index_by_hw_if_index, hw_if_indices_by_side[s], si - sm->interface_pool);
    }

  /* Inherit MAC address from outer ring. */
  clib_memcpy (si->my_address, hws[SRP_RING_OUTER]->hw_address,
	  vec_len (hws[SRP_RING_OUTER]->hw_address));

  /* Default time to wait to restore signal. */
  si->config.wait_to_restore_idle_delay = 60;
  si->config.ips_tx_interval = 1;
}

void srp_register_interface (u32 * hw_if_indices_by_side)
{
  srp_register_interface_helper (hw_if_indices_by_side, /* redistribute */ 1);
}

void srp_interface_set_hw_wrap_function (u32 hw_if_index, srp_hw_wrap_function_t * f)
{
  srp_interface_t * si = srp_get_interface_from_vnet_hw_interface (hw_if_index);
  si->hw_wrap_function = f;
}

void srp_interface_set_hw_enable_function (u32 hw_if_index, srp_hw_enable_function_t * f)
{
  srp_interface_t * si = srp_get_interface_from_vnet_hw_interface (hw_if_index);
  si->hw_enable_function = f;
}

void srp_interface_enable_ips (u32 hw_if_index)
{
  srp_main_t * sm = &srp_main;
  srp_interface_t * si = srp_get_interface_from_vnet_hw_interface (hw_if_index);

  si->ips_process_enable = 1;

  vlib_node_set_state (sm->vlib_main, srp_ips_process_node.index, VLIB_NODE_STATE_POLLING);
}

static uword
srp_is_valid_class_for_interface (vnet_main_t * vnm, u32 hw_if_index, u32 hw_class_index)
{
  srp_interface_t * si = srp_get_interface_from_vnet_hw_interface (hw_if_index);

  if (! si)
    return 0;

  /* Both sides must be admin down. */
  if (vnet_sw_interface_is_admin_up (vnm, si->rings[SRP_RING_OUTER].sw_if_index))
    return 0;
  if (vnet_sw_interface_is_admin_up (vnm, si->rings[SRP_RING_INNER].sw_if_index))
    return 0;
					 
  return 1;
}

static void
srp_interface_hw_class_change (vnet_main_t * vnm, u32 hw_if_index,
			       u32 old_hw_class_index, u32 new_hw_class_index)
{
  srp_main_t * sm = &srp_main;
  srp_interface_t * si = srp_get_interface_from_vnet_hw_interface (hw_if_index);
  vnet_hw_interface_t * hi;
  vnet_device_class_t * dc;
  u32 r, to_srp;

  if (!si) {
      clib_warning ("srp interface no set si = 0");
      return;
  }

  to_srp = new_hw_class_index == srp_hw_interface_class.index;

  /* Changing class on either outer or inner rings implies changing the class
     of the other. */
  for (r = 0; r < SRP_N_RING; r++)
    {
      srp_interface_ring_t * ir = &si->rings[r];

      hi = vnet_get_hw_interface (vnm, ir->hw_if_index);
      dc = vnet_get_device_class (vnm, hi->dev_class_index);

      /* hw_if_index itself will be handled by caller. */
      if (ir->hw_if_index != hw_if_index)
	{
	  vnet_hw_interface_init_for_class (vnm, ir->hw_if_index,
					    new_hw_class_index,
					    to_srp ? si - sm->interface_pool : ~0);

	  if (dc->hw_class_change)
	    dc->hw_class_change (vnm, ir->hw_if_index, new_hw_class_index);
	}
      else
	hi->hw_instance = to_srp ? si - sm->interface_pool : ~0;
    }

  if (si->hw_enable_function)
    si->hw_enable_function (si, /* enable */ to_srp);
}

VNET_HW_INTERFACE_CLASS (srp_hw_interface_class) = {
  .name = "SRP",
  .format_address = format_ethernet_address,
  .format_header = format_srp_header_with_length,
  .format_device = format_srp_device,
  .unformat_hw_address = unformat_ethernet_address,
  .unformat_header = unformat_srp_header,
  .build_rewrite = srp_build_rewrite,
  .update_adjacency = ethernet_update_adjacency,
  .is_valid_class_for_interface = srp_is_valid_class_for_interface,
  .hw_class_change = srp_interface_hw_class_change,
};

static void serialize_srp_interface_config_msg (serialize_main_t * m, va_list * va)
{
  srp_interface_t * si = va_arg (*va, srp_interface_t *);
  srp_main_t * sm = &srp_main;

  ASSERT (! pool_is_free (sm->interface_pool, si));
  serialize_integer (m, si - sm->interface_pool, sizeof (u32));
  serialize (m, serialize_f64, si->config.wait_to_restore_idle_delay);
  serialize (m, serialize_f64, si->config.ips_tx_interval);
}

static void unserialize_srp_interface_config_msg (serialize_main_t * m, va_list * va)
{
  CLIB_UNUSED (mc_main_t * mcm) = va_arg (*va, mc_main_t *);
  srp_main_t * sm = &srp_main;
  srp_interface_t * si;
  u32 si_index;

  unserialize_integer (m, &si_index, sizeof (u32));
  si = pool_elt_at_index (sm->interface_pool, si_index);
  unserialize (m, unserialize_f64, &si->config.wait_to_restore_idle_delay);
  unserialize (m, unserialize_f64, &si->config.ips_tx_interval);
}

MC_SERIALIZE_MSG (srp_interface_config_msg, static) = {
  .name = "vnet_srp_interface_config",
  .serialize = serialize_srp_interface_config_msg,
  .unserialize = unserialize_srp_interface_config_msg,
};

void srp_interface_get_interface_config (u32 hw_if_index, srp_interface_config_t * c)
{
  srp_interface_t * si = srp_get_interface_from_vnet_hw_interface (hw_if_index);
  ASSERT (si != 0);
  c[0] = si->config;
}

void srp_interface_set_interface_config (u32 hw_if_index, srp_interface_config_t * c)
{
  srp_main_t * sm = &srp_main;
  vlib_main_t * vm = sm->vlib_main;
  srp_interface_t * si = srp_get_interface_from_vnet_hw_interface (hw_if_index);
  ASSERT (si != 0);
  if (memcmp (&si->config, &c[0], sizeof (c[0])))
    {
      si->config = c[0];
      if (vm->mc_main)
	mc_serialize (vm->mc_main, &srp_interface_config_msg, si);
    }
}

#if DEBUG > 0

#define VNET_SIMULATED_SRP_TX_NEXT_SRP_INPUT VNET_INTERFACE_TX_N_NEXT

/* Echo packets back to srp input. */
static uword
simulated_srp_interface_tx (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * frame)
{
  u32 n_left_from, n_left_to_next, n_copy, * from, * to_next;
  u32 next_index = VNET_SIMULATED_SRP_TX_NEXT_SRP_INPUT;
  u32 i;
  vlib_buffer_t * b;

  n_left_from = frame->n_vectors;
  from = vlib_frame_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      n_copy = clib_min (n_left_from, n_left_to_next);

      clib_memcpy (to_next, from, n_copy * sizeof (from[0]));
      n_left_to_next -= n_copy;
      n_left_from -= n_copy;
      for (i = 0; i < n_copy; i++)
	{
	  b = vlib_get_buffer (vm, from[i]);
	  /* TX interface will be fake eth; copy to RX for benefit of srp-input. */
	  b->sw_if_index[VLIB_RX] = b->sw_if_index[VLIB_TX];
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return n_left_from;
}

static u8 * format_simulated_srp_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "fake-srp%d", dev_instance);
}

VNET_DEVICE_CLASS (srp_simulated_device_class,static) = {
  .name = "Simulated srp",
  .format_device_name = format_simulated_srp_name,
  .tx_function = simulated_srp_interface_tx,
};

static clib_error_t *
create_simulated_srp_interfaces (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  u8 address[6];
  u32 hw_if_index;
  vnet_hw_interface_t * hi;
  static u32 instance;

  if (! unformat_user (input, unformat_ethernet_address, &address))
    {
      memset (address, 0, sizeof (address));
      address[0] = 0xde;
      address[1] = 0xad;
      address[5] = instance;
    }

  hw_if_index = vnet_register_interface (vnm,
					 srp_simulated_device_class.index,
					 instance++,
					 srp_hw_interface_class.index, 0);

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  srp_setup_node (vm, hi->output_node_index);

  hi->min_packet_bytes = 40 + 16;

  /* Standard default ethernet MTU. */
  hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] = 1500;

  vec_free (hi->hw_address);
  vec_add (hi->hw_address, address, sizeof (address));

  {
    uword slot;

    slot = vlib_node_add_named_next_with_slot
      (vm, hi->tx_node_index,
       "srp-input",
       VNET_SIMULATED_SRP_TX_NEXT_SRP_INPUT);
    ASSERT (slot == VNET_SIMULATED_SRP_TX_NEXT_SRP_INPUT);
  }

  return /* no error */ 0;
}

static VLIB_CLI_COMMAND (create_simulated_srp_interface_command) = {
  .path = "srp create-interfaces",
  .short_help = "Create simulated srp interface",
  .function = create_simulated_srp_interfaces,
};
#endif
