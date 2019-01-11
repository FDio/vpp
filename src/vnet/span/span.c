/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include <vnet/feature/feature.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>

#include <vnet/span/span.h>

span_main_t span_main;

typedef enum
{
  SPAN_DISABLE = 0,
  SPAN_RX = 1,
  SPAN_TX = 2,
  SPAN_BOTH = SPAN_RX | SPAN_TX
} span_state_t;

static_always_inline u32
span_dst_set (span_mirror_t * sm, u32 dst_sw_if_index, int enable)
{
  if (dst_sw_if_index == ~0)
    {
      ASSERT (enable == 0);
      clib_bitmap_zero (sm->mirror_ports);
    }
  else
    sm->mirror_ports =
      clib_bitmap_set (sm->mirror_ports, dst_sw_if_index, enable);

  u32 last = sm->num_mirror_ports;
  sm->num_mirror_ports = clib_bitmap_count_set_bits (sm->mirror_ports);
  return last;
}

int
span_add_delete_entry (vlib_main_t * vm,
		       u32 src_sw_if_index, u32 dst_sw_if_index, u8 state,
		       span_feat_t sf)
{
  span_main_t *sm = &span_main;

  if (state > SPAN_BOTH)
    return VNET_API_ERROR_UNIMPLEMENTED;

  if ((src_sw_if_index == ~0) || (dst_sw_if_index == ~0 && state > 0)
      || (src_sw_if_index == dst_sw_if_index))
    return VNET_API_ERROR_INVALID_INTERFACE;

  vec_validate_aligned (sm->interfaces, src_sw_if_index,
			CLIB_CACHE_LINE_BYTES);

  span_interface_t *si = vec_elt_at_index (sm->interfaces, src_sw_if_index);

  int rx = ! !(state & SPAN_RX);
  int tx = ! !(state & SPAN_TX);

  span_mirror_t *rxm = &si->mirror_rxtx[sf][VLIB_RX];
  span_mirror_t *txm = &si->mirror_rxtx[sf][VLIB_TX];

  u32 last_rx_ports_count = span_dst_set (rxm, dst_sw_if_index, rx);
  u32 last_tx_ports_count = span_dst_set (txm, dst_sw_if_index, tx);

  int enable_rx = last_rx_ports_count == 0 && rxm->num_mirror_ports == 1;
  int disable_rx = last_rx_ports_count > 0 && rxm->num_mirror_ports == 0;
  int enable_tx = last_tx_ports_count == 0 && txm->num_mirror_ports == 1;
  int disable_tx = last_tx_ports_count > 0 && txm->num_mirror_ports == 0;

  switch (sf)
    {
    case SPAN_FEAT_DEVICE:
      if (enable_rx || disable_rx)
	vnet_feature_enable_disable ("device-input", "span-input",
				     src_sw_if_index, rx, 0, 0);
      if (enable_tx || disable_tx)
	vnet_feature_enable_disable ("interface-output", "span-output",
				     src_sw_if_index, tx, 0, 0);
      break;
    case SPAN_FEAT_L2:
      if (enable_rx || disable_rx)
	l2input_intf_bitmap_enable (src_sw_if_index, L2INPUT_FEAT_SPAN, rx);
      if (enable_tx || disable_tx)
	l2output_intf_bitmap_enable (src_sw_if_index, L2OUTPUT_FEAT_SPAN, tx);
      break;
    default:
      return VNET_API_ERROR_UNIMPLEMENTED;
    }

  if (dst_sw_if_index != ~0 && dst_sw_if_index > sm->max_sw_if_index)
    sm->max_sw_if_index = dst_sw_if_index;

  return 0;
}

static uword
unformat_span_state (unformat_input_t * input, va_list * args)
{
  span_state_t *state = va_arg (*args, span_state_t *);
  if (unformat (input, "disable"))
    *state = SPAN_DISABLE;
  else if (unformat (input, "rx"))
    *state = SPAN_RX;
  else if (unformat (input, "tx"))
    *state = SPAN_TX;
  else if (unformat (input, "both"))
    *state = SPAN_BOTH;
  else
    return 0;
  return 1;
}

static clib_error_t *
set_interface_span_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  span_main_t *sm = &span_main;
  u32 src_sw_if_index = ~0;
  u32 dst_sw_if_index = ~0;
  span_feat_t sf = SPAN_FEAT_DEVICE;
  span_state_t state = SPAN_BOTH;
  int state_set = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    sm->vnet_main, &src_sw_if_index))
	;
      else if (unformat (input, "destination %U", unformat_vnet_sw_interface,
			 sm->vnet_main, &dst_sw_if_index))
	;
      else if (unformat (input, "%U", unformat_span_state, &state))
	{
	  if (state_set)
	    return clib_error_return (0, "Multiple mirror states in input");
	  state_set = 1;
	}
      else if (unformat (input, "l2"))
	sf = SPAN_FEAT_L2;
      else
	return clib_error_return (0, "Invalid input");
    }

  int rv =
    span_add_delete_entry (vm, src_sw_if_index, dst_sw_if_index, state, sf);
  if (rv == VNET_API_ERROR_INVALID_INTERFACE)
    return clib_error_return (0, "Invalid interface");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_span_command, static) = {
  .path = "set interface span",
  .short_help = "set interface span <if-name> [l2] {disable | destination <if-name> [both|rx|tx]}",
  .function = set_interface_span_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_interfaces_span_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  span_main_t *sm = &span_main;
  span_interface_t *si;
  vnet_main_t *vnm = &vnet_main;
  u8 header = 1;
  static const char *states[] = {
    [SPAN_DISABLE] = "none",
    [SPAN_RX] = "rx",
    [SPAN_TX] = "tx",
    [SPAN_BOTH] = "both"
  };
  u8 *s = 0;

  /* *INDENT-OFF* */
  vec_foreach (si, sm->interfaces)
  {
  span_mirror_t * drxm = &si->mirror_rxtx[SPAN_FEAT_DEVICE][VLIB_RX];
  span_mirror_t * dtxm = &si->mirror_rxtx[SPAN_FEAT_DEVICE][VLIB_TX];

  span_mirror_t * lrxm = &si->mirror_rxtx[SPAN_FEAT_L2][VLIB_RX];
  span_mirror_t * ltxm = &si->mirror_rxtx[SPAN_FEAT_L2][VLIB_TX];

    if (drxm->num_mirror_ports || dtxm->num_mirror_ports ||
        lrxm->num_mirror_ports || ltxm->num_mirror_ports)
      {
	u32 i;
	clib_bitmap_t *d = clib_bitmap_dup_or (drxm->mirror_ports, dtxm->mirror_ports);
	clib_bitmap_t *l = clib_bitmap_dup_or (lrxm->mirror_ports, ltxm->mirror_ports);
	clib_bitmap_t *b = clib_bitmap_dup_or (d, l);
	if (header)
	  {
	    vlib_cli_output (vm, "%-32s %-32s  %6s   %6s", "Source", "Destination",
			     "Device", "L2");
	    header = 0;
	  }
	s = format (s, "%U", format_vnet_sw_if_index_name, vnm,
		    si - sm->interfaces);
	clib_bitmap_foreach (i, b, (
	  {
	    int device = (clib_bitmap_get (drxm->mirror_ports, i) +
		         clib_bitmap_get (dtxm->mirror_ports, i) * 2);
	    int l2 = (clib_bitmap_get (lrxm->mirror_ports, i) +
		      clib_bitmap_get (ltxm->mirror_ports, i) * 2);

	    vlib_cli_output (vm, "%-32v %-32U (%6s) (%6s)", s,
			     format_vnet_sw_if_index_name, vnm, i,
			     states[device], states[l2]);
	    vec_reset_length (s);
	  }));
	clib_bitmap_free (b);
	clib_bitmap_free (l);
	clib_bitmap_free (d);
      }
      }
  /* *INDENT-ON* */
  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_interfaces_span_command, static) = {
  .path = "show interface span",
  .short_help = "Shows SPAN mirror table",
  .function = show_interfaces_span_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
