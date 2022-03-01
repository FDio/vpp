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

static int
span_enable_disable_feature (u32 sw_if_index, const char *in_arc,
			     const char *in_feat, int update_rx, int rx,
			     const char *out_arc, const char *out_feat,
			     int update_tx, int tx)
{
  int err;

  if (update_rx && (err = vnet_feature_enable_disable (in_arc, in_feat,
						       sw_if_index, rx, 0, 0)))
    return err;

  if (update_tx && (err = vnet_feature_enable_disable (out_arc, out_feat,
						       sw_if_index, tx, 0, 0)))
    {
      if (update_rx)
	vnet_feature_enable_disable (in_arc, in_feat, sw_if_index, !rx, 0, 0);
      return err;
    }

  return 0;
}

int
span_add_delete_entry (vlib_main_t * vm,
		       u32 src_sw_if_index, u32 dst_sw_if_index, u8 state,
		       span_feat_t sf)
{
  span_main_t *sm = &span_main;
  int err = 0;

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
  int update_rx = enable_rx || disable_rx;
  int update_tx = enable_tx || disable_tx;

  switch (sf)
    {
    case SPAN_FEAT_DEVICE:
      err = span_enable_disable_feature (
	src_sw_if_index, "device-input", "span-input", update_rx, rx,
	"interface-output", "span-output", update_tx, tx);
      break;
    case SPAN_FEAT_IP4:
      err = span_enable_disable_feature (
	src_sw_if_index, "ip4-unicast", "span-ip4-input", update_rx, rx,
	"ip4-output", "span-ip4-output", update_tx, tx);
      break;
    case SPAN_FEAT_IP6:
      err = span_enable_disable_feature (
	src_sw_if_index, "ip6-unicast", "span-ip6-input", update_rx, rx,
	"ip6-output", "span-ip6-output", update_tx, tx);
      break;
    case SPAN_FEAT_L2:
      if (update_rx)
	l2input_intf_bitmap_enable (src_sw_if_index, L2INPUT_FEAT_SPAN, rx);
      if (update_tx)
	l2output_intf_bitmap_enable (src_sw_if_index, L2OUTPUT_FEAT_SPAN, tx);
      break;
    default:
      return VNET_API_ERROR_UNIMPLEMENTED;
    }

  if (err)
    return err;

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
  unformat_input_t _line_input, *line_input = &_line_input;
  span_main_t *sm = &span_main;
  u32 src_sw_if_index = ~0;
  u32 dst_sw_if_index = ~0;
  span_feat_t sf = SPAN_FEAT_DEVICE;
  span_state_t state = SPAN_BOTH;
  int state_set = 0;
  clib_error_t *err = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    sm->vnet_main, &src_sw_if_index))
	;
      else if (unformat (line_input, "destination %U",
			 unformat_vnet_sw_interface, sm->vnet_main,
			 &dst_sw_if_index))
	;
      else if (unformat (line_input, "%U", unformat_span_state, &state))
	{
	  if (state_set)
	    {
	      err = clib_error_return (0, "Multiple mirror states in input");
	      goto out;
	    }
	  state_set = 1;
	}
      else if (unformat (line_input, "l2"))
	sf = SPAN_FEAT_L2;
      else if (unformat (line_input, "ip4"))
	sf = SPAN_FEAT_IP4;
      else if (unformat (line_input, "ip6"))
	sf = SPAN_FEAT_IP6;
      else
	{
	  err = clib_error_return (0, "Invalid input");
	  goto out;
	}
    }

  int rv =
    span_add_delete_entry (vm, src_sw_if_index, dst_sw_if_index, state, sf);
  switch (rv)
    {
    case 0:
      /* success */
      break;
    case VNET_API_ERROR_INVALID_INTERFACE:
      err = clib_error_return (0, "Invalid interface");
      break;
    default:
      err = clib_error_return (0, "Error %d", rv);
      break;
    }

out:
  unformat_free (line_input);
  return err;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_span_command, static) = {
  .path = "set interface span",
  .short_help = "set interface span <if-name> [l2|ip4|ip6] {disable | "
		"destination <if-name> [both|rx|tx]}",
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
  static const char *states[] = {
    [SPAN_DISABLE] = "none",
    [SPAN_RX] = "rx",
    [SPAN_TX] = "tx",
    [SPAN_BOTH] = "both"
  };
  clib_bitmap_t *bm = 0;
  u8 *s = 0;
  uword bi;
  int i;

  vlib_cli_output (vm, "%-32s %-32s  %6s   %6s   %6s   %6s", "Source",
		   "Destination", "Device", "L2", "IP4", "IP6");
  vec_foreach (si, sm->interfaces)
    {
      vec_reset_length (s);
      s = format (s, "%-32U ", format_vnet_sw_if_index_name, vnm,
		  si - sm->interfaces);
      vec_reset_length (bm);
      /* build list of destination for this source */
      for (i = 0; i < SPAN_FEAT_N; i++)
	{
	  bm = clib_bitmap_or (bm, si->mirror_rxtx[i][VLIB_RX].mirror_ports);
	  bm = clib_bitmap_or (bm, si->mirror_rxtx[i][VLIB_TX].mirror_ports);
	}
      clib_bitmap_foreach (bi, bm)
	{
	  /* display state for each destination */
	  vec_set_len (s, 33);
	  s = format (s, "%-32U", format_vnet_sw_if_index_name, vnm, bi);
	  for (i = 0; i < SPAN_FEAT_N; i++)
	    {
	      u8 st = clib_bitmap_get (
			si->mirror_rxtx[i][VLIB_RX].mirror_ports, bi) +
		      clib_bitmap_get (
			si->mirror_rxtx[i][VLIB_TX].mirror_ports, bi) *
			2;
	      s = format (s, " (%6s)", states[st]);
	    }
	  vlib_cli_output (vm, "%v", s);
	}
    }

  clib_bitmap_free (bm);
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
