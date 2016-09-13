/*
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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

/**
 * @file
 * @brief LLDP CLI handling
 *
 */
#include <vnet/lisp-cp/lisp_types.h>
#include <vnet/lldp/lldp_node.h>

#ifndef ETHER_ADDR_LEN
#include <net/ethernet.h>
#endif

typedef enum lldp_cfg_err
{
  lldp_ok,
  lldp_not_supported,
  lldp_invalid_arg,
} lldp_cfg_err_t;

static clib_error_t *
lldp_cfg_err_to_clib_err (lldp_cfg_err_t e)
{

  switch (e)
    {
    case lldp_ok:
      return 0;
    case lldp_not_supported:
      return clib_error_return (0, "not supported");
    case lldp_invalid_arg:
      return clib_error_return (0, "invalid argument");
    }
  return 0;
}

static lldp_cfg_err_t
lldp_cfg_intf_set (u32 hw_if_index, int enable)
{
  lldp_main_t *lm = &lldp_main;
  vnet_main_t *vnm = lm->vnet_main;
  ethernet_main_t *em = &ethernet_main;
  const vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  const ethernet_interface_t *eif = ethernet_get_interface (em, hw_if_index);

  if (!eif)
    {
      return lldp_not_supported;
    }

  if (enable)
    {
      lldp_intf_t *n = lldp_get_intf (lm, hw_if_index);
      if (n)
	{
	  /* already enabled */
	  return 0;
	}
      n = lldp_create_intf (lm, hw_if_index);
      const vnet_sw_interface_t *sw =
	vnet_get_sw_interface (lm->vnet_main, hi->sw_if_index);
      if (sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
	{
	  lldp_schedule_intf (lm, n);
	}
    }
  else
    {
      lldp_intf_t *n = lldp_get_intf (lm, hi->sw_if_index);
      lldp_delete_intf (lm, n);
    }

  return 0;
}

static clib_error_t *
lldp_intf_cmd (vlib_main_t * vm, unformat_input_t * input,
	       vlib_cli_command_t * cmd)
{
  lldp_main_t *lm = &lldp_main;
  vnet_main_t *vnm = lm->vnet_main;
  u32 hw_if_index;
  int enable = 0;

  if (unformat (input, "%U %U", unformat_vnet_hw_interface, vnm, &hw_if_index,
		unformat_vlib_enable_disable, &enable))
    {
      return
	lldp_cfg_err_to_clib_err (lldp_cfg_intf_set (hw_if_index, enable));
    }
  else
    {
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, input);
    }
  return 0;
}

static lldp_cfg_err_t
lldp_cfg_set (u8 ** host, int hold_time, int tx_interval)
{
  lldp_main_t *lm = &lldp_main;
  int reschedule = 0;
  if (host && *host)
    {
      vec_free (lm->sys_name);
      lm->sys_name = *host;
      *host = NULL;
    }
  if (hold_time)
    {
      if (hold_time < LLDP_MIN_TX_HOLD || hold_time > LLDP_MAX_TX_HOLD)
	{
	  return lldp_invalid_arg;
	}
      if (lm->msg_tx_hold != hold_time)
	{
	  lm->msg_tx_hold = hold_time;
	  reschedule = 1;
	}
    }
  if (tx_interval)
    {
      if (tx_interval < LLDP_MIN_TX_INTERVAL ||
	  tx_interval > LLDP_MAX_TX_INTERVAL)
	{
	  return lldp_invalid_arg;
	}
      if (lm->msg_tx_interval != tx_interval)
	{
	  reschedule = 1;
	  lm->msg_tx_interval = tx_interval;
	}
    }
  if (reschedule)
    {
      vlib_process_signal_event (lm->vlib_main, lm->lldp_process_node_index,
				 LLDP_EVENT_RESCHEDULE, 0);
    }
  return lldp_ok;
}

static clib_error_t *
lldp_cfg_cmd (vlib_main_t * vm, unformat_input_t * input,
	      vlib_cli_command_t * cmd)
{
  int hold_time = 0;
  int tx_interval = 0;
  u8 *host = NULL;
  clib_error_t *ret = NULL;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "system-name %s", &host))
	{
	}
      else if (unformat (input, "tx-hold %d", &hold_time))
	{
	  if (hold_time < LLDP_MIN_TX_HOLD || hold_time > LLDP_MAX_TX_HOLD)
	    {
	      ret =
		clib_error_return (0,
				   "invalid tx-hold `%d' (out of range <%d,%d>)",
				   hold_time, LLDP_MIN_TX_HOLD,
				   LLDP_MAX_TX_HOLD);
	      goto out;
	    }
	}
      else if (unformat (input, "tx-interval %d", &tx_interval))
	{
	  if (tx_interval < LLDP_MIN_TX_INTERVAL ||
	      tx_interval > LLDP_MAX_TX_INTERVAL)
	    {
	      ret =
		clib_error_return (0,
				   "invalid tx-interval `%d' (out of range <%d,%d>)",
				   tx_interval, LLDP_MIN_TX_INTERVAL,
				   LLDP_MAX_TX_INTERVAL);
	      goto out;
	    }
	}
      else
	{
	  ret = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
	  goto out;
	}
    }
  ret =
    lldp_cfg_err_to_clib_err (lldp_cfg_set (&host, hold_time, tx_interval));
out:
  vec_free (host);
  return ret;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(set_interface_lldp_cmd, static) = {
  .path = "set interface lldp",
  .short_help = "set interface lldp <interface> (enable | disable) ",
  .function = lldp_intf_cmd,
};

VLIB_CLI_COMMAND(set_lldp_cmd, static) = {
  .path = "set lldp",
  .short_help = "set lldp [system-name <string>] [tx-hold <value>] "
                "[tx-interval <value>]",
  .function = lldp_cfg_cmd,
};
/* *INDENT-ON* */

static const char *
lldp_chassis_id_subtype_str (lldp_chassis_id_subtype_t t)
{
  switch (t)
    {
#define F(num, val, str) \
  case num:              \
    return str;
      foreach_chassis_id_subtype (F)
#undef F
    }
  return "unknown chassis subtype";
}

static const char *
lldp_port_id_subtype_str (lldp_port_id_subtype_t t)
{
  switch (t)
    {
#define F(num, val, str) \
  case num:              \
    return str;
      foreach_port_id_subtype (F)
#undef F
    }
  return "unknown port subtype";
}

/*
 * format port id subtype&value
 *
 * @param va - 1st argument - unsigned - port id subtype
 * @param va - 2nd argument - u8* - port id
 * @param va - 3rd argument - unsigned - port id length
 * @param va - 4th argument - int - 1 for detailed output, 0 for simple
 */
u8 *
format_lldp_port_id (u8 * s, va_list * va)
{
  const lldp_port_id_subtype_t subtype = va_arg (*va, unsigned);
  const u8 *id = va_arg (*va, u8 *);
  const unsigned len = va_arg (*va, unsigned);
  const int detail = va_arg (*va, int);
  if (!id)
    {
      return s;
    }
  switch (subtype)
    {
    case LLDP_PORT_ID_SUBTYPE_NAME (intf_alias):
      /* fallthrough */
    case LLDP_PORT_ID_SUBTYPE_NAME (port_comp):
      /* fallthrough */
    case LLDP_PORT_ID_SUBTYPE_NAME (local):
      /* fallthrough */
    case LLDP_PORT_ID_SUBTYPE_NAME (intf_name):
      if (detail)
	{
	  s = format (s, "%U(%s)", format_ascii_bytes, id, len,
		      lldp_port_id_subtype_str (subtype));
	}
      else
	{
	  s = format (s, "%U", format_ascii_bytes, id, len);
	}
      break;
    case LLDP_PORT_ID_SUBTYPE_NAME (mac_addr):
      if (ETHER_ADDR_LEN == len)
	{
	  if (detail)
	    {
	      s = format (s, "%U(%s)", format_mac_address, id,
			  lldp_port_id_subtype_str (subtype));
	    }
	  else
	    {
	      s = format (s, "%U", format_mac_address, id);
	    }
	  break;
	}
      /* fallthrough */
    case LLDP_PORT_ID_SUBTYPE_NAME (net_addr):
      /* TODO */
      /* fallthrough */
    default:
      if (detail)
	{
	  s = format (s, "%U(%s)", format_hex_bytes, id, len,
		      lldp_port_id_subtype_str (subtype));
	}
      else
	{
	  s = format (s, "%U", format_hex_bytes, id, len);
	}
      break;
    }
  return s;
}

/*
 * format chassis id subtype&value
 *
 * @param s format string
 * @param va - 1st argument - unsigned - chassis id subtype
 * @param va - 2nd argument - u8* - chassis id
 * @param va - 3rd argument - unsigned - chassis id length
 * @param va - 4th argument - int - 1 for detailed output, 0 for simple
 */
u8 *
format_lldp_chassis_id (u8 * s, va_list * va)
{
  const lldp_chassis_id_subtype_t subtype =
    va_arg (*va, lldp_chassis_id_subtype_t);
  const u8 *id = va_arg (*va, u8 *);
  const unsigned len = va_arg (*va, unsigned);
  const int detail = va_arg (*va, int);
  if (!id)
    {
      return s;
    }
  switch (subtype)
    {
    case LLDP_CHASS_ID_SUBTYPE_NAME (chassis_comp):
      /* fallthrough */
    case LLDP_CHASS_ID_SUBTYPE_NAME (intf_alias):
      /* fallthrough */
    case LLDP_CHASS_ID_SUBTYPE_NAME (port_comp):
      /* fallthrough */
    case LLDP_PORT_ID_SUBTYPE_NAME (local):
      /* fallthrough */
    case LLDP_CHASS_ID_SUBTYPE_NAME (intf_name):
      if (detail)
	{
	  s = format (s, "%U(%s)", format_ascii_bytes, id, len,
		      lldp_chassis_id_subtype_str (subtype));
	}
      else
	{
	  s = format (s, "%U", format_ascii_bytes, id, len);
	}
      break;
    case LLDP_CHASS_ID_SUBTYPE_NAME (mac_addr):
      if (ETHER_ADDR_LEN == len)
	{
	  if (detail)
	    {
	      s = format (s, "%U(%s)", format_mac_address, id,
			  lldp_chassis_id_subtype_str (subtype));
	    }
	  else
	    {
	      s = format (s, "%U", format_mac_address, id);
	    }
	  break;
	}
      /* fallthrough */
    case LLDP_CHASS_ID_SUBTYPE_NAME (net_addr):
      /* TODO */
    default:
      if (detail)
	{
	  s = format (s, "%U(%s)", format_hex_bytes, id, len,
		      lldp_chassis_id_subtype_str (subtype));
	}
      else
	{
	  s = format (s, "%U", format_hex_bytes, id, len);
	}
      break;
    }
  return s;
}

/*
 * convert a tlv code to human-readable string
 */
static const char *
lldp_tlv_code_str (lldp_tlv_code_t t)
{
  switch (t)
    {
#define F(n, t, s) \
  case n:          \
    return s;
      foreach_lldp_tlv_type (F)
#undef F
    }
  return "unknown lldp tlv";
}

/*
 * format a single LLDP TLV
 *
 * @param s format string
 * @param va variable list - pointer to lldp_tlv_t is expected
 */
u8 *
format_lldp_tlv (u8 * s, va_list * va)
{
  const lldp_tlv_t *tlv = va_arg (*va, lldp_tlv_t *);
  if (!tlv)
    {
      return s;
    }
  u16 l = lldp_tlv_get_length (tlv);
  switch (lldp_tlv_get_code (tlv))
    {
    case LLDP_TLV_NAME (chassis_id):
      s = format (s, "%U", format_lldp_chassis_id,
		  ((lldp_chassis_id_tlv_t *) tlv)->subtype,
		  ((lldp_chassis_id_tlv_t *) tlv)->id,
		  l - STRUCT_SIZE_OF (lldp_chassis_id_tlv_t, subtype), 1);
      break;
    case LLDP_TLV_NAME (port_id):
      s = format (s, "%U", format_lldp_port_id,
		  ((lldp_port_id_tlv_t *) tlv)->subtype,
		  ((lldp_port_id_tlv_t *) tlv)->id,
		  l - STRUCT_SIZE_OF (lldp_port_id_tlv_t, subtype), 1);
      break;
    case LLDP_TLV_NAME (ttl):
      s = format (s, "%d", ntohs (((lldp_ttl_tlv_t *) tlv)->ttl));
      break;
    case LLDP_TLV_NAME (sys_name):
      /* fallthrough */
    case LLDP_TLV_NAME (sys_desc):
      s = format (s, "%U", format_ascii_bytes, tlv->v, l);
      break;
    default:
      s = format (s, "%U", format_hex_bytes, tlv->v, l);
    }

  return s;
}

static u8 *
format_time_ago (u8 * s, va_list * va)
{
  f64 ago = va_arg (*va, double);
  f64 now = va_arg (*va, double);
  if (ago < 0.01)
    {
      return format (s, "never");
    }
  return format (s, "%.1fs ago", now - ago);
}

static u8 *
format_lldp_intfs_detail (u8 * s, vlib_main_t * vm, const lldp_main_t * lm)
{
  vnet_main_t *vnm = &vnet_main;
  const lldp_intf_t *n;
  const vnet_hw_interface_t *hw;
  const vnet_sw_interface_t *sw;
  s = format (s, "LLDP configuration:\n");
  if (lm->sys_name)
    {
      s = format (s, "Configured system name: %U\n", format_ascii_bytes,
		  lm->sys_name, vec_len (lm->sys_name));
    }
  s = format (s, "Configured tx-hold: %d\n", (int) lm->msg_tx_hold);
  s = format (s, "Configured tx-interval: %d\n", (int) lm->msg_tx_interval);
  s = format (s, "\nLLDP-enabled interface table:\n");
  f64 now = vlib_time_now (vm);

  /* *INDENT-OFF* */
  pool_foreach(
      n, lm->intfs, ({
        hw = vnet_get_hw_interface(vnm, n->hw_if_index);
        sw = vnet_get_sw_interface(lm->vnet_main, hw->sw_if_index);
        /* Interface shutdown */
        if (!(sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
          {
            s = format(s, "\nInterface name: %s\nInterface/peer state: "
                          "interface down\nLast packet sent: %U\n",
                       hw->name, format_time_ago, n->last_sent, now);
          }
        else if (now < n->last_heard + n->ttl)
          {
            s = format(s,
                       "\nInterface name: %s\nInterface/peer state: "
                       "active\nPeer chassis ID: %U\nRemote port ID: %U\nLast "
                       "packet sent: %U\nLast packet received: %U\n",
                       hw->name, format_lldp_chassis_id, n->chassis_id_subtype,
                       n->chassis_id, vec_len(n->chassis_id), 1,
                       format_lldp_port_id, n->port_id_subtype, n->port_id,
                       vec_len(n->port_id), 1, format_time_ago, n->last_sent,
                       now, format_time_ago, n->last_heard, now);
          }
        else
          {
            s = format(s, "\nInterface name: %s\nInterface/peer state: "
                          "inactive(timeout)\nLast known peer chassis ID: "
                          "%U\nLast known peer port ID: %U\nLast packet sent: "
                          "%U\nLast packet received: %U\n",
                       hw->name, format_lldp_chassis_id, n->chassis_id_subtype,
                       n->chassis_id, vec_len(n->chassis_id), 1,
                       format_lldp_port_id, n->port_id_subtype, n->port_id,
                       vec_len(n->port_id), 1, format_time_ago, n->last_sent,
                       now, format_time_ago, n->last_heard, now);
          }
      }));
  /* *INDENT-ON* */
  return s;
}

static u8 *
format_lldp_intfs (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  const lldp_main_t *lm = va_arg (*va, lldp_main_t *);
  const int detail = va_arg (*va, int);
  vnet_main_t *vnm = &vnet_main;
  const lldp_intf_t *n;

  if (detail)
    {
      return format_lldp_intfs_detail (s, vm, lm);
    }

  f64 now = vlib_time_now (vm);
  s = format (s, "%-25s %-25s %-25s %=15s %=15s %=10s\n", "Local interface",
	      "Peer chassis ID", "Remote port ID", "Last heard", "Last sent",
	      "Status");

  /* *INDENT-OFF* */
  pool_foreach(
      n, lm->intfs, ({
        const vnet_hw_interface_t *hw =
            vnet_get_hw_interface(vnm, n->hw_if_index);
        const vnet_sw_interface_t *sw =
            vnet_get_sw_interface(lm->vnet_main, hw->sw_if_index);
        /* Interface shutdown */
        if (!(sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
          continue;
        if (now < n->last_heard + n->ttl)
          {
            s = format(s, "%-25s %-25U %-25U %=15U %=15U %=10s\n", hw->name,
                       format_lldp_chassis_id, n->chassis_id_subtype,
                       n->chassis_id, vec_len(n->chassis_id), 0,
                       format_lldp_port_id, n->port_id_subtype, n->port_id,
                       vec_len(n->port_id), 0, format_time_ago, n->last_heard,
                       now, format_time_ago, n->last_sent, now, "active");
          }
        else
          {
            s = format(s, "%-25s %-25s %-25s %=15U %=15U %=10s\n", hw->name,
                       "", "", format_time_ago, n->last_heard, now,
                       format_time_ago, n->last_sent, now, "inactive");
          }
      }));
  /* *INDENT-ON* */
  return s;
}

static clib_error_t *
show_lldp (vlib_main_t * vm, unformat_input_t * input,
	   CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  lldp_main_t *lm = &lldp_main;

  if (unformat (input, "detail"))
    {
      vlib_cli_output (vm, "%U\n", format_lldp_intfs, vm, lm, 1);
    }
  else
    {
      vlib_cli_output (vm, "%U\n", format_lldp_intfs, vm, lm, 0);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(show_lldp_command, static) = {
  .path = "show lldp",
  .short_help = "show lldp [detail]",
  .function = show_lldp,
};
/* *INDENT-ON* */

/*
 * packet trace format function, very similar to
 * lldp_packet_scan except that we call the per TLV format
 * functions instead of the per TLV processing functions
 */
u8 *
lldp_input_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  const lldp_input_trace_t *t = va_arg (*args, lldp_input_trace_t *);
  const u8 *cur;
  const lldp_tlv_t *tlv;
  cur = t->data;
  while (((cur + lldp_tlv_get_length ((lldp_tlv_t *) cur)) <
	  t->data + t->len))
    {
      tlv = (lldp_tlv_t *) cur;
      if (cur == t->data)
	{
	  s = format (s, "TLV #%d(%s): %U\n", lldp_tlv_get_code (tlv),
		      lldp_tlv_code_str (lldp_tlv_get_code (tlv)),
		      format_lldp_tlv, tlv);
	}
      else
	{
	  s = format (s, "  TLV #%d(%s): %U\n", lldp_tlv_get_code (tlv),
		      lldp_tlv_code_str (lldp_tlv_get_code (tlv)),
		      format_lldp_tlv, tlv);
	}
      cur += STRUCT_SIZE_OF (lldp_tlv_t, head) + lldp_tlv_get_length (tlv);
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
