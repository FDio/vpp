/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>
#include <vppinfra/format_table.h>

static u8 *
format_ice_aq_health_code (u8 *s, va_list *args)
{
  u32 code = va_arg (*args, u32);

  switch (code)
    {
#define _(v, n, d, l)                                                                              \
  case ICE_AQ_HEALTH_##n:                                                                          \
    return format (s, "%s: %s", #l, d);
      foreach_ice_aq_health_status
#undef _
	default : return format (s, "unknown health status");
    }
}

static u8 *
format_ice_aq_health_source (u8 *s, va_list *args)
{
  u32 source = va_arg (*args, u32);

  static const char *names[] = {
#define _(v, n, d) [ICE_AQ_HEALTH_SOURCE_##n] = d,
    foreach_ice_aq_health_source
#undef _
  };

  if (source < ARRAY_LEN (names) && names[source])
    return format (s, "%s", names[source]);

  return format (s, "unknown (%u)", source);
}

static u8 *
format_ice_aq_health_details (u8 *s, va_list *args)
{
  const ice_aqc_health_status_elem_t *h = va_arg (*args, const ice_aqc_health_status_elem_t *);
  u32 first = h->internal_data1, second = h->internal_data2;

  if (first == ICE_AQ_HEALTH_DATA_UNDEFINED)
    return s;

  switch (h->status_code)
    {
    case ICE_AQ_HEALTH_ERR_LAST_FAIL_AQ:
      s = format (s, "failed command: %U", format_ice_adminq_opcode, first);

      if (second != ICE_AQ_HEALTH_DATA_UNDEFINED)
	s = format (s, ", PF: %u", second);

      return s;

    case ICE_AQ_HEALTH_ERR_UNKNOWN_MOD_STRICT:
    case ICE_AQ_HEALTH_ERR_UNKNOWN_MOD_LENIENT:
    case ICE_AQ_HEALTH_ERR_MOD_TYPE:
    case ICE_AQ_HEALTH_ERR_MOD_QUAL:
    case ICE_AQ_HEALTH_ERR_MOD_COMM:
    case ICE_AQ_HEALTH_ERR_MOD_CONFLICT:
    case ICE_AQ_HEALTH_ERR_MOD_NOT_PRESENT:
    case ICE_AQ_HEALTH_INFO_MOD_UNDERUTILIZED:
    case ICE_AQ_HEALTH_ERR_MOD_DIAGNOSTIC_FEATURE:
    case ICE_AQ_HEALTH_ERR_INVALID_LINK_CFG:
    case ICE_AQ_HEALTH_ERR_PORT_ACCESS:
    case ICE_AQ_HEALTH_ERR_PORT_UNREACHABLE:
    case ICE_AQ_HEALTH_INFO_PORT_SPEED_MOD_LIMITED:
    case ICE_AQ_HEALTH_ERR_PARALLEL_FAULT:
    case ICE_AQ_HEALTH_INFO_PORT_SPEED_PHY_LIMITED:
    case ICE_AQ_HEALTH_ERR_NETLIST:
    case ICE_AQ_HEALTH_ERR_TOPO_CONFLICT:
    case ICE_AQ_HEALTH_ERR_LINK_HW_ACCESS:
    case ICE_AQ_HEALTH_ERR_LINK_RUNTIME:
    case ICE_AQ_HEALTH_ERR_DNL_INIT:
    case ICE_AQ_HEALTH_ERR_PHY_FW_LOAD:
      return format (s, ", port: %u", first);

    case ICE_AQ_HEALTH_ERR_FW_PFR_FAIL:
      return format (s, ", PF: %u", first);

    case ICE_AQ_HEALTH_ERR_FLASH_ACCESS:
      {
	static const char *access[] = {
	  "read",
	  "write",
	  "erase",
	};

	if (first < ARRAY_LEN (access))
	  return format (s, ", access: %s", access[first]);

	return format (s, ", unknown access type: %u", first);
      }

    case ICE_AQ_HEALTH_ERR_NVM_COMPAT:
    case ICE_AQ_HEALTH_ERR_OROM_COMPAT:
      s = format (s, ", expected device ID: 0x%04x", first);

      if (second != ICE_AQ_HEALTH_DATA_UNDEFINED)
	s = format (s, ", expected module ID: 0x%04x", second);

      return s;

    case ICE_AQ_HEALTH_ERR_NVM_SEC_VIOLATION:
    case ICE_AQ_HEALTH_ERR_OROM_SEC_VIOLATION:
      return format (s, ", minimum security version: %u", first);

    case ICE_AQ_HEALTH_ERR_DCB_MIB:
      s = format (s, ", port: %u", first);

      if (second != ICE_AQ_HEALTH_DATA_UNDEFINED)
	s = format (s, ", MIB ID: %u", second);

      return s;

    case ICE_AQ_HEALTH_ERR_RESOURCE_ALLOC_FAIL:
      s = format (s, ", resource type: %u", first);

      if (second != ICE_AQ_HEALTH_DATA_UNDEFINED)
	s = format (s, ", PF: %u", second);

      return s;

    case ICE_AQ_HEALTH_ERR_LAST_MNG_FAIL:
      s = format (s, ", management type: %u", first);

      if (second != ICE_AQ_HEALTH_DATA_UNDEFINED)
	s = format (s, ", failed management opcode: 0x%04x", second);

      return s;

    default:
      if (first)
	s = format (s, ", undocumented internal data 1: 0x%08x", first);

      if (second && second != ICE_AQ_HEALTH_DATA_UNDEFINED)
	s = format (s, ", undocumented internal data 2: 0x%08x", second);

      return s;
    }
}

typedef struct
{
  const char *name;
  u8 set;
} ice_aq_status_flag_t;

static u8 *
format_ice_aq_status_flags (u8 *s, va_list *args)
{
  const ice_aq_status_flag_t *flags = va_arg (*args, const ice_aq_status_flag_t *);
  uword count = va_arg (*args, uword);
  int separator = 0;

  for (uword i = 0; i < count; i++)
    if (flags[i].set)
      {
	s = format (s, "%s%s", separator ? ", " : "", flags[i].name);
	separator = 1;
      }

  return separator ? format_word_wrap_last_line_with_indent (s, 100, 2) : format (s, "none");
}

static u8 *
format_ice_aq_link_status (u8 *s, va_list *args)
{
  const ice_aqc_link_status_t *link = va_arg (*args, const ice_aqc_link_status_t *);
  u32 size = va_arg (*args, u32);
  u32 indent = format_get_indent (s);
  const ice_aq_status_flag_t link_flags[] = {
    {
      .name = "link up",
      .set = link->link_info.link_up,
    },
    {
      .name = "link fault",
      .set = link->link_info.link_fault,
    },
    {
      .name = "TX fault",
      .set = link->link_info.tx_fault,
    },
    {
      .name = "RX fault",
      .set = link->link_info.rx_fault,
    },
    {
      .name = "remote fault",
      .set = link->link_info.remote_fault,
    },
    {
      .name = "port link up",
      .set = link->link_info.port_link_up,
    },
    {
      .name = "media available",
      .set = link->link_info.media_available,
    },
    {
      .name = "signal detected",
      .set = link->link_info.signal_detect,
    },
  };
  const ice_aq_status_flag_t an_flags[] = {
    {
      .name = "completed",
      .set = link->an_info.completed,
    },
    {
      .name = "partner ability",
      .set = link->an_info.link_partner_ability,
    },
    {
      .name = "parallel detection fault",
      .set = link->an_info.parallel_detection_fault,
    },
    {
      .name = "FEC enabled",
      .set = link->an_info.fec_enabled,
    },
    {
      .name = "PHY low power",
      .set = link->an_info.phy_low_power,
    },
    {
      .name = "pause TX",
      .set = link->an_info.pause_tx,
    },
    {
      .name = "pause RX",
      .set = link->an_info.pause_rx,
    },
    {
      .name = "qualified module",
      .set = link->an_info.qualified_module,
    },
  };
  const ice_aq_status_flag_t alarm_flags[] = {
    {
      .name = "PHY temperature alarm",
      .set = link->ext_info.phy_temperature_alarm,
    },
    {
      .name = "excessive errors",
      .set = link->ext_info.excessive_errors,
    },
  };
  const ice_aq_status_flag_t config_flags[] = {
    {
      .name = "configuration error",
      .set = link->link_cfg_err.config_error,
    },
    {
      .name = "invalid port option",
      .set = link->link_cfg_err.invalid_port_option,
    },
    {
      .name = "invalid feature or configuration",
      .set = link->link_cfg_err.invalid_feature_or_config,
    },
    {
      .name = "critical SDP error",
      .set = link->link_cfg_err.critical_sdp_error,
    },
    {
      .name = "unsupported module power",
      .set = link->link_cfg_err.unsupported_module_power,
    },
    {
      .name = "external PHY load failure",
      .set = link->link_cfg_err.external_phy_load_failure,
    },
    {
      .name = "invalid maximum power limit",
      .set = link->link_cfg_err.invalid_max_power_limit,
    },
  };
  const ice_aq_status_flag_t topology_flags[] = {
    {
      .name = "topology conflict",
      .set = link->topo_media_conflict.topology_conflict,
    },
    {
      .name = "media conflict",
      .set = link->topo_media_conflict.media_conflict,
    },
    {
      .name = "topology corrupt",
      .set = link->topo_media_conflict.topology_corrupt,
    },
    {
      .name = "topology unreachable",
      .set = link->topo_media_conflict.topology_unreachable,
    },
    {
      .name = "topology underutilized",
      .set = link->topo_media_conflict.topology_underutilized,
    },
    {
      .name = "media underutilized",
      .set = link->topo_media_conflict.media_underutilized,
    },
    {
      .name = "unsupported media",
      .set = link->topo_media_conflict.unsupported_media,
    },
  };
  const ice_aq_status_flag_t loopback_flags[] = {
    {
      .name = "local PHY",
      .set = link->lb_status.local_phy,
    },
    {
      .name = "remote PHY",
      .set = link->lb_status.remote_phy,
    },
    {
      .name = "local MAC",
      .set = link->lb_status.local_mac,
    },
  };
  const ice_aq_status_flag_t fec[] = {
    {
      .name = "25G BASE-R",
      .set = link->cfg.kr_25g_fec,
    },
    {
      .name = "RS-528",
      .set = link->cfg.rs_528_fec,
    },
    {
      .name = "RS-544",
      .set = link->cfg.rs_544_fec,
    },
    {
      .name = "RS-272",
      .set = link->ext_fec_status.rs_272_fec,
    },
  };
  const struct
  {
    const char *name;
    const ice_aq_status_flag_t *flags;
    uword count;
  } groups[] = {
    {
      .name = "link",
      .flags = link_flags,
      .count = ARRAY_LEN (link_flags),
    },
    {
      .name = "autoneg",
      .flags = an_flags,
      .count = ARRAY_LEN (an_flags),
    },
    {
      .name = "alarms",
      .flags = alarm_flags,
      .count = ARRAY_LEN (alarm_flags),
    },
    {
      .name = "configuration errors",
      .flags = config_flags,
      .count = ARRAY_LEN (config_flags),
    },
    {
      .name = "topology/media",
      .flags = topology_flags,
      .count = ARRAY_LEN (topology_flags),
    },
    {
      .name = "loopback",
      .flags = loopback_flags,
      .count = ARRAY_LEN (loopback_flags),
    },
    {
      .name = "FEC",
      .flags = fec,
      .count = ARRAY_LEN (fec),
    },
  };
  static const char *tx_states[] = {
#define _(v, n, d) [ICE_AQ_LINK_TX_##n] = d,
    foreach_ice_aq_link_tx_state
#undef _
  };

  s = format (s, "PHY types: %U", format_ice_phy_types, link->phy_type_low, link->phy_type_high);
  s = format_word_wrap_last_line_with_indent (s, 100, 2);

  for (u32 i = 0; i < ARRAY_LEN (groups); i++)
    {
      s = format_newline (s, indent);
      s = format (s, "%s: %U", groups[i].name, format_ice_aq_status_flags, groups[i].flags,
		  groups[i].count);
    }

  s = format_newline (s, indent);
  s = format (s, "TX %s, pacing %u (%s), module power class %u", tx_states[link->ext_info.tx_state],
	      link->cfg.pacing, link->cfg.fixed_pacing ? "fixed" : "dynamic",
	      link->power_desc.power_class);

  if (link->lb_status.local_phy || link->lb_status.remote_phy)
    s = format (s, ", loopback PHY index %u", link->lb_status.phy_index);

  if (size >= ICE_AQC_LINK_STATUS_V2_SIZE)
    {
      const ice_aq_status_flag_t advertised[] = {
	{
	  .name = "10G KR",
	  .set = link->lp_fec_adv.kr_10g,
	},
	{
	  .name = "25G KR",
	  .set = link->lp_fec_adv.kr_25g,
	},
	{
	  .name = "RS-528",
	  .set = link->lp_fec_adv.rs_528,
	},
	{
	  .name = "272 50G",
	  .set = link->lp_fec_adv.kr_272_50g,
	},
	{
	  .name = "272 100G",
	  .set = link->lp_fec_adv.kr_272_100g,
	},
	{
	  .name = "272 200G",
	  .set = link->lp_fec_adv.kr_272_200g,
	},
      };
      const ice_aq_status_flag_t requested[] = {
	{
	  .name = "10G KR",
	  .set = link->lp_fec_req.kr_10g,
	},
	{
	  .name = "25G KR",
	  .set = link->lp_fec_req.kr_25g,
	},
	{
	  .name = "RS-528",
	  .set = link->lp_fec_req.rs_528,
	},
	{
	  .name = "272",
	  .set = link->lp_fec_req.kr_272,
	},
      };
      const ice_aq_status_flag_t pause[] = {
	{
	  .name = "pause",
	  .set = link->lp_flowcontrol.pause,
	},
	{
	  .name = "asymmetric pause",
	  .set = link->lp_flowcontrol.asymmetric_pause,
	},
      };

      s = format_newline (s, indent);
      s = format (s, "partner PHY types: %U", format_ice_phy_types, link->lp_phy_type_low,
		  link->lp_phy_type_high);
      s = format_newline (s, indent);
      s = format (s, "partner advertised FEC: %U", format_ice_aq_status_flags, advertised,
		  ARRAY_LEN (advertised));
      s = format_newline (s, indent);
      s = format (s, "partner requested FEC: %U", format_ice_aq_status_flags, requested,
		  ARRAY_LEN (requested));
      s = format_newline (s, indent);
      s = format (s, "partner flow control: %U", format_ice_aq_status_flags, pause,
		  ARRAY_LEN (pause));
    }

  return s;
}

static u8 *
format_ice_aq_return_status (u8 *s, va_list *args)
{
  u32 status = va_arg (*args, u32);
  static const char *names[] = {
#define _(v, n) [ICE_AQ_RC_##n] = #n,
    foreach_ice_aq_rc
#undef _
  };

  if (status < ARRAY_LEN (names) && names[status])
    return format (s, "%s (%u)", names[status], status);

  return format (s, "unknown status %u", status);
}

u8 *
format_ice_aq_flags (u8 *s, va_list *args)
{
  ice_aq_desc_flags_t flags = {
    .as_u16 = va_arg (*args, u32),
  };
  int separator = 0;
  static const char *names[16] = {
    [0] = "done",
    [1] = "complete",
    [2] = "error",
    [3] = "VF event",
    [9] = "large buffer",
    [10] = "firmware reads buffer",
    [11] = "VF context",
    [12] = "buffer present",
    [13] = "suppress interrupt",
    [14] = "interrupt on error",
    [15] = "flush on error",
  };

  for (u32 bit = 0; bit < ARRAY_LEN (names); bit++)
    if (flags.as_u16 & (1U << bit))
      {
	s = format (s, "%s", separator ? ", " : "");

	if (names[bit])
	  s = format (s, "%s", names[bit]);
	else
	  s = format (s, "reserved bit %u", bit);

	separator = 1;
      }

  return separator ? s : format (s, "none");
}

#define foreach_ice_aq_notification_kind                                                           \
  _ (EVENT, "event")                                                                               \
  _ (COMPLETION, "async completion")                                                               \
  _ (MAILBOX, "mailbox message")                                                                   \
  _ (UNKNOWN, "ARQ notification")

typedef enum
{
#define _(n, d) ICE_AQ_NOTIFICATION_##n,
  foreach_ice_aq_notification_kind
#undef _
} ice_aq_notification_kind_t;

static ice_aq_notification_kind_t
ice_aq_notification_kind (u16 opcode)
{

  switch (opcode)
    {
    case ICE_AQC_OP_NVM_ERASE:
    case ICE_AQC_OP_NVM_WRITE:
    case ICE_AQC_OP_NVM_WRITE_ACTIVATE:
    case ICE_AQC_OP_DIS_TXQS:
      return ICE_AQ_NOTIFICATION_COMPLETION;

    case ICE_AQC_OP_GET_LINK_STATUS:
    case ICE_AQC_OP_LLDP_MIB_CHANGE:
    case ICE_AQC_OP_EVENT_CGU_ERROR:
    case ICE_AQC_OP_EVENT_LAN_OVERFLOW:
    case ICE_AQC_OP_HEALTH_STATUS_EVENT:
    case ICE_AQC_OP_FW_LOG_EVENT:
      return ICE_AQ_NOTIFICATION_EVENT;

    case ICE_AQC_OP_SEND_MSG_TO_PF:
    case ICE_AQC_OP_SEND_MSG_TO_VF:
      return ICE_AQ_NOTIFICATION_MAILBOX;

    default:
      return ICE_AQ_NOTIFICATION_UNKNOWN;
    }
}

u8 *
format_ice_aq_event (u8 *s, va_list *args)
{
  const ice_aq_event_t *event = va_arg (*args, const ice_aq_event_t *);
  const ice_aq_desc_t *d = &event->desc;
  ice_aq_notification_kind_t kind = ice_aq_notification_kind (d->opcode);
  static const char *names[] = {
#define _(n, d) [ICE_AQ_NOTIFICATION_##n] = d,
    foreach_ice_aq_notification_kind
#undef _
  };
  u32 data_len = event->data_len;
  u32 indent = format_get_indent (s);

  s = format (s, "%s: %U, flags: %U", names[kind], format_ice_adminq_opcode, d->opcode,
	      format_ice_aq_flags, d->flags.as_u16);

  if (kind == ICE_AQ_NOTIFICATION_COMPLETION || (kind == ICE_AQ_NOTIFICATION_UNKNOWN && d->retval))
    s = format (s, ", return status: %U", format_ice_aq_return_status, d->retval);

  s = format_word_wrap_last_line_with_indent (s, 100, 2);
  s = format_newline (s, indent + 2);

  switch (d->opcode)
    {
    case ICE_AQC_OP_GET_LINK_STATUS:
      {
	const ice_aqc_link_status_t *link = (const void *) event->data;

	if (event->data_len < ICE_AQC_LINK_STATUS_V1_SIZE)
	  {
	    s = format (s, "short link status payload: %u bytes", event->data_len);
	    break;
	  }

	s = format (s, "link status: lport %u %s speed %U max frame %u",
		    d->params.link_status.lport_num, link->link_info.link_up ? "up" : "down",
		    format_vnet_hw_interface_link_speed, ice_aq_link_speed_from_status (link),
		    link->max_frame_size);
	s = format_newline (s, indent + 2);
	s = format (s, "%U", format_ice_aq_link_status, link, data_len);
	break;
      }

    case ICE_AQC_OP_LLDP_MIB_CHANGE:
      {
	const ice_aqc_lldp_mib_event_t *mib = &d->params.lldp_mib_event;
	static const char *types[] = {
	  "local",
	  "remote",
	  "local and remote",
	  "reserved",
	};
	static const char *bridges[] = {
	  "nearest bridge",
	  "non-TPMR",
	  "reserved",
	  "reserved",
	};
	static const char *tx_states[] = {
	  "active",
	  "suspended",
	  "reserved",
	  "flushed",
	};
	static const char *dcbx_modes[] = {
	  "not applicable",
	  "CEE",
	  "IEEE",
	  "reserved",
	};

	s = format (s, "LLDP MIB change: %s, %s, TX %s, DCBX %s, local %u bytes, remote %u bytes",
		    types[mib->mib_type], bridges[mib->bridge_type], tx_states[mib->tx_state],
		    dcbx_modes[mib->dcbx_mode], mib->local_len, mib->remote_len);
	break;
      }

    case ICE_AQC_OP_DIS_TXQS:
      s =
	format (s, "TX queue cleanup: caller %U command tag %u", format_ice_adminq_opcode,
		d->params.txq_cleanup_event.caller_opcode, d->params.txq_cleanup_event.command_tag);
      break;

    case ICE_AQC_OP_EVENT_CGU_ERROR:
      s = format (
	s,
	"CGU error: SyncE lock loss %u, holdover change %u, time-sync lock loss %u "
	"(0x%02x)",
	d->params.cgu_error_event.synce_lock_loss, d->params.cgu_error_event.holdover_change,
	d->params.cgu_error_event.timesync_lock_loss, d->params.cgu_error_event.error_type);
      break;

    case ICE_AQC_OP_EVENT_LAN_OVERFLOW:
      s = format (s, "LAN queue overflow: PRTDCB_RUPTQ 0x%08x QTX_CTL 0x%08x",
		  d->params.lan_overflow_event.prtdcb_ruptq, d->params.lan_overflow_event.qtx_ctl);
      break;

    case ICE_AQC_OP_HEALTH_STATUS_EVENT:
      {
	const ice_aqc_health_status_elem_t *elements = (const void *) event->data;
	u32 count =
	  clib_min (d->params.health_status_event.count, event->data_len / sizeof (*elements));

	s = format (s, "health status: %u %s", d->params.health_status_event.count,
		    d->params.health_status_event.count == 1 ? "entry" : "entries");

	for (u32 i = 0; i < count; i++)
	  {
	    const ice_aqc_health_status_elem_t *h = elements + i;

	    s = format_newline (s, indent + 4);
	    s = format (s, "%U (0x%04x), source: %U", format_ice_aq_health_code, h->status_code,
			h->status_code, format_ice_aq_health_source, h->event_source);

	    if (h->status_code == ICE_AQ_HEALTH_ERR_LAST_FAIL_AQ &&
		h->internal_data1 != ICE_AQ_HEALTH_DATA_UNDEFINED)
	      s = format_newline (s, indent + 6);

	    s = format (s, "%U", format_ice_aq_health_details, h);
	    s = format_word_wrap_last_line_with_indent (s, 100, 2);
	  }

	if (count != d->params.health_status_event.count)
	  {
	    s = format_newline (s, indent + 4);
	    s = format (s, "truncated health status payload: %u complete entries", count);
	  }

	break;
      }

    case ICE_AQC_OP_FW_LOG_EVENT:
      s = format (s,
		  "firmware log: timestamp %lu more data %u command flags 0x%02x "
		  "response flags 0x%02x",
		  ((u64) d->params.fw_log_event.timestamp_high << 32) |
		    d->params.fw_log_event.timestamp_low,
		  d->params.fw_log_event.more_data, d->params.fw_log_event.command_flags,
		  d->params.fw_log_event.response_flags);
      break;

    case ICE_AQC_OP_NVM_ERASE:
    case ICE_AQC_OP_NVM_WRITE:
      s = format (s, "NVM completion: module 0x%04x offset 0x%06x length %u flags 0x%02x",
		  d->params.nvm_event.module,
		  d->params.nvm_event.offset_low | (d->params.nvm_event.offset_high << 16),
		  d->params.nvm_event.length, d->params.nvm_event.command_flags);
      break;

    case ICE_AQC_OP_NVM_WRITE_ACTIVATE:
      s = format (s, "NVM activation completion: flags 0x%02x flags2 0x%02x",
		  d->params.nvm_event.command_flags, d->params.nvm_event.offset_high);
      break;

    case ICE_AQC_OP_SEND_MSG_TO_PF:
    case ICE_AQC_OP_SEND_MSG_TO_VF:
      {
	i32 status = d->cookie_low;

	s = format (s, "mailbox message: %s ID %u virtchnl opcode %u status %d",
		    d->opcode == ICE_AQC_OP_SEND_MSG_TO_PF ? "to PF" : "to VF",
		    d->params.pf_vf_msg.id, d->cookie_high, status);
	break;
      }

    default:
      s = format (s, "unrecognized event, descriptor parameters: %U", format_hex_bytes, &d->params,
		  sizeof (d->params));
      break;
    }

  s = format_word_wrap_last_line_with_indent (s, 100, 2);

  if (event->data_len < d->datalen)
    {
      s = format_newline (s, indent + 2);
      s = format (s, "payload truncated: retained %u of %u bytes", event->data_len, d->datalen);
    }

  return s;
}

static u8 *
format_ice_aq_history_entry (u8 *s, va_list *args)
{
  const ice_aq_event_t *event = va_arg (*args, const ice_aq_event_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%U", format_time_float, NULL, event->timestamp);
  s = format_newline (s, indent + 2);
  return format (s, "%U", format_ice_aq_event, event);
}

static u8 *
format_ice_aq (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  ice_dev_t *id = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);
  u64 retained = clib_min (id->aq_event_count, ICE_AQ_EVENT_HISTORY_SIZE);
  table_t rings = {};
  static const struct
  {
    const char *name;
    u32 len, head, tail, base_low, base_high;
  } registers[] = {
    {
      "ATQ",
      ICE_PF_FW_ATQLEN,
      ICE_PF_FW_ATQH,
      ICE_PF_FW_ATQT,
      ICE_PF_FW_ATQBAL,
      ICE_PF_FW_ATQBAH,
    },
    {
      "ARQ",
      ICE_PF_FW_ARQLEN,
      ICE_PF_FW_ARQH,
      ICE_PF_FW_ARQT,
      ICE_PF_FW_ARQBAL,
      ICE_PF_FW_ARQBAH,
    },
  };

  s = format (s, "AdminQ: allocated %s, alive %u, failed %u, receive active %u, MSI-X enabled %u",
	      id->aq ? "yes" : "no", id->aq_alive, id->aq_failed, id->arq_active,
	      id->arq_irq_enabled);
  s = format_word_wrap_last_line_with_indent (s, 100, 2);
  s = format_newline (s, indent);
  s = format (s, "Ring entries %u, buffer size %u, next ATQ %u, next ARQ %u", ICE_AQ_LEN,
	      ICE_AQ_BUF_SIZE, id->atq_next, id->arq_next);
  s = format_newline (s, indent);
  s = format (s, "Health notifications: supported %u, enabled %u", id->health_events_supported,
	      id->health_events_enabled);

  if (id->bar0)
    {
      table_add_hdr_row (&rings, 9, "ring", "entries", "DMA address", "head", "tail", "enabled",
			 "VF error", "overflow", "critical");

      for (u32 i = 0; i < ARRAY_LEN (registers); i++)
	{
	  ice_reg_aq_len_t len = {
	    .as_u32 = ice_reg_read (dev, registers[i].len),
	  };
	  u64 base = ((u64) ice_reg_read (dev, registers[i].base_high) << 32) |
		     ice_reg_read (dev, registers[i].base_low);

	  table_format_cell (&rings, i, 0, "%s", registers[i].name);
	  table_format_cell (&rings, i, 1, "%u", len.length);
	  table_format_cell (&rings, i, 2, "0x%016lx", base);
	  table_format_cell (&rings, i, 3, "%u", ice_reg_read (dev, registers[i].head));
	  table_format_cell (&rings, i, 4, "%u", ice_reg_read (dev, registers[i].tail));
	  table_format_cell (&rings, i, 5, "%u", len.enable);
	  table_format_cell (&rings, i, 6, "%u", len.vf_error);
	  table_format_cell (&rings, i, 7, "%u", len.overflow);
	  table_format_cell (&rings, i, 8, "%u", len.critical_error);
	}

      s = format (s, "\n");
      s = format_newline (s, indent);
      s = format (s, "AdminQ rings:");
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_table, &rings);
      table_free (&rings);
    }

  s = format (s, "\n");
  s = format_newline (s, indent);
  s = format (s, "AdminQ events: retained %lu of %lu (oldest first)", retained, id->aq_event_count);

  for (u64 i = id->aq_event_count - retained; i < id->aq_event_count; i++)
    {
      const ice_aq_event_t *event = id->aq_events + i % ICE_AQ_EVENT_HISTORY_SIZE;

      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_ice_aq_history_entry, event);
    }

  if (!retained)
    {
      s = format_newline (s, indent + 2);
      s = format (s, "none");
    }

  return s;
}

vnet_dev_rv_t
ice_dump_aq (__clib_unused vlib_main_t *vm, vnet_dev_t *dev, void *data)
{
  u8 **s = data;

  *s = format (*s, "%U", format_ice_aq, dev);
  return VNET_DEV_OK;
}
