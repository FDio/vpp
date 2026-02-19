/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Cisco and/or its affiliates.
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/epoll.h>

#include "daq_vpp.h"

static DAQ_VariableDesc_t vpp_variable_descriptions[] = {
  { .name = "debug",
    .description = "Enable debugging output to stdout",
    .flags = DAQ_VAR_DESC_FORBIDS_ARGUMENT },
  { .name = "debug-msg",
    .description = "Enable verbose message and packet dump debugging",
    .flags = DAQ_VAR_DESC_FORBIDS_ARGUMENT },
  { .name = "trace-ring",
    .description = "Enable low-overhead DAQ call trace ring buffer",
    .flags = DAQ_VAR_DESC_FORBIDS_ARGUMENT },
  { .name = "trace-ring-size",
    .description = "Set trace ring size (power-of-two entries)",
    .flags = DAQ_VAR_DESC_REQUIRES_ARGUMENT },
  { .name = "trace-ring-dump-on-error",
    .description = "Dump trace ring when DAQ reports an error",
    .flags = DAQ_VAR_DESC_FORBIDS_ARGUMENT },
  { .name = "socket",
    .description = "Path to VPP unix domain socket",
    .flags = DAQ_VAR_DESC_REQUIRES_ARGUMENT },
};

int
daq_vpp_get_variable_descs (const DAQ_VariableDesc_t **var_desc_table)
{
  *var_desc_table = vpp_variable_descriptions;

  return sizeof (vpp_variable_descriptions) / sizeof (DAQ_VariableDesc_t);
}

int
daq_vpp_parse_config (daq_vpp_ctx_t *ctx, DAQ_ModuleConfig_h modcfg)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  unsigned long v;
  const char *varKey, *varValue;

  vdm->daq_base_api.config_first_variable (modcfg, &varKey, &varValue);
  while (varKey)
    {
      if (!strcmp (varKey, "debug"))
	vdm->debug = true;
      else if (!strcmp (varKey, "debug-msg"))
	vdm->debug_msg = vdm->debug = true;
      else if (!strcmp (varKey, "trace-ring"))
	vdm->trace_ring_enable = true;
      else if (!strcmp (varKey, "trace-ring-size"))
	{
	  char *end = 0;
	  v = strtoul (varValue, &end, 10);
	  if (end == varValue || *end != 0 || v == 0 || !is_pow2 (v))
	    return daq_vpp_err (ctx, "trace-ring-size must be a positive power-of-two");
	  vdm->trace_ring_size = (uint32_t) v;
	  vdm->trace_ring_enable = true;
	}
      else if (!strcmp (varKey, "trace-ring-dump-on-error"))
	{
	  vdm->trace_ring_enable = true;
	  vdm->trace_ring_dump_on_err = true;
	}
      else if (!strcmp (varKey, "socket"))
	{
	  vdm->socket_name = varValue;
	}
      else
	return daq_vpp_err (ctx, "unknown config key '%s'", varKey);

      vdm->daq_base_api.config_next_variable (modcfg, &varKey, &varValue);
    }

  if (vdm->trace_ring_enable && vdm->trace_ring == 0)
    {
      if (vdm->trace_ring_size == 0)
	vdm->trace_ring_size = DAQ_VPP_TRACE_RING_DEFAULT_SIZE;
      return daq_vpp_trace_ring_init (ctx);
    }

  return DAQ_SUCCESS;
}
