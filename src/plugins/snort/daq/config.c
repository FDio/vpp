/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Cisco and/or its affiliates.
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <assert.h>
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

  const char *varKey, *varValue;
  vdm->daq_base_api.config_first_variable (modcfg, &varKey, &varValue);
  while (varKey)
    {
      if (!strcmp (varKey, "debug"))
	vdm->debug = true;
      else if (!strcmp (varKey, "debug-msg"))
	vdm->debug_msg = vdm->debug = true;
      else if (!strcmp (varKey, "socket"))
	{
	  vdm->socket_name = varValue;
	}
      else
	return daq_vpp_err (ctx, "unknown config key '%s'", varKey);

      vdm->daq_base_api.config_next_variable (modcfg, &varKey, &varValue);
    }
  return DAQ_SUCCESS;
}
