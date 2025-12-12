/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

/* trace_config.h -- iOAM trace configuration utility routines */

#ifndef include_vnet_trace_config_h
#define include_vnet_trace_config_h

extern trace_main_t trace_main;

always_inline trace_profile *
trace_profile_find (void)
{
  trace_main_t *sm = &trace_main;

  return (&(sm->profile));
}

#endif
