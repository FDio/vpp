
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) <current-year> <your-organization>
 */

/* tracedump.h - skeleton vpp engine plug-in header file */

#ifndef __included_tracedump_h__
#define __included_tracedump_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /*
   * cached reply data
   * traces [client_id][thread_id][trace]
   */
  vlib_trace_header_t ****traces;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} tracedump_main_t;

extern tracedump_main_t tracedump_main;

#endif /* __included_tracedump_h__ */
