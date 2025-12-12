
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco and/or its affiliates.
 */

/* fateshare.h - skeleton vpp engine plug-in header file */

#ifndef __included_fateshare_h__
#define __included_fateshare_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef struct
{
  /* convenience */
  vlib_main_t *vlib_main;

  u8 *monitor_cmd;
  u8 *monitor_logfile;
  pid_t monitor_pid;
  u8 **commands;
} fateshare_main_t;

extern fateshare_main_t fateshare_main;

#endif /* __included_fateshare_h__ */
