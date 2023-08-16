/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _CNXK_H_
#define _CNXK_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

typedef enum
{
  CNXK_DEVICE_TYPE_UNKNOWN = 0,
  CNXK_DEVICE_TYPE_RVU_PF,
  CNXK_DEVICE_TYPE_CPT_VF,
} __clib_packed cnxk_device_type_t;

typedef struct cnxk_mbox cnxk_mbox_t;

typedef struct
{
  cnxk_device_type_t type;
  void *bar2;
  void *bar4;
  cnxk_mbox_t *mbox;
} cnxk_device_t;

/* format.c */
format_function_t format_cnxk_port_status;

#endif /* _CNXK_H_ */
