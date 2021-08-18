/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef included_npol_h
#define included_npol_h

#include <vnet/ip/ip.h>
#include <vnet/ip/ip_types_api.h>
#include <acl/public_inlines.h>

#include <npol/npol.api_enum.h>
#include <npol/npol.api_types.h>
#include <npol/npol_interface.h>

#define NPOL_INVALID_INDEX ((u32) ~0)

#define SRC 0
#define DST 1

#define NPOL_ACTION_ALLOW   2
#define NPOL_ACTION_UNKNOWN 1
#define NPOL_ACTION_DENY    0

typedef struct
{
  u16 start;
  u16 end;
} npol_port_range_t;

typedef struct
{
  u32 calico_acl_user_id;

  /* API message ID base */
  u16 msg_id_base;

} npol_main_t;

extern npol_main_t npol_main;

#endif
