/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vlib/pci/pci.h"
#include "vnet/error.h"
#include "vppinfra/error.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_cnxk/cnxk.h>

u8 *
format_cnxk_port_status (u8 *s, va_list *args)
{
  return s;
}
