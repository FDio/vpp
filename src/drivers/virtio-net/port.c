/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <driver.h>

vnet_dev_rv_t
vn_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vn_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  return VNET_DEV_OK;
}

void
vn_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
}
