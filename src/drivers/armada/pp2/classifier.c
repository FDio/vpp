/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

void
mvpp2x_cls_oversize_rxq_set (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  mvpp2_reg_write (mp->hif_base, MVPP2_CLS_OVERSIZE_RXQ_LOW_REG (mp->id), mp->first_rxq);
}
