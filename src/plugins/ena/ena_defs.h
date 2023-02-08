/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_DEFS_H_
#define _ENA_DEFS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

#define PCI_VENDOR_ID_AMAZON		   0x1d0f
#define PCI_DEVICE_ID_AMAZON_ENA_PF	   0x0ec2
#define PCI_DEVICE_ID_AMAZON_ENA_PF_RSERV0 0x1ec2
#define PCI_DEVICE_ID_AMAZON_ENA_VF	   0xec20
#define PCI_DEVICE_ID_AMAZON_ENA_VF_RSERV0 0xec21

#include <ena/ena_reg_defs.h>
#include <ena/ena_admin_defs.h>
#include <ena/ena_aenq_defs.h>
#include <ena/ena_io_defs.h>

/*
 * MMIO Response
 */
typedef struct
{
  u16 req_id;
  u16 reg_off;
  u32 reg_val;
} ena_mmio_resp_t;

#endif /* _ENA_DEFS_H_ */
