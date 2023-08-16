/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_DEFS_H_
#define _ENA_DEFS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <dev_ena/ena_reg_defs.h>
#include <dev_ena/ena_admin_defs.h>
#include <dev_ena/ena_aenq_defs.h>
#include <dev_ena/ena_io_defs.h>

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
