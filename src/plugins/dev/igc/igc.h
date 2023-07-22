/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _IGC_H_
#define _IGC_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#include <dev/igc/igc_regs.h>

/* format.c */
format_function_t format_igc_reg_write;
format_function_t format_igc_reg_read;

#endif /* _IGC_H_ */
