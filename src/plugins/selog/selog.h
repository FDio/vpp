/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_selog_h__
#define __included_selog_h__

#include <vppinfra/elog.h>
#include <vppinfra/file.h>
#include <svm/ssvm.h>
#include "selog_shared.h"
typedef struct
{
  u8 *ssvm_name;
} selog_config_t;
typedef struct
{
  elog_main_t *em;
  ssvm_private_t ssvm;
  selog_config_t config;
  selog_shared_header_t *shr;
  u16 msg_id_base;
} selog_main_t;

extern selog_main_t selog_main;
#endif /* __included_selog_h__ */