/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_selog_shared_h__
#define __included_selog_shared_h__
#include <vppinfra/elog.h>
typedef struct
{
  elog_main_t em;
} selog_shared_header_t;

#endif