/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef __ADJ_NSH_H__
#define __ADJ_NSH_H__

#include <vnet/adj/adj.h>

typedef struct _nsh_main_placeholder
{
  u8 output_feature_arc_index;
} nsh_main_placeholder_t;

extern nsh_main_placeholder_t nsh_main_placeholder;

#endif
