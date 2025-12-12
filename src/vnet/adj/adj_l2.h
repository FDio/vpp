/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef __ADJ_L2_H__
#define __ADJ_L2_H__

#include <vnet/adj/adj.h>

extern vlib_node_registration_t adj_l2_midchain_node;
extern vlib_node_registration_t adj_l2_rewrite_node;

#endif
