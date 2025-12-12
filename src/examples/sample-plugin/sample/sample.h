/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef __included_sample_h__
#define __included_sample_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    /* convenience */
    vnet_main_t * vnet_main;
} sample_main_t;

extern sample_main_t sample_main;

extern vlib_node_registration_t sample_node;

#define SAMPLE_PLUGIN_BUILD_VER "1.0"

#endif /* __included_sample_h__ */
