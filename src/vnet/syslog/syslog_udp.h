/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

/**
 * @file syslog_udp.h
 * syslog protocol UDP transport layer declaration (RFC5426)
 */
#ifndef __included_syslog_udp_h__
#define __included_syslog_udp_h__

#include <vnet/syslog/syslog.h>

/**
 * @brief Add UDP/IP transport layer by prepending it to existing data
 */
void syslog_add_udp_transport (vlib_main_t * vm, u32 bi);

#endif /* __included_syslog_udp_h__ */
