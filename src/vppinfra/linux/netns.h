/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#ifndef included_vppinfra_netns_h
#define included_vppinfra_netns_h

#include <vppinfra/clib.h>

int clib_netns_open (u8 *netns);
int clib_setns (int nfd);

#endif /* included_vppinfra_netns_h */
