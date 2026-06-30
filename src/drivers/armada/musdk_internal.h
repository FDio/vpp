/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef included_armada_musdk_internal_h
#define included_armada_musdk_internal_h

#include <pp2/pp2.h>

#define PP2_LOOPBACK_PORT   3
#define PP2_LOOPBACK_TXQ_ID ((MVPP2_MAX_TCONT + PP2_LOOPBACK_PORT) * MVPP2_MAX_TXQ)

void musdk_release_descs (vlib_main_t *, vnet_dev_t *, u16, struct pp2_ppio_desc[]);

void pp2_bm_flush_pools (vnet_dev_t *, uintptr_t, u16);
void pp2_bm_pool_assign (vnet_dev_port_t *, u32, u32, u32);

vnet_dev_rv_t mvpp2_uio_init (vnet_dev_t *, int *);
vnet_dev_rv_t mvpp2_uio_map (vnet_dev_t *, int, const char *, u32 *, void **);
u8 mvpp2_uio_exists (vnet_dev_t *, u8);
void mvpp2_uio_deinit (vnet_dev_t *);

#endif /* included_armada_musdk_internal_h */
