/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef included_armada_musdk_internal_h
#define included_armada_musdk_internal_h

#include <pp2/pp2.h>

void pp2_port_restore_fc_isr (vnet_dev_port_t *);
void pp2_port_rxqs_fc_state_reset (vnet_dev_port_t *);
void pp2_cls_mng_config_default_cos_queue (vnet_dev_port_t *);
void pp2_cls_mng_rss_port_init (vnet_dev_port_t *);
void pp2_port_clear_fc_isr (vnet_dev_port_t *);
void pp2_port_defaults_set (vnet_dev_port_t *);
void pp2_port_egress_disable (vnet_dev_port_t *);
void pp2_port_ingress_disable (vnet_dev_port_t *);
void pp2_port_interrupts_disable (vnet_dev_port_t *);

vnet_dev_rv_t mvpp2_uio_init (vnet_dev_t *, int *);
vnet_dev_rv_t mvpp2_uio_map (vnet_dev_t *, int, const char *, u32 *, void **);
void mvpp2_uio_deinit (vnet_dev_t *);

#endif /* included_armada_musdk_internal_h */
