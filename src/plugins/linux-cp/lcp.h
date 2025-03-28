/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef __LCP_H__
#define __LCP_H__

#include <vlib/vlib.h>

#define LCP_NS_LEN 32

typedef struct lcp_main_s
{
  u16 msg_id_base;		    /* API message ID base */
  u8 *default_namespace;	    /* default namespace if set */
  int default_ns_fd;
  u8 lcp_auto_subint; /* Automatically create/delete LCP sub-interfaces */
  u8 lcp_sync;	      /* Automatically sync VPP changes to LCP */
  u8 lcp_sync_unnumbered;      /* Automatically sync unnumbered interfaces to LCP */
  u8 del_static_on_link_down;  /* Delete static routes when link goes down */
  u8 del_dynamic_on_link_down; /* Delete dynamic routes when link goes down */
  u16 num_rx_queues;
  u16 num_tx_queues;
  u8 test_mode;	      /* Set when Unit testing */
  u8 netlink_processing_active; /* Set while a batch of Netlink messages are
				   being processed */
  uword *osi_protos_enabled;	/* bitmap of OSI protos passed through */
} lcp_main_t;

extern lcp_main_t lcp_main;

/**
 * Get/Set the default namespace for LCP host taps.
 */
int lcp_set_default_ns (u8 *ns);
u8 *lcp_get_default_ns (void); /* Returns NULL or shared string */
int lcp_get_default_ns_fd (void);

/**
 * Get/Set whether to delete static routes when the link goes down.
 */
void lcp_set_del_static_on_link_down (u8 is_del);
u8 lcp_get_del_static_on_link_down (void);

/**
 * Get/Set whether to delete dynamic routes when the link goes down.
 */
void lcp_set_del_dynamic_on_link_down (u8 is_del);
u8 lcp_get_del_dynamic_on_link_down (void);

/**
 * Get/Set when we're processing a batch of netlink messages.
 * This is used to avoid looping messages between lcp-sync and netlink.
 */
void lcp_set_netlink_processing_active (u8 is_processing);
u8 lcp_get_netlink_processing_active (void);

/**
 * Get/Set the default queue number for LCP host taps.
 */
void lcp_set_default_num_queues (u16 num_queues, u8 is_tx);
u16 lcp_get_default_num_queues (u8 is_tx);

/**
 * Enable an OSI protocol for passthrough by linux-cp-punt-xc
 */
int lcp_osi_proto_enable (u8 proto);

/**
 * Retrieve vec of OSI protos enabled for passthrough
 */
int lcp_osi_proto_get_enabled (u8 **protos);

#endif
