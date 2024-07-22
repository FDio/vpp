/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
  u8 del_static_on_link_down;  /* Delete static routes when link goes down */
  u8 del_dynamic_on_link_down; /* Delete dynamic routes when link goes down */
  u8 test_mode;	      /* Set when Unit testing */
  u8 netlink_processing_active; /* Set while a batch of Netlink messages are
				   being processed */
  u8 route_no_paths; /* Add routes with no paths as local */
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
 * Get/Set whether to install routes with no paths as local
 */
void lcp_set_route_no_paths (u8 is_del);
u8 lcp_get_route_no_paths (void);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
