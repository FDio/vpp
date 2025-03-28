/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <sched.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/socket.h>
#include <net/if.h>

#include <vlib/unix/plugin.h>
#include <vnet/api_errno.h>

#include <plugins/linux-cp/lcp.h>
#include <plugins/linux-cp/lcp_interface.h>
#include <plugins/osi/osi.h>

lcp_main_t lcp_main;

u8 *
lcp_get_default_ns (void)
{
  lcp_main_t *lcpm = &lcp_main;

  if (!lcpm->default_namespace || lcpm->default_namespace[0] == 0)
    return NULL;

  return lcpm->default_namespace;
}

int
lcp_get_default_ns_fd (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->default_ns_fd;
}

/*
 * ns is expected to be or look like a NUL-terminated C string.
 */
int
lcp_set_default_ns (u8 *ns)
{
  lcp_main_t *lcpm = &lcp_main;
  char *p;
  int len;
  u8 *s;

  p = (char *) ns;
  len = clib_strnlen (p, LCP_NS_LEN);
  if (len >= LCP_NS_LEN)
    return -1;

  if (!p || *p == 0)
    {
      lcpm->default_namespace = NULL;
      if (lcpm->default_ns_fd > 0)
	close (lcpm->default_ns_fd);
      lcpm->default_ns_fd = 0;
      return 0;
    }

  vec_validate_init_c_string (lcpm->default_namespace, p,
			      clib_strnlen (p, LCP_NS_LEN));
  s = format (0, "/var/run/netns/%s%c", (char *) lcpm->default_namespace, 0);
  lcpm->default_ns_fd = open ((char *) s, O_RDONLY);
  vec_free (s);

  return 0;
}

void
lcp_set_sync (u8 is_auto)
{
  lcp_main_t *lcpm = &lcp_main;

  lcpm->lcp_sync = (is_auto != 0);

  // If we set to 'on', do a one-off sync of LCP interfaces
  if (is_auto)
    lcp_itf_pair_sync_state_all ();
}

int
lcp_sync (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->lcp_sync;
}

void
lcp_set_sync_unnumbered (u8 is_sync)
{
  lcp_main_t *lcpm = &lcp_main;

  lcpm->lcp_sync_unnumbered = (is_sync != 0);

  // If we set to 'on', do a one-off sync of LCP interfaces
  if (is_sync)
    lcp_itf_pair_sync_state_all ();
}

int
lcp_sync_unnumbered (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->lcp_sync_unnumbered;
}

void
lcp_set_auto_subint (u8 is_auto)
{
  lcp_main_t *lcpm = &lcp_main;

  lcpm->lcp_auto_subint = (is_auto != 0);
}

int
lcp_auto_subint (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->lcp_auto_subint;
}

void
lcp_set_del_static_on_link_down (u8 is_del)
{
  lcp_main_t *lcpm = &lcp_main;

  lcpm->del_static_on_link_down = (is_del != 0);
}

u8
lcp_get_del_static_on_link_down (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->del_static_on_link_down;
}

void
lcp_set_del_dynamic_on_link_down (u8 is_del)
{
  lcp_main_t *lcpm = &lcp_main;

  lcpm->del_dynamic_on_link_down = (is_del != 0);
}

u8
lcp_get_del_dynamic_on_link_down (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->del_dynamic_on_link_down;
}

void
lcp_set_netlink_processing_active (u8 is_processing)
{
  lcp_main_t *lcpm = &lcp_main;

  lcpm->netlink_processing_active = (is_processing != 0);
}

u8
lcp_get_netlink_processing_active (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->netlink_processing_active;
}

void
lcp_set_default_num_queues (u16 num_queues, u8 is_tx)
{
  lcp_main_t *lcpm = &lcp_main;

  if (is_tx)
    lcpm->num_tx_queues = num_queues;
  else
    lcpm->num_rx_queues = num_queues;
}

u16
lcp_get_default_num_queues (u8 is_tx)
{
  lcp_main_t *lcpm = &lcp_main;

  if (is_tx)
    return lcpm->num_tx_queues;

  return lcpm->num_rx_queues ?: vlib_num_workers ();
}

typedef int (*osi_reg_fn) (osi_protocol_t protocol, u32 node_index);
static osi_reg_fn osi_reg_p = NULL;

int
lcp_osi_proto_enable (u8 proto)
{
  lcp_main_t *lcpm = &lcp_main;

  /* don't do anything if it's already enabled */
  if (clib_bitmap_get (lcpm->osi_protos_enabled, proto))
    return 0;

  if (!osi_reg_p)
    osi_reg_p = vlib_get_plugin_symbol ("osi_plugin.so", "osi_register_input_protocol");
  if (!osi_reg_p)
    return VNET_API_ERROR_FEATURE_DISABLED;

  vlib_main_t *vm = vlib_get_main ();
  vlib_node_t *lcp_punt_xc_node = vlib_get_node_by_name (vm, (u8 *) "linux-cp-punt-xc");
  if (!lcp_punt_xc_node)
    return VNET_API_ERROR_UNIMPLEMENTED;

  int rv = osi_reg_p ((osi_protocol_t) proto, lcp_punt_xc_node->index);
  if (!rv)
    lcpm->osi_protos_enabled = clib_bitmap_set (lcpm->osi_protos_enabled, proto, 1);

  return rv;
}

int
lcp_osi_proto_get_enabled (u8 **protos)
{
  lcp_main_t *lcpm = &lcp_main;
  uword i;

  if (!protos)
    return VNET_API_ERROR_INVALID_ARGUMENT;

  clib_bitmap_foreach (i, lcpm->osi_protos_enabled)
    vec_add1 (*protos, i);

  return 0;
}
