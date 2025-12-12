/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef included_vnet_device_netlink_h
#define included_vnet_device_netlink_h

clib_error_t *vnet_netlink_set_link_name (int ifindex, char *new_ifname);
clib_error_t *vnet_netlink_set_link_netns (int ifindex, int netns_fd,
					   char *new_ifname);
clib_error_t *vnet_netlink_set_link_master (int ifindex, char *master_ifname);
clib_error_t *vnet_netlink_set_link_addr (int ifindex, u8 * addr);
clib_error_t *vnet_netlink_set_link_state (int ifindex, int up);
clib_error_t *vnet_netlink_get_link_mtu (int ifindex, u32 *mtu);
clib_error_t *vnet_netlink_set_link_mtu (int ifindex, int mtu);
clib_error_t *vnet_netlink_add_ip4_addr (int ifindex, void *addr,
					 int pfx_len);
clib_error_t *vnet_netlink_del_ip4_addr (int ifindex, void *addr, int pfx_len);
clib_error_t *vnet_netlink_add_ip6_addr (int ifindex, void *addr,
					 int pfx_len);
clib_error_t *vnet_netlink_del_ip6_addr (int ifindex, void *addr, int pfx_len);
clib_error_t *vnet_netlink_add_ip4_route (void *dst, u8 dst_len, void *gw);
clib_error_t *vnet_netlink_add_ip6_route (void *dst, u8 dst_len, void *gw);

#endif /* included_vnet_device_netlink_h */
