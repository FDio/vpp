/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef included_vnet_device_netlink_h
#define included_vnet_device_netlink_h

clib_error_t *vnet_netlink_set_if_mtu (int ifindex, int mtu);
clib_error_t *vnet_netlink_set_if_namespace (int ifindex, char *net_ns);
clib_error_t *vnet_netlink_set_if_master (int ifindex, int master_ifindex);
clib_error_t *vnet_netlink_add_ip4_addr (int ifindex, void *addr,
					 int pfx_len);
clib_error_t *vnet_netlink_add_ip6_addr (int ifindex, void *addr,
					 int pfx_len);

#endif /* included_vnet_device_netlink_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
