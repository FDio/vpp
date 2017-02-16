/*
 * dhcp_proxy.h: DHCP v4 & v6 proxy common functions/types
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#ifndef included_dhcp_proxy_h
#define included_dhcp_proxy_h

#include <vnet/vnet.h>
#include <vnet/dhcp/dhcp4_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/format.h>
#include <vnet/udp/udp.h>

typedef enum {
#define dhcp_proxy_error(n,s) DHCP_PROXY_ERROR_##n,
#include <vnet/dhcp/dhcp4_proxy_error.def>
#undef dhcp_proxy_error
  DHCP_PROXY_N_ERROR,
} dhcp_proxy_error_t;

typedef enum {
#define dhcpv6_proxy_error(n,s) DHCPV6_PROXY_ERROR_##n,
#include <vnet/dhcp/dhcp6_proxy_error.def>
#undef dhcpv6_proxy_error
  DHCPV6_PROXY_N_ERROR,
} dhcpv6_proxy_error_t;


/**
 * @brief The Virtual Sub-net Selection information for a given RX FIB
 */
typedef struct dhcp_vss_t_ {
    /**
     * @brief ?? RFC doesn't say
     */
    u32 oui;
    /**
     * @brief VPN-ID
     */
    u32 fib_id;
} dhcp_vss_t;

/**
 * @brief A representation of a single DHCP Server within a given VRF config
 */
typedef struct dhcp_server_t_
{
    /**
     * @brief The address of the DHCP server to which to relay the client's
     *        messages
     */
    ip46_address_t dhcp_server;

    /**
     * @brief The FIB index (not the external Table-ID) in which the server
     *        is reachable.
     */
    u32 server_fib_index;
} dhcp_server_t;

/**
 * @brief A DHCP proxy represenation fpr per-client VRF config
 */
typedef struct dhcp_proxy_t_ {
    /**
     * @brief The set of DHCP servers to which messages are relayed.
     *  If multiple servers are configured then discover/solict messages
     * are relayed to each. A cookie is maintained for the relay, and only
     * one message is replayed to the client, based on the presence of the
     * cookie.
     * The expectation is there are only 1 or 2 servers, hence no fancy DB.
     */
    dhcp_server_t *dhcp_servers;

    /**
     * @brief Hash table of pending requets key'd on the clients MAC address
     */
    uword *dhcp_pending;

    /**
     * @brief A lock for the pending request DB.
     */
    int lock;

    /**
     * @brief The source address to use in relayed messaes
     */
    ip46_address_t dhcp_src_address;

    /**
     * @brief The FIB index (not the external Table-ID) in which the client
     *        is resides.
     */
    u32 rx_fib_index;
} dhcp_proxy_t;

#define DHCP_N_PROTOS (FIB_PROTOCOL_IP6 + 1)

/**
 * @brief Collection of global DHCP proxy data
 */
typedef struct {
  /* Pool of DHCP servers */
  dhcp_proxy_t *dhcp_servers[DHCP_N_PROTOS];

  /* Pool of selected DHCP server. Zero is the default server */
  u32 * dhcp_server_index_by_rx_fib_index[DHCP_N_PROTOS];

  /* to drop pkts in server-to-client direction */
  u32 error_drop_node_index;

  dhcp_vss_t *vss[DHCP_N_PROTOS];

  /* hash lookup specific vrf_id -> option 82 vss suboption  */
  u32 *vss_index_by_rx_fib_index[DHCP_N_PROTOS];
} dhcp_proxy_main_t;

extern dhcp_proxy_main_t dhcp_proxy_main;

/**
 * @brief Send the details of a proxy session to the API client during a dump
 */
void dhcp_send_details (fib_protocol_t proto,
                        void *opaque,
                        u32 context,
                        dhcp_proxy_t *proxy);

/**
 * @brief Show (on CLI) a VSS config during a show walk
 */
int dhcp_vss_show_walk (dhcp_vss_t *vss,
                        u32 rx_table_id,
                        void *ctx);

/**
 * @brief Configure/set a new VSS info
 */
int dhcp_proxy_set_vss(fib_protocol_t proto,
                       u32 vrf_id,
                       u32 oui,
                       u32 fib_id,
                       int is_del);

/**
 * @brief Dump the proxy configs to the API
 */
void dhcp_proxy_dump(fib_protocol_t proto,
                     void *opaque,
                     u32 context);

/**
 * @brief Add a new DHCP proxy server configuration.
 * @return 1 is the config is new,
 *         0 otherwise (implying a modify of an existing)
 */
int dhcp_proxy_server_add(fib_protocol_t proto,
                          ip46_address_t *addr,
                          ip46_address_t *src_address,
                          u32 rx_fib_iindex,
                          u32 server_table_id);

/**
 * @brief Delete a DHCP proxy config
 * @return 1 if the proxy is deleted, 0 otherwise
 */
int dhcp_proxy_server_del(fib_protocol_t proto,
                          u32 rx_fib_index,
                          ip46_address_t *addr,
                          u32 server_table_id);

u32
dhcp_proxy_rx_table_get_table_id (fib_protocol_t proto,
                                  u32 fib_index);

/**
 * @brief Callback function invoked for each DHCP proxy entry
 *  return 0 to break the walk, non-zero otherwise.
 */
typedef int (*dhcp_proxy_walk_fn_t)(dhcp_proxy_t *server,
                                    void *ctx);

/**
 * @brief Walk/Visit each DHCP proxy server
 */
void dhcp_proxy_walk(fib_protocol_t proto,
                     dhcp_proxy_walk_fn_t fn,
                     void *ctx);

/**
 * @brief Callback function invoked for each DHCP VSS entry
 *  return 0 to break the walk, non-zero otherwise.
 */
typedef int (*dhcp_vss_walk_fn_t)(dhcp_vss_t *server,
                                  u32 rx_table_id,
                                  void *ctx);

/**
 * @brief Walk/Visit each DHCP proxy VSS
 */
void dhcp_vss_walk(fib_protocol_t proto,
                   dhcp_vss_walk_fn_t fn,
                   void *ctx);

/**
 * @brief Lock a proxy object to prevent simultaneous access of its
 *  pending store
 */
void dhcp_proxy_lock (dhcp_proxy_t *server);

/**
 * @brief Lock a proxy object to prevent simultaneous access of its
 *  pending store
 */
void dhcp_proxy_unlock (dhcp_proxy_t *server);

/**
 * @brief Get the VSS data for the FIB index
 */
static inline dhcp_vss_t *
dhcp_get_vss_info (dhcp_proxy_main_t *dm,
                   u32 rx_fib_index,
                   fib_protocol_t proto)
{
  dhcp_vss_t *v = NULL;

  if (vec_len(dm->vss_index_by_rx_fib_index[proto]) > rx_fib_index &&
      dm->vss_index_by_rx_fib_index[proto][rx_fib_index] != ~0)
  {
      v = pool_elt_at_index (
              dm->vss[proto],
              dm->vss_index_by_rx_fib_index[proto][rx_fib_index]);
  }

  return (v);
}

/**
 * @brief Get the DHCP proxy server data for the FIB index
 */
static inline dhcp_proxy_t *
dhcp_get_proxy (dhcp_proxy_main_t *dm,
                u32 rx_fib_index,
                fib_protocol_t proto)
{
  dhcp_proxy_t *s = NULL;

  if (vec_len(dm->dhcp_server_index_by_rx_fib_index[proto]) > rx_fib_index &&
      dm->dhcp_server_index_by_rx_fib_index[proto][rx_fib_index] != ~0)
  {
      s = pool_elt_at_index (
              dm->dhcp_servers[proto],
              dm->dhcp_server_index_by_rx_fib_index[proto][rx_fib_index]);
  }

  return (s);
}

int dhcp6_proxy_set_server (ip46_address_t *addr,
                            ip46_address_t *src_addr,
                            u32 rx_table_id,
                            u32 server_table_id,
                            int is_del);
int dhcp4_proxy_set_server (ip46_address_t *addr,
                            ip46_address_t *src_addr,
                            u32 rx_table_id,
                            u32 server_table_id,
                            int is_del);

#endif /* included_dhcp_proxy_h */
