/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef included_dns_h
#define included_dns_h

#include <vppinfra/time.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>

#include <vppinfra/hash.h>
#include <dns/dns_packet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/lock.h>
#include <vlibapi/api_common.h>

typedef struct
{
  u32 request_type;
  u32 client_index;
  u32 client_context;
  u8 is_ip6;
  u16 dst_port;
  u16 id;
  u16 pad;
  u8 dst_address[16];
  u8 *name;
  dns_query_t query;
} dns_pending_request_t;

typedef enum
{
  DNS_API_PENDING_NAME_TO_IP = 1,
  DNS_API_PENDING_IP_TO_NAME,
  DNS_PEER_PENDING_NAME_TO_IP,
  DNS_PEER_PENDING_IP_TO_NAME,
} dns_pending_request_type_t;

typedef struct
{
  /** flags */
  volatile u8 flags;

  /** The name in "normal human being" notation, e.g. www.foobar.com */
  u8 *name;

  /** For CNAME records, the "next name" to resolve */
  u8 *cname;

  /** Expiration time */
  f64 expiration_time;

  /** Cached dns request, for sending retries */
  u8 *dns_request;

  /** Retry parameters */
  int retry_count;
  int server_rotor;
  int server_af;
  int server_fails;
  f64 retry_timer;

  /** Cached dns response */
  u8 *dns_response;

  /** Clients / peers awaiting responses */
  dns_pending_request_t *pending_requests;
} dns_cache_entry_t;

#define DNS_CACHE_ENTRY_FLAG_VALID	(1<<0) /**< we have Actual Data */
#define DNS_CACHE_ENTRY_FLAG_STATIC	(1<<1) /**< static entry */
#define DNS_CACHE_ENTRY_FLAG_CNAME	(1<<2) /**< CNAME (indirect) entry */

#define DNS_RETRIES_PER_SERVER 3

#define DNS_RESOLVER_EVENT_RESOLVED	1
#define DNS_RESOLVER_EVENT_PENDING	2


typedef struct
{
  /** Pool of cache entries */
  dns_cache_entry_t *entries;

  /** Pool indices of unresolved entries */
  u32 *unresolved_entries;

  /** Find cached record by name */
  uword *cache_entry_by_name;
  clib_spinlock_t cache_lock;
  int cache_lock_tag;

  /** enable / disable flag */
  int is_enabled;

  /** udp port registration complete */
  int udp_ports_registered;

  /** upstream name servers, e.g. 8.8.8.8 */
  ip4_address_t *ip4_name_servers;
  ip6_address_t *ip6_name_servers;

  /** resolver process node index */
  u32 resolver_process_node_index;

  /** config parameters */
  u32 name_cache_size;
  u32 max_ttl_in_seconds;
  u32 random_seed;

  /** message-ID base */
  u16 msg_id_base;

  /* convenience */
  vnet_main_t *vnet_main;
  api_main_t *api_main;
} dns_main_t;

extern dns_main_t dns_main;

extern vlib_node_registration_t dns46_reply_node;
extern vlib_node_registration_t dns4_request_node;
extern vlib_node_registration_t dns6_request_node;

#define foreach_dns46_request_error                                     \
_(NONE, "No error")							\
_(UNIMPLEMENTED, "Unimplemented")                                       \
_(PROCESSED, "DNS request pkts processed")                              \
_(IP_OPTIONS, "DNS pkts with ip options (dropped)")                     \
_(BAD_REQUEST, "DNS pkts with serious discrepancies (dropped)")         \
_(TOO_MANY_REQUESTS, "DNS pkts asking too many questions")              \
_(RESOLUTION_REQUIRED, "DNS pkts pending upstream name resolution")

typedef enum
{
#define _(sym,str) DNS46_REQUEST_ERROR_##sym,
  foreach_dns46_request_error
#undef _
    DNS46_REQUEST_N_ERROR,
} dns46_request_error_t;

#define foreach_dns46_reply_error                       \
_(DISABLED, "DNS pkts punted (feature disabled)")       \
_(PROCESSED, "DNS reply pkts processed")                \
_(NO_ELT, "No DNS pool element")                        \
_(FORMAT_ERROR, "DNS format errors")                    \
_(TEST_DROP, "DNS reply pkt dropped for test purposes") \
_(MULTIPLE_REPLY, "DNS multiple reply packets")	        \
_(NO_UNRESOLVED_ENTRY, "No unresolved entry for pkt")

typedef enum
{
#define _(sym,str) DNS46_REPLY_ERROR_##sym,
  foreach_dns46_reply_error
#undef _
    DNS46_REPLY_N_ERROR,
} dns46_reply_error_t;

void vnet_send_dns_request (vlib_main_t * vm, dns_main_t * dm,
			    dns_cache_entry_t * ep);
int vnet_dns_cname_indirection_nolock (vlib_main_t * vm, dns_main_t * dm,
				       u32 ep_index, u8 * reply);

int vnet_dns_delete_entry_by_index_nolock (dns_main_t * dm, u32 index);

void vnet_dns_format_name (u8 **name, u8 qtype);

int
vnet_dns_resolve_name (vlib_main_t * vm, dns_main_t * dm, u8 * name,
		       dns_pending_request_t * t, dns_cache_entry_t ** retp);

void
vnet_dns_send_dns6_request (vlib_main_t * vm, dns_main_t * dm,
			    dns_cache_entry_t * ep, ip6_address_t * server);
void
vnet_dns_send_dns4_request (vlib_main_t * vm, dns_main_t * dm,
			    dns_cache_entry_t * ep, ip4_address_t * server);

void vnet_send_dns4_reply (vlib_main_t * vm, dns_main_t * dm,
			   dns_pending_request_t * t, dns_cache_entry_t * ep,
			   vlib_buffer_t * b0);

void vnet_send_dns6_reply (vlib_main_t * vm, dns_main_t * dm,
			   dns_pending_request_t * t, dns_cache_entry_t * ep,
			   vlib_buffer_t * b0);

u8 *vnet_dns_labels_to_name (u8 * label, u8 * full_text,
			     u8 ** parse_from_here);

void vnet_dns_create_resolver_process (vlib_main_t * vm, dns_main_t * dm);

format_function_t format_dns_reply;

static inline void
dns_cache_lock (dns_main_t * dm, int tag)
{
  if (dm->cache_lock)
    {
      ASSERT (tag);
      ASSERT (dm->cache_lock_tag == 0);
      clib_spinlock_lock (&dm->cache_lock);
      dm->cache_lock_tag = tag;
    }
}

static inline void
dns_cache_unlock (dns_main_t * dm)
{
  if (dm->cache_lock)
    {
      ASSERT (dm->cache_lock_tag);
      dm->cache_lock_tag = 0;
      clib_spinlock_unlock (&dm->cache_lock);
    }
}

#endif /* included_dns_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
