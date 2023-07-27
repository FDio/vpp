/*
 * Copyright (c) 2023 Intel and/or its affiliates.
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

#include "kernel_libipsec_ipsec.h"
#include "../common/kernel_vpp_net.h"
#include "../common/kernel_vpp_shared.h"

#include <library.h>
#include <daemon.h>
#include <threading/mutex.h>
#include <utils/debug.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/vnet.h>
#include <collections/hashtable.h>
#include <threading/mutex.h>
#include <processing/jobs/callback_job.h>
#include <vpp-api/client/stat_client.h>

#define vl_typedefs
#define vl_endianfun
/* Include the (first) vlib-api API definition layer */
#include <vlibmemory/vl_memory_api_h.h>
/* Include the current layer (third) vpp API definition layer */
#include <vpp/api/vpe_types.api.h>
#include <vpp/api/vpe.api.h>

#include <vnet/ip-neighbor/ip_neighbor.api_enum.h>
#include <vnet/ip-neighbor/ip_neighbor.api_types.h>
#include <vnet/ipsec/ipsec.api_enum.h>
#include <vnet/ipsec/ipsec.api_types.h>
#include <vnet/interface.api_enum.h>
#include <vnet/interface.api_types.h>
#include <vnet/ipip/ipip.api_enum.h>
#include <vnet/ipip/ipip.api_types.h>
#include <vnet/tunnel/tunnel_types.api_enum.h>
#include <vnet/tunnel/tunnel_types.api_types.h>
#undef vl_typedefs
#undef vl_endianfun

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <dirent.h>

/**
 * One and only instance of the daemon.
 */
daemon_t *charon;

typedef struct private_kernel_libipsec_vpp_ipsec_t
  private_kernel_libipsec_vpp_ipsec_t;

typedef struct kernel_vpp_listener
{
  listener_t public;
  struct private_kernel_libipsec_vpp_ipsec_t *ipsec;
} kernel_vpp_listener_t;

struct private_kernel_libipsec_vpp_ipsec_t
{

  /**
   * Public libipsec_ipsec interface
   */
  kernel_libipsec_vpp_ipsec_t public;

  /**
   * Next security association database entry ID to allocate
   */
  refcount_t next_sad_id;

  /**
   * Mutex to lock access to various lists
   */
  mutex_t *mutex;

  /**
   * Hash table of instaled SA, as kernel_ipsec_sa_id_t => sa_t
   */
  hashtable_t *sas;

  /**
   * List of installed policies (policy_entry_t)
   */
  linked_list_t *policies;

  /**
   * List of exclude routes (exclude_route_t)
   */
  linked_list_t *excludes;

  /**
   * Whether the remote TS may equal the IKE peer
   */
  bool allow_peer_ts;

  /**
   * Next SPI to allocate
   */
  refcount_t nextspi;

  /**
   * Mix value to distribute SPI allocation randomly
   */
  uint32_t mixspi;

  /**
   * Connections to VPP Stats
   */
  stat_client_main_t *sm;
};

typedef struct exclude_route_t exclude_route_t;

/**
 * Exclude route definition
 */
struct exclude_route_t
{
  /** Destination address to exclude */
  host_t *dst;
  /** Source address for route */
  host_t *src;
  /** Nexthop exclude has been installed */
  host_t *gtw;
  /** References to this route */
  int refs;
};

/**
 * Security association entry
 */
typedef struct
{
  /** VPP SA ID */
  uint32_t sa_id;
  uint32_t stat_index;
  kernel_ipsec_sa_id_t *sa_id_p;
} sa_t;

/**
 * Hash function for IPsec SA
 */
static u_int
sa_hash (kernel_ipsec_sa_id_t *sa)
{
  return chunk_hash_inc (
    sa->src->get_address (sa->src),
    chunk_hash_inc (
      sa->dst->get_address (sa->dst),
      chunk_hash_inc (chunk_from_thing (sa->spi),
		      chunk_hash (chunk_from_thing (sa->proto)))));
}

/**
 * Equality function for IPsec SA
 */
static bool
sa_equals (kernel_ipsec_sa_id_t *sa, kernel_ipsec_sa_id_t *other_sa)
{
  return sa->src->ip_equals (sa->src, other_sa->src) &&
	 sa->dst->ip_equals (sa->dst, other_sa->dst) &&
	 sa->spi == other_sa->spi && sa->proto == other_sa->proto;
}

/**
 * Initialize seeds for SPI generation
 */
static bool
init_spi (private_kernel_libipsec_vpp_ipsec_t *this)
{
  bool ok = TRUE;
  rng_t *rng;

  rng = lib->crypto->create_rng (lib->crypto, RNG_STRONG);
  if (!rng)
    {
      return FALSE;
    }
  ok =
    rng->get_bytes (rng, sizeof (this->nextspi), (uint8_t *) &this->nextspi);
  if (ok)
    {
      ok =
	rng->get_bytes (rng, sizeof (this->mixspi), (uint8_t *) &this->mixspi);
    }
  rng->destroy (rng);
  return ok;
}

/**
 * Map an integer x with a one-to-one function using quadratic residues
 */
static u_int
permute (u_int x, u_int p)
{
  u_int qr;

  x = x % p;
  qr = ((uint64_t) x * x) % p;
  if (x <= p / 2)
    {
      return qr;
    }
  return p - qr;
}

/**
 * Clean up an exclude route entry
 */
static void
exclude_route_destroy (exclude_route_t *this)
{
  this->dst->destroy (this->dst);
  this->src->destroy (this->src);
  this->gtw->destroy (this->gtw);
  free (this);
}

CALLBACK (exclude_route_match, bool, exclude_route_t *current, va_list args)
{
  host_t *dst;

  VA_ARGS_VGET (args, dst);
  return dst->ip_equals (dst, current->dst);
}

typedef struct route_entry_t route_entry_t;

/**
 * Installed routing entry
 */
struct route_entry_t
{
  /** Name of the interface the route is bound to */
  char *if_name;
  /** Source IP of the route */
  host_t *src_ip;
  /** Gateway of the route */
  host_t *gateway;
  /** Destination net */
  chunk_t dst_net;
  /** Destination net prefixlen */
  uint8_t prefixlen;
  /** Reference to exclude route, if any */
  exclude_route_t *exclude;
};

/**
 * Destroy a route_entry_t object
 */
static void
route_entry_destroy (route_entry_t *this)
{
  free (this->if_name);
  DESTROY_IF (this->src_ip);
  DESTROY_IF (this->gateway);
  chunk_free (&this->dst_net);
  free (this);
}

/**
 * Compare two route_entry_t objects
 */
static bool
route_entry_equals (route_entry_t *a, route_entry_t *b)
{
  if ((!a->src_ip && !b->src_ip) ||
      (a->src_ip && b->src_ip && a->src_ip->ip_equals (a->src_ip, b->src_ip)))
    {
      if ((!a->gateway && !b->gateway) ||
	  (a->gateway && b->gateway &&
	   a->gateway->ip_equals (a->gateway, b->gateway)))
	{
	  return a->if_name && b->if_name && streq (a->if_name, b->if_name) &&
		 chunk_equals (a->dst_net, b->dst_net) &&
		 a->prefixlen == b->prefixlen;
	}
    }
  return FALSE;
}

typedef struct policy_entry_t policy_entry_t;

/**
 * Installed policy
 */
struct policy_entry_t
{
  /** Direction of this policy: in, out, forward */
  uint8_t direction;
  /** Parameters of installed policy */
  struct
  {
    /** Subnet and port */
    host_t *net;
    /** Subnet mask */
    uint8_t mask;
    /** Protocol */
    uint8_t proto;

  } src, dst;
  /** Associated route installed for this policy */
  route_entry_t *route;
  /** References to this policy */
  int refs;
  /** Parameters of associated SA installed for this policy */
  struct
  {
    /** SPI */
    uint32_t spi;
    /** Protocol (ESP/AH) */
    uint8_t proto;
  } sa;
};

/**
 * Helper struct for expiration events
 */
typedef struct
{

  private_kernel_libipsec_vpp_ipsec_t *manager;

  kernel_ipsec_sa_id_t *sa_id;

  /**
   * 0 if this is a hard expire, otherwise the offset in s (soft->hard)
   */
  uint32_t hard_offset;

} vpp_sa_expired_t;

/**
 * Get sw_if_index from interface name
 */
static uint32_t
get_sw_if_index (char *interface)
{
  char *out = NULL;
  int out_len, name_filter_len = 0, msg_len = 0;
  int num, i;
  vl_api_sw_interface_dump_t *mp = NULL;
  vl_api_sw_interface_details_t *rmp = NULL;
  uint32_t sw_if_index = ~0;

  if (interface == NULL)
    goto error;

  name_filter_len = strlen (interface);
  msg_len = sizeof (*mp) + name_filter_len;
  mp = vl_msg_api_alloc (msg_len);
  clib_memset (mp, 0, msg_len);
  u16 msg_id = vl_msg_api_get_msg_index ((u8 *) "sw_interface_dump_aa610c27");
  mp->_vl_msg_id = htons (msg_id);
  mp->name_filter_valid = TRUE;
  mp->name_filter.length = htonl (name_filter_len);
  memcpy ((char *) mp->name_filter.buf, interface, name_filter_len);

  if (vac->send_dump (vac, (char *) mp, msg_len, &out, &out_len))
    {
      goto error;
    }
  if (!out_len)
    {
      goto error;
    }
  num = out_len / sizeof (*rmp);
  rmp = (vl_api_sw_interface_details_t *) out;
  for (i = 0; i < num; i++)
    {
      if (strlen (rmp->interface_name) &&
	  streq (interface, rmp->interface_name))
	{
	  sw_if_index = ntohl (rmp->sw_if_index);
	  break;
	}
      rmp += 1;
    }

error:
  if (out)
    free (out);
  if (mp)
    vl_msg_api_free (mp);
  return sw_if_index;
}

/**
 * Create a policy_entry_t object
 */
static policy_entry_t *
create_policy_entry (traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
		     policy_dir_t dir)
{
  policy_entry_t *this;
  INIT (this, .direction = dir, );

  src_ts->to_subnet (src_ts, &this->src.net, &this->src.mask);
  dst_ts->to_subnet (dst_ts, &this->dst.net, &this->dst.mask);

  /* src or dest proto may be "any" (0), use more restrictive one */
  this->src.proto =
    max (src_ts->get_protocol (src_ts), dst_ts->get_protocol (dst_ts));
  this->src.proto = this->src.proto ? this->src.proto : 0;
  this->dst.proto = this->src.proto;
  return this;
}

/** \brief Update tunnel protect
    @param sw_if_index - software interface index of the interface to update
   tunnel protect
    @param sa_in - index of sa to attach for inbound
    @param sa_out - index of sa to attach for outbound
*/
void
kernel_libipsec_vpp_tunnel_protect_update (uint32_t sw_if_index,
					   uint32_t sa_in, uint32_t sa_out)
{
  vl_api_ipsec_tunnel_protect_update_t *mp;
  vl_api_ipsec_tunnel_protect_update_reply_t *rmp;

  char *out = NULL;
  int out_len;
  int msg_length = sizeof (*mp) + sizeof (*mp->tunnel.sa_in);
  mp = vl_msg_api_alloc (msg_length);
  memset (mp, 0, msg_length);

  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_tunnel_protect_update_30d5f133");
  mp->_vl_msg_id = htons (msg_id);

  mp->tunnel.sw_if_index = htonl (sw_if_index);
  mp->tunnel.sa_out = htonl (sa_out);
  mp->tunnel.n_sa_in = 1;
  // mp->tunnel.sa_in[0] = htonl(sa_in);
  u32 *d = (void *) mp + sizeof (*mp);
  d[0] = htonl (sa_in);

  if (vac->send (vac, (char *) mp, msg_length, &out, &out_len))
    {
      DBG1 (DBG_KNL, "failed send vac to tunnel protect");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "tunnel protected failed send rv:%d",
	    ntohl (rmp->retval));
      goto error;
    }

error:
  if (out != NULL)
    free (out);
  if (mp != NULL)
    vl_msg_api_free (mp);
}

/** \brief Set state up/down on the interface
    @param sw_if_index - software interface index to set state up/down
    @param is_up - state is up ?
*/
void
kernel_libipsec_vpp_sw_interface_set_up (uint32_t sw_if_index, int is_up)
{
  vl_api_sw_interface_set_flags_t *mp;
  vl_api_sw_interface_set_flags_reply_t *rmp;
  char *out = NULL;
  int out_len;
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "sw_interface_set_flags_f5aec1b8");
  mp->_vl_msg_id = htons (msg_id);
  mp->sw_if_index = htonl (sw_if_index);

  if (is_up == TRUE)
    mp->flags = htonl (IF_STATUS_API_FLAG_ADMIN_UP);
  else
    mp->flags = htonl (0);

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "failed send vac to set flags");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "%s failed send set flags rv:%d",
	    is_up ? "add" : "remove", ntohl (rmp->retval));
      goto error;
    }

error:
  if (out != NULL)
    free (out);
  if (mp != NULL)
    vl_msg_api_free (mp);
}

/** \brief Set unnumbered interface add / del request
    @param sw_if_index - software interface index with an IP address
    @param unnumbered_sw_if_index - software interface index which will use the
   address
    @param is_add - if non-zero set the association, else unset it
*/
void
kernel_libipsec_vpp_sw_interface_set_unnumbered (
  uint32_t sw_if_index, uint32_t unnumbered_sw_if_index, int is_add)
{
  vl_api_sw_interface_set_unnumbered_t *mp = NULL;
  vl_api_sw_interface_set_unnumbered_reply_t *rmp = NULL;
  char *out = NULL;
  int out_len;
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "sw_interface_set_unnumbered_154a6439");
  mp->_vl_msg_id = htons (msg_id);
  mp->is_add = htonl (is_add);
  mp->sw_if_index = htonl (sw_if_index); /* use this int address */
  mp->unnumbered_sw_if_index =
    htonl (unnumbered_sw_if_index); /* on this interface */

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "failed send vac to set unnumbered");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "%s failed send vac to set unnumbered rv:%d",
	    is_add ? "add" : "remove", ntohl (rmp->retval));
      goto error;
    }

error:
  if (out != NULL)
    free (out);
  if (mp != NULL)
    vl_msg_api_free (mp);
}

/** \brief Delete ipip tunnel
    @param sw_if_index - software interface index to deleted tunnel protect
    @return - status of deleted ipip tunnel
*/
bool
kernel_libipsec_vpp_delete_ipip_tunnel (uint32_t sw_if_index)
{
  vl_api_ipip_del_tunnel_t *mp = NULL;
  vl_api_ipip_del_tunnel_reply_t *rmp = NULL;
  char *out;
  int out_len;
  bool status = false;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  u16 msg_id = vl_msg_api_get_msg_index ((u8 *) "ipip_del_tunnel_f9e6675e");
  mp->_vl_msg_id = htons (msg_id);
  mp->sw_if_index = htonl (sw_if_index);

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac deleting tunnel failed");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "deleting tunnel failed rv:%d", ntohl (rmp->retval));
      goto error;
    }
  else
    {
      DBG1 (DBG_KNL, "deleting tunnel success sw_if_index: %d", sw_if_index);
      status = true;
    }

error:
  if (out != NULL)
    free (out);
  if (mp != NULL)
    vl_msg_api_free (mp);

  return status;
}

/** \brief Delete tunnel protect
    @param sw_if_index - index of the interface to deleting tunnel protect
    @return - status od deleted tunnel protect
*/
bool
kernel_libipsec_vpp_delete_tunnel_protect (uint32_t sw_if_index)
{
  vl_api_ipsec_tunnel_protect_del_t *mp = NULL;
  vl_api_ipsec_tunnel_protect_del_reply_t *rmp = NULL;
  char *out;
  int out_len;
  bool status = false;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_tunnel_protect_del_cd239930");
  mp->_vl_msg_id = htons (msg_id);
  mp->sw_if_index = htonl (sw_if_index);

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac send deleting tunnel protect failed");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "deleting tunnel protect failed rv:%d",
	    ntohl (rmp->retval));
      goto error;
    }
  else
    {
      DBG1 (DBG_KNL, "deleting tunnel protect success sw_if_index: %d",
	    sw_if_index);
      status = true;
    }

error:
  if (out != NULL)
    free (out);
  if (mp != NULL)
    vl_msg_api_free (mp);

  return status;
}

/** \brief Create ipip tunnel
    @param src - source address of tunnel
    @param dst - destination address of tunnel
    @param user_instance - instance for created ipip tunnel
    @return - software interface index of created ipip tunnel
*/
uint32_t
kernel_libipsec_vpp_create_ipip_tunnel (host_t *src, host_t *dst,
					uint32_t user_instance)
{

  vl_api_ipip_add_tunnel_t *mp = NULL;
  vl_api_ipip_add_tunnel_reply_t *rmp = NULL;
  char *out;
  int out_len;
  bool is_ipv6 = false;
  chunk_t src_chunk, dst_chunk;
  uint32_t sw_if_index = ~0;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  u16 msg_id = vl_msg_api_get_msg_index ((u8 *) "ipip_add_tunnel_2ac399f5");
  mp->_vl_msg_id = htons (msg_id);
  mp->tunnel.sw_if_index = htonl (~0);
  mp->tunnel.instance = htonl (user_instance);
  mp->tunnel.table_id = htonl (0);
  mp->tunnel.flags = htonl (TUNNEL_API_ENCAP_DECAP_FLAG_NONE);
  mp->tunnel.mode = htonl (TUNNEL_API_MODE_P2P);
  mp->tunnel.dscp = htonl (IP_DSCP_CS0);

  if (src->get_family (src) == AF_INET6)
    {
      is_ipv6 = true;
      mp->tunnel.src.af = htonl (ADDRESS_IP6);
      mp->tunnel.dst.af = htonl (ADDRESS_IP6);
    }
  else
    {
      mp->tunnel.src.af = htonl (ADDRESS_IP4);
      mp->tunnel.dst.af = htonl (ADDRESS_IP4);
    }

  src_chunk = src->get_address (src);
  memcpy (is_ipv6 ? mp->tunnel.src.un.ip6 : mp->tunnel.src.un.ip4,
	  src_chunk.ptr, src_chunk.len);
  dst_chunk = dst->get_address (dst);
  memcpy (is_ipv6 ? mp->tunnel.dst.un.ip6 : mp->tunnel.dst.un.ip4,
	  dst_chunk.ptr, dst_chunk.len);

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac adding tunnel failed");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "add tunnel failed rv:%d", ntohl (rmp->retval));
      goto error;
    }
  else
    {
      DBG4 (DBG_KNL, "add tunnel success sw_if_index: %d",
	    ntohl (rmp->sw_if_index));
      sw_if_index = ntohl (rmp->sw_if_index);
    }

error:
  if (out != NULL)
    free (out);
  if (mp != NULL)
    vl_msg_api_free (mp);

  return sw_if_index;
}

/** \brief Delete ipip tunnel
    @param user_instance - instance for delete ipip tunnel
    @return - status of deleted ipip tunnel
*/
bool
kernel_libipsec_vpp_delete_tunnel (uint32_t user_instance)
{
  char if_name[64];
  snprintf (if_name, sizeof (if_name), "ipip%u", user_instance);
  uint32_t sw_if_index = ~0;
  bool status = false;

  sw_if_index = get_sw_if_index (if_name);
  if (sw_if_index != ~0)
    {
      /* set interface state ipip[user_instance] down */
      kernel_libipsec_vpp_sw_interface_set_up (sw_if_index, false);
      kernel_libipsec_vpp_delete_tunnel_protect (sw_if_index);
      kernel_libipsec_vpp_delete_ipip_tunnel (sw_if_index);
      status = true;
    }

  return status;
}

/** \brief Get exists or create tunnel
    @param src - source of tunnel
    @param dst - destination of tunnel
    @param user_instance - index of tunnel
    @return - software interface index of tunnel
*/
uint32_t
kernel_libipsec_vpp_get_or_create_tunnel (host_t *src, host_t *dst,
					  uint32_t user_instance)
{
  char if_name[64];
  snprintf (if_name, sizeof (if_name), "ipip%u", user_instance);
  uint32_t sw_if_index = ~0, sw_if_index_unnumbered = ~0;

  sw_if_index = get_sw_if_index (if_name);
  if (sw_if_index != ~0)
    DBG4 (DBG_KNL, "Found: %s interface with sw_if_index %u", if_name,
	  sw_if_index);
  else
    {
      /* create ipip tunnel src *src* dst *dst* instance [user_instance] */
      sw_if_index =
	kernel_libipsec_vpp_create_ipip_tunnel (src, dst, user_instance);
      DBG4 (DBG_KNL, "Created a new tunnel by sw_if_index %u with name: %s",
	    sw_if_index, if_name);
      /* set interface state ipip[user_instance] up */
      kernel_libipsec_vpp_sw_interface_set_up (sw_if_index, true);

      /* set unnumbered ip */
      char *interface = NULL;

      for (int i = 0; i < N_RETRY_GET_IF; i++)
	{
	  if (!charon->kernel->get_interface (charon->kernel, src, &interface))
	    {
	      DBG1 (DBG_KNL, "not find interface with ip-addr: %H", src);
	      free (interface);
	      interface = NULL;
	      sleep (1);
	    }
	  if (interface)
	    {
	      DBG4 (DBG_KNL, "found interface with ip-addr: %H", src);
	      break;
	    }
	}

      sw_if_index_unnumbered = get_sw_if_index (interface);

      if (sw_if_index_unnumbered != ~0)
	{
	  DBG4 (DBG_KNL, "sw_if_index_enumered %d", sw_if_index_unnumbered);
	}
      else
	{
	  DBG1 (DBG_KNL, "not found sw_if_index_unnumbered");
	}

      /* set interface unnumbered ipip[user_instance] use [eth2] */
      kernel_libipsec_vpp_sw_interface_set_unnumbered (sw_if_index_unnumbered,
						       sw_if_index, true);
    }

  return sw_if_index;
}

/**
 * Destroy a policy_entry_t object
 */
static void
policy_entry_destroy (policy_entry_t *this)
{
  if (this->route)
    {
      route_entry_destroy (this->route);
    }
  DESTROY_IF (this->src.net);
  DESTROY_IF (this->dst.net);
  free (this);
}

CALLBACK (policy_entry_equals, bool, policy_entry_t *a, va_list args)
{
  policy_entry_t *b;

  VA_ARGS_VGET (args, b);
  return a->direction == b->direction && a->src.proto == b->src.proto &&
	 a->dst.proto == b->dst.proto && a->src.mask == b->src.mask &&
	 a->dst.mask == b->dst.mask &&
	 a->src.net->equals (a->src.net, b->src.net) &&
	 a->dst.net->equals (a->dst.net, b->dst.net);
}

METHOD (kernel_ipsec_t, get_features, kernel_feature_t,
	private_kernel_libipsec_vpp_ipsec_t *this)
{
  return KERNEL_REQUIRE_UDP_ENCAPSULATION | KERNEL_ESP_V3_TFC;
}

METHOD (kernel_ipsec_t, get_spi, status_t,
	private_kernel_libipsec_vpp_ipsec_t *this, host_t *src, host_t *dst,
	uint8_t protocol, uint32_t *spi)
{
  static const u_int p = 268435399, offset = 0xc0000000;

  *spi = htonl (offset + permute (ref_get (&this->nextspi) ^ this->mixspi, p));
  return SUCCESS;
}

METHOD (kernel_ipsec_t, get_cpi, status_t,
	private_kernel_libipsec_vpp_ipsec_t *this, host_t *src, host_t *dst,
	uint16_t *cpi)
{
  return NOT_SUPPORTED;
}

/**
 * Clean up expire data
 */
static void
expire_data_destroy (vpp_sa_expired_t *data)
{
  free (data);
}

/**
 * Callback for expiration events
 */
static job_requeue_t
sa_expired (vpp_sa_expired_t *expired)
{
  private_kernel_libipsec_vpp_ipsec_t *this = expired->manager;
  sa_t *sa;
  kernel_ipsec_sa_id_t *id = expired->sa_id;

  this->mutex->lock (this->mutex);
  sa = this->sas->get (this->sas, id);

  if (sa)
    {
      charon->kernel->expire (charon->kernel, id->proto, id->spi, id->dst,
			      FALSE);
    }

  if (id->src)
    id->src->destroy (id->src);
  if (id->dst)
    id->dst->destroy (id->dst);
  free (id);
  this->mutex->unlock (this->mutex);
  return JOB_REQUEUE_NONE;
}

/**
 * Schedule a job to handle IPsec SA expiration
 */
static void
schedule_expiration (private_kernel_libipsec_vpp_ipsec_t *this,
		     kernel_ipsec_add_sa_t *entry,
		     kernel_ipsec_sa_id_t *entry2)
{
  lifetime_cfg_t *lifetime = entry->lifetime;
  vpp_sa_expired_t *expired;
  callback_job_t *job;
  uint32_t timeout;
  kernel_ipsec_sa_id_t *id;

  if (!lifetime->time.life)
    { /* no expiration at all */
      return;
    }

  INIT (id, .src = entry2->src->clone (entry2->src),
	.dst = entry2->dst->clone (entry2->dst), .spi = entry2->spi,
	.proto = entry2->proto, );

  INIT (expired, .manager = this, .sa_id = id, );

  /* schedule a rekey first, a hard timeout will be scheduled then, if any */
  expired->hard_offset = lifetime->time.life - lifetime->time.rekey;
  timeout = lifetime->time.rekey;

  if (lifetime->time.life <= lifetime->time.rekey || lifetime->time.rekey == 0)
    { /* no rekey, schedule hard timeout */
      expired->hard_offset = 0;
      timeout = lifetime->time.life;
    }

  job =
    callback_job_create ((callback_job_cb_t) sa_expired, expired,
			 (callback_job_cleanup_t) expire_data_destroy, NULL);
  lib->scheduler->schedule_job (lib->scheduler, (job_t *) job, timeout);
}

METHOD (kernel_ipsec_t, add_sa, status_t,
	private_kernel_libipsec_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_add_sa_t *data)
{
  char *out = NULL;
  int out_len;
  vl_api_ipsec_sad_entry_add_del_t *mp;
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
  uint32_t sad_id = ref_get (&this->next_sad_id);
  uint8_t ca = 0, ia = 0;
  status_t rv = FAILED;
  chunk_t src, dst;
  kernel_ipsec_sa_id_t *sa_id;
  sa_t *sa;
  int key_len = data->enc_key.len;

  if ((data->enc_alg == ENCR_AES_CTR) ||
      (data->enc_alg == ENCR_AES_GCM_ICV8) ||
      (data->enc_alg == ENCR_AES_GCM_ICV12) ||
      (data->enc_alg == ENCR_AES_GCM_ICV16))
    {
      static const int SALT_SIZE =
	4; /* See how enc_size is calculated at keymat_v2.derive_child_keys */
      key_len = key_len - SALT_SIZE;
    }
  u32 natt_port = lib->settings->get_int (
    lib->settings, "%s.plugins.socket-default.natt", IKEV2_NATT_PORT, lib->ns);
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
  mp->_vl_msg_id = htons (msg_id);
  mp->is_add = 1;
  mp->entry.sad_id = htonl (sad_id);
  mp->entry.spi = id->spi;
  mp->entry.protocol = id->proto == IPPROTO_ESP ? htonl (IPSEC_API_PROTO_ESP) :
							htonl (IPSEC_API_PROTO_AH);

  switch (data->enc_alg)
    {
    case ENCR_NULL:
      ca = IPSEC_API_CRYPTO_ALG_NONE;
      break;
    case ENCR_AES_CBC:
      switch (key_len * 8)
	{
	case 128:
	  ca = IPSEC_API_CRYPTO_ALG_AES_CBC_128;
	  break;
	case 192:
	  ca = IPSEC_API_CRYPTO_ALG_AES_CBC_192;
	  break;
	case 256:
	  ca = IPSEC_API_CRYPTO_ALG_AES_CBC_256;
	  break;
	default:
	  DBG1 (DBG_KNL, "Key length %d is not supported by VPP!",
		key_len * 8);
	  goto error;
	}
      break;
    case ENCR_AES_CTR:
      switch (key_len * 8)
	{
	case 128:
	  ca = IPSEC_API_CRYPTO_ALG_AES_CTR_128;
	  break;
	case 192:
	  ca = IPSEC_API_CRYPTO_ALG_AES_CTR_192;
	  break;
	case 256:
	  ca = IPSEC_API_CRYPTO_ALG_AES_CTR_256;
	  break;
	default:
	  DBG1 (DBG_KNL, "Key length %d is not supported by VPP!",
		key_len * 8);
	  goto error;
	}
      break;
    case ENCR_AES_GCM_ICV8:
    case ENCR_AES_GCM_ICV12:
    case ENCR_AES_GCM_ICV16:
      switch (key_len * 8)
	{
	case 128:
	  ca = IPSEC_API_CRYPTO_ALG_AES_GCM_128;
	  break;
	case 192:
	  ca = IPSEC_API_CRYPTO_ALG_AES_GCM_192;
	  break;
	case 256:
	  ca = IPSEC_API_CRYPTO_ALG_AES_GCM_256;
	  break;
	default:
	  DBG1 (DBG_KNL, "Key length %d is not supported by VPP!",
		key_len * 8);
	  goto error;
	}
      break;
    case ENCR_DES:
      ca = IPSEC_API_CRYPTO_ALG_DES_CBC;
      break;
    case ENCR_3DES:
      ca = IPSEC_API_CRYPTO_ALG_3DES_CBC;
      break;
    default:
      DBG1 (DBG_KNL, "algorithm %N not supported by VPP!",
	    encryption_algorithm_names, data->enc_alg);
      goto error;
    }
  mp->entry.crypto_algorithm = htonl (ca);
  mp->entry.crypto_key.length = key_len < 128 ? key_len : 128;
  memcpy (mp->entry.crypto_key.data, data->enc_key.ptr,
	  mp->entry.crypto_key.length);

  /* copy salt for AEAD algorithms */
  if ((data->enc_alg == ENCR_AES_CTR) ||
      (data->enc_alg == ENCR_AES_GCM_ICV8) ||
      (data->enc_alg == ENCR_AES_GCM_ICV12) ||
      (data->enc_alg == ENCR_AES_GCM_ICV16))
    {
      memcpy (&mp->entry.salt, data->enc_key.ptr + mp->entry.crypto_key.length,
	      4);
    }

  switch (data->int_alg)
    {
    case AUTH_UNDEFINED:
      ia = IPSEC_API_INTEG_ALG_NONE;
      break;
    case AUTH_HMAC_MD5_96:
      ia = IPSEC_API_INTEG_ALG_MD5_96;
      break;
    case AUTH_HMAC_SHA1_96:
      ia = IPSEC_API_INTEG_ALG_SHA1_96;
      break;
    case AUTH_HMAC_SHA2_256_96:
      ia = IPSEC_API_INTEG_ALG_SHA_256_96;
      break;
    case AUTH_HMAC_SHA2_256_128:
      ia = IPSEC_API_INTEG_ALG_SHA_256_128;
      break;
    case AUTH_HMAC_SHA2_384_192:
      ia = IPSEC_API_INTEG_ALG_SHA_384_192;
      break;
    case AUTH_HMAC_SHA2_512_256:
      ia = IPSEC_API_INTEG_ALG_SHA_512_256;
      break;
    default:
      DBG1 (DBG_KNL, "algorithm %N not supported by VPP!",
	    integrity_algorithm_names, data->int_alg);
      goto error;
      break;
    }
  mp->entry.integrity_algorithm = htonl (ia);
  mp->entry.integrity_key.length =
    data->int_key.len < 128 ? data->int_key.len : 128;
  memcpy (mp->entry.integrity_key.data, data->int_key.ptr,
	  mp->entry.integrity_key.length);

  int flags = IPSEC_API_SAD_FLAG_NONE;
  // if (data->inbound)
  // flags |= IPSEC_API_SAD_FLAG_IS_INBOUND;
  /* like the kernel-netlink plugin, anti-replay can be disabled with zero
   * replay_window, but window size cannot be customized for vpp */
  if (data->replay_window)
    flags |= IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY;
  if (data->esn)
    flags |= IPSEC_API_SAD_FLAG_USE_ESN;
  /* if (this->use_tunnel_mode_sa && data->mode == MODE_TUNNEL) */
  /*
  if (data->mode == MODE_TUNNEL)
    {
      if (id->src->get_family (id->src) == AF_INET6)
	flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL_V6;
      else
	flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL;
    }
    */
  if (data->encap)
    {
      DBG1 (DBG_KNL, "UDP encap");
      flags |= IPSEC_API_SAD_FLAG_UDP_ENCAP;
      mp->entry.udp_src_port = htons (natt_port);
      mp->entry.udp_dst_port = htons (natt_port);
    }
  mp->entry.flags = htonl (flags);

  bool is_ipv6 = false;
  if (id->src->get_family (id->src) == AF_INET6)
    {
      is_ipv6 = true;
      mp->entry.tunnel_src.af = htonl (ADDRESS_IP6);
      mp->entry.tunnel_dst.af = htonl (ADDRESS_IP6);
    }
  else
    {
      mp->entry.tunnel_src.af = htonl (ADDRESS_IP4);
      mp->entry.tunnel_dst.af = htonl (ADDRESS_IP4);
    }
  src = id->src->get_address (id->src);
  memcpy (is_ipv6 ? mp->entry.tunnel_src.un.ip6 : mp->entry.tunnel_src.un.ip4,
	  src.ptr, src.len);
  dst = id->dst->get_address (id->dst);
  memcpy (is_ipv6 ? mp->entry.tunnel_dst.un.ip6 : mp->entry.tunnel_dst.un.ip4,
	  dst.ptr, dst.len);
  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac adding SA failed");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "add SA failed rv:%d", ntohl (rmp->retval));
      goto error;
    }

  this->mutex->lock (this->mutex);
  INIT (sa_id, .src = id->src->clone (id->src),
	.dst = id->dst->clone (id->dst), .spi = id->spi, .proto = id->proto, );
  INIT (sa, .sa_id = sad_id, .stat_index = ntohl (rmp->stat_index),
	.sa_id_p = sa_id, );
  DBG4 (DBG_KNL, "put sa by its sa_id %x with spi: %x !!!!!!", sad_id,
	ntohl (id->spi));
  this->sas->put (this->sas, sa_id, sa);
  schedule_expiration (this, data, id);
  this->mutex->unlock (this->mutex);
  rv = SUCCESS;

error:
  free (out);
  vl_msg_api_free (mp);
  return rv;
}

METHOD (kernel_ipsec_t, update_sa, status_t,
	private_kernel_libipsec_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_update_sa_t *data)
{
  return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, query_sa, status_t,
	private_kernel_libipsec_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
	time_t *time)
{
  status_t rv = FAILED;
  sa_t *sa;
  u32 *dir = NULL;
  int i, k;
  stat_segment_data_t *res = NULL;
  u8 **pattern = 0;
  uint64_t res_bytes = 0;
  uint64_t res_packets = 0;

  this->mutex->lock (this->mutex);
  sa = this->sas->get (this->sas, id);
  if (!sa)
    {
      this->mutex->unlock (this->mutex);
      DBG1 (DBG_KNL, "SA not found");
      return NOT_FOUND;
    }

  if (this->sm == NULL)
    {
      stat_client_main_t *sm = NULL;
      sm = stat_client_get ();

      if (!sm)
	{
	  DBG1 (DBG_KNL, "Not connecting with stats segmentation");
	  this->mutex->unlock (this->mutex);
	  return NOT_FOUND;
	}
      this->sm = sm;
      int rv_stat = stat_segment_connect_r ("/run/vpp/stats.sock", this->sm);
      if (rv_stat != 0)
	{
	  stat_client_free (this->sm);
	  this->sm = NULL;
	  DBG1 (DBG_KNL, "Not connecting with stats segmentation");
	  this->mutex->unlock (this->mutex);
	  return NOT_FOUND;
	}
    }

  vec_add1 (pattern, (u8 *) "/net/ipsec/sa");
  dir = stat_segment_ls_r ((u8 **) pattern, this->sm);
  res = stat_segment_dump_r (dir, this->sm);
  /* i-loop for each results find by pattern - here two:
   * 1. /net/ipsec/sa
   * 2. /net/ipsec/sa/lost
   */
  for (i = 0; i < vec_len (res); i++)
    {
      switch (res[i].type)
	{
	/* type for how many packets are lost */
	case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	  if (res[i].simple_counter_vec == 0)
	    continue;
	  break;
	/* type for counter for each SA */
	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  if (res[i].combined_counter_vec == 0)
	    continue;
	  /* k-loop for each threads - that you run VPP */
	  for (k = 0; k < vec_len (res[i].combined_counter_vec); k++)
	    {
	      if (sa->stat_index <= vec_len (res[i].combined_counter_vec[k]))
		{
		  DBG4 (DBG_KNL, "Thread: %d, Packets: %lu, Bytes: %lu", k,
			res[i].combined_counter_vec[k][sa->stat_index].packets,
			res[i].combined_counter_vec[k][sa->stat_index].bytes);
		  res_bytes +=
		    res[i].combined_counter_vec[k][sa->stat_index].bytes;
		  res_packets +=
		    res[i].combined_counter_vec[k][sa->stat_index].packets;
		}
	    }
	  break;
	case STAT_DIR_TYPE_NAME_VECTOR:
	  if (res[i].name_vector == 0)
	    continue;
	  break;
	}
    }

  vec_free (pattern);
  vec_free (dir);
  stat_segment_data_free (res);

  if (bytes)
    {
      *bytes = res_bytes;
    }
  if (packets)
    {
      *packets = res_packets;
    }
  if (time)
    {
      *time = 0;
    }

  this->mutex->unlock (this->mutex);
  rv = SUCCESS;
  return rv;
}

METHOD (kernel_ipsec_t, del_sa, status_t,
	private_kernel_libipsec_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_del_sa_t *data)
{
  char *out = NULL;
  int out_len;
  vl_api_ipsec_sad_entry_add_del_t *mp = NULL;
  vl_api_ipsec_sad_entry_add_del_reply_t *rmp = NULL;
  status_t rv = FAILED;
  sa_t *sa;

  this->mutex->lock (this->mutex);
  sa = this->sas->get (this->sas, id);
  if (!sa)
    {
      DBG1 (DBG_KNL, "SA not found");
      rv = NOT_FOUND;
      goto error;
    }
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->is_add = 0;
  u16 msg_id =
    vl_msg_api_get_msg_index ((u8 *) "ipsec_sad_entry_add_del_ab64b5c6");
  mp->_vl_msg_id = htons (msg_id);
  mp->entry.sad_id = htonl (sa->sa_id);

  if (vac->send (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG1 (DBG_KNL, "vac removing SA failed");
      goto error;
    }
  rmp = (void *) out;
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "del SA failed rv:%d", ntohl (rmp->retval));
      goto error;
    }

  DBG1 (DBG_KNL, "removing SA: %x", ntohl (sa->sa_id_p->spi));
  void *temp = this->sas->remove (this->sas, id);
  if (sa->sa_id_p)
    {
      if (sa->sa_id_p->src)
	sa->sa_id_p->src->destroy (sa->sa_id_p->src);
      if (sa->sa_id_p->dst)
	sa->sa_id_p->dst->destroy (sa->sa_id_p->dst);
      free (sa->sa_id_p);
    }
  free (sa);
  rv = SUCCESS;
error:
  free (out);
  vl_msg_api_free (mp);
  this->mutex->unlock (this->mutex);
  return rv;
}

METHOD (kernel_ipsec_t, flush_sas, status_t,
	private_kernel_libipsec_vpp_ipsec_t *this)
{
  /* TODO: add support for flush_sas!*/
  return SUCCESS;
}

/**
 * Add an explicit exclude route to a routing entry
 */
static void
add_exclude_route (private_kernel_libipsec_vpp_ipsec_t *this,
		   route_entry_t *route, host_t *src, host_t *dst)
{
  exclude_route_t *exclude;
  host_t *gtw;

  if (this->excludes->find_first (this->excludes, exclude_route_match,
				  (void **) &exclude, dst))
    {
      route->exclude = exclude;
      exclude->refs++;
    }

  if (!route->exclude)
    {
      DBG1 (DBG_KNL, "installing new exclude route for %H src %H", dst, src);
      gtw = charon->kernel->get_nexthop (charon->kernel, dst, -1, NULL, NULL);
      if (gtw)
	{
	  char *if_name = NULL;

	  if (charon->kernel->get_interface (charon->kernel, src, &if_name) &&
	      charon->kernel->add_route (
		charon->kernel, dst->get_address (dst),
		dst->get_family (dst) == AF_INET ? 32 : 128, gtw, src, if_name,
		TRUE) == SUCCESS)
	    {
	      INIT (exclude, .dst = dst->clone (dst), .src = src->clone (src),
		    .gtw = gtw->clone (gtw), .refs = 1, );
	      route->exclude = exclude;
	      this->excludes->insert_last (this->excludes, exclude);
	    }
	  else
	    {
	      DBG1 (DBG_KNL, "installing exclude route for %H failed", dst);
	    }
	  gtw->destroy (gtw);
	  free (if_name);
	}
      else
	{
	  DBG1 (DBG_KNL, "gateway lookup for %H failed", dst);
	}
    }
}

/**
 * Remove an exclude route attached to a routing entry
 */
static void
remove_exclude_route (private_kernel_libipsec_vpp_ipsec_t *this,
		      route_entry_t *route)
{
  char *if_name = NULL;
  host_t *dst;

  if (!route->exclude || --route->exclude->refs > 0)
    {
      return;
    }
  this->excludes->remove (this->excludes, route->exclude, NULL);

  dst = route->exclude->dst;
  DBG2 (DBG_KNL, "uninstalling exclude route for %H src %H", dst,
	route->exclude->src);
  if (charon->kernel->get_interface (charon->kernel, route->exclude->src,
				     &if_name) &&
      charon->kernel->del_route (charon->kernel, dst->get_address (dst),
				 dst->get_family (dst) == AF_INET ? 32 : 128,
				 route->exclude->gtw, route->exclude->src,
				 if_name, TRUE) != SUCCESS)
    {
      DBG1 (DBG_KNL, "uninstalling exclude route for %H failed", dst);
    }
  exclude_route_destroy (route->exclude);
  route->exclude = NULL;
  free (if_name);
}

/**
 * Install a route for the given policy
 *
 * this->mutex is released by this function
 */
static bool
install_route (private_kernel_libipsec_vpp_ipsec_t *this, host_t *src,
	       host_t *dst, traffic_selector_t *src_ts,
	       traffic_selector_t *dst_ts, policy_entry_t *policy_in,
	       policy_entry_t *policy_out, uint32_t if_id)
{
  route_entry_t *route, *old;
  host_t *src_ip = NULL;
  bool is_virtual;

  DBG4 (DBG_KNL, "install_route: src: %H, dst: %H, src_ts: %R, dst_ts: %R",
	src, dst, src_ts, dst_ts);
  if (policy_out == NULL)
    {
      this->mutex->unlock (this->mutex);
      return TRUE;
    }

  /* found SA for outbound policy */
  kernel_ipsec_sa_id_t o_key, i_key;
  sa_t *i_sa = NULL, *o_sa = NULL;
  uint32_t sw_if_index_ipip_tun = ~0;

  o_key.src = NULL;
  o_key.dst = NULL;
  i_key.src = NULL;
  i_key.dst = NULL;

  o_key.src = src->clone (src);
  o_key.dst = dst->clone (dst);
  o_key.proto = policy_out->sa.proto;
  o_key.spi = policy_out->sa.spi;
  o_sa = this->sas->get (this->sas, &o_key);

  /* found SA for inbound policy */
  if (policy_in != NULL)
    {
      i_key.src = dst->clone (dst);
      i_key.dst = src->clone (src);
      i_key.proto = policy_in->sa.proto;
      i_key.spi = policy_in->sa.spi;
      i_sa = this->sas->get (this->sas, &i_key);
    }

  /* found exists interface */
  sw_if_index_ipip_tun =
    kernel_libipsec_vpp_get_or_create_tunnel (src, dst, if_id);

  if (i_sa != NULL && o_sa != NULL && sw_if_index_ipip_tun != ~0)
    {
      kernel_libipsec_vpp_tunnel_protect_update (sw_if_index_ipip_tun,
						 i_sa->sa_id, o_sa->sa_id);
    }

  /* clean-up - these variables are not need anymore */
  if (o_key.src)
    o_key.src->destroy (o_key.src);
  if (o_key.dst)
    o_key.dst->destroy (o_key.dst);
  if (i_key.src)
    i_key.src->destroy (i_key.src);
  if (i_key.dst)
    i_key.dst->destroy (i_key.dst);

  /*
  if (charon->kernel->get_address_by_ts (charon->kernel, src_ts, &src_ip,
					 &is_virtual) != SUCCESS)
    {
      traffic_selector_t *multicast, *broadcast = NULL;
      bool ignore = FALSE;

      this->mutex->unlock (this->mutex);
      DBG1 (DBG_KNL, "%s get_address_by_ts 1", __func__);
      switch (src_ts->get_type (src_ts))
	{
	case TS_IPV4_ADDR_RANGE:
	  multicast =
	    traffic_selector_create_from_cidr ("224.0.0.0/4", 0, 0, 0xffff);
	  broadcast = traffic_selector_create_from_cidr ("255.255.255.255/32",
							 0, 0, 0xffff);
	  break;
	case TS_IPV6_ADDR_RANGE:
	  multicast =
	    traffic_selector_create_from_cidr ("ff00::/8", 0, 0, 0xffff);
	  break;
	default:
	  return FALSE;
	}
      ignore = src_ts->is_contained_in (src_ts, multicast);
      ignore |= broadcast && src_ts->is_contained_in (src_ts, broadcast);
      multicast->destroy (multicast);
      DESTROY_IF (broadcast);
      if (!ignore)
	{
	  DBG1 (DBG_KNL, "error installing route with policy %R === %R %N",
		src_ts, dst_ts, policy_dir_names, policy_out->direction);
	}
      return ignore;
    }
    */
  char if_name[64];
  snprintf (if_name, sizeof (if_name), "ipip%u", if_id);

  INIT (route, .if_name = strdup (if_name), .src_ip = src_ip,
	.dst_net =
	  chunk_clone (policy_out->dst.net->get_address (policy_out->dst.net)),
	.prefixlen = policy_out->dst.mask, );
  //#ifndef __linux__
  /* on Linux we can't install a gateway */
  /*route->gateway =
    charon->kernel->get_nexthop (charon->kernel, dst, -1, src, NULL);
    */
  //#endif

  if (policy_out->route)
    {
      old = policy_out->route;

      if (route_entry_equals (old, route))
	{ /* such a route already exists */
	  route_entry_destroy (route);
	  this->mutex->unlock (this->mutex);
	  return TRUE;
	}
      /* uninstall previously installed route */
      /*if (charon->kernel->del_route (charon->kernel, old->dst_net,
				     old->prefixlen, old->gateway, old->src_ip,
				     old->if_name, FALSE) != SUCCESS)*/
      if (0)
	{
	  DBG1 (DBG_KNL,
		"error uninstalling route installed with policy "
		"%R === %R %N",
		src_ts, dst_ts, policy_dir_names, policy_out->direction);
	}
      route_entry_destroy (old);
      policy_out->route = NULL;
    }

  if (!this->allow_peer_ts && dst_ts->is_host (dst_ts, dst))
    {
      DBG1 (DBG_KNL,
	    "can't install route for %R === %R %N, conflicts with "
	    "IKE traffic",
	    src_ts, dst_ts, policy_dir_names, policy_out->direction);
      route_entry_destroy (route);
      this->mutex->unlock (this->mutex);
      return FALSE;
    }
  /* if remote traffic selector covers the IKE peer, add an exclude route */
  if (!this->allow_peer_ts && dst_ts->includes (dst_ts, dst))
    {
      /* add exclude route for peer */
      add_exclude_route (this, route, src, dst);
    }

  switch (charon->kernel->add_route (charon->kernel, route->dst_net,
				     route->prefixlen, NULL, NULL,
				     route->if_name, FALSE))
    {
    case ALREADY_DONE:
      /* route exists, do not uninstall */
      remove_exclude_route (this, route);
      route_entry_destroy (route);
      this->mutex->unlock (this->mutex);
      return TRUE;
    case SUCCESS:
      /* cache the installed route */
      policy_out->route = route;
      this->mutex->unlock (this->mutex);
      return TRUE;
    default:
      DBG1 (DBG_KNL, "installing route failed: %R src %H dev %s", dst_ts,
	    route->src_ip, route->if_name);
      remove_exclude_route (this, route);
      route_entry_destroy (route);
      this->mutex->unlock (this->mutex);
      return FALSE;
    }
}

METHOD (kernel_ipsec_t, add_policy, status_t,
	private_kernel_libipsec_vpp_ipsec_t *this,
	kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
  policy_entry_t *policy, *found = NULL;
  policy_entry_t *policy2, *found2 = NULL;
  policy_entry_t *policy_in = NULL, *policy_out = NULL;
  status_t status;
  host_t *src = NULL, *dst = NULL;
  traffic_selector_t *src_ts = NULL, *dst_ts = NULL;
  uint32_t if_id = id->if_id;
  policy_dir_t dir = POLICY_FWD;

  DBG4 (DBG_KNL, "**** add_policy, SPI: %0x, dir: %s",
	ntohl (data->sa->esp.spi),
	id->dir == POLICY_OUT ?
		"POLICY_OUT" :
		(id->dir == POLICY_IN ? "POLICY_IN" : "POLICY_FWD"));

  /* we track policies in order to install routes */
  policy = create_policy_entry (id->src_ts, id->dst_ts, id->dir);

  this->mutex->lock (this->mutex);
  if (this->policies->find_first (this->policies, policy_entry_equals,
				  (void **) &found, policy))
    {
      policy_entry_destroy (policy);
      policy = found;
    }
  else
    { /* use the new one, if we have no such policy */
      this->policies->insert_last (this->policies, policy);
    }
  policy->refs++;

  /* check if SA is ESP */
  if (data->sa->esp.use == TRUE && data->sa->ah.use == FALSE)
    {
      policy->sa.spi = data->sa->esp.spi;
      policy->sa.proto = IPPROTO_ESP;
    }
  /* check if SA is AH */
  else if (data->sa->esp.use == FALSE && data->sa->ah.use == TRUE)
    {
      policy->sa.spi = data->sa->ah.spi;
      policy->sa.proto = IPPROTO_AH;
    }
  else
    DBG1 (DBG_KNL, "invalid value for protocol !!!");

  if (id->dir != POLICY_FWD)
    {
      if (id->dir == POLICY_IN)
	dir = POLICY_OUT;
      else if (id->dir == POLICY_OUT)
	dir = POLICY_IN;

      policy2 = create_policy_entry (id->dst_ts, id->src_ts, dir);

      if (this->policies->find_first (this->policies, policy_entry_equals,
				      (void **) &found2, policy2))
	{
	  policy_entry_destroy (policy2);
	  policy2 = found2;
	}
      else
	{ /* do not found the second policy */
	  policy_entry_destroy (policy2);
	  policy2 = NULL;
	}

      /* Assigned variables depends on directory the first policy */
      if (id->dir == POLICY_IN)
	{
	  policy_in = policy;
	  policy_out = policy2;
	  src = data->dst;
	  dst = data->src;
	  src_ts = id->dst_ts;
	  dst_ts = id->src_ts;
	}
      else if (id->dir == POLICY_OUT)
	{
	  policy_in = policy2;
	  policy_out = policy;
	  src = data->src;
	  dst = data->dst;
	  src_ts = id->src_ts;
	  dst_ts = id->dst_ts;
	}

      /* Passed arguments always if they will be for outbound policy */
      if (!install_route (this, src, dst, src_ts, dst_ts, policy_in,
			  policy_out, if_id))
	{
	  return FAILED;
	}
    }
  else
    {
      this->mutex->unlock (this->mutex);
    }
  return SUCCESS;
}

METHOD (kernel_ipsec_t, query_policy, status_t,
	private_kernel_libipsec_vpp_ipsec_t *this,
	kernel_ipsec_policy_id_t *id, kernel_ipsec_query_policy_t *data,
	time_t *use_time)
{
  return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, del_policy, status_t,
	private_kernel_libipsec_vpp_ipsec_t *this,
	kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
  policy_entry_t *policy, *found = NULL;
  policy_entry_t *policy_in = NULL, *found_in = NULL;
  status_t status;

  status = SUCCESS;

  DBG1 (DBG_KNL, "**** del_policy, SPI: %0x, dir: %s",
	ntohl (data->sa->esp.spi),
	id->dir == POLICY_OUT ?
		"POLICY_OUT" :
		(id->dir == POLICY_IN ? "POLICY_IN" : "POLICY_FWD"));

  policy = create_policy_entry (id->src_ts, id->dst_ts, id->dir);

  this->mutex->lock (this->mutex);
  if (!this->policies->find_first (this->policies, policy_entry_equals,
				   (void **) &found, policy))
    {
      policy_entry_destroy (policy);
      this->mutex->unlock (this->mutex);
      return status;
    }
  policy_entry_destroy (policy);
  policy = found;

  if (--policy->refs > 0)
    { /* policy is still in use */
      this->mutex->unlock (this->mutex);
      return status;
    }

  /* only [out] policy has this variable */
  if (policy->route)
    {
      /* find [in] policy and also deleted tunnel ipip protect */
      policy_dir_t dir;
      if (id->dir == POLICY_IN)
	dir = POLICY_OUT;
      else if (id->dir == POLICY_OUT)
	dir = POLICY_IN;

      policy_in = create_policy_entry (id->dst_ts, id->src_ts, dir);

      if (this->policies->find_first (this->policies, policy_entry_equals,
				      (void **) &found_in, policy_in))
	{
	  policy_entry_destroy (policy_in);
	  policy_in = found_in;
	}
      else
	{ /* do not found the second policy */
	  policy_entry_destroy (policy_in);
	  policy_in = NULL;
	}

      route_entry_t *route = policy->route;

      if (charon->kernel->del_route (
	    charon->kernel, route->dst_net, route->prefixlen, route->gateway,
	    route->src_ip, route->if_name, FALSE) != SUCCESS)
	{
	  DBG1 (DBG_KNL,
		"error uninstalling route installed with "
		"policy %R === %R %N",
		id->src_ts, id->dst_ts, policy_dir_names, id->dir);
	}
      DBG1 (DBG_KNL,
	    "uninstalling route installed with "
	    "policy %R === %R %N",
	    id->src_ts, id->dst_ts, policy_dir_names, id->dir);

      if (!kernel_libipsec_vpp_delete_tunnel (id->if_id))
	DBG1 (DBG_KNL, "deleted ipip tunnel - failed");

      remove_exclude_route (this, route);
    }
  this->policies->remove (this->policies, policy, NULL);
  policy_entry_destroy (policy);
  this->mutex->unlock (this->mutex);
  return status;
}

METHOD (kernel_ipsec_t, flush_policies, status_t,
	private_kernel_libipsec_vpp_ipsec_t *this)
{
  return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, bypass_socket, bool,
	private_kernel_libipsec_vpp_ipsec_t *this, int fd, int family)
{
  /* we use exclude routes for this */
  return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_libipsec_vpp_ipsec_t *this, int fd, int family,
	uint16_t port)
{
  return NOT_SUPPORTED;
}

METHOD (kernel_ipsec_t, destroy, void,
	private_kernel_libipsec_vpp_ipsec_t *this)
{
  this->policies->destroy_function (this->policies,
				    (void *) policy_entry_destroy);
  this->excludes->destroy (this->excludes);
  this->mutex->destroy (this->mutex);
  if (this->sm)
    {
      stat_segment_disconnect_r (this->sm);
      stat_client_free (this->sm);
      this->sm = NULL;
    }
  free (this);
}

/*
 * Described in header.
 */
kernel_libipsec_vpp_ipsec_t *
kernel_libipsec_vpp_ipsec_create ()
{
  private_kernel_libipsec_vpp_ipsec_t *this;

  INIT(this,
		.public = {
			.interface = {
				.get_features = _get_features,
				.get_spi = _get_spi,
				.get_cpi = _get_cpi,
				.add_sa  = _add_sa,
				.update_sa = _update_sa,
				.query_sa = _query_sa,
				.del_sa = _del_sa,
				.flush_sas = _flush_sas,
				.add_policy = _add_policy,
				.query_policy = _query_policy,
				.del_policy = _del_policy,
				.flush_policies = _flush_policies,
				.bypass_socket = _bypass_socket,
				.enable_udp_decap = _enable_udp_decap,
				.destroy = _destroy,
			},
		},
        .next_sad_id = 0,
        .mutex = mutex_create(MUTEX_TYPE_DEFAULT),
        .policies = linked_list_create(),
        .excludes = linked_list_create(),
        .sas = hashtable_create((hashtable_hash_t)sa_hash,
                (hashtable_equals_t)sa_equals, 32),
        .allow_peer_ts = lib->settings->get_bool(lib->settings,
                        "%s.plugins.kernel-libipsec-vpp.allow_peer_ts", FALSE, lib->ns),
        .sm = NULL,
);

  if (!init_spi (this))
    {
      destroy (this);
      return NULL;
    }

  return &this->public;
};
