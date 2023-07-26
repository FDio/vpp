/*
 * Copyright (c) 2022 Intel and/or its affiliates.
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

#include <utils/debug.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <threading/thread.h>
#include <threading/mutex.h>

#define vl_typedefs
#define vl_endianfun
/* Include the (first) vlib-api API definition layer */
#include <vlibmemory/vl_memory_api_h.h>
/* Include the current layer (third) vpp API definition layer */
#include <vpp/api/vpe_types.api.h>
#include <vpp/api/vpe.api.h>

#include <vnet/ip-neighbor/ip_neighbor.api_enum.h>
#include <vnet/ip-neighbor/ip_neighbor.api_types.h>
#include <vnet/ip/ip.api_enum.h>
#include <vnet/ip/ip.api_types.h>
#include <vnet/interface.api_enum.h>
#include <vnet/interface.api_types.h>
#undef vl_typedefs
#undef vl_endianfun

#include "kernel_vpp_net.h"
#include "kernel_vpp_shared.h"

typedef struct private_kernel_vpp_net_t private_kernel_vpp_net_t;

/**
 * Private data of kernel_vpp_net implementation.
 */
struct private_kernel_vpp_net_t
{

  /**
   * Public interface.
   */
  kernel_vpp_net_t public;

  /**
   * Mutex to access interface list
   */
  mutex_t *mutex;

  /**
   * Known interfaces, as iface_t
   */
  linked_list_t *ifaces;

  /**
   * Inteface update thread
   */
  thread_t *net_update;

  /**
   * TRUE if interface events enabled
   */
  bool events_on;
};

/**
 * Interface entry
 */
typedef struct
{
  /** interface index */
  uint32_t index;
  /** interface name */
  char if_name[64];
  /** list of known addresses, as host_t */
  linked_list_t *addrs;
  /** TRUE if up */
  bool up;
} iface_t;

/**
 * Address enumerator
 */
typedef struct
{
  /** implements enumerator_t */
  enumerator_t public;
  /** what kind of address should we enumerate? */
  kernel_address_type_t which;
  /** enumerator over interfaces */
  enumerator_t *ifaces;
  /** current enumerator over addresses, or NULL */
  enumerator_t *addrs;
  /** mutex to unlock on destruction */
  mutex_t *mutex;
} addr_enumerator_t;

/**
 * FIB path entry
 */
typedef struct
{
  chunk_t next_hop;
  uint32_t sw_if_index;
  uint8_t preference;
} fib_path_t;

/**
 * Get an iface entry for a local address
 */
static iface_t *
address2entry (private_kernel_vpp_net_t *this, host_t *ip)
{
  enumerator_t *ifaces, *addrs;
  iface_t *entry, *found = NULL;
  host_t *host;

  ifaces = this->ifaces->create_enumerator (this->ifaces);
  while (!found && ifaces->enumerate (ifaces, &entry))
    {
      addrs = entry->addrs->create_enumerator (entry->addrs);
      while (!found && addrs->enumerate (addrs, &host))
	{
	  if (host->ip_equals (host, ip))
	    {
	      found = entry;
	    }
	}
      addrs->destroy (addrs);
    }
  ifaces->destroy (ifaces);

  return found;
}

/**
 * Add or remove a route
 */
static status_t
manage_route (private_kernel_vpp_net_t *this, bool add, chunk_t dst,
	      uint8_t prefixlen, host_t *gtw, char *name)
{
  char *out;
  int out_len;
  enumerator_t *enumerator;
  iface_t *entry;
  vl_api_ip_route_add_del_t *mp;
  vl_api_ip_route_add_del_reply_t *rmp;
  vl_api_fib_path_t *apath;
  bool exists = FALSE;

  for (int i = 0; i < N_RETRY_GET_IF; i++)
    {
      this->mutex->lock (this->mutex);
      enumerator = this->ifaces->create_enumerator (this->ifaces);
      while (enumerator->enumerate (enumerator, &entry))
	{
	  if (streq (name, entry->if_name))
	    {
	      exists = TRUE;
	      break;
	    }
	}
      enumerator->destroy (enumerator);
      this->mutex->unlock (this->mutex);

      if (!exists)
	{
	  DBG1 (DBG_NET, "if_name %s not found", name);
	  sleep (1);
	}
      else
	break;
    }

  if (!exists)
    {
      DBG1 (DBG_NET, "if_name %s not found", name);
      return NOT_FOUND;
    }

  mp = vl_msg_api_alloc (sizeof (*mp) + sizeof (*apath));
  memset (mp, 0, sizeof (*mp) + sizeof (*apath));
  u16 msg_id = vl_msg_api_get_msg_index ((u8 *) "ip_route_add_del_b8ecfe0d");
  mp->_vl_msg_id = ntohs (msg_id);
  mp->is_add = add;
  mp->route.prefix.len = prefixlen;
  mp->route.n_paths = 1;
  apath = &mp->route.paths[0];
  apath->sw_if_index = ntohl (entry->index);
  apath->rpf_id = ~0;
  apath->weight = 1;
  switch (dst.len)
    {
    case 4:
      mp->route.prefix.address.af = ntohl (ADDRESS_IP4);
      memcpy (&mp->route.prefix.address.un.ip4, dst.ptr, dst.len);
      if (gtw)
	{
	  chunk_t addr = gtw->get_address (gtw);
	  apath->proto = ntohl (FIB_API_PATH_NH_PROTO_IP4);
	  memcpy (&apath->nh.address.ip4, addr.ptr, dst.len);
	}
      break;
    case 16:
      mp->route.prefix.address.af = ntohl (ADDRESS_IP6);
      memcpy (&mp->route.prefix.address.un.ip6, dst.ptr, dst.len);
      if (gtw)
	{
	  chunk_t addr = gtw->get_address (gtw);
	  apath->proto = ntohl (FIB_API_PATH_NH_PROTO_IP6);
	  memcpy (&apath->nh.address.ip6, addr.ptr, dst.len);
	}
      break;
    default:
      vl_msg_api_free (mp);
      return FAILED;
    }

  if (vac->send (vac, (char *) mp, sizeof (*mp) + sizeof (*apath), &out,
		 &out_len))
    {
      DBG1 (DBG_KNL, "vac %sing route failed", add ? "add" : "remov");
      vl_msg_api_free (mp);
      return FAILED;
    }
  rmp = (void *) out;
  vl_msg_api_free (mp);
  if (rmp->retval)
    {
      DBG1 (DBG_KNL, "%s route failed %d", add ? "add" : "delete",
	    ntohl (rmp->retval));
      free (out);
      return FAILED;
    }
  free (out);
  return SUCCESS;
}

/**
 * Check if an address or net (addr with prefix net bits) is in
 * subnet (net with net_len net bits)
 */
static bool
addr_in_subnet (chunk_t addr, int prefix, chunk_t net, int net_len)
{
  static const u_char mask[] = {
    0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe
  };
  int byte = 0;

  if (net_len == 0)
    { /* any address matches a /0 network */
      return TRUE;
    }
  if (addr.len != net.len || net_len > 8 * net.len || prefix < net_len)
    {
      return FALSE;
    }
  /* scan through all bytes in network order */
  while (net_len > 0)
    {
      if (net_len < 8)
	{
	  return (mask[net_len] & addr.ptr[byte]) ==
		 (mask[net_len] & net.ptr[byte]);
	}
      else
	{
	  if (addr.ptr[byte] != net.ptr[byte])
	    {
	      return FALSE;
	    }
	  byte++;
	  net_len -= 8;
	}
    }
  return TRUE;
}

/**
 * Get a route: If "nexthop" the nexthop is returned, source addr otherwise
 */
static host_t *
get_route (private_kernel_vpp_net_t *this, host_t *dest, int prefix,
	   bool nexthop, char **iface, host_t *src)
{
  fib_path_t path;
  char *out, *tmp;
  int out_len, i, num;
  vl_api_fib_path_t *fp;
  host_t *addr = NULL;
  enumerator_t *enumerator;
  iface_t *entry;
  int family;

  path.sw_if_index = ~0;
  path.preference = ~0;
  path.next_hop = chunk_empty;

  vl_api_ip_route_dump_t *mp;
  vl_api_ip_route_details_t *rmp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  u16 msg_id = vl_msg_api_get_msg_index ((u8 *) "ip_route_dump_b9d2e09e");
  mp->_vl_msg_id = htons (msg_id);
  mp->table.is_ip6 = dest->get_family (dest) == AF_INET6 ? 1 : 0;
  if (vac->send_dump (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      vl_msg_api_free (mp);
      DBG2 (DBG_KNL, "send VL_API_IP_ROUTE_ADD_DEL failed");
      return NULL;
    }
  vl_msg_api_free (mp);

  if (dest->get_family (dest) == AF_INET)
    {
      i = 0;
      family = AF_INET;
      if (prefix == -1)
	prefix = 32;

      tmp = out;
      while (tmp < (out + out_len))
	{
	  rmp = (void *) tmp;
	  num = rmp->route.n_paths;

	  if (rmp->route.prefix.len &&
	      addr_in_subnet (
		dest->get_address (dest), prefix,
		chunk_create (rmp->route.prefix.address.un.ip4, 4),
		rmp->route.prefix.len))
	    {
	      fp = rmp->route.paths;
	      for (i = 0; i < num; i++)
		{
#define IS_IP4_ANY(a) (a[0] == 0 && a[1] == 0 && a[2] == 0 & a[3] == 0)
		  if (fp->type == FIB_API_PATH_TYPE_DROP)
		    {
		      fp++;
		      continue;
		    }
		  if ((fp->preference < path.preference) ||
		      (path.sw_if_index == ~0) ||
		      IS_IP4_ANY (path.next_hop.ptr))
		    {
		      path.sw_if_index = ntohl (fp->sw_if_index);
		      path.preference = fp->preference;
		      if (path.next_hop.ptr)
			vl_msg_api_free (path.next_hop.ptr);
		      path.next_hop = chunk_create (fp->nh.address.ip4, 4);
		    }
		  fp++;
		}
	    }
	  tmp += sizeof (*rmp) + (sizeof (*fp) * num);
	}
    }
  else
    {
      DBG1 (DBG_KNL, "not yet support ip6");
      return NULL;
    }

  if (path.next_hop.len)
    {
      if (nexthop)
	{
	  if (iface)
	    {
	      *iface = NULL;
	      this->mutex->lock (this->mutex);
	      enumerator = this->ifaces->create_enumerator (this->ifaces);
	      while (enumerator->enumerate (enumerator, &entry))
		{
		  if (entry->index == path.sw_if_index)
		    {
		      *iface = strdup (entry->if_name);
		      break;
		    }
		}
	      enumerator->destroy (enumerator);
	      this->mutex->unlock (this->mutex);
	    }
	  addr = host_create_from_chunk (family, path.next_hop, 0);
	}
      else
	{
	  if (src)
	    {
	      addr = src->clone (src);
	    }
	}
    }

  free (out);

  return addr;
}

METHOD (enumerator_t, addr_enumerate, bool, addr_enumerator_t *this,
	va_list args)
{
  iface_t *entry;
  host_t **host;

  VA_ARGS_VGET (args, host);

  while (TRUE)
    {
      while (!this->addrs)
	{
	  if (!this->ifaces->enumerate (this->ifaces, &entry))
	    {
	      return FALSE;
	    }
	  if (!entry->up && !(this->which & ADDR_TYPE_DOWN))
	    {
	      continue;
	    }
	  this->addrs = entry->addrs->create_enumerator (entry->addrs);
	}
      if (this->addrs->enumerate (this->addrs, host))
	{
	  return TRUE;
	}
      this->addrs->destroy (this->addrs);
      this->addrs = NULL;
    }
}

METHOD (enumerator_t, addr_destroy, void, addr_enumerator_t *this)
{
  DESTROY_IF (this->addrs);
  this->ifaces->destroy (this->ifaces);
  this->mutex->unlock (this->mutex);
  free (this);
}

METHOD (kernel_net_t, get_interface_name, bool, private_kernel_vpp_net_t *this,
	host_t *ip, char **name)
{
  iface_t *entry;

  this->mutex->lock (this->mutex);
  entry = address2entry (this, ip);
  if (entry && name)
    {
      *name = strdup (entry->if_name);
    }
  this->mutex->unlock (this->mutex);

  return entry != NULL;
}

METHOD (kernel_net_t, create_address_enumerator, enumerator_t *,
	private_kernel_vpp_net_t *this, kernel_address_type_t which)
{
  addr_enumerator_t *enumerator;

  if (!(which & ADDR_TYPE_REGULAR))
    {
      /* we currently have no virtual, but regular IPs only */
      return enumerator_create_empty ();
    }

  this->mutex->lock (this->mutex);

  INIT(enumerator,
        .public = {
            .enumerate = enumerator_enumerate_default,
            .venumerate = _addr_enumerate,
            .destroy = _addr_destroy,
        },
        .which = which,
        .ifaces = this->ifaces->create_enumerator(this->ifaces),
        .mutex = this->mutex,
    );
  return &enumerator->public;
}

METHOD (kernel_net_t, get_source_addr, host_t *,
	private_kernel_vpp_net_t *this, host_t *dest, host_t *src)
{
  return get_route (this, dest, -1, FALSE, NULL, src);
}

METHOD (kernel_net_t, get_nexthop, host_t *, private_kernel_vpp_net_t *this,
	host_t *dest, int prefix, host_t *src, char **iface)
{
  return get_route (this, dest, prefix, TRUE, iface, src);
}

METHOD (kernel_net_t, add_ip, status_t, private_kernel_vpp_net_t *this,
	host_t *virtual_ip, int prefix, char *iface_name)
{
  return NOT_SUPPORTED;
}

METHOD (kernel_net_t, del_ip, status_t, private_kernel_vpp_net_t *this,
	host_t *virtual_ip, int prefix, bool wait)
{
  return NOT_SUPPORTED;
}

METHOD (kernel_net_t, add_route, status_t, private_kernel_vpp_net_t *this,
	chunk_t dst_net, u_int8_t prefixlen, host_t *gateway, host_t *src_ip,
	char *if_name)
{
  return manage_route (this, TRUE, dst_net, prefixlen, gateway, if_name);
}

METHOD (kernel_net_t, del_route, status_t, private_kernel_vpp_net_t *this,
	chunk_t dst_net, u_int8_t prefixlen, host_t *gateway, host_t *src_ip,
	char *if_name)
{
  return manage_route (this, FALSE, dst_net, prefixlen, gateway, if_name);
}

static void
iface_destroy (iface_t *this)
{
  this->addrs->destroy_offset (this->addrs, offsetof (host_t, destroy));
  free (this);
}

METHOD (kernel_net_t, destroy, void, private_kernel_vpp_net_t *this)
{
  this->net_update->cancel (this->net_update);
  this->mutex->destroy (this->mutex);
  this->ifaces->destroy_function (this->ifaces, (void *) iface_destroy);
  free (this);
}

/**
 * Update addresses for an iface entry
 */
static void
update_addrs (private_kernel_vpp_net_t *this, iface_t *entry)
{
  char *out;
  int out_len, i, num;
  vl_api_ip_address_dump_t *mp;
  vl_api_ip_address_details_t *rmp, *tmp;
  linked_list_t *addrs;
  host_t *host;
  enumerator_t *enumerator;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  u16 msg_id = vl_msg_api_get_msg_index ((u8 *) "ip_address_dump_2d033de4");
  mp->_vl_msg_id = htons (msg_id);
  mp->sw_if_index = htonl (entry->index);
  mp->is_ipv6 = 0;
  if (vac->send_dump (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG2 (DBG_NET, "update_addrs : send VL_API_IP_ADDRESS_DUMP ipv4 failed");
      vl_msg_api_free (mp);
      return;
    }
  num = out_len / sizeof (*rmp);
  addrs = linked_list_create ();
  tmp = (vl_api_ip_address_details_t *) out;
  for (i = 0; i < num; i++)
    {
      rmp = tmp;
      tmp += 1;
      host = host_create_from_chunk (
	AF_INET, chunk_create (rmp->prefix.address.un.ip4, 4), 0);
      addrs->insert_last (addrs, host);
    }
  free (out);

  mp->is_ipv6 = 1;
  if (vac->send_dump (vac, (char *) mp, sizeof (*mp), &out, &out_len))
    {
      DBG2 (DBG_NET, "update_addrs : send VL_API_IP_ADDRESS_DUMP ipv6 failed");
      vl_msg_api_free (mp);
      return;
    }
  num = out_len / sizeof (*rmp);
  tmp = (vl_api_ip_address_details_t *) out;
  for (i = 0; i < num; i++)
    {
      rmp = tmp;
      tmp += 1;
      host = host_create_from_chunk (
	AF_INET6, chunk_create (rmp->prefix.address.un.ip6, 16), 0);
      addrs->insert_last (addrs, host);
    }
  vl_msg_api_free (mp);
  free (out);

  /* clean-up */
  enumerator = entry->addrs->create_enumerator (entry->addrs);
  while (enumerator->enumerate (enumerator, &host))
    {
      host->destroy (host);
    }
  enumerator->destroy (enumerator);
  entry->addrs->destroy (entry->addrs);
  entry->addrs =
    linked_list_create_from_enumerator (addrs->create_enumerator (addrs));
  addrs->destroy (addrs);
}

/**
 * VPP API interface event callback
 */
static void
event_cb (char *data, int data_len, void *ctx)
{
  private_kernel_vpp_net_t *this = ctx;
  vl_api_sw_interface_event_t *event;
  vl_api_if_status_flags_t flags;
  iface_t *entry;
  enumerator_t *enumerator;

  event = (void *) data;
  this->mutex->lock (this->mutex);
  enumerator = this->ifaces->create_enumerator (this->ifaces);
  while (enumerator->enumerate (enumerator, &entry))
    {
      if (entry->index == ntohl (event->sw_if_index))
	{
	  flags = ntohl (event->flags);
	  if (event->deleted)
	    {
	      this->ifaces->remove_at (this->ifaces, enumerator);
	      DBG2 (DBG_NET, "interface deleted %u %s", entry->index,
		    entry->if_name);
	      iface_destroy (entry);
	    }
	  else if (entry->up != (flags & IF_STATUS_API_FLAG_LINK_UP))
	    {
	      entry->up = (flags & IF_STATUS_API_FLAG_LINK_UP) ? TRUE : FALSE;
	      DBG2 (DBG_NET, "interface state changed %u %s %s", entry->index,
		    entry->if_name, entry->up ? "UP" : "DOWN");
	    }
	  break;
	}
    }
  enumerator->destroy (enumerator);
  this->mutex->unlock (this->mutex);
}

/**
 * Inteface update thread (update interface list and interface address)
 */
static void *
net_update_thread_fn (private_kernel_vpp_net_t *this)
{
  status_t rv;
  while (1)
    {
      char *out;
      int out_len;
      vl_api_sw_interface_dump_t *mp;
      vl_api_sw_interface_details_t *rmp;
      enumerator_t *enumerator;
      iface_t *entry;

      mp = vl_msg_api_alloc (sizeof (*mp));
      memset (mp, 0, sizeof (*mp));
      u16 msg_id =
	vl_msg_api_get_msg_index ((u8 *) "sw_interface_dump_aa610c27");
      mp->_vl_msg_id = htons (msg_id);
      mp->name_filter_valid = 0;
      rv = vac->send_dump (vac, (u8 *) mp, sizeof (*mp), &out, &out_len);
      if (!rv)
	{
	  int i, num;
	  this->mutex->lock (this->mutex);
	  enumerator = this->ifaces->create_enumerator (this->ifaces);
	  num = out_len / sizeof (*rmp);
	  rmp = (vl_api_sw_interface_details_t *) out;
	  for (i = 0; i < num; i++)
	    {
	      bool exists = FALSE;
	      if (i)
		rmp += 1;
	      while (enumerator->enumerate (enumerator, &entry))
		{
		  if (entry->index == ntohl (rmp->sw_if_index))
		    {
		      exists = TRUE;
		      break;
		    }
		}
	      if (!exists)
		{
		  INIT (entry, .index = ntohl (rmp->sw_if_index),
			.up = (rmp->flags & IF_STATUS_API_FLAG_LINK_UP) ?
				      TRUE :
				      FALSE,
			.addrs = linked_list_create (), );
		  memcpy (entry->if_name, rmp->interface_name, 63);
		  this->ifaces->insert_last (this->ifaces, entry);
		}
	      update_addrs (this, entry);
	    }
	  enumerator->destroy (enumerator);
	  this->mutex->unlock (this->mutex);
	  free (out);
	}
      vl_msg_api_free (mp);

      if (!this->events_on)
	{
	  vl_api_want_interface_events_t *emp;
	  api_main_t *am = vlibapi_get_main ();

	  emp = vl_msg_api_alloc (sizeof (*emp));
	  clib_memset (emp, 0, sizeof (*emp));
	  u16 msg_id =
	    vl_msg_api_get_msg_index ((u8 *) "want_interface_events_476f5a08");
	  emp->_vl_msg_id = ntohs (msg_id);
	  emp->enable_disable = 1;
	  emp->pid = ntohl (am->our_pid);
	  u16 msg_id_sw_interface_event =
	    vl_msg_api_get_msg_index ((u8 *) "sw_interface_event_2d3d95a7");
	  rv = vac->register_event (vac, (char *) emp, sizeof (*emp), event_cb,
				    msg_id_sw_interface_event, this);
	  if (!rv)
	    this->events_on = TRUE;
	}

      sleep (2);
    }
  return NULL;
}

kernel_vpp_net_t *
kernel_vpp_net_create ()
{
  private_kernel_vpp_net_t *this;

  INIT(this,
        .public = {
            .interface = {
                .get_interface = _get_interface_name,
                .create_address_enumerator = _create_address_enumerator,
                .get_source_addr = _get_source_addr,
                .get_nexthop = _get_nexthop,
                .add_ip = _add_ip,
                .del_ip = _del_ip,
                .add_route = _add_route,
                .del_route = _del_route,
                .destroy = _destroy,
            },
        },
        .mutex = mutex_create(MUTEX_TYPE_DEFAULT),
        .ifaces = linked_list_create(),
        .events_on = FALSE,
    );

  this->net_update =
    thread_create ((thread_main_t) net_update_thread_fn, this);

  return &this->public;
}
