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

#include <vnet/dns/dns.h>

#include <vnet/vnet.h>
#include <vnet/fib/fib.h>
#include <vlibmemory/api.h>

#include <vnet/udp/udp.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

dns_main_t dns_main;

static int
dns_cache_clear (dns_main_t * dm)
{
  dns_cache_entry_t *ep;

  if (dm->is_enabled == 0)
    return VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED;

  dns_cache_lock (dm);

  /* *INDENT-OFF* */
  pool_foreach (ep, dm->entries,
  ({
    vec_free (ep->name);
    vec_free (ep->api_clients_to_notify);
    vec_free (ep->api_client_contexts);
    vec_free (ep->ip4_peers_to_notify);
    vec_free (ep->ip6_peers_to_notify);
  }));
  /* *INDENT-ON* */

  pool_free (dm->entries);
  hash_free (dm->cache_entry_by_name);
  dm->cache_entry_by_name = hash_create_string (0, sizeof (uword));
  vec_free (dm->unresolved_entries);
  dns_cache_unlock (dm);
  return 0;
}

static int
dns_enable_disable (dns_main_t * dm, int is_enable)
{
  vlib_thread_main_t *tm = &vlib_thread_main;
  u32 n_vlib_mains = tm->n_vlib_mains;

  if (is_enable)
    {
      if (vec_len (dm->ip4_name_servers) == 0
	  && (vec_len (dm->ip6_name_servers) == 0))
	return VNET_API_ERROR_NO_NAME_SERVERS;

      if (dm->cache_entry_by_name == 0)
	{
	  if (n_vlib_mains > 1)
	    dm->cache_lock = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
						     CLIB_CACHE_LINE_BYTES);

	  dm->cache_entry_by_name = hash_create_string (0, sizeof (uword));
	}

      dm->is_enabled = 1;
    }
  else
    {
      dns_cache_clear (dm);
      dm->is_enabled = 0;
    }
  return 0;
}

static void vl_api_dns_enable_disable_t_handler
  (vl_api_dns_enable_disable_t * mp)
{
  vl_api_dns_enable_disable_reply_t *rmp;
  dns_main_t *dm = &dns_main;
  int rv;

  rv = dns_enable_disable (dm, mp->enable);

  REPLY_MACRO (VL_API_DNS_ENABLE_DISABLE_REPLY);
}

static int
dns6_name_server_add_del (dns_main_t * dm,
			  u8 * server_address_as_u8, int is_add)
{
  int i;
  ip6_address_t *ap;

  if (is_add)
    {
      /* Already there? done... */
      for (i = 0; i < vec_len (dm->ip6_name_servers); i++)
	{
	  if (!memcmp (dm->ip6_name_servers + i, server_address_as_u8,
		       sizeof (ip6_address_t)))
	    return 0;
	}

      vec_add2 (dm->ip6_name_servers, ap, 1);
      clib_memcpy (ap, server_address_as_u8, sizeof (*ap));
    }
  else
    {
      for (i = 0; i < vec_len (dm->ip6_name_servers); i++)
	{
	  if (!memcmp (dm->ip6_name_servers + i, server_address_as_u8,
		       sizeof (ip6_address_t)))
	    {
	      vec_delete (dm->ip6_name_servers, 1, i);
	      return 0;
	    }
	}
      return VNET_API_ERROR_NAME_SERVER_NOT_FOUND;
    }
  return 0;
}

static int
dns4_name_server_add_del (dns_main_t * dm,
			  u8 * server_address_as_u8, int is_add)
{
  int i;
  ip4_address_t *ap;

  if (is_add)
    {
      /* Already there? done... */
      for (i = 0; i < vec_len (dm->ip4_name_servers); i++)
	{
	  if (!memcmp (dm->ip4_name_servers + i, server_address_as_u8,
		       sizeof (ip4_address_t)))
	    return 0;
	}

      vec_add2 (dm->ip4_name_servers, ap, 1);
      clib_memcpy (ap, server_address_as_u8, sizeof (*ap));
    }
  else
    {
      for (i = 0; i < vec_len (dm->ip4_name_servers); i++)
	{
	  if (!memcmp (dm->ip4_name_servers + i, server_address_as_u8,
		       sizeof (ip4_address_t)))
	    {
	      vec_delete (dm->ip4_name_servers, 1, i);
	      return 0;
	    }
	}
      return VNET_API_ERROR_NAME_SERVER_NOT_FOUND;
    }
  return 0;
}

static void vl_api_dns_name_server_add_del_t_handler
  (vl_api_dns_name_server_add_del_t * mp)
{
  dns_main_t *dm = &dns_main;
  vl_api_dns_name_server_add_del_reply_t *rmp;
  int rv;

  if (mp->is_ip6)
    rv = dns6_name_server_add_del (dm, mp->server_address, mp->is_add);
  else
    rv = dns4_name_server_add_del (dm, mp->server_address, mp->is_add);

  REPLY_MACRO (VL_API_DNS_NAME_SERVER_ADD_DEL_REPLY);
}

static void
send_dns4_request (dns_main_t * dm,
		   dns_cache_entry_t * ep, ip4_address_t * server)
{
  vlib_main_t *vm = dm->vlib_main;
  f64 now = vlib_time_now (vm);
  u32 bi;
  vlib_buffer_t *b;
  ip4_header_t *ip;
  fib_prefix_t prefix;
  fib_node_index_t fei;
  u32 sw_if_index, fib_index;
  udp_header_t *udp;
  ip4_main_t *im4 = &ip4_main;
  ip_lookup_main_t *lm4 = &im4->lookup_main;
  ip_interface_address_t *ia = 0;
  ip4_address_t *src_address;
  u8 *dns_request;
  vlib_frame_t *f;
  u32 *to_next;

  ASSERT (ep->dns_request);

  /* Find a FIB path to the server */
  clib_memcpy (&prefix.fp_addr.ip4, server, sizeof (*server));
  prefix.fp_proto = FIB_PROTOCOL_IP4;
  prefix.fp_len = 32;

  fib_index = fib_table_find (prefix.fp_proto, 0 /* default VRF for now */ );
  if (fib_index == (u32) ~ 0)
    {
      clib_warning ("no fib table");
      return;
    }

  fei = fib_table_lookup (fib_index, &prefix);

  /* Couldn't find route to destination. Bail out. */
  if (fei == FIB_NODE_INDEX_INVALID)
    {
      clib_warning ("no route to DNS server");
      return;
    }

  sw_if_index = fib_entry_get_resolving_interface (fei);

  if (sw_if_index == ~0)
    {
      clib_warning
	("route to %U exists, fei %d, get_resolving_interface returned"
	 " ~0", fei, format_ip4_address, &prefix.fp_addr);
      return;
    }

  /* *INDENT-OFF* */
  foreach_ip_interface_address(lm4, ia, sw_if_index, 1 /* honor unnummbered */,
  ({
    src_address = ip_interface_address_get_address (lm4, ia);
    goto found_src_address;
  }));
  /* *INDENT-ON* */

  clib_warning ("FIB BUG");
  return;

found_src_address:

  /* Go get a buffer */
  if (vlib_buffer_alloc (dm->vlib_main, &bi, 1) != 1)
    return;

  b = vlib_get_buffer (vm, bi);
  b->current_length = sizeof (ip4_header_t) + sizeof (udp_header_t) +
    vec_len (ep->dns_request);
  b->total_length_not_including_first_buffer = 0;
  b->flags =
    VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_LOCALLY_ORIGINATED;
  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;	/* "local0" */
  vnet_buffer (b)->sw_if_index[VLIB_TX] = 0;	/* default VRF for now */

  ip = vlib_buffer_get_current (b);
  memset (ip, 0, sizeof (*ip));
  udp = (udp_header_t *) (ip + 1);
  memset (udp, 0, sizeof (*udp));

  dns_request = (u8 *) (udp + 1);

  /* IP header */
  ip->ip_version_and_header_length = 0x45;
  ip->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b));
  ip->ttl = 255;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = src_address->as_u32;
  ip->dst_address.as_u32 = server->as_u32;
  ip->checksum = ip4_header_checksum (ip);

  /* UDP header */
  udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_dns_reply);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_dns);
  udp->length = clib_host_to_net_u16 (sizeof (udp_header_t) +
				      vec_len (ep->dns_request));
  udp->checksum = 0;

  /* The actual DNS request */
  clib_memcpy (dns_request, ep->dns_request, vec_len (ep->dns_request));

  /* Ship it to ip4_lookup */
  f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);

  ep->retry_timer = now + 2.0;
}

static void
send_dns6_request (dns_main_t * dm,
		   dns_cache_entry_t * ep, ip6_address_t * server)
{
  vlib_main_t *vm = dm->vlib_main;
  f64 now = vlib_time_now (vm);
  u32 bi;
  vlib_buffer_t *b;
  ip6_header_t *ip;
  fib_prefix_t prefix;
  fib_node_index_t fei;
  u32 sw_if_index, fib_index;
  udp_header_t *udp;
  ip6_main_t *im6 = &ip6_main;
  ip_lookup_main_t *lm6 = &im6->lookup_main;
  ip_interface_address_t *ia = 0;
  ip6_address_t *src_address;
  u8 *dns_request;
  vlib_frame_t *f;
  u32 *to_next;
  int junk __attribute__ ((unused));

  ASSERT (ep->dns_request);

  /* Find a FIB path to the server */
  clib_memcpy (&prefix.fp_addr, server, sizeof (*server));
  prefix.fp_proto = FIB_PROTOCOL_IP6;
  prefix.fp_len = 32;

  fib_index = fib_table_find (prefix.fp_proto, 0 /* default VRF for now */ );
  if (fib_index == (u32) ~ 0)
    {
      clib_warning ("no fib table");
      return;
    }

  fei = fib_table_lookup (fib_index, &prefix);

  /* Couldn't find route to destination. Bail out. */
  if (fei == FIB_NODE_INDEX_INVALID)
    {
      clib_warning ("no route to DNS server");
    }

  sw_if_index = fib_entry_get_resolving_interface (fei);

  /* *INDENT-OFF* */
  foreach_ip_interface_address(lm6, ia, sw_if_index, 1 /* honor unnummbered */,
  ({
    src_address = ip_interface_address_get_address (lm6, ia);
    goto found_src_address;
  }));
  /* *INDENT-ON* */

  clib_warning ("FIB BUG");
  return;

found_src_address:

  /* Go get a buffer */
  if (vlib_buffer_alloc (dm->vlib_main, &bi, 1) != 1)
    return;

  b = vlib_get_buffer (vm, bi);
  b->current_length = sizeof (ip6_header_t) + sizeof (udp_header_t) +
    vec_len (ep->dns_request);
  b->total_length_not_including_first_buffer = 0;
  b->flags =
    VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_LOCALLY_ORIGINATED;

  ip = vlib_buffer_get_current (b);
  memset (ip, 0, sizeof (*ip));
  udp = (udp_header_t *) (ip + 1);
  memset (udp, 0, sizeof (*udp));

  dns_request = (u8 *) (udp + 1);

  /* IP header */
  ip->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x6 << 28);

  ip->payload_length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b)
			  - sizeof (ip6_header_t));
  ip->hop_limit = 255;
  ip->protocol = IP_PROTOCOL_UDP;
  clib_memcpy (&ip->src_address, src_address, sizeof (ip6_address_t));
  clib_memcpy (&ip->dst_address, server, sizeof (ip6_address_t));

  /* UDP header */
  udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_dns_reply);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_dns);
  udp->length = clib_host_to_net_u16 (sizeof (udp_header_t) +
				      vec_len (ep->dns_request));
  udp->checksum = 0;
  udp->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip, &junk);

  /* The actual DNS request */
  clib_memcpy (dns_request, ep->dns_request, vec_len (ep->dns_request));

  /* Ship it to ip6_lookup */
  f = vlib_get_frame_to_node (vm, ip6_lookup_node.index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;

  ep->retry_timer = now + 2.0;
}

/**
 * Translate "foo.com" into "0x3 f o o 0x3 c o m 0x0"
 * A historical / hysterical micro-TLV scheme. DGMS.
 */
u8 *
name_to_labels (u8 * name)
{
  int i;
  int last_label_index;
  u8 *rv;

  rv = vec_dup (name);

  /* punch in space for the first length */
  vec_insert (rv, 1, 0);
  last_label_index = 0;
  i = 1;

  while (i < vec_len (rv))
    {
      if (rv[i] == '.')
	{
	  rv[last_label_index] = (i - last_label_index) - 1;
	  if ((i - last_label_index) > 63)
	    clib_warning ("stupid name, label length %d",
			  i - last_label_index);
	  last_label_index = i;
	  rv[i] = 0;
	}
      i++;
    }
  /* Set the last real label length */
  rv[last_label_index] = (i - last_label_index) - 1;

  /*
   * Add a [sic] NULL root label. Otherwise, the name parser can't figure out
   * where to stop.
   */
  vec_add1 (rv, 0);
  return rv;
}

/**
 * arc-function for the above.
 * Translate "0x3 f o o 0x3 c o m 0x0" into "foo.com"
 * Produces a non-NULL-terminated u8 *vector. %v format is your friend.
 */
u8 *
labels_to_name (u8 * label, u8 * full_text, u8 ** parse_from_here)
{
  u8 *reply = 0;
  u16 offset;
  u8 len;
  int i;

  *parse_from_here = 0;

  /* chase initial pointer? */
  if ((label[0] & 0xC0) == 0xC0)
    {
      *parse_from_here = label + 2;
      offset = ((label[0] & 0x3f) << 8) + label[1];
      label = full_text + offset;
    }

  len = *label++;

  while (len)
    {
      for (i = 0; i < len; i++)
	vec_add1 (reply, *label++);

      /* chase pointer? */
      if ((label[0] & 0xC0) == 0xC0)
	{
	  *parse_from_here = label + 2;
	  offset = ((label[0] & 0x3f) << 8) + label[1];
	  label = full_text + offset;
	}

      len = *label++;
      if (len)
	vec_add1 (reply, '.');
    }
  if (*parse_from_here == 0)
    *parse_from_here = label;
  return reply;
}

void
vnet_send_dns_request (dns_main_t * dm, dns_cache_entry_t * ep)
{
  dns_header_t *h;
  dns_query_t *qp;
  u16 tmp;
  u8 *request;
  u32 qp_offset;

  /* Construct the dns request, if we haven't been here already */
  if (vec_len (ep->dns_request) == 0)
    {
      /*
       * Start with the variadic portion of the exercise.
       * Turn the name into a set of DNS "labels". Max length
       * per label is 63, enforce that.
       */
      request = name_to_labels (ep->name);
      qp_offset = vec_len (request);

      /* Add space for the query header */
      vec_validate (request, qp_offset + sizeof (dns_query_t) - 1);

      qp = (dns_query_t *) (request + qp_offset);

      qp->type = clib_host_to_net_u16 (DNS_TYPE_ALL);
      qp->class = clib_host_to_net_u16 (DNS_CLASS_IN);

      /* Punch in space for the dns_header_t */
      vec_insert (request, sizeof (dns_header_t), 0);

      h = (dns_header_t *) request;

      /* Transaction ID = pool index */
      h->id = clib_host_to_net_u16 (ep - dm->entries);

      /* Ask for a recursive lookup */
      tmp = DNS_RD | DNS_OPCODE_QUERY;
      h->flags = clib_host_to_net_u16 (tmp);
      h->qdcount = clib_host_to_net_u16 (1);
      h->nscount = 0;
      h->arcount = 0;

      ep->dns_request = request;
    }

  /* Work out which server / address family we're going to use */

  /* Retry using current server */
  if (ep->retry_count++ < DNS_RETRIES_PER_SERVER)
    {
      if (ep->server_af == 1 /* ip6 */ )
	{
	  if (vec_len (dm->ip6_name_servers))
	    {
	      send_dns6_request (dm, ep,
				 dm->ip6_name_servers + ep->server_rotor);
	      goto out;
	    }
	  else
	    ep->server_af = 0;
	}
      if (vec_len (dm->ip4_name_servers))
	{
	  send_dns4_request (dm, ep, dm->ip4_name_servers + ep->server_rotor);
	  goto out;
	}
    }
  else				/* switch to a new server */
    {
      ep->retry_count = 1;
      ep->server_rotor++;
      if (ep->server_af == 1 /* ip6 */ )
	{
	  if (ep->server_rotor >= vec_len (dm->ip6_name_servers))
	    {
	      ep->server_rotor = 0;
	      ep->server_af = vec_len (dm->ip4_name_servers) > 0 ? 0 : 1;
	    }
	}
      else
	{
	  if (ep->server_rotor >= vec_len (dm->ip4_name_servers))
	    {
	      ep->server_rotor = 0;
	      ep->server_af = vec_len (dm->ip6_name_servers) > 0 ? 1 : 0;
	    }
	}
    }

  if (ep->server_af == 1 /* ip6 */ )
    send_dns6_request (dm, ep, dm->ip6_name_servers + ep->server_rotor);
  else
    send_dns4_request (dm, ep, dm->ip4_name_servers + ep->server_rotor);

out:

  vlib_process_signal_event_mt (dm->vlib_main, dns_resolver_node.index,
				DNS_RESOLVER_EVENT_PENDING, 0);
}

int
vnet_dns_delete_entry_by_index_nolock (dns_main_t * dm, u32 index)
{
  dns_cache_entry_t *ep;
  int i;

  if (dm->is_enabled == 0)
    return VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED;

  if (pool_is_free_index (dm->entries, index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  ep = pool_elt_at_index (dm->entries, index);

  if (!(ep->flags & DNS_CACHE_ENTRY_FLAG_VALID))
    {
      for (i = 0; i < vec_len (dm->unresolved_entries); i++)
	if (index == dm->unresolved_entries[i])
	  {
	    vec_delete (dm->unresolved_entries, 1, i);
	    goto found;
	  }
      clib_warning ("pool elt %d supposedly pending, but not found...",
		    index);
    }

found:
  hash_unset_mem (dm->cache_entry_by_name, ep->name);
  vec_free (ep->name);
  vec_free (ep->api_clients_to_notify);
  vec_free (ep->api_client_contexts);
  vec_free (ep->ip4_peers_to_notify);
  vec_free (ep->ip6_peers_to_notify);
  pool_put (dm->entries, ep);

  return 0;
}

static int
dns_delete_by_name (dns_main_t * dm, u8 * name)
{
  int rv;
  uword *p;

  if (dm->is_enabled == 0)
    return VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED;

  dns_cache_lock (dm);
  p = hash_get_mem (dm->cache_entry_by_name, name);
  if (!p)
    {
      dns_cache_unlock (dm);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
  rv = vnet_dns_delete_entry_by_index_nolock (dm, p[0]);

  dns_cache_unlock (dm);

  return rv;
}

static int
delete_random_entry (dns_main_t * dm)
{
  int rv;
  u32 victim_index, start_index, i;
  u32 limit;
  dns_cache_entry_t *ep;

  if (dm->is_enabled == 0)
    return VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED;

  dns_cache_lock (dm);
  limit = pool_elts (dm->entries);
  start_index = random_u32 (&dm->random_seed) % limit;

  for (i = 0; i < limit; i++)
    {
      victim_index = (start_index + i) % limit;

      if (!pool_is_free_index (dm->entries, victim_index))
	{
	  ep = pool_elt_at_index (dm->entries, victim_index);
	  /* Delete only valid, non-static entries */
	  if ((ep->flags & DNS_CACHE_ENTRY_FLAG_VALID)
	      && ((ep->flags & DNS_CACHE_ENTRY_FLAG_STATIC) == 0))
	    {
	      rv = vnet_dns_delete_entry_by_index_nolock (dm, victim_index);
	      dns_cache_unlock (dm);
	      return rv;
	    }
	}
    }
  dns_cache_unlock (dm);

  clib_warning ("Couldn't find an entry to delete?");
  return VNET_API_ERROR_UNSPECIFIED;
}

static int
dns_add_static_entry (dns_main_t * dm, u8 * name, u8 * dns_reply_data)
{
  dns_cache_entry_t *ep;
  uword *p;
  int rv;

  if (dm->is_enabled == 0)
    return VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED;

  dns_cache_lock (dm);
  p = hash_get_mem (dm->cache_entry_by_name, name);
  if (p)
    {
      dns_cache_unlock (dm);
      return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
    }

  if (pool_elts (dm->entries) == dm->name_cache_size)
    {
      /* Will only fail if the cache is totally filled w/ static entries... */
      rv = delete_random_entry (dm);
      if (rv)
	{
	  dns_cache_unlock (dm);
	  return rv;
	}
    }

  pool_get (dm->entries, ep);
  memset (ep, 0, sizeof (*ep));

  /* Note: consumes the name vector */
  ep->name = name;
  hash_set_mem (dm->cache_entry_by_name, ep->name, ep - dm->entries);
  ep->flags = DNS_CACHE_ENTRY_FLAG_VALID | DNS_CACHE_ENTRY_FLAG_STATIC;
  ep->dns_response = dns_reply_data;

  dns_cache_unlock (dm);
  return 0;
}

static int
dns_resolve_name (dns_main_t * dm,
		  u8 * name, u32 client_index, u32 client_context,
		  dns_cache_entry_t ** retp)
{
  dns_cache_entry_t *ep;
  int rv;
  f64 now;
  uword *p;

  now = vlib_time_now (dm->vlib_main);

  /* In case we can't actually answer the question right now... */
  *retp = 0;

  dns_cache_lock (dm);
  p = hash_get_mem (dm->cache_entry_by_name, name);
  if (p)
    {
      ep = pool_elt_at_index (dm->entries, p[0]);
      if (ep->flags & DNS_CACHE_ENTRY_FLAG_VALID)
	{
	  /* Has the entry expired? */
	  if (((ep->flags & DNS_CACHE_ENTRY_FLAG_STATIC) == 0)
	      && (now > ep->expiration_time))
	    {
	      clib_warning ("Re-resolve %s", name);
	      /* Yes, kill it... */
	      vnet_dns_delete_entry_by_index_nolock (dm, p[0]);
	      goto re_resolve;
	    }

	  /* Note: caller must drop the lock! */
	  *retp = ep;
	  return (0);
	}
    }

  if (pool_elts (dm->entries) == dm->name_cache_size)
    {
      /* Will only fail if the cache is totally filled w/ static entries... */
      rv = delete_random_entry (dm);
      if (rv)
	{
	  dns_cache_unlock (dm);
	  return rv;
	}
    }

re_resolve:
  /* add new hash table entry */
  pool_get (dm->entries, ep);
  memset (ep, 0, sizeof (*ep));

  ep->name = format (0, "%s%c", name, 0);
  _vec_len (ep->name) = vec_len (ep->name) - 1;

  hash_set_mem (dm->cache_entry_by_name, ep->name, ep - dm->entries);

  vec_add1 (dm->unresolved_entries, ep - dm->entries);
  vec_add1 (ep->api_clients_to_notify, client_index);
  vec_add1 (ep->api_client_contexts, client_context);
  vnet_send_dns_request (dm, ep);
  dns_cache_unlock (dm);

  return 0;
}

/**
 * Handle cname indirection. JFC. Called with the cache locked.
 * returns 0 if the reply is not a CNAME.
 */

int
vnet_dns_cname_indirection_nolock (dns_main_t * dm, dns_cache_entry_t * ep,
				   u8 * reply)
{
  dns_header_t *h;
  dns_query_t *qp;
  dns_rr_t *rr;
  u8 *curpos;
  u8 *pos, *pos2;
  int len, i;
  u8 *cname = 0;
  u8 *request = 0;
  u32 qp_offset;
  u16 flags;
  u16 rcode;

  h = (dns_header_t *) reply;
  flags = clib_net_to_host_u16 (h->flags);
  rcode = flags & DNS_RCODE_MASK;

  /* See if the response is OK */
  switch (rcode)
    {
    case DNS_RCODE_NO_ERROR:
      break;

    case DNS_RCODE_NAME_ERROR:
    case DNS_RCODE_FORMAT_ERROR:
    case DNS_RCODE_SERVER_FAILURE:
    case DNS_RCODE_NOT_IMPLEMENTED:
    case DNS_RCODE_REFUSED:
      return 0;
    }

  curpos = (u8 *) (h + 1);
  pos = curpos;
  len = *pos++;

  /* Skip the questions */
  for (i = 0; i < clib_net_to_host_u16 (h->qdcount); i++)
    {
      while (len)
	{
	  pos += len;
	  len = *pos++;
	}
      qp = (dns_query_t *) pos;
      pos += sizeof (*qp);
    }
  pos2 = pos;
  /* expect a pointer chase here for a CNAME record */
  if ((pos2[0] & 0xC0) == 0xC0)
    pos += 2;
  else
    return 0;

  rr = (dns_rr_t *) pos;

  /* This is a real record, not a CNAME record */
  if (clib_net_to_host_u16 (rr->type) != DNS_TYPE_CNAME)
    return 0;

  /* Crap. Chase the CNAME name chain. */

  cname = labels_to_name (rr->rdata, reply, &pos2);
  request = name_to_labels (cname);
  vec_free (cname);

  qp_offset = vec_len (request);

  /* Add space for the query header */
  vec_validate (request, qp_offset + sizeof (dns_query_t) - 1);

  qp = (dns_query_t *) (request + qp_offset);

  qp->type = clib_host_to_net_u16 (DNS_TYPE_ALL);
  qp->class = clib_host_to_net_u16 (DNS_CLASS_IN);

  /* Punch in space for the dns_header_t */
  vec_insert (request, sizeof (dns_header_t), 0);

  h = (dns_header_t *) request;

  /* Transaction ID = pool index */
  h->id = clib_host_to_net_u16 (ep - dm->entries);

  /* Ask for a recursive lookup */
  h->flags = clib_host_to_net_u16 (DNS_RD | DNS_OPCODE_QUERY);
  h->qdcount = clib_host_to_net_u16 (1);
  h->nscount = 0;
  h->arcount = 0;

  vec_free (ep->dns_request);
  ep->dns_request = request;
  ep->retry_timer = vlib_time_now (dm->vlib_main) + 2.0;
  ep->retry_count = 0;

  /*
   * Enable this to watch recursive resolution happen...
   * fformat (stdout, "%U", format_dns_reply, request, 2);
   */

  if (ep->server_af == 1 /* ip6 */ )
    send_dns6_request (dm, ep, dm->ip6_name_servers + ep->server_rotor);
  else
    send_dns4_request (dm, ep, dm->ip4_name_servers + ep->server_rotor);

  vec_free (reply);
  return (1);
}

int
vnet_dns_response_to_reply (u8 * response,
			    vl_api_dns_resolve_name_reply_t * rmp,
			    u32 * min_ttlp)
{
  dns_header_t *h;
  dns_query_t *qp;
  dns_rr_t *rr;
  int i, limit;
  u8 len;
  u8 *curpos, *pos;
  u16 flags;
  u16 rcode;
  u32 ttl;

  h = (dns_header_t *) response;
  flags = clib_net_to_host_u16 (h->flags);
  rcode = flags & DNS_RCODE_MASK;

  /* See if the response is OK, etc. */
  switch (rcode)
    {
    default:
    case DNS_RCODE_NO_ERROR:
      break;

    case DNS_RCODE_NAME_ERROR:
    case DNS_RCODE_FORMAT_ERROR:
      return VNET_API_ERROR_NAME_SERVER_NO_SUCH_NAME;

    case DNS_RCODE_SERVER_FAILURE:
    case DNS_RCODE_NOT_IMPLEMENTED:
    case DNS_RCODE_REFUSED:
      return VNET_API_ERROR_NAME_SERVER_NEXT_SERVER;
    }

  /* No answers? Loser... */
  if (clib_net_to_host_u16 (h->anscount) < 1)
    return VNET_API_ERROR_NAME_SERVER_NO_ADDRESSES;

  curpos = (u8 *) (h + 1);

  /* Skip the name we asked about */
  pos = curpos;
  len = *pos++;
  /* Should never happen, but stil... */
  if ((len & 0xC0) == 0xC0)
    curpos += 2;
  else
    {
      /* skip the name / label-set */
      while (len)
	{
	  pos += len;
	  len = *pos++;
	}
      curpos = pos;
    }
  /* Skip queries */
  limit = clib_net_to_host_u16 (h->qdcount);
  qp = (dns_query_t *) curpos;
  qp += limit;
  curpos = (u8 *) qp;

  /* Parse answers */
  limit = clib_net_to_host_u16 (h->anscount);

  for (i = 0; i < limit; i++)
    {
      pos = curpos;

      /* Expect pointer chases in the answer section... */
      if ((pos[0] & 0xC0) == 0xC0)
	curpos += 2;
      else
	{
	  len = *pos++;
	  while (len)
	    {
	      if ((pos[0] & 0xC0) == 0xC0)
		{
		  curpos = pos + 2;
		  break;
		}
	      pos += len;
	      len = *pos++;
	    }
	  curpos = pos;
	}

      rr = (dns_rr_t *) curpos;

      switch (clib_net_to_host_u16 (rr->type))
	{
	case DNS_TYPE_A:
	  /* Collect an ip4 address. Do not pass go. Do not collect $200 */
	  memcpy (rmp->ip4_address, rr->rdata, sizeof (ip4_address_t));
	  rmp->ip4_set = 1;
	  ttl = clib_net_to_host_u32 (rr->ttl);
	  if (min_ttlp && *min_ttlp > ttl)
	    *min_ttlp = ttl;
	  break;
	case DNS_TYPE_AAAA:
	  /* Collect an ip6 address. Do not pass go. Do not collect $200 */
	  memcpy (rmp->ip6_address, rr->rdata, sizeof (ip6_address_t));
	  ttl = clib_net_to_host_u32 (rr->ttl);
	  if (min_ttlp && *min_ttlp > ttl)
	    *min_ttlp = ttl;
	  rmp->ip6_set = 1;
	  break;
	default:
	  break;
	}
      /* Might as well stop ASAP */
      if (rmp->ip4_set && rmp->ip6_set)
	break;
      curpos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
    }

  if ((rmp->ip4_set + rmp->ip6_set) == 0)
    return VNET_API_ERROR_NAME_SERVER_NO_ADDRESSES;
  return 0;
}

static void
vl_api_dns_resolve_name_t_handler (vl_api_dns_resolve_name_t * mp)
{
  dns_main_t *dm = &dns_main;
  vl_api_dns_resolve_name_reply_t *rmp;
  dns_cache_entry_t *ep;
  int rv;

  /* Sanitize the name slightly */
  mp->name[ARRAY_LEN (mp->name) - 1] = 0;

  rv = dns_resolve_name (dm, mp->name, mp->client_index, mp->context, &ep);

  /* Error, e.g. not enabled? Tell the user */
  if (rv < 0)
    {
      REPLY_MACRO (VL_API_DNS_RESOLVE_NAME_REPLY);
      return;
    }

  /* Resolution pending? Don't reply... */
  if (ep == 0)
    return;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_DNS_RESOLVE_NAME_REPLY,
  ({
    rv = vnet_dns_response_to_reply (ep->dns_response, rmp, 0 /* ttl-ptr */);
    rmp->retval = clib_host_to_net_u32 (rv);
  }));
  /* *INDENT-ON* */

  /*
   * dns_resolve_name leaves the cache locked when it returns
   * a cached result, so unlock it here.
   */
  dns_cache_unlock (dm);
}

#define vl_msg_name_crc_list
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_dns;
#undef _
}

#define foreach_dns_api_msg                             \
_(DNS_ENABLE_DISABLE, dns_enable_disable)               \
_(DNS_NAME_SERVER_ADD_DEL, dns_name_server_add_del)     \
_(DNS_RESOLVE_NAME, dns_resolve_name)

static clib_error_t *
dns_api_hookup (vlib_main_t * vm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_dns_api_msg;
#undef _

  setup_message_id_table (&api_main);
  return 0;
}

VLIB_API_INIT_FUNCTION (dns_api_hookup);


static clib_error_t *
dns_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  dns_main_t *dm = &dns_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "max-cache-size %u", &dm->name_cache_size))
	;
      else if (unformat (input, "max-ttl %u", &dm->max_ttl_in_seconds))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (dns_config_fn, "dns");

static clib_error_t *
dns_init (vlib_main_t * vm)
{
  dns_main_t *dm = &dns_main;

  dm->vlib_main = vm;
  dm->vnet_main = vnet_get_main ();
  dm->name_cache_size = 65535;
  dm->max_ttl_in_seconds = 86400;
  dm->random_seed = 0xDEADDABE;

  udp_register_dst_port (vm, UDP_DST_PORT_dns_reply, dns46_reply_node.index,
			 1 /* is_ip4 */ );

  udp_register_dst_port (vm, UDP_DST_PORT_dns_reply6, dns46_reply_node.index,
			 0 /* is_ip4 */ );

#if 0
  udp_register_dst_port (vm, UDP_DST_PORT_dns, dns4_request_node.index,
			 1 /* is_ip4 */ );
  udp_register_dst_port (vm, UDP_DST_PORT_dns6, dns6_request_node.index,
			 0 /* is_ip4 */ );
#endif

  return 0;
}

VLIB_INIT_FUNCTION (dns_init);

uword
unformat_dns_reply (unformat_input_t * input, va_list * args)
{
  u8 **result = va_arg (*args, u8 **);
  u8 **namep = va_arg (*args, u8 **);
  ip4_address_t a4;
  ip6_address_t a6;
  int a4_set = 0;
  int a6_set = 0;
  u8 *name;
  int name_set = 0;
  u8 *ce;
  u32 qp_offset;
  dns_header_t *h;
  dns_query_t *qp;
  dns_rr_t *rr;
  u8 *rru8;

  if (unformat (input, "%v", &name))
    name_set = 1;

  if (unformat (input, "%U", unformat_ip4_address, &a4))
    {
      a4_set = 1;
      if (unformat (input, "%U", unformat_ip6_address, &a6))
	a6_set = 1;
    }

  if (unformat (input, "%U", unformat_ip6_address, &a6))
    {
      a6_set = 1;
      if (unformat (input, "%U", unformat_ip4_address, &a6))
	a4_set = 1;
    }

  /* Must have a name */
  if (!name_set)
    return 0;

  /* Must have at least one address */
  if (!(a4_set + a6_set))
    return 0;

  /* Build a fake DNS cache entry string, one hemorrhoid at a time */
  ce = name_to_labels (name);
  qp_offset = vec_len (ce);

  /* Add space for the query header */
  vec_validate (ce, qp_offset + sizeof (dns_query_t) - 1);
  qp = (dns_query_t *) (ce + qp_offset);

  qp->type = clib_host_to_net_u16 (DNS_TYPE_ALL);
  qp->class = clib_host_to_net_u16 (DNS_CLASS_IN);

  /* Punch in space for the dns_header_t */
  vec_insert (ce, sizeof (dns_header_t), 0);

  h = (dns_header_t *) ce;

  /* Fake Transaction ID */
  h->id = 0xFFFF;

  h->flags = clib_host_to_net_u16 (DNS_RD | DNS_RA);
  h->qdcount = clib_host_to_net_u16 (1);
  h->anscount = clib_host_to_net_u16 (a4_set + a6_set);
  h->nscount = 0;
  h->arcount = 0;

  /* Now append one or two A/AAAA RR's... */
  if (a4_set)
    {
      /* Pointer to the name (DGMS) */
      vec_add1 (ce, 0xC0);
      vec_add1 (ce, 0x0C);
      vec_add2 (ce, rru8, sizeof (*rr) + 4);
      rr = (void *) rru8;
      rr->type = clib_host_to_net_u16 (DNS_TYPE_A);
      rr->class = clib_host_to_net_u16 (DNS_CLASS_IN);
      rr->ttl = clib_host_to_net_u32 (86400);
      rr->rdlength = clib_host_to_net_u16 (4);
      memcpy (rr->rdata, &a4, sizeof (a4));
    }
  if (a6_set)
    {
      /* Pointer to the name (DGMS) */
      vec_add1 (ce, 0xC0);
      vec_add1 (ce, 0x0C);
      vec_add2 (ce, rru8, sizeof (*rr) + 16);
      rr = (void *) rru8;
      rr->type = clib_host_to_net_u16 (DNS_TYPE_AAAA);
      rr->class = clib_host_to_net_u16 (DNS_CLASS_IN);
      rr->ttl = clib_host_to_net_u32 (86400);
      rr->rdlength = clib_host_to_net_u16 (16);
      memcpy (rr->rdata, &a6, sizeof (a6));
    }
  *result = ce;
  if (namep)
    *namep = name;
  else
    vec_free (name);

  return 1;
}

u8 *
format_dns_query (u8 * s, va_list * args)
{
  u8 **curpos = va_arg (*args, u8 **);
  int verbose = va_arg (*args, int);
  u8 *pos;
  dns_query_t *qp;
  int len, i;
  if (verbose > 1)
    s = format (s, "    Name: ");

  /* Unwind execrated counted-label sheit */
  pos = *curpos;
  len = *pos++;

  while (len)
    {
      for (i = 0; i < len; i++)
	vec_add1 (s, *pos++);

      len = *pos++;
      if (len)
	vec_add1 (s, '.');
      else
	{
	  vec_add1 (s, ':');
	  vec_add1 (s, ' ');
	}
    }

  qp = (dns_query_t *) pos;
  if (verbose > 1)
    {
      switch (clib_net_to_host_u16 (qp->type))
	{
	case DNS_TYPE_A:
	  s = format (s, "type A\n");
	  break;
	case DNS_TYPE_AAAA:
	  s = format (s, "type AAAA\n");
	  break;
	case DNS_TYPE_ALL:
	  s = format (s, "type ALL\n");
	  break;

	default:
	  s = format (s, "type %d\n", clib_net_to_host_u16 (qp->type));
	  break;
	}
    }

  pos += sizeof (*qp);

  *curpos = pos;
  return s;
}

/**
 * format dns reply data
 * verbose > 1, dump everything
 * verbose == 1, dump all A and AAAA records
 * verbose == 0, dump one A record, and one AAAA record
 */

u8 *
format_dns_reply_data (u8 * s, va_list * args)
{
  u8 *reply = va_arg (*args, u8 *);
  u8 **curpos = va_arg (*args, u8 **);
  int verbose = va_arg (*args, int);
  int *print_ip4 = va_arg (*args, int *);
  int *print_ip6 = va_arg (*args, int *);
  int len;
  u8 *pos, *pos2;
  dns_rr_t *rr;
  int i;
  int initial_pointer_chase = 0;
  u16 *tp;

  pos = pos2 = *curpos;

  if (verbose > 1)
    s = format (s, "    ");

  /* chase pointer? almost always yes here... */
  if (pos2[0] == 0xc0)
    {
      pos2 = reply + pos2[1];
      pos += 2;
      initial_pointer_chase = 1;
    }

  len = *pos2++;

  while (len)
    {
      for (i = 0; i < len; i++)
	{
	  if (verbose > 1)
	    vec_add1 (s, *pos2);
	  pos2++;
	}
      len = *pos2++;
      if (len)
	{
	  if (verbose > 1)
	    vec_add1 (s, '.');
	}
      else
	{
	  if (verbose > 1)
	    vec_add1 (s, ' ');
	}
    }

  if (initial_pointer_chase == 0)
    pos = pos2;

  rr = (dns_rr_t *) pos;

  switch (clib_net_to_host_u16 (rr->type))
    {
    case DNS_TYPE_A:
      if (verbose > 1)
	{
	  s = format (s, "A: ttl %d %U\n", clib_net_to_host_u32 (rr->ttl),
		      format_ip4_address, rr->rdata);
	}
      else
	{
	  if (*print_ip4)
	    s = format (s, "%U [%u] ", format_ip4_address, rr->rdata,
			clib_net_to_host_u32 (rr->ttl));
	  if (verbose == 0)
	    *print_ip4 = 0;

	}
      pos += sizeof (*rr) + 4;
      break;

    case DNS_TYPE_AAAA:
      if (verbose > 1)
	{
	  s = format (s, "AAAA: ttl %d %U\n", clib_net_to_host_u32 (rr->ttl),
		      format_ip6_address, rr->rdata);
	}
      else
	{
	  if (*print_ip6)
	    s = format (s, "%U [%u] ", format_ip6_address, rr->rdata,
			clib_net_to_host_u32 (rr->ttl));
	  if (verbose == 0)
	    *print_ip6 = 0;
	}
      pos += sizeof (*rr) + 16;
      break;

    case DNS_TYPE_TEXT:
      if (verbose > 1)
	{
	  s = format (s, "TEXT: ");
	  for (i = 0; i < clib_net_to_host_u16 (rr->rdlength); i++)
	    vec_add1 (s, rr->rdata[i]);
	  vec_add1 (s, '\n');
	}
      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      break;

    case DNS_TYPE_NAMESERVER:
      if (verbose > 1)
	{
	  s = format (s, "Nameserver: ");
	  pos2 = rr->rdata;

	  /* chase pointer? */
	  if (pos2[0] == 0xc0)
	    pos2 = reply + pos2[1];

	  len = *pos2++;

	  while (len)
	    {
	      for (i = 0; i < len; i++)
		vec_add1 (s, *pos2++);

	      /* chase pointer, typically to offset 12... */
	      if (pos2[0] == 0xC0)
		pos2 = reply + pos2[1];

	      len = *pos2++;
	      if (len)
		vec_add1 (s, '.');
	      else
		vec_add1 (s, '\n');
	    }
	}
      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      break;

    case DNS_TYPE_MAIL_EXCHANGE:
      if (verbose > 1)
	{
	  tp = (u16 *) rr->rdata;

	  s = format (s, "Mail Exchange: Preference %d ", (u32)
		      clib_net_to_host_u16 (*tp));

	  pos2 = rr->rdata + 2;

	  /* chase pointer? */
	  if (pos2[0] == 0xc0)
	    pos2 = reply + pos2[1];

	  len = *pos2++;

	  while (len)
	    {
	      for (i = 0; i < len; i++)
		vec_add1 (s, *pos2++);

	      /* chase pointer */
	      if (pos2[0] == 0xC0)
		pos2 = reply + pos2[1];

	      len = *pos2++;
	      if (len)
		vec_add1 (s, '.');
	      else
		vec_add1 (s, '\n');
	    }
	}

      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      break;

    case DNS_TYPE_CNAME:
      if (verbose > 1)
	{
	  tp = (u16 *) rr->rdata;

	  s = format (s, "CNAME: ");

	  pos2 = rr->rdata;

	  /* chase pointer? */
	  if (pos2[0] == 0xc0)
	    pos2 = reply + pos2[1];

	  len = *pos2++;

	  while (len)
	    {
	      for (i = 0; i < len; i++)
		vec_add1 (s, *pos2++);

	      /* chase pointer */
	      if (pos2[0] == 0xC0)
		pos2 = reply + pos2[1];

	      len = *pos2++;
	      if (len)
		vec_add1 (s, '.');
	      else
		vec_add1 (s, '\n');
	    }
	}
      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      break;

    default:
      if (verbose > 1)
	s = format (s, "type %d: len %d\n",
		    (int) clib_net_to_host_u16 (rr->type),
		    sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength));
      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      break;
    }

  *curpos = pos;

  return s;
}

u8 *
format_dns_reply (u8 * s, va_list * args)
{
  u8 *reply_as_u8 = va_arg (*args, u8 *);
  int verbose = va_arg (*args, int);
  dns_header_t *h;
  u16 id, flags;
  u8 *curpos;
  int i;
  int print_ip4 = 1;
  int print_ip6 = 1;

  h = (dns_header_t *) reply_as_u8;
  id = clib_net_to_host_u16 (h->id);
  flags = clib_net_to_host_u16 (h->flags);

  if (verbose > 1)
    {
      s = format (s, "DNS %s: id %d\n", (flags & DNS_QR) ? "reply" : "query",
		  id);
      s = format (s, "  %s %s %s %s\n",
		  (flags & DNS_RA) ? "recur" : "no-recur",
		  (flags & DNS_RD) ? "recur-des" : "no-recur-des",
		  (flags & DNS_TC) ? "trunc" : "no-trunc",
		  (flags & DNS_AA) ? "auth" : "non-auth");
      s = format (s, "  %d queries, %d answers, %d name-servers,"
		  " %d add'l recs\n",
		  clib_net_to_host_u16 (h->qdcount),
		  clib_net_to_host_u16 (h->anscount),
		  clib_net_to_host_u16 (h->nscount),
		  clib_net_to_host_u16 (h->arcount));
    }

  curpos = (u8 *) (h + 1);

  if (h->qdcount)
    {
      if (verbose > 1)
	s = format (s, "  Queries:\n");
      for (i = 0; i < clib_net_to_host_u16 (h->qdcount); i++)
	{
	  /* The query is variable-length, so curpos is a value-result parm */
	  s = format (s, "%U", format_dns_query, &curpos, verbose);
	}
    }
  if (h->anscount)
    {
      if (verbose > 1)
	s = format (s, "  Replies:\n");

      for (i = 0; i < clib_net_to_host_u16 (h->anscount); i++)
	{
	  /* curpos is a value-result parm */
	  s = format (s, "%U", format_dns_reply_data, reply_as_u8, &curpos,
		      verbose, &print_ip4, &print_ip6);
	}
    }
  return s;
}

u8 *
format_dns_cache (u8 * s, va_list * args)
{
  dns_main_t *dm = va_arg (*args, dns_main_t *);
  f64 now = va_arg (*args, f64);
  int verbose = va_arg (*args, int);
  u8 *name = va_arg (*args, u8 *);
  dns_cache_entry_t *ep;
  char *ss;
  uword *p;

  if (dm->is_enabled == 0)
    {
      s = format (s, "The DNS cache is disabled...");
      return s;
    }

  if (pool_elts (dm->entries) == 0)
    {
      s = format (s, "The DNS cache is empty...");
      return s;
    }

  dns_cache_lock (dm);

  if (name)
    {
      p = hash_get_mem (dm->cache_entry_by_name, name);
      if (!p)
	{
	  s = format (s, "%s is not in the cache...", name);
	  dns_cache_unlock (dm);
	  return (s);
	}

      ep = pool_elt_at_index (dm->entries, p[0]);
      /* Magic to spit out a C-initializer to research hemorrhoids... */
      if (verbose == 3)
	{
	  int i, j;
	  s = format (s, "static u8 dns_reply_data_initializer[] =\n");
	  s = format (s, "{\n");
	  j = 0;
	  for (i = 0; i < vec_len (ep->dns_response); i++)
	    {
	      if (j++ == 8)
		{
		  j = 0;
		  vec_add1 (s, '\n');
		}
	      s = format (s, "0x%02x, ", ep->dns_response[i]);
	    }
	  s = format (s, "};\n");
	}
      else
	{
	  if (ep->flags & DNS_CACHE_ENTRY_FLAG_VALID)
	    {
	      ASSERT (ep->dns_response);
	      if (ep->flags & DNS_CACHE_ENTRY_FLAG_STATIC)
		ss = "[S] ";
	      else
		ss = "    ";

	      s = format (s, "%s%s -> %U", ss, ep->name,
			  format_dns_reply, ep->dns_response, verbose);
	      if (!(ep->flags & DNS_CACHE_ENTRY_FLAG_STATIC))
		{
		  f64 time_left = ep->expiration_time - now;
		  if (time_left > 0.0)
		    s = format (s, "  TTL left %.1f", time_left);
		  else
		    s = format (s, "  EXPIRED");
		}
	    }
	  else
	    {
	      ASSERT (ep->dns_request);
	      s = format (s, "[P] %U", format_dns_reply, ep->dns_request,
			  verbose);
	    }
	  vec_add1 (s, '\n');
	}
      return s;
    }

  /* *INDENT-OFF* */
  pool_foreach (ep, dm->entries,
  ({
    if (ep->flags & DNS_CACHE_ENTRY_FLAG_VALID)
      {
        ASSERT (ep->dns_response);
        if (ep->flags & DNS_CACHE_ENTRY_FLAG_STATIC)
          ss = "[S] ";
        else
          ss = "    ";

        s = format (s, "%s%s -> %U", ss, ep->name,
                    format_dns_reply,
                    ep->dns_response,
                    verbose);
        if (!(ep->flags & DNS_CACHE_ENTRY_FLAG_STATIC))
          {
            f64 time_left = ep->expiration_time - now;
            if (time_left > 0.0)
              s = format (s, "  TTL left %.1f", time_left);
            else
              s = format (s, "  EXPIRED");
          }
      }
    else
      {
        ASSERT (ep->dns_request);
        s = format (s, "[P] %U", format_dns_reply, ep->dns_request,
                    verbose);
      }
    vec_add1 (s, '\n');
  }));
  /* *INDENT-ON* */

  dns_cache_unlock (dm);

  return s;
}

static clib_error_t *
show_dns_cache_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  dns_main_t *dm = &dns_main;
  int verbose = 0;
  u8 *name = 0;
  f64 now = vlib_time_now (vm);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %d", &verbose))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "name %s", &name))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  vlib_cli_output (vm, "%U", format_dns_cache, dm, now, verbose, name);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_dns_cache_command) =
{
  .path = "show dns cache",
  .short_help = "show dns cache [verbose [nn]]",
  .function = show_dns_cache_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dns_cache_add_del_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  dns_main_t *dm = &dns_main;
  u8 *dns_reply_data;
  u8 *name;
  int is_add = -1;
  int is_clear = -1;
  int rv;
  clib_error_t *error;

  if (unformat (input, "add"))
    is_add = 1;
  if (unformat (input, "del"))
    is_add = 0;
  if (unformat (input, "clear"))
    is_clear = 1;

  if (is_add == -1 && is_clear == -1)
    return clib_error_return (0, "add / del / clear required...");

  if (is_clear == 1)
    {
      rv = dns_cache_clear (dm);
      switch (rv)
	{
	case 0:
	  return 0;

	case VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED:
	  error = clib_error_return (0, "Name resolution not enabled");
	  return error;
	}
    }

  /* Delete (by name)? */
  if (is_add == 0)
    {
      if (unformat (input, "%v", &name))
	{
	  rv = dns_delete_by_name (dm, name);
	  switch (rv)
	    {
	    case VNET_API_ERROR_NO_SUCH_ENTRY:
	      error = clib_error_return (0, "%v not in the cache...", name);
	      vec_free (name);
	      return error;

	    case VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED:
	      error = clib_error_return (0, "Name resolution not enabled");
	      vec_free (name);
	      return error;

	    case 0:
	      vec_free (name);
	      return 0;

	    default:
	      error = clib_error_return (0, "dns_delete_by_name returned %d",
					 rv);
	      vec_free (name);
	      return error;
	    }
	}
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, input);
    }

  /* Note: dns_add_static_entry consumes the name vector if OK... */
  if (unformat (input, "%U", unformat_dns_reply, &dns_reply_data, &name))
    {
      rv = dns_add_static_entry (dm, name, dns_reply_data);
      switch (rv)
	{
	case VNET_API_ERROR_ENTRY_ALREADY_EXISTS:
	  vec_free (name);
	  vec_free (dns_reply_data);
	  return clib_error_return (0, "%v already in the cache...", name);
	case 0:
	  return 0;

	default:
	  return clib_error_return (0, "dns_add_static_entry returned %d",
				    rv);
	}
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dns_cache_add_del_command) =
{
  .path = "dns cache",
  .short_help = "dns cache [add|del|clear] <name> [ip4][ip6]",
  .function = dns_cache_add_del_command_fn,
};
/* *INDENT-ON* */

#define DNS_FORMAT_TEST 1

#if DNS_FORMAT_TEST > 0
#if 0
/* yahoo.com */
static u8 dns_reply_data_initializer[] =
  { 0x0, 0x0, 0x81, 0x80, 0x0, 0x1, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x5,
  0x79, 0x61, 0x68, 0x6f, 0x6f, 0x3, 0x63, 0x6f, 0x6d,
  0x0,				/* null lbl */
  0x0, 0xff,			/* type ALL */
  0x0, 0x1,			/* class IN */
  0xc0, 0xc,			/* pointer to yahoo.com name */
  0x0, 0x10, 0x0, 0x1, 0x0, 0x0, 0x6, 0x5c, 0x0, 0x24, 0x23,
  0x76, 0x3d, 0x73, 0x70, 0x66, 0x31, 0x20, 0x72, 0x65, 0x64, 0x69, 0x72,
  0x65, 0x63, 0x74, 0x3d, 0x5f, 0x73, 0x70, 0x66, 0x2e, 0x6d, 0x61, 0x69,
  0x6c, 0x2e, 0x79, 0x61, 0x68, 0x6f, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0xc0,
  0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x1, 0x50, 0xd4, 0x0, 0x6, 0x3, 0x6e, 0x73,
  0x35, 0xc0, 0xc, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x1, 0x50, 0xd4, 0x0,
  0x6, 0x3, 0x6e, 0x73, 0x34, 0xc0, 0xc, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0,
  0x1, 0x50, 0xd4, 0x0, 0x6, 0x3, 0x6e, 0x73, 0x31, 0xc0, 0xc, 0xc0, 0xc,
  0x0, 0x2, 0x0, 0x1, 0x0, 0x1, 0x50, 0xd4, 0x0, 0x6, 0x3, 0x6e, 0x73, 0x32,
  0xc0, 0xc, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x1, 0x50, 0xd4, 0x0, 0x6,
  0x3, 0x6e, 0x73, 0x33, 0xc0, 0xc, 0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0,
  0x6, 0x5c, 0x0, 0x19, 0x0, 0x1, 0x4, 0x6d, 0x74, 0x61, 0x36, 0x3, 0x61,
  0x6d, 0x30, 0x8, 0x79, 0x61, 0x68, 0x6f, 0x6f, 0x64, 0x6e, 0x73, 0x3,
  0x6e,
  0x65, 0x74, 0x0, 0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x6, 0x5c, 0x0,
  0x9, 0x0, 0x1, 0x4, 0x6d, 0x74, 0x61, 0x37, 0xc0, 0xb8, 0xc0, 0xc, 0x0,
  0xf, 0x0, 0x1, 0x0, 0x0, 0x6, 0x5c, 0x0, 0x9, 0x0, 0x1, 0x4, 0x6d, 0x74,
  0x61, 0x35, 0xc0, 0xb8, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x6,
  0x5c, 0x0, 0x10, 0x20, 0x1, 0x49, 0x98, 0x0, 0x44, 0x2, 0x4, 0x0, 0x0,
  0x0,
  0x0, 0x0, 0x0, 0x0, 0xa7, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x6,
  0x5c, 0x0, 0x10, 0x20, 0x1, 0x49, 0x98, 0x0, 0xc, 0xa, 0x6, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x2, 0x40, 0x8, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x6,
  0x5c, 0x0, 0x10, 0x20, 0x1, 0x49, 0x98, 0x0, 0x58, 0xc, 0x2, 0x0, 0x0,
  0x0,
  0x0, 0x0, 0x0, 0x0, 0xa9, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x6,
  0x5c, 0x0, 0x4, 0x62, 0x8a, 0xfd, 0x6d, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1,
  0x0,
  0x0, 0x6, 0x5c, 0x0, 0x4, 0xce, 0xbe, 0x24, 0x2d, 0xc0, 0xc, 0x0, 0x1,
  0x0,
  0x1, 0x0, 0x0, 0x6, 0x5c, 0x0, 0x4, 0x62, 0x8b, 0xb4, 0x95, 0xc0, 0xc,
  0x0,
  0x6, 0x0, 0x1, 0x0, 0x0, 0x6, 0x5c, 0x0, 0x2d, 0xc0, 0x7b, 0xa, 0x68,
  0x6f,
  0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x9, 0x79, 0x61, 0x68,
  0x6f, 0x6f, 0x2d, 0x69, 0x6e, 0x63, 0xc0, 0x12, 0x78, 0x3a, 0x85, 0x44,
  0x0, 0x0, 0xe, 0x10, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x1b, 0xaf, 0x80, 0x0, 0x0,
  0x2, 0x58
};

/* www.cisco.com, has no addresses in reply */
static u8 dns_reply_data_initializer[] = {
  0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x05,
  0x63, 0x69, 0x73, 0x63, 0x6f, 0x03, 0x63, 0x6f, 0x6d,

  0x00, 0x00, 0xff, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05,
  0x00, 0x01, 0x00, 0x00, 0x0b, 0xd3, 0x00, 0x1a, 0x03,
  0x77, 0x77, 0x77, 0x05, 0x63, 0x69, 0x73, 0x63, 0x6f,
  0x03, 0x63, 0x6f, 0x6d, 0x06, 0x61, 0x6b, 0x61, 0x64,
  0x6e, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00,
};
#else
/* google.com */
static u8 dns_reply_data_initializer[] =
  { 0x0, 0x0, 0x81, 0x80, 0x0, 0x1, 0x0, 0xe, 0x0, 0x0, 0x0, 0x0, 0x6,
  0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0xff,
  0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2b, 0x0, 0x4,
  0xac, 0xd9, 0x3, 0x2e, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x1,
  0x2b,
  0x0, 0x10, 0x26, 0x7, 0xf8, 0xb0, 0x40, 0x4, 0x8, 0xf, 0x0, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x20, 0xe, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x1, 0x51, 0x7f,
  0x0, 0x6, 0x3, 0x6e, 0x73, 0x31, 0xc0, 0xc, 0xc0, 0xc, 0x0, 0x6, 0x0, 0x1,
  0x0, 0x0, 0x0, 0x3b, 0x0, 0x22, 0xc0, 0x54, 0x9, 0x64, 0x6e, 0x73, 0x2d,
  0x61, 0x64, 0x6d, 0x69, 0x6e, 0xc0, 0xc, 0xa, 0x3d, 0xc7, 0x30, 0x0, 0x0,
  0x3, 0x84, 0x0, 0x0, 0x3, 0x84, 0x0, 0x0, 0x7, 0x8, 0x0, 0x0, 0x0, 0x3c,
  0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x2, 0x57, 0x0, 0x11, 0x0, 0x1e,
  0x4, 0x61, 0x6c, 0x74, 0x32, 0x5, 0x61, 0x73, 0x70, 0x6d, 0x78, 0x1, 0x6c,
  0xc0, 0xc, 0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x2, 0x57, 0x0, 0x4,
  0x0, 0xa, 0xc0, 0x9b, 0xc0, 0xc, 0x0, 0x10, 0x0, 0x1, 0x0, 0x0, 0xe, 0xf,
  0x0, 0x24, 0x23, 0x76, 0x3d, 0x73, 0x70, 0x66, 0x31, 0x20, 0x69, 0x6e,
  0x63, 0x6c, 0x75, 0x64, 0x65, 0x3a, 0x5f, 0x73, 0x70, 0x66, 0x2e, 0x67,
  0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x7e, 0x61,
  0x6c, 0x6c, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x1, 0x51, 0x7f, 0x0, 0x6,
  0x3, 0x6e, 0x73, 0x32, 0xc0, 0xc, 0xc0, 0xc, 0x1, 0x1, 0x0, 0x1, 0x0, 0x1,
  0x51, 0x7f, 0x0, 0xf, 0x0, 0x5, 0x69, 0x73, 0x73, 0x75, 0x65, 0x70, 0x6b,
  0x69, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0,
  0x1, 0x51, 0x7f, 0x0, 0x6, 0x3, 0x6e, 0x73, 0x34, 0xc0, 0xc, 0xc0, 0xc,
  0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x2, 0x57, 0x0, 0x9, 0x0, 0x28, 0x4, 0x61,
  0x6c, 0x74, 0x33, 0xc0, 0x9b, 0xc0, 0xc, 0x0, 0x2, 0x0, 0x1, 0x0, 0x1,
  0x51, 0x7f, 0x0, 0x6, 0x3, 0x6e, 0x73, 0x33, 0xc0, 0xc, 0xc0, 0xc, 0x0,
  0xf, 0x0, 0x1, 0x0, 0x0, 0x2, 0x57, 0x0, 0x9, 0x0, 0x32, 0x4, 0x61, 0x6c,
  0x74, 0x34, 0xc0, 0x9b, 0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x2,
  0x57,
  0x0, 0x9, 0x0, 0x14, 0x4, 0x61, 0x6c, 0x74, 0x31, 0xc0, 0x9b
};
#endif

static clib_error_t *
test_dns_fmt_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 *dns_reply_data = 0;
  int verbose = 0;
  int rv;
  vl_api_dns_resolve_name_reply_t _rm, *rmp = &_rm;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %d", &verbose))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  vec_validate (dns_reply_data, ARRAY_LEN (dns_reply_data_initializer) - 1);

  memcpy (dns_reply_data, dns_reply_data_initializer,
	  ARRAY_LEN (dns_reply_data_initializer));

  vlib_cli_output (vm, "%U", format_dns_reply, dns_reply_data, verbose);

  memset (rmp, 0, sizeof (*rmp));

  rv = vnet_dns_response_to_reply (dns_reply_data, rmp, 0 /* ttl-ptr */ );

  switch (rv)
    {
    case VNET_API_ERROR_NAME_SERVER_NO_ADDRESSES:
      vlib_cli_output (vm, "no addresses found...");
      break;

    default:
      vlib_cli_output (vm, "response to reply returned %d", rv);
      break;

    case 0:
      if (rmp->ip4_set)
	vlib_cli_output (vm, "ip4 address: %U", format_ip4_address,
			 (ip4_address_t *) rmp->ip4_address);
      if (rmp->ip6_set)
	vlib_cli_output (vm, "ip6 address: %U", format_ip6_address,
			 (ip6_address_t *) rmp->ip6_address);
      break;
    }

  vec_free (dns_reply_data);

  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_dns_fmt_command) =
{
  .path = "test dns format",
  .short_help = "test dns format",
  .function = test_dns_fmt_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
test_dns_unfmt_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 *dns_reply_data = 0;
  int verbose = 0;
  int reply_set = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %d", &verbose))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "%U", unformat_dns_reply, &dns_reply_data))
	reply_set = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (reply_set == 0)
    return clib_error_return (0, "dns data not set...");

  vlib_cli_output (vm, "%U", format_dns_reply, dns_reply_data, verbose);

  vec_free (dns_reply_data);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_dns_unfmt_command) =
{
  .path = "test dns unformat",
  .short_help = "test dns unformat <name> [ip4][ip6]",
  .function = test_dns_unfmt_command_fn,
};
/* *INDENT-ON* */
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
