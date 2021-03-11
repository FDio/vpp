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

#include <vnet/vnet.h>
#include <vnet/udp/udp_local.h>
#include <vnet/plugin/plugin.h>
#include <vnet/fib/fib_table.h>
#include <dns/dns.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

/* define message IDs */
#include <dns/dns.api_enum.h>
#include <dns/dns.api_types.h>

#define REPLY_MSG_ID_BASE dm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* Macro to finish up custom dump fns */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

dns_main_t dns_main;

#define foreach_query_type                                                    \
  _ (A, "_A", 2)                                                              \
  _ (AAAA, "_AAAA", 5)                                                        \
  _ (NAMESERVER, "_NS", 3)                                                    \
  _ (CNAME, "_CNAME", 6)                                                      \
  _ (MAIL_EXCHANGE, "_MX", 3)                                                 \
  _ (PTR, "_PTR", 4)

void
vnet_dns_format_name (u8 **name, u8 qtype)
{
  int l;

  switch (qtype)
    {
#define _(type, str, len)                                                     \
  case DNS_TYPE_##type:                                                       \
    l = vec_len (*name);                                                      \
    vec_validate (*name, l + len);                                            \
    memcpy (*name + l, str, len);                                             \
    break;
      foreach_query_type;
#undef _
    }
}

static int
dns_cache_clear (dns_main_t * dm)
{
  dns_cache_entry_t *ep;

  if (dm->is_enabled == 0)
    return VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED;

  dns_cache_lock (dm, 1);

  /* *INDENT-OFF* */
  pool_foreach (ep, dm->entries)
   {
    vec_free (ep->name);
    vec_free (ep->pending_requests);
  }
  /* *INDENT-ON* */

  pool_free (dm->entries);
  hash_free (dm->cache_entry_by_name);
  dm->cache_entry_by_name = hash_create_string (0, sizeof (uword));
  vec_free (dm->unresolved_entries);
  dns_cache_unlock (dm);
  return 0;
}

static int
dns_enable_disable (vlib_main_t * vm, dns_main_t * dm, int is_enable)
{
  vlib_thread_main_t *tm = &vlib_thread_main;
  u32 n_vlib_mains = tm->n_vlib_mains;

  /* Create the resolver process if not done already */
  vnet_dns_create_resolver_process (vm, dm);

  if (is_enable)
    {
      if (vec_len (dm->ip4_name_servers) == 0
	  && (vec_len (dm->ip6_name_servers) == 0))
	return VNET_API_ERROR_NO_NAME_SERVERS;

      if (dm->udp_ports_registered == 0)
	{
	  udp_register_dst_port (vm, UDP_DST_PORT_dns_reply,
				 dns46_reply_node.index, 1 /* is_ip4 */ );

	  udp_register_dst_port (vm, UDP_DST_PORT_dns_reply6,
				 dns46_reply_node.index, 0 /* is_ip4 */ );

	  udp_register_dst_port (vm, UDP_DST_PORT_dns,
				 dns4_request_node.index, 1 /* is_ip4 */ );

	  udp_register_dst_port (vm, UDP_DST_PORT_dns6,
				 dns6_request_node.index, 0 /* is_ip4 */ );

	  dm->udp_ports_registered = 1;
	}

      if (dm->cache_entry_by_name == 0)
	{
	  if (n_vlib_mains > 1)
	    clib_spinlock_init (&dm->cache_lock);

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
  vlib_main_t *vm = vlib_get_main ();
  dns_main_t *dm = &dns_main;
  int rv;

  rv = dns_enable_disable (vm, dm, mp->enable);

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

void
vnet_dns_send_dns4_request (vlib_main_t * vm, dns_main_t * dm,
			    dns_cache_entry_t * ep, ip4_address_t * server)
{
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
      if (0)
	clib_warning ("no fib table");
      return;
    }

  fei = fib_table_lookup (fib_index, &prefix);

  /* Couldn't find route to destination. Bail out. */
  if (fei == FIB_NODE_INDEX_INVALID)
    {
      if (0)
	clib_warning ("no route to DNS server");
      return;
    }

  sw_if_index = fib_entry_get_resolving_interface (fei);

  if (sw_if_index == ~0)
    {
      if (0)
	clib_warning
	  ("route to %U exists, fei %d, get_resolving_interface returned"
	   " ~0", format_ip4_address, &prefix.fp_addr, fei);
      return;
    }

  /* *INDENT-OFF* */
  foreach_ip_interface_address(lm4, ia, sw_if_index, 1 /* honor unnumbered */,
  ({
    src_address = ip_interface_address_get_address (lm4, ia);
    goto found_src_address;
  }));
  /* *INDENT-ON* */

  clib_warning ("FIB BUG");
  return;

found_src_address:

  /* Go get a buffer */
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
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
  clib_memset (ip, 0, sizeof (*ip));
  udp = (udp_header_t *) (ip + 1);
  clib_memset (udp, 0, sizeof (*udp));

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

void
vnet_dns_send_dns6_request (vlib_main_t * vm, dns_main_t * dm,
			    dns_cache_entry_t * ep, ip6_address_t * server)
{
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
      if (0)
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
  foreach_ip_interface_address(lm6, ia, sw_if_index, 1 /* honor unnumbered */,
  ({
    src_address = ip_interface_address_get_address (lm6, ia);
    goto found_src_address;
  }));
  /* *INDENT-ON* */

  clib_warning ("FIB BUG");
  return;

found_src_address:

  /* Go get a buffer */
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return;

  b = vlib_get_buffer (vm, bi);
  b->current_length = sizeof (ip6_header_t) + sizeof (udp_header_t) +
    vec_len (ep->dns_request);
  b->total_length_not_including_first_buffer = 0;
  b->flags =
    VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_LOCALLY_ORIGINATED;

  ip = vlib_buffer_get_current (b);
  clib_memset (ip, 0, sizeof (*ip));
  udp = (udp_header_t *) (ip + 1);
  clib_memset (udp, 0, sizeof (*udp));

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
vnet_dns_labels_to_name (u8 * label, u8 * full_text, u8 ** parse_from_here)
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
vnet_send_dns_request (vlib_main_t * vm, dns_main_t * dm,
		       dns_cache_entry_t * ep)
{
  dns_header_t *h;
  dns_query_t *qp;
  u16 tmp;
  u8 *request;
  u32 qp_offset;

  /* This can easily happen if sitting in GDB, etc. */
  if (ep->flags & DNS_CACHE_ENTRY_FLAG_VALID || ep->server_fails > 1)
    return;

  /* Construct the dns request, if we haven't been here already */
  if (vec_len (ep->dns_request) == 0)
    {
      /*
       * Start with the variadic portion of the exercise.
       * Turn the name into a set of DNS "labels". Max length
       * per label is 63, enforce that.
       */
      if (vec_len (ep->pending_requests) == 0)
	return;

      request = name_to_labels (ep->pending_requests->name);
      qp_offset = vec_len (request);

      /*
       * At least when testing against "known good" DNS servers:
       * it turns out that sending 2x requests - one for an A-record
       * and another for a AAAA-record - seems to work better than
       * sending a DNS_TYPE_ALL request.
       */

      /* Add space for the query header */
      vec_validate (request, 2 * qp_offset + 2 * sizeof (dns_query_t) - 1);

      qp = (dns_query_t *) (request + qp_offset);

      *qp = ep->pending_requests->query;

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
	      vnet_dns_send_dns6_request
		(vm, dm, ep, dm->ip6_name_servers + ep->server_rotor);
	      goto out;
	    }
	  else
	    ep->server_af = 0;
	}
      if (vec_len (dm->ip4_name_servers))
	{
	  vnet_dns_send_dns4_request
	    (vm, dm, ep, dm->ip4_name_servers + ep->server_rotor);
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
    vnet_dns_send_dns6_request
      (vm, dm, ep, dm->ip6_name_servers + ep->server_rotor);
  else
    vnet_dns_send_dns4_request
      (vm, dm, ep, dm->ip4_name_servers + ep->server_rotor);

out:

  vlib_process_signal_event_mt (vm,
				dm->resolver_process_node_index,
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
  vec_free (ep->pending_requests);
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

  dns_cache_lock (dm, 2);
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

  /*
   * Silence spurious coverity warning. We know pool_elts >> 0, or
   * we wouldn't be here...
   */
#ifdef __COVERITY__
  if (pool_elts (dm->entries) == 0)
    return VNET_API_ERROR_UNSPECIFIED;
#endif

  dns_cache_lock (dm, 3);
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

  dns_cache_lock (dm, 4);
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
  clib_memset (ep, 0, sizeof (*ep));

  /* Note: consumes the name vector */
  ep->name = name;
  /* make sure it NULL-terminated as hash_set_mem will use strlen() */
  vec_terminate_c_string (ep->name);
  hash_set_mem (dm->cache_entry_by_name, name, ep - dm->entries);
  ep->flags = DNS_CACHE_ENTRY_FLAG_VALID | DNS_CACHE_ENTRY_FLAG_STATIC;
  ep->dns_response = dns_reply_data;

  dns_cache_unlock (dm);
  return 0;
}

int
vnet_dns_resolve_name (vlib_main_t * vm, dns_main_t * dm, u8 * name,
		       dns_pending_request_t * t, dns_cache_entry_t ** retp)
{
  dns_cache_entry_t *ep;
  int rv;
  f64 now;
  uword *p;
  dns_pending_request_t *pr;
  int count;

  now = vlib_time_now (vm);

  /* In case we can't actually answer the question right now... */
  *retp = 0;

  /* binary API caller might forget to set the name. Guess how we know. */
  if (name[0] == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  dns_cache_lock (dm, 5);
search_again:
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
	      int i;
	      u32 *indices_to_delete = 0;

	      /*
	       * Take out the rest of the resolution chain
	       * This isn't optimal, but it won't happen very often.
	       */
	      while (ep)
		{
		  if ((ep->flags & DNS_CACHE_ENTRY_FLAG_CNAME))
		    {
		      vec_add1 (indices_to_delete, ep - dm->entries);

		      p = hash_get_mem (dm->cache_entry_by_name, ep->cname);
		      if (!p)
			break;
		      ep = pool_elt_at_index (dm->entries, p[0]);
		    }
		  else
		    {
		      vec_add1 (indices_to_delete, ep - dm->entries);
		      break;
		    }
		}
	      for (i = 0; i < vec_len (indices_to_delete); i++)
		{
		  /* Reenable to watch re-resolutions */
		  if (0)
		    {
		      ep = pool_elt_at_index (dm->entries,
					      indices_to_delete[i]);
		      clib_warning ("Re-resolve %s", ep->name);
		    }

		  vnet_dns_delete_entry_by_index_nolock
		    (dm, indices_to_delete[i]);
		}
	      vec_free (indices_to_delete);
	      /* Yes, kill it... */
	      goto re_resolve;
	    }

	  if (ep->flags & DNS_CACHE_ENTRY_FLAG_CNAME)
	    {
	      name = ep->cname;
	      goto search_again;
	    }
	  *retp = ep;
	  dns_cache_unlock (dm);
	  return (0);
	}
      else
	{
	  /*
	   * Resolution pending. Add request to the pending vector
	   * by copying the template request
	   */
	  vec_add2 (ep->pending_requests, pr, 1);
	  memcpy (pr, t, sizeof (*pr));
	  dns_cache_unlock (dm);
	  return (0);
	}
    }

re_resolve:
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

  /* add new hash table entry */
  pool_get (dm->entries, ep);
  clib_memset (ep, 0, sizeof (*ep));

  ep->name = format (0, "%s%c", name, 0);
  _vec_len (ep->name) = vec_len (ep->name) - 1;

  hash_set_mem (dm->cache_entry_by_name, ep->name, ep - dm->entries);

  vec_add1 (dm->unresolved_entries, ep - dm->entries);
  vec_add2 (ep->pending_requests, pr, 1);

  pr->request_type = t->request_type;

  /* Remember details so we can reply later... */
  if (t->request_type == DNS_API_PENDING_NAME_TO_IP ||
      t->request_type == DNS_API_PENDING_IP_TO_NAME)
    {
      pr->client_index = t->client_index;
      pr->client_context = t->client_context;
    }
  else
    {
      pr->client_index = ~0;
      pr->is_ip6 = t->is_ip6;
      pr->dst_port = t->dst_port;
      pr->id = t->id;
      pr->name = t->name;
      pr->query = t->query;
      if (t->is_ip6)
	count = 16;
      else
	count = 4;
      clib_memcpy (pr->dst_address, t->dst_address, count);
    }

  vnet_send_dns_request (vm, dm, ep);
  dns_cache_unlock (dm);
  return 0;
}

#define foreach_notification_to_move            \
_(pending_requests)

/**
 * Handle cname indirection. JFC. Called with the cache locked.
 * returns 0 if the reply is not a CNAME.
 */

int
vnet_dns_cname_indirection_nolock (vlib_main_t * vm, dns_main_t * dm,
				   u32 ep_index, u8 * reply)
{
  dns_header_t *h;
  dns_query_t *qp;
  dns_rr_t *rr;
  u8 *curpos;
  u8 *pos, *pos2;
  u8 *cname_pos = 0;
  int len, i;
  u8 *cname = 0;
  u8 *request = 0;
  u8 *name_copy;
  u32 qp_offset;
  u16 flags;
  u16 rcode;
  dns_cache_entry_t *ep, *next_ep;
  f64 now;

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
      return -1;
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
      pos += sizeof (dns_query_t);
    }
  pos2 = pos;
  /* expect a pointer chase here for a CNAME record */
  if ((pos2[0] & 0xC0) == 0xC0)
    pos += 2;
  else
    return 0;

  /* Walk the answer(s) to see what to do next */
  for (i = 0; i < clib_net_to_host_u16 (h->anscount); i++)
    {
      rr = (dns_rr_t *) pos;
      switch (clib_net_to_host_u16 (rr->type))
	{
	  /* Real address record? Done.. */
	case DNS_TYPE_A:
	case DNS_TYPE_AAAA:
	  return 0;
	  /*
	   * Maybe chase a CNAME pointer?
	   * It's not unheard-of for name-servers to return
	   * both CNAME and A/AAAA records...
	   */
	case DNS_TYPE_CNAME:
	  cname_pos = pos;
	  break;

	  /* Some other junk, e.g. a nameserver... */
	default:
	  break;
	}
      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      /* Skip name... */
      if ((pos2[0] & 0xc0) == 0xc0)
	pos += 2;
    }

  /* Neither a CNAME nor a real address. Try another server */
  if (cname_pos == 0)
    {
      flags &= ~DNS_RCODE_MASK;
      flags |= DNS_RCODE_NAME_ERROR;
      h->flags = clib_host_to_net_u16 (flags);
      return -1;
    }

  /* This is a CNAME record, chase the name chain. */
  pos = cname_pos;

  /* The last request is no longer pending.. */
  for (i = 0; i < vec_len (dm->unresolved_entries); i++)
    if (ep_index == dm->unresolved_entries[i])
      {
	vec_delete (dm->unresolved_entries, 1, i);
	goto found_last_request;
      }
  clib_warning ("pool elt %d supposedly pending, but not found...", ep_index);
  return -1;

found_last_request:

  now = vlib_time_now (vm);
  cname = vnet_dns_labels_to_name (rr->rdata, reply, &pos2);
  /* Save the cname */
  vec_add1 (cname, 0);
  _vec_len (cname) -= 1;
  ep = pool_elt_at_index (dm->entries, ep_index);
  ep->cname = cname;
  ep->flags |= (DNS_CACHE_ENTRY_FLAG_CNAME | DNS_CACHE_ENTRY_FLAG_VALID);
  /* Save the response */
  if (ep->dns_response)
    vec_free (ep->dns_response);
  ep->dns_response = reply;
  /* Set up expiration time */
  ep->expiration_time = now + clib_net_to_host_u32 (rr->ttl);

  pool_get (dm->entries, next_ep);

  /* Need to recompute ep post pool-get */
  ep = pool_elt_at_index (dm->entries, ep_index);

  clib_memset (next_ep, 0, sizeof (*next_ep));
  next_ep->name = vec_dup (cname);
  vec_add1 (next_ep->name, 0);
  _vec_len (next_ep->name) -= 1;

  hash_set_mem (dm->cache_entry_by_name, next_ep->name,
		next_ep - dm->entries);

  /* Use the same server */
  next_ep->server_rotor = ep->server_rotor;
  next_ep->server_af = ep->server_af;

  /* Move notification data to the next name in the chain */
#define _(a) next_ep->a = ep->a; ep->a = 0;
  foreach_notification_to_move;
#undef _

  request = name_to_labels (cname);
  name_copy = vec_dup (request);

  qp_offset = vec_len (request);

  /* Add space for the query header */
  vec_validate (request, 2 * qp_offset + 2 * sizeof (dns_query_t) - 1);

  qp = (dns_query_t *) (request + qp_offset);

  qp->type = clib_host_to_net_u16 (DNS_TYPE_A);
  qp->class = clib_host_to_net_u16 (DNS_CLASS_IN);
  clib_memcpy (qp, name_copy, vec_len (name_copy));
  qp = (dns_query_t *) (((u8 *) qp) + vec_len (name_copy));
  vec_free (name_copy);

  qp->type = clib_host_to_net_u16 (DNS_TYPE_AAAA);
  qp->class = clib_host_to_net_u16 (DNS_CLASS_IN);

  /* Punch in space for the dns_header_t */
  vec_insert (request, sizeof (dns_header_t), 0);

  h = (dns_header_t *) request;

  /* Transaction ID = pool index */
  h->id = clib_host_to_net_u16 (next_ep - dm->entries);

  /* Ask for a recursive lookup */
  h->flags = clib_host_to_net_u16 (DNS_RD | DNS_OPCODE_QUERY);
  h->qdcount = clib_host_to_net_u16 (2);
  h->nscount = 0;
  h->arcount = 0;

  next_ep->dns_request = request;
  next_ep->retry_timer = now + 2.0;
  next_ep->retry_count = 0;

  /*
   * Enable this to watch recursive resolution happen...
   * fformat (stdout, "%U", format_dns_reply, request, 2);
   */

  vec_add1 (dm->unresolved_entries, next_ep - dm->entries);
  vnet_send_dns_request (vm, dm, next_ep);
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
  u8 *curpos, *pos, *pos2;
  u16 flags;
  u16 rcode;
  u32 ttl;
  int pointer_chase;

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
      pos = pos2 = curpos;
      pointer_chase = 0;

      /* Expect pointer chases in the answer section... */
      if ((pos2[0] & 0xC0) == 0xC0)
	{
	  pos = pos2 + 2;
	  pos2 = response + ((pos2[0] & 0x3f) << 8) + pos2[1];
	  pointer_chase = 1;
	}

      len = *pos2++;

      while (len)
	{
	  pos2 += len;
	  if ((pos2[0] & 0xc0) == 0xc0)
	    {
	      /*
	       * If we've already done one pointer chase,
	       * do not move the pos pointer.
	       */
	      if (pointer_chase == 0)
		pos = pos2 + 2;
	      pos2 = response + ((pos2[0] & 0x3f) << 8) + pos2[1];
	      len = *pos2++;
	      pointer_chase = 1;
	    }
	  else
	    len = *pos2++;
	}

      if (pointer_chase == 0)
	pos = pos2;

      rr = (dns_rr_t *) pos;

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
      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      curpos = pos;
    }

  if ((rmp->ip4_set + rmp->ip6_set) == 0)
    return VNET_API_ERROR_NAME_SERVER_NO_ADDRESSES;
  return 0;
}

int
vnet_dns_response_to_reply6 (u8 *response,
			     vl_api_dns_resolve_name6_reply_t *rmp,
			     u32 *min_ttlp)
{
  dns_header_t *h;
  dns_query_t *qp;
  dns_rr_t *rr;
  int i, limit;
  u8 len;
  u8 *curpos, *pos, *pos2;
  u16 flags;
  u16 rcode;
  u32 ttl;
  int pointer_chase;

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
      pos = pos2 = curpos;
      pointer_chase = 0;

      /* Expect pointer chases in the answer section... */
      if ((pos2[0] & 0xC0) == 0xC0)
	{
	  pos = pos2 + 2;
	  pos2 = response + ((pos2[0] & 0x3f) << 8) + pos2[1];
	  pointer_chase = 1;
	}

      len = *pos2++;

      while (len)
	{
	  pos2 += len;
	  if ((pos2[0] & 0xc0) == 0xc0)
	    {
	      /*
	       * If we've already done one pointer chase,
	       * do not move the pos pointer.
	       */
	      if (pointer_chase == 0)
		pos = pos2 + 2;
	      pos2 = response + ((pos2[0] & 0x3f) << 8) + pos2[1];
	      len = *pos2++;
	      pointer_chase = 1;
	    }
	  else
	    len = *pos2++;
	}

      if (pointer_chase == 0)
	pos = pos2;

      rr = (dns_rr_t *) pos;

      if (clib_net_to_host_u16 (rr->type) != DNS_TYPE_AAAA)
	return VNET_API_ERROR_NAME_SERVER_NO_ADDRESSES;

      /* Collect an ip6 address. Do not pass go. Do not collect $200 */
      memcpy (rmp->ip6_address, rr->rdata, sizeof (ip6_address_t));
      ttl = clib_net_to_host_u32 (rr->ttl);
      if (min_ttlp && *min_ttlp > ttl)
	*min_ttlp = ttl;
      rmp->ip6_set = 1;

      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      curpos = pos;
    }

  return 0;
}

int
vnet_dns_response_to_name (u8 * response,
			   vl_api_dns_resolve_ip_reply_t * rmp,
			   u32 * min_ttlp)
{
  dns_header_t *h;
  dns_query_t *qp;
  dns_rr_t *rr;
  int i, limit;
  u8 len;
  u8 *curpos, *pos, *pos2;
  u16 flags;
  u16 rcode;
  u8 *name;
  u32 ttl;
  u8 *junk __attribute__ ((unused));
  int name_set = 0;
  int pointer_chase;

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
      pos = pos2 = curpos;
      pointer_chase = 0;

      /* Expect pointer chases in the answer section... */
      if ((pos2[0] & 0xC0) == 0xC0)
	{
	  pos = pos2 + 2;
	  pos2 = response + ((pos2[0] & 0x3f) << 8) + pos2[1];
	  pointer_chase = 1;
	}

      len = *pos2++;

      while (len)
	{
	  pos2 += len;
	  if ((pos2[0] & 0xc0) == 0xc0)
	    {
	      /*
	       * If we've already done one pointer chase,
	       * do not move the pos pointer.
	       */
	      if (pointer_chase == 0)
		pos = pos2 + 2;
	      pos2 = response + ((pos2[0] & 0x3f) << 8) + pos2[1];
	      len = *pos2++;
	      pointer_chase = 1;
	    }
	  else
	    len = *pos2++;
	}

      if (pointer_chase == 0)
	pos = pos2;

      rr = (dns_rr_t *) pos;

      switch (clib_net_to_host_u16 (rr->type))
	{
	case DNS_TYPE_PTR:
	  name = vnet_dns_labels_to_name (rr->rdata, response, &junk);
	  memcpy (rmp->name, name, vec_len (name));
	  ttl = clib_net_to_host_u32 (rr->ttl);
	  if (min_ttlp)
	    *min_ttlp = ttl;
	  rmp->name[vec_len (name)] = 0;
	  name_set = 1;
	  break;
	default:
	  break;
	}
      /* Might as well stop ASAP */
      if (name_set == 1)
	break;
      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      curpos = pos;
    }

  if (name_set == 0)
    return VNET_API_ERROR_NAME_SERVER_NO_SUCH_NAME;
  return 0;
}

static void
vl_api_dns_resolve_name_t_handler (vl_api_dns_resolve_name_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  dns_main_t *dm = &dns_main;
  vl_api_dns_resolve_name_reply_t *rmp;
  dns_cache_entry_t *ep;
  dns_pending_request_t _t0, *t0 = &_t0;
  u8 *name_ex = 0;
  int rv;

  /* Sanitize the name slightly */
  mp->name[ARRAY_LEN (mp->name) - 1] = 0;

  t0->request_type = DNS_API_PENDING_NAME_TO_IP;
  t0->client_index = mp->client_index;
  t0->client_context = mp->context;
  t0->query.type = clib_host_to_net_u16 (DNS_TYPE_A);
  t0->query.class = clib_host_to_net_u16 (DNS_CLASS_IN);

  int len = strlen ((char *) mp->name);
  vec_validate (name_ex, len);
  clib_memcpy (name_ex, mp->name, len);
  _vec_len (name_ex) -= 1;

  vnet_dns_format_name (&name_ex, DNS_TYPE_A);
  rv = vnet_dns_resolve_name (vm, dm, name_ex, t0, &ep);
  vec_free (name_ex);

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
}

static void
vl_api_dns_resolve_name6_t_handler (vl_api_dns_resolve_name6_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  dns_main_t *dm = &dns_main;
  vl_api_dns_resolve_name6_reply_t *rmp;
  dns_cache_entry_t *ep;
  dns_pending_request_t _t0, *t0 = &_t0;
  u8 *name_ex = 0;
  int rv;

  /* Sanitize the name slightly */
  mp->name[ARRAY_LEN (mp->name) - 1] = 0;

  t0->request_type = DNS_API_PENDING_NAME_TO_IP;
  t0->client_index = mp->client_index;
  t0->client_context = mp->context;
  t0->query.type = clib_host_to_net_u16 (DNS_TYPE_AAAA);
  t0->query.class = clib_host_to_net_u16 (DNS_CLASS_IN);

  int len = strlen ((char *) mp->name);
  vec_validate (name_ex, len);
  clib_memcpy (name_ex, mp->name, len);
  _vec_len (name_ex) -= 1;

  vnet_dns_format_name (&name_ex, DNS_TYPE_AAAA);
  rv = vnet_dns_resolve_name (vm, dm, name_ex, t0, &ep);
  vec_free (name_ex);

  /* Error, e.g. not enabled? Tell the user */
  if (rv < 0)
    {
      REPLY_MACRO (VL_API_DNS_RESOLVE_NAME6_REPLY);
      return;
    }

  /* Resolution pending? Don't reply... */
  if (ep == 0)
    return;

  REPLY_MACRO2 (VL_API_DNS_RESOLVE_NAME6_REPLY, ({
		  rv = vnet_dns_response_to_reply6 (ep->dns_response, rmp,
						    0 /* ttl-ptr */);
		  rmp->retval = clib_host_to_net_u32 (rv);
		}));
}

static void
vl_api_dns_resolve_ip_t_handler (vl_api_dns_resolve_ip_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  dns_main_t *dm = &dns_main;
  vl_api_dns_resolve_ip_reply_t *rmp;
  dns_cache_entry_t *ep;
  int rv;
  int i, len;
  u8 *lookup_name = 0;
  u8 digit, nybble;
  dns_pending_request_t _t0, *t0 = &_t0;

  if (mp->is_ip6)
    {
      for (i = 15; i >= 0; i--)
	{
	  digit = mp->address[i];
	  nybble = (digit & 0x0F);
	  if (nybble > 9)
	    vec_add1 (lookup_name, (nybble - 10) + 'a');
	  else
	    vec_add1 (lookup_name, nybble + '0');
	  vec_add1 (lookup_name, '.');
	  nybble = (digit & 0xF0) >> 4;
	  if (nybble > 9)
	    vec_add1 (lookup_name, (nybble - 10) + 'a');
	  else
	    vec_add1 (lookup_name, nybble + '0');
	  vec_add1 (lookup_name, '.');
	}
      len = vec_len (lookup_name);
      vec_validate (lookup_name, len + 8);
      memcpy (lookup_name + len, "ip6.arpa", 8);
    }
  else
    {
      for (i = 3; i >= 0; i--)
	{
	  digit = mp->address[i];
	  lookup_name = format (lookup_name, "%d.", digit);
	}
      lookup_name = format (lookup_name, "in-addr.arpa");
    }

  vec_add1 (lookup_name, 0);

  t0->request_type = DNS_API_PENDING_IP_TO_NAME;
  t0->client_index = mp->client_index;
  t0->client_context = mp->context;

  rv = vnet_dns_resolve_name (vm, dm, lookup_name, t0, &ep);

  vec_free (lookup_name);

  /* Error, e.g. not enabled? Tell the user */
  if (rv < 0)
    {
      REPLY_MACRO (VL_API_DNS_RESOLVE_IP_REPLY);
      return;
    }

  /* Resolution pending? Don't reply... */
  if (ep == 0)
    return;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_DNS_RESOLVE_IP_REPLY,
  ({
    rv = vnet_dns_response_to_name (ep->dns_response, rmp, 0 /* ttl-ptr */);
    rmp->retval = clib_host_to_net_u32 (rv);
  }));
  /* *INDENT-ON* */
}

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
  u8 *type;
  u8 *ce;
  u32 qp_offset;
  dns_header_t *h;
  dns_query_t *qp;
  dns_rr_t *rr;
  u8 *rru8;

  /* Must have a name */
  if (!unformat (input, "%v", &name))
    return 0;

  /* Must have a type */
  if (!unformat (input, "%v", &type))
    return 0;

  if ((0 != clib_memcmp (&type, "aaaa", 5)) ||
      (0 != clib_memcmp (&type, "AAAA", 5)))
    {
      if (unformat (input, "%U", unformat_ip6_address, &a6))
	a6_set = 1;
    }

  if ((0 != clib_memcmp (&type, "a", 2)) ||
      (0 != clib_memcmp (&type, "A", 2)))
    if (unformat (input, "%U", unformat_ip4_address, &a4))
      a4_set = 1;

  /* Must have at least one address */
  if (!(a4_set + a6_set))
    return 0;

  /* Build a fake DNS cache entry string, one hemorrhoid at a time */
  ce = name_to_labels (name);
  qp_offset = vec_len (ce);

  /* Add space for the query header */
  vec_validate (ce, qp_offset + sizeof (dns_query_t) - 1);
  qp = (dns_query_t *) (ce + qp_offset);

  qp->class = clib_host_to_net_u16 (DNS_CLASS_IN);
  if (a4_set)
    qp->type = clib_host_to_net_u16 (DNS_TYPE_A);
  else if (a6_set)
    qp->type = clib_host_to_net_u16 (DNS_TYPE_AAAA);

  /* Punch in space for the dns_header_t */
  vec_insert (ce, sizeof (dns_header_t), 0);

  h = (dns_header_t *) ce;

  /* Fake Transaction ID */
  h->id = 0xFFFF;

  h->flags = clib_host_to_net_u16 (DNS_RD | DNS_RA);
  h->qdcount = clib_host_to_net_u16 (1);
  h->anscount = clib_host_to_net_u16 (1);
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

      if (namep)
	{
	  *namep = name;
	  vnet_dns_format_name (namep, DNS_TYPE_A);
	}
      else
	vec_free (name);
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

      if (namep)
	{
	  *namep = name;
	  vnet_dns_format_name (namep, DNS_TYPE_AAAA);
	}
      else
	vec_free (name);
    }
  *result = ce;

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

#define foreach_query_type1                                                   \
  _ (A, "type A     ")                                                        \
  _ (AAAA, "type AAAA  ")                                                     \
  _ (NAMESERVER, "type NS    ")                                               \
  _ (CNAME, "type CNAME ")                                                    \
  _ (MAIL_EXCHANGE, "type MX    ")                                            \
  _ (PTR, "type PTR   ")                                                      \
  _ (ALL, "type ALL   ")

  switch (clib_net_to_host_u16 (qp->type))
    {
#define _(type, str)                                                          \
  case DNS_TYPE_##type:                                                       \
    s = format (s, str);                                                      \
    break;
      foreach_query_type1;
#undef _
    default:
      s = format (s, "type %-5d ", clib_net_to_host_u16 (qp->type));
      break;
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
  int pointer_chase = 0;
  u16 *tp;
  u16 rrtype_host_byte_order;

  pos = pos2 = *curpos;

  if (verbose > 1)
    s = format (s, "    ");

  /* chase pointer? almost always yes here... */
  if ((pos2[0] & 0xc0) == 0xc0)
    {
      pos = pos2 + 2;
      pos2 = reply + ((pos2[0] & 0x3f) << 8) + pos2[1];
      pointer_chase = 1;
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
      if ((pos2[0] & 0xc0) == 0xc0)
	{
	  /*
	   * If we've already done one pointer chase,
	   * do not move the pos pointer.
	   */
	  if (pointer_chase == 0)
	    pos = pos2 + 2;
	  pos2 = reply + ((pos2[0] & 0x3f) << 8) + pos2[1];
	  len = *pos2++;
	  pointer_chase = 1;
	}
      else
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

  if (pointer_chase == 0)
    pos = pos2;

  rr = (dns_rr_t *) pos;
  rrtype_host_byte_order = clib_net_to_host_u16 (rr->type);

  switch (rrtype_host_byte_order)
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

    case DNS_TYPE_HINFO:
      {
	/* Two counted strings. DGMS */
	u8 *len;
	u8 *curpos;
	int i;
	if (verbose > 1)
	  {
	    s = format (s, "HINFO: ");
	    len = rr->rdata;
	    curpos = len + 1;
	    for (i = 0; i < *len; i++)
	      vec_add1 (s, *curpos++);

	    vec_add1 (s, ' ');
	    len = curpos++;
	    for (i = 0; i < *len; i++)
	      vec_add1 (s, *curpos++);

	    vec_add1 (s, '\n');
	  }
      }
      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      break;

    case DNS_TYPE_NAMESERVER:
      if (verbose > 1)
	{
	  s = format (s, "Nameserver: ");
	  pos2 = rr->rdata;

	  /* chase pointer? */
	  if ((pos2[0] & 0xc0) == 0xc0)
	    {
	      pos = pos2 + 2;
	      pos2 = reply + ((pos2[0] & 0x3f) << 8) + pos2[1];
	    }

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

    case DNS_TYPE_PTR:
    case DNS_TYPE_CNAME:
      if (verbose > 1)
	{
	  tp = (u16 *) rr->rdata;

	  if (rrtype_host_byte_order == DNS_TYPE_CNAME)
	    s = format (s, "CNAME: ");
	  else
	    s = format (s, "PTR: ");

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

  dns_cache_lock (dm, 6);

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

	      if (verbose < 2 && ep->flags & DNS_CACHE_ENTRY_FLAG_CNAME)
		s = format (s, "%s%s -> %s", ss, ep->name, ep->cname);
	      else
		s = format (s, "%s%s -> %U", ss, ep->name, format_dns_reply,
			    ep->dns_response, verbose);
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

  s = format (s, "DNS cache contains %d entries\n", pool_elts (dm->entries));

  if (verbose > 0)
    {
      /* *INDENT-OFF* */
      pool_foreach (ep, dm->entries)
       {
        if (ep->flags & DNS_CACHE_ENTRY_FLAG_VALID)
          {
            ASSERT (ep->dns_response);
            if (ep->flags & DNS_CACHE_ENTRY_FLAG_STATIC)
              ss = "[S] ";
            else
              ss = "    ";

            if (verbose < 2 && ep->flags & DNS_CACHE_ENTRY_FLAG_CNAME)
              s = format (s, "%s%s -> %s", ss, ep->name, ep->cname);
            else
	      s = format (s, "%s%s -> %U", ss, ep->name, format_dns_reply,
			  ep->dns_response, verbose);
	    if (!(ep->flags & DNS_CACHE_ENTRY_FLAG_STATIC))
	      {
		f64 time_left = ep->expiration_time - now;
		if (time_left > 0.0)
		  s = format (s, "  TTL left %.1f", time_left);
		else
		  s = format (s, "  EXPIRED");

		if (verbose > 2)
		  s = format (s, "    %d client notifications pending\n",
			      vec_len (ep->pending_requests));
	      }
	  }
	else
	  {
	    ASSERT (ep->dns_request);
	    s =
	      format (s, "[P] %U", format_dns_reply, ep->dns_request, verbose);
	  }
	vec_add1 (s, '\n');
      }
      /* *INDENT-ON* */
    }

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
show_dns_servers_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  dns_main_t *dm = &dns_main;
  int i;

  if ((vec_len (dm->ip4_name_servers) + vec_len (dm->ip6_name_servers)) == 0)
    return clib_error_return (0, "No name servers configured...");

  if (vec_len (dm->ip4_name_servers))
    {
      vlib_cli_output (vm, "ip4 name servers:");
      for (i = 0; i < vec_len (dm->ip4_name_servers); i++)
	vlib_cli_output (vm, "%U", format_ip4_address,
			 dm->ip4_name_servers + i);
    }
  if (vec_len (dm->ip6_name_servers))
    {
      vlib_cli_output (vm, "ip6 name servers:");
      for (i = 0; i < vec_len (dm->ip6_name_servers); i++)
	vlib_cli_output (vm, "%U", format_ip6_address,
			 dm->ip4_name_servers + i);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_dns_server_command) =
{
  .path = "show dns servers",
  .short_help = "show dns servers",
  .function = show_dns_servers_command_fn,
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

/* bind8 (linux widget, w/ nasty double pointer chasees */
static u8 dns_reply_data_initializer[] = {
  /* 0 */
  0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08,
  /* 8 */
  0x00, 0x06, 0x00, 0x06, 0x0a, 0x6f, 0x72, 0x69,
  /* 16 */
  0x67, 0x69, 0x6e, 0x2d, 0x77, 0x77, 0x77, 0x05,
  /* 24 */
  0x63, 0x69, 0x73, 0x63, 0x6f, 0x03, 0x63, 0x6f,
  /* 32 */
  0x6d, 0x00, 0x00, 0xff, 0x00, 0x01, 0x0a, 0x6f,
  /* 40 */
  0x72, 0x69, 0x67, 0x69, 0x6e, 0x2d, 0x77, 0x77,
  /* 48 */
  0x77, 0x05, 0x43, 0x49, 0x53, 0x43, 0x4f, 0xc0,

  /* 56 */
  0x1d, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x05,

  /* 64 */
  0x9a, 0x00, 0x18, 0x15, 0x72, 0x63, 0x64,
  0x6e, 0x39, 0x2d, 0x31, 0x34, 0x70, 0x2d, 0x64, 0x63,
  0x7a, 0x30, 0x35, 0x6e, 0x2d, 0x67, 0x73, 0x73, 0x31,
  0xc0, 0x17, 0xc0, 0x26, 0x00, 0x02, 0x00, 0x01, 0x00,
  0x00, 0x05, 0x9a, 0x00, 0x1a, 0x17, 0x61, 0x6c, 0x6c,
  0x6e, 0x30, 0x31, 0x2d, 0x61, 0x67, 0x30, 0x39, 0x2d,
  0x64, 0x63, 0x7a, 0x30, 0x33, 0x6e, 0x2d, 0x67, 0x73,
  0x73, 0x31, 0xc0, 0x17, 0xc0, 0x26, 0x00, 0x02, 0x00,
  0x01, 0x00, 0x00, 0x05, 0x9a, 0x00, 0x10, 0x0d, 0x72,
  0x74, 0x70, 0x35, 0x2d, 0x64, 0x6d, 0x7a, 0x2d, 0x67,
  0x73, 0x73, 0x31, 0xc0, 0x17, 0xc0, 0x26, 0x00, 0x02,
  0x00, 0x01, 0x00, 0x00, 0x05, 0x9a, 0x00, 0x18, 0x15,
  0x6d, 0x74, 0x76, 0x35, 0x2d, 0x61, 0x70, 0x31, 0x30,
  0x2d, 0x64, 0x63, 0x7a, 0x30, 0x36, 0x6e, 0x2d, 0x67,
  0x73, 0x73, 0x31, 0xc0, 0x17, 0xc0, 0x26, 0x00, 0x02,
  0x00, 0x01, 0x00, 0x00, 0x05, 0x9a, 0x00, 0x1b, 0x18,
  0x73, 0x6e, 0x67, 0x64, 0x63, 0x30, 0x31, 0x2d, 0x61,
  0x62, 0x30, 0x37, 0x2d, 0x64, 0x63, 0x7a, 0x30, 0x31,
  0x6e, 0x2d, 0x67, 0x73, 0x73, 0x31, 0xc0, 0x17, 0xc0,
  0x26, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x05, 0x9a,
  0x00, 0x1a, 0x17, 0x61, 0x65, 0x72, 0x30, 0x31, 0x2d,
  0x72, 0x34, 0x63, 0x32, 0x35, 0x2d, 0x64, 0x63, 0x7a,
  0x30, 0x31, 0x6e, 0x2d, 0x67, 0x73, 0x73, 0x31, 0xc0,
  0x17, 0xc0, 0x26, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x81, 0x00, 0x04, 0x48, 0xa3, 0x04, 0xa1, 0xc0,
  0x26, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x82,
  0x00, 0x10, 0x20, 0x01, 0x04, 0x20, 0x12, 0x01, 0x00,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
  0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x05,
  0x9a, 0x00, 0x02, 0xc0, 0xf4, 0xc0, 0x0c, 0x00, 0x02,
  0x00, 0x01, 0x00, 0x00, 0x05, 0x9a, 0x00, 0x02, 0xc0,
  0xcd, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00,
  0x05, 0x9a, 0x00, 0x02, 0xc0, 0x8d, 0xc0, 0x0c, 0x00,
  0x02, 0x00, 0x01, 0x00, 0x00, 0x05, 0x9a, 0x00, 0x02,
  0xc0, 0x43, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00,
  0x00, 0x05, 0x9a, 0x00, 0x02, 0xc0, 0xa9, 0xc0, 0x0c,
  0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x05, 0x9a, 0x00,
  0x02, 0xc0, 0x67, 0xc0, 0x8d, 0x00, 0x01, 0x00, 0x01,
  0x00, 0x00, 0x07, 0x08, 0x00, 0x04, 0x40, 0x66, 0xf6,
  0x05, 0xc0, 0xa9, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
  0x07, 0x08, 0x00, 0x04, 0xad, 0x24, 0xe0, 0x64, 0xc0,
  0x43, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x07, 0x08,
  0x00, 0x04, 0x48, 0xa3, 0x04, 0x1c, 0xc0, 0xf4, 0x00,
  0x01, 0x00, 0x01, 0x00, 0x00, 0x07, 0x08, 0x00, 0x04,
  0xad, 0x26, 0xd4, 0x6c, 0xc0, 0x67, 0x00, 0x01, 0x00,
  0x01, 0x00, 0x00, 0x07, 0x08, 0x00, 0x04, 0xad, 0x25,
  0x90, 0x64, 0xc0, 0xcd, 0x00, 0x01, 0x00, 0x01, 0x00,
  0x00, 0x07, 0x08, 0x00, 0x04, 0xad, 0x27, 0x70, 0x44,
};

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

#else
/* www.weatherlink.com */
static u8 dns_reply_data_initializer[] = {
  0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x0b,
  0x77, 0x65, 0x61, 0x74, 0x68, 0x65, 0x72, 0x6c, 0x69,
  0x6e, 0x6b, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0xff,
  0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00,
  0x00, 0x0c, 0x9e, 0x00, 0x1f, 0x0e, 0x64, 0x33, 0x6b,
  0x72, 0x30, 0x67, 0x75, 0x62, 0x61, 0x31, 0x64, 0x76,
  0x77, 0x66, 0x0a, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66,
  0x72, 0x6f, 0x6e, 0x74, 0x03, 0x6e, 0x65, 0x74, 0x00,
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

  clib_memset (rmp, 0, sizeof (*rmp));

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

static clib_error_t *
test_dns_expire_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  dns_main_t *dm = &dns_main;
  u8 *name = 0;
  uword *p;
  clib_error_t *e;
  dns_cache_entry_t *ep;

  if (unformat (input, "%v", &name))
    {
      vec_add1 (name, 0);
      _vec_len (name) -= 1;
    }
  else
    return clib_error_return (0, "no name provided");

  dns_cache_lock (dm, 7);

  p = hash_get_mem (dm->cache_entry_by_name, name);
  if (!p)
    {
      dns_cache_unlock (dm);
      e = clib_error_return (0, "%s is not in the cache...", name);
      vec_free (name);
      return e;
    }

  ep = pool_elt_at_index (dm->entries, p[0]);

  ep->expiration_time = 0;

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_dns_expire_command) =
{
  .path = "test dns expire",
  .short_help = "test dns expire <name>",
  .function = test_dns_expire_command_fn,
};
/* *INDENT-ON* */
#endif

void
vnet_send_dns6_reply (vlib_main_t * vm, dns_main_t * dm,
		      dns_pending_request_t * pr, dns_cache_entry_t * ep,
		      vlib_buffer_t * b0)
{
  clib_warning ("Unimplemented...");
}


void
vnet_send_dns4_reply (vlib_main_t * vm, dns_main_t * dm,
		      dns_pending_request_t * pr, dns_cache_entry_t * ep,
		      vlib_buffer_t * b0)
{
  u32 bi = 0;
  fib_prefix_t prefix;
  fib_node_index_t fei;
  u32 sw_if_index, fib_index;
  ip4_main_t *im4 = &ip4_main;
  ip_lookup_main_t *lm4 = &im4->lookup_main;
  ip_interface_address_t *ia = 0;
  ip4_address_t *src_address;
  ip4_header_t *ip;
  udp_header_t *udp;
  dns_header_t *dh;
  vlib_frame_t *f;
  u32 *to_next;
  u8 *dns_response;
  u8 *reply;
  vl_api_dns_resolve_name_reply_t _rnr, *rnr = &_rnr;
  vl_api_dns_resolve_ip_reply_t _rir, *rir = &_rir;
  u32 ttl = 64, tmp;
  u32 qp_offset;
  dns_query_t *qp;
  dns_rr_t *rr;
  u8 *rrptr;
  int is_fail = 0;
  int is_recycle = (b0 != 0);

  ASSERT (ep && ep->dns_response);

  if (pr->request_type == DNS_PEER_PENDING_NAME_TO_IP)
    {
      /* Quick and dirty way to dig up the A-record address. $$ FIXME */
      clib_memset (rnr, 0, sizeof (*rnr));
      if (vnet_dns_response_to_reply (ep->dns_response, rnr, &ttl))
	{
	  /* clib_warning ("response_to_reply failed..."); */
	  is_fail = 1;
	}
      if (rnr->ip4_set == 0 && rnr->ip6_set == 0)
	{
	  /* clib_warning ("No A-record..."); */
	  is_fail = 1;
	}
    }
  else if (pr->request_type == DNS_PEER_PENDING_IP_TO_NAME)
    {
      clib_memset (rir, 0, sizeof (*rir));
      if (vnet_dns_response_to_name (ep->dns_response, rir, &ttl))
	{
	  /* clib_warning ("response_to_name failed..."); */
	  is_fail = 1;
	}
    }
  else
    {
      clib_warning ("Unknown request type %d", pr->request_type);
      return;
    }

  /* Initialize a buffer */
  if (b0 == 0)
    {
      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	return;
      b0 = vlib_get_buffer (vm, bi);
    }
  else
    {
      /* Use the buffer we were handed. Reinitialize it... */
      vlib_buffer_t bt = { };
      /* push/pop the reference count */
      u8 save_ref_count = b0->ref_count;
      vlib_buffer_copy_template (b0, &bt);
      b0->ref_count = save_ref_count;
      bi = vlib_get_buffer_index (vm, b0);
    }

  if (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
    vlib_buffer_free_one (vm, b0->next_buffer);

  /*
   * Reset the buffer. We recycle the DNS request packet in the cache
   * hit case, and reply immediately from the request node.
   *
   * In the resolution-required / deferred case, resetting a freshly-allocated
   * buffer won't hurt. We hope.
   */
  b0->flags |= (VNET_BUFFER_F_LOCALLY_ORIGINATED
		| VLIB_BUFFER_TOTAL_LENGTH_VALID);
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;	/* "local0" */
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = 0;	/* default VRF for now */

  /* Find a FIB path to the peer we're trying to answer */
  clib_memcpy (&prefix.fp_addr.ip4, pr->dst_address, sizeof (ip4_address_t));
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
  foreach_ip_interface_address(lm4, ia, sw_if_index, 1 /* honor unnumbered */,
  ({
    src_address = ip_interface_address_get_address (lm4, ia);
    goto found_src_address;
  }));
  /* *INDENT-ON* */

  clib_warning ("FIB BUG");
  return;

found_src_address:

  ip = vlib_buffer_get_current (b0);
  udp = (udp_header_t *) (ip + 1);
  dns_response = (u8 *) (udp + 1);
  clib_memset (ip, 0, sizeof (*ip) + sizeof (*udp));

  /*
   * Start with the variadic portion of the exercise.
   * Turn the name into a set of DNS "labels". Max length
   * per label is 63, enforce that.
   */
  reply = name_to_labels (pr->name);
  vec_free (pr->name);

  qp_offset = vec_len (reply);

  /* Add space for the query header */
  vec_validate (reply, qp_offset + sizeof (dns_query_t) - 1);

  qp = (dns_query_t *) (reply + qp_offset);

  *qp = pr->query;

  /* Punch in space for the dns_header_t */
  vec_insert (reply, sizeof (dns_header_t), 0);

  dh = (dns_header_t *) reply;

  /* Transaction ID = pool index */
  dh->id = pr->id;

  /* Announce that we did a recursive lookup */
  tmp = DNS_AA | DNS_RA | DNS_RD | DNS_OPCODE_QUERY | DNS_QR;
  if (is_fail)
    tmp |= DNS_RCODE_NAME_ERROR;
  dh->flags = clib_host_to_net_u16 (tmp);
  dh->qdcount = clib_host_to_net_u16 (1);
  dh->anscount = (is_fail == 0) ? clib_host_to_net_u16 (1) : 0;
  dh->nscount = 0;
  dh->arcount = 0;

  /* If the name resolution worked, cough up an appropriate RR */
  if (is_fail == 0)
    {
      /* Add the answer. First, a name pointer (0xC00C) */
      vec_add1 (reply, 0xC0);
      vec_add1 (reply, 0x0C);

      /* Now, add single A-rec RR */
      if (pr->request_type == DNS_PEER_PENDING_NAME_TO_IP)
	{
	  if (rnr->ip4_set)
	    {
	      vec_add2 (reply, rrptr,
			sizeof (dns_rr_t) + sizeof (ip4_address_t));
	      rr = (dns_rr_t *) rrptr;

	      rr->type = clib_host_to_net_u16 (DNS_TYPE_A);
	      rr->class = clib_host_to_net_u16 (1 /* internet */);
	      rr->ttl = clib_host_to_net_u32 (ttl);
	      rr->rdlength = clib_host_to_net_u16 (sizeof (ip4_address_t));
	      clib_memcpy (rr->rdata, rnr->ip4_address,
			   sizeof (ip4_address_t));
	    }
	  else if (rnr->ip6_set)
	    {
	      vec_add2 (reply, rrptr,
			sizeof (dns_rr_t) + sizeof (ip6_address_t));
	      rr = (dns_rr_t *) rrptr;

	      rr->type = clib_host_to_net_u16 (DNS_TYPE_AAAA);
	      rr->class = clib_host_to_net_u16 (1 /* internet */);
	      rr->ttl = clib_host_to_net_u32 (ttl);
	      rr->rdlength = clib_host_to_net_u16 (sizeof (ip6_address_t));
	      clib_memcpy (rr->rdata, rnr->ip6_address,
			   sizeof (ip6_address_t));
	    }
	}
      else
	{
	  /* Or a single PTR RR */
	  u8 *vecname = format (0, "%s", rir->name);
	  u8 *label_vec = name_to_labels (vecname);
	  vec_free (vecname);

	  vec_add2 (reply, rrptr, sizeof (dns_rr_t) + vec_len (label_vec));
	  rr = (dns_rr_t *) rrptr;
	  rr->type = clib_host_to_net_u16 (DNS_TYPE_PTR);
	  rr->class = clib_host_to_net_u16 (1 /* internet */ );
	  rr->ttl = clib_host_to_net_u32 (ttl);
	  rr->rdlength = clib_host_to_net_u16 (vec_len (label_vec));
	  clib_memcpy (rr->rdata, label_vec, vec_len (label_vec));
	  vec_free (label_vec);
	}
    }
  clib_memcpy (dns_response, reply, vec_len (reply));

  /* Set the packet length */
  b0->current_length = sizeof (*ip) + sizeof (*udp) + vec_len (reply);

  /* IP header */
  ip->ip_version_and_header_length = 0x45;
  ip->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  ip->ttl = 255;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = src_address->as_u32;
  clib_memcpy (ip->dst_address.as_u8, pr->dst_address,
	       sizeof (ip4_address_t));
  ip->checksum = ip4_header_checksum (ip);

  /* UDP header */
  udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_dns);
  udp->dst_port = pr->dst_port;
  udp->length = clib_host_to_net_u16 (sizeof (udp_header_t) +
				      vec_len (reply));
  udp->checksum = 0;
  vec_free (reply);

  /*
   * Ship pkts made out of whole cloth to ip4_lookup
   * Caller will ship recycled dns reply packets to ip4_lookup
   */
  if (is_recycle == 0)
    {
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi;
      f->n_vectors = 1;
      vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
    }
}

#include <dns/dns.api.c>
static clib_error_t *
dns_init (vlib_main_t * vm)
{
  dns_main_t *dm = &dns_main;

  dm->vnet_main = vnet_get_main ();
  dm->name_cache_size = 1000;
  dm->max_ttl_in_seconds = 86400;
  dm->random_seed = 0xDEADDABE;
  dm->api_main = vlibapi_get_main ();

  /* Ask for a correctly-sized block of API message decode slots */
  dm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (dns_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Simple DNS name resolver",
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
