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
dns_enable_disable (dns_main_t * dm, int is_enable)
{

  if (is_enable)
    {
      if (vec_len (dm->ip4_name_servers) == 0
	  && (vec_len (dm->ip6_name_servers) == 0))
	return VNET_API_ERROR_NO_NAME_SERVERS;

      if (dm->cache_entry_by_name.mheap == 0)
	clib_bihash_init_8_8 (&dm->cache_entry_by_name,
			      "DNS cache entry by name",
			      dm->name_cache_buckets, dm->name_cache_size);
      vec_validate (dm->bucket_locks, dm->name_cache_buckets - 1);

      dm->is_enabled = 1;
    }
  else
    {
      /* $$$ clean out the tables */
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
      /* $$$$ HACK HACK HACK */
      sw_if_index = 1;
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

/* translate foo.com into "0x3 f o o 0x3 c o m "*/
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

      /* Add space for the rr header */
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
	      return;
	    }
	  else
	    ep->server_af = 0;
	}
      if (vec_len (dm->ip4_name_servers))
	{
	  send_dns4_request (dm, ep, dm->ip4_name_servers + ep->server_rotor);
	  return;
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

  vlib_process_signal_event_mt (dm->vlib_main, dns_resolver_node.index,
				DNS_RESOLVER_EVENT_PENDING, 0);
}


static int
dns_resolve_name (dns_main_t * dm,
		  u8 * name, u32 client_index, u32 client_context,
		  dns_cache_entry_t ** retp)
{
  clib_bihash_kv_8_8_t kv;
  uword signature;
  int rv;
  int name_length;
  u32 pool_index, bucket_index;
  dns_cache_entry_t *ep, *new_ep;
  u64 hash;

  /* In case we can't actually answer the question right now... */
  *retp = 0;

  name_length = strlen ((char *) name);

  if (dm->is_enabled == 0)
    return VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED;

  signature = hash_memory (name, name_length, 0xfeedbeef);

  kv.key = signature;
  kv.value = ~0ULL;

  hash = clib_bihash_hash_8_8 (&kv);
  bucket_index = hash & (dm->cache_entry_by_name.nbuckets - 1);

  /* Lock the bucket, to protect the entry chain */
  while (__sync_lock_test_and_set (dm->bucket_locks + bucket_index, 1))
    ;

  /* See if we know this name already */
  if (clib_bihash_search_8_8 (&dm->cache_entry_by_name, &kv, &kv) == 0)
    {
      pool_index = kv.value;

      do
	{
	  ep = pool_elt_at_index (dm->entries, pool_index);
	  pool_index = ep->next_index;

	  /* Names match exactly? */
	  if (vec_len (ep->name) == name_length &&
	      !memcmp (ep->name, name, name_length))
	    {
	      if (ep->flags & DNS_CACHE_ENTRY_FLAG_VALID)
		{
		  /* Winner */
		  *retp = ep;
		  dm->bucket_locks[bucket_index] = 0;
		  return 0;
		}
	      else
		{
		  /* Add a notification request */
		  *retp = 0;
		  vec_add1 (ep->api_clients_to_notify, client_index);
		  /* Result is pending resolution */
		  dm->bucket_locks[bucket_index] = 0;
		  return 1;
		}
	    }
	}
      while (pool_index != ~0);

      /* Hash collision, add an elt to resolve */
      pool_get (dm->entries, new_ep);
      memset (new_ep, 0, sizeof (*new_ep));

      new_ep->next_index = ~0;
      ep->next_index = new_ep - dm->entries;

      new_ep->name = format (0, "%s%c", name, 0);
      _vec_len (new_ep->name) = vec_len (new_ep->name) - 1;
      dm->bucket_locks[bucket_index] = 0;

      vec_add1 (dm->unresolved_entries, new_ep - dm->entries);
      vec_add1 (new_ep->api_clients_to_notify, client_index);
      vec_add1 (new_ep->api_client_contexts, client_context);
      vnet_send_dns_request (dm, new_ep);
      *retp = 0;
      return 0;
    }

  /* add new hash table entry */
  pool_get (dm->entries, new_ep);
  memset (new_ep, 0, sizeof (*new_ep));

  new_ep->next_index = ~0;

  new_ep->name = format (0, "%s%c", name, 0);
  _vec_len (new_ep->name) = vec_len (new_ep->name) - 1;

  kv.value = new_ep - dm->entries;

  rv = clib_bihash_add_del_8_8 (&dm->cache_entry_by_name,
				&kv, 1 /* is_add */ );

  if (rv < 0)
    {
      pool_put (dm->entries, new_ep);
      clib_warning ("clib_bihash_add_del returned %d", rv);
      return VNET_API_ERROR_UNSPECIFIED;
    }

  dm->bucket_locks[bucket_index] = 0;

  vec_add1 (dm->unresolved_entries, new_ep - dm->entries);
  vec_add1 (new_ep->api_clients_to_notify, client_index);
  vec_add1 (new_ep->api_client_contexts, client_context);
  vnet_send_dns_request (dm, new_ep);
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
      /* *INDENT-OFF* */
      REPLY_MACRO2 (VL_API_DNS_RESOLVE_NAME_REPLY,
      ({
        rmp->reply_length = 0;
      }));
      /* *INDENT-ON* */
      return;
    }

  /* Resolution pending? Don't reply... */
  if (ep == 0)
    return;

  /* *INDENT-OFF* */
  REPLY_MACRO3(VL_API_DNS_RESOLVE_NAME_REPLY, vec_len(ep->dns_response),
  ({
    rmp->reply_length = clib_host_to_net_u32(vec_len(ep->dns_response));
    clib_memcpy (rmp->reply_data, ep->dns_response,
                 vec_len (ep->dns_response));

  }));
  /* *INDENT-ON* */
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

  return 0;
}

VLIB_API_INIT_FUNCTION (dns_api_hookup);


static clib_error_t *
dns_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  dns_main_t *dm = &dns_main;
  u64 tmp;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name-cache-size %U", unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  dm->name_cache_size = tmp;
	}
      else if (unformat (input, "name-cache-buckets %d",
			 &dm->name_cache_buckets))
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
  dm->name_cache_buckets = 1024;
  dm->name_cache_size = 128 << 10;

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


u8 *
format_dns_query (u8 * s, va_list * args)
{
  u8 **curpos = va_arg (*args, u8 **);
  u8 *pos;
  dns_query_t *qp;
  int len, i;

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
	vec_add1 (s, ' ');
    }

  qp = (dns_query_t *) pos;
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
  pos += sizeof (*qp);

  *curpos = pos;
  return s;
}

u8 *
format_dns_reply_data (u8 * s, va_list * args)
{
  u8 *reply = va_arg (*args, u8 *);
  u8 **curpos = va_arg (*args, u8 **);
  int len;
  u8 *pos, *pos2;
  dns_rr_t *rr;
  int i;
  int initial_pointer_chase = 0;
  u16 *tp;

  pos = pos2 = *curpos;

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
	vec_add1 (s, *pos2++);
      len = *pos2++;
      if (len)
	vec_add1 (s, '.');
      else
	vec_add1 (s, ' ');
    }

  if (initial_pointer_chase == 0)
    pos = pos2;

  rr = (dns_rr_t *) pos;

  switch (clib_net_to_host_u16 (rr->type))
    {
    case DNS_TYPE_A:
      s = format (s, "A: ttl %d %U\n", clib_net_to_host_u32 (rr->ttl),
		  format_ip4_address, rr->rdata);
      pos += sizeof (*rr) + 4;
      break;

    case DNS_TYPE_AAAA:
      s = format (s, "AAAA: ttl %d %U\n", clib_net_to_host_u32 (rr->ttl),
		  format_ip6_address, rr->rdata);
      pos += sizeof (*rr) + 16;
      break;

    case DNS_TYPE_TEXT:
      s = format (s, "TEXT: ");
      for (i = 0; i < clib_net_to_host_u16 (rr->rdlength); i++)
	vec_add1 (s, rr->rdata[i]);
      vec_add1 (s, '\n');
      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      break;

    case DNS_TYPE_NAMESERVER:
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
      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      break;

    case DNS_TYPE_MAIL_EXCHANGE:
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

      pos += sizeof (*rr) + clib_net_to_host_u16 (rr->rdlength);
      break;

    default:
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
  int verbose __attribute__ ((unused)) = va_arg (*args, int);
  dns_header_t *h;
  u16 id, flags;
  u8 *curpos;
  int i;

  h = (dns_header_t *) reply_as_u8;
  id = clib_net_to_host_u16 (h->id);
  flags = clib_net_to_host_u16 (h->flags);

  s = format (s, "DNS %s: id %d\n", (flags & DNS_QR) ? "reply" : "query", id);
  s = format (s, "  %s %s %s %s\n",
	      (flags & DNS_RA) ? "recur" : "no-recur",
	      (flags & DNS_RD) ? "recur-des" : "no-recur-des",
	      (flags & DNS_TC) ? "trunc" : "no-trunc",
	      (flags & DNS_AA) ? "auth" : "non-auth");

  s = format (s, "  %d queries, %d answers, %d name-servers, %d add'l recs\n",
	      clib_net_to_host_u16 (h->qdcount),
	      clib_net_to_host_u16 (h->anscount),
	      clib_net_to_host_u16 (h->nscount),
	      clib_net_to_host_u16 (h->arcount));

  curpos = (u8 *) (h + 1);

  if (h->qdcount)
    {
      s = format (s, "  Queries:\n");
      for (i = 0; i < clib_net_to_host_u16 (h->qdcount); i++)
	{
	  /* The query is variable-length, so curpos is a value-result parm */
	  s = format (s, "%U", format_dns_query, &curpos);
	}
    }
  if (h->anscount)
    {
      s = format (s, "  Replies:\n");
      for (i = 0; i < clib_net_to_host_u16 (h->anscount); i++)
	{
	  /* curpos is a value-result parm */
	  s = format (s, "%U", format_dns_reply_data, reply_as_u8, &curpos);
	}
    }
  return s;
}

#if 0
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
  0x6d, 0x30, 0x8, 0x79, 0x61, 0x68, 0x6f, 0x6f, 0x64, 0x6e, 0x73, 0x3, 0x6e,
  0x65, 0x74, 0x0, 0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x6, 0x5c, 0x0,
  0x9, 0x0, 0x1, 0x4, 0x6d, 0x74, 0x61, 0x37, 0xc0, 0xb8, 0xc0, 0xc, 0x0,
  0xf, 0x0, 0x1, 0x0, 0x0, 0x6, 0x5c, 0x0, 0x9, 0x0, 0x1, 0x4, 0x6d, 0x74,
  0x61, 0x35, 0xc0, 0xb8, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x6,
  0x5c, 0x0, 0x10, 0x20, 0x1, 0x49, 0x98, 0x0, 0x44, 0x2, 0x4, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0xa7, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x6,
  0x5c, 0x0, 0x10, 0x20, 0x1, 0x49, 0x98, 0x0, 0xc, 0xa, 0x6, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x2, 0x40, 0x8, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x6,
  0x5c, 0x0, 0x10, 0x20, 0x1, 0x49, 0x98, 0x0, 0x58, 0xc, 0x2, 0x0, 0x0, 0x0,
  0x0, 0x0, 0x0, 0x0, 0xa9, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x6,
  0x5c, 0x0, 0x4, 0x62, 0x8a, 0xfd, 0x6d, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0,
  0x0, 0x6, 0x5c, 0x0, 0x4, 0xce, 0xbe, 0x24, 0x2d, 0xc0, 0xc, 0x0, 0x1, 0x0,
  0x1, 0x0, 0x0, 0x6, 0x5c, 0x0, 0x4, 0x62, 0x8b, 0xb4, 0x95, 0xc0, 0xc, 0x0,
  0x6, 0x0, 0x1, 0x0, 0x0, 0x6, 0x5c, 0x0, 0x2d, 0xc0, 0x7b, 0xa, 0x68, 0x6f,
  0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x9, 0x79, 0x61, 0x68,
  0x6f, 0x6f, 0x2d, 0x69, 0x6e, 0x63, 0xc0, 0x12, 0x78, 0x3a, 0x85, 0x44,
  0x0, 0x0, 0xe, 0x10, 0x0, 0x0, 0x1, 0x2c, 0x0, 0x1b, 0xaf, 0x80, 0x0, 0x0,
  0x2, 0x58
};

static u8 dns_reply_data_initializer[] =
  { 0x0, 0x0, 0x81, 0x80, 0x0, 0x1, 0x0, 0xe, 0x0, 0x0, 0x0, 0x0, 0x6,
  0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0xff,
  0x0, 0x1, 0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2b, 0x0, 0x4,
  0xac, 0xd9, 0x3, 0x2e, 0xc0, 0xc, 0x0, 0x1c, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2b,
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
  0x74, 0x34, 0xc0, 0x9b, 0xc0, 0xc, 0x0, 0xf, 0x0, 0x1, 0x0, 0x0, 0x2, 0x57,
  0x0, 0x9, 0x0, 0x14, 0x4, 0x61, 0x6c, 0x74, 0x31, 0xc0, 0x9b
};

static clib_error_t *
test_dns_fmt_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 *dns_reply_data = 0;

  vec_validate (dns_reply_data, ARRAY_LEN (dns_reply_data_initializer) - 1);

  memcpy (dns_reply_data, dns_reply_data_initializer,
	  ARRAY_LEN (dns_reply_data_initializer));

  vlib_cli_output (vm, "%U", format_dns_reply, dns_reply_data, 1);

  vec_free (dns_reply_data);

  return 0;
}

VLIB_CLI_COMMAND (test_dns_fmt_command) =
{
.path = "test dns format",.short_help = "test dns format",.function =
    test_dns_fmt_command_fn,};
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
