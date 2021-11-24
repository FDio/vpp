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

#include <dns/dns.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>

/* define message IDs */
#include <dns/dns.api_enum.h>
#include <dns/dns.api_types.h>

#include <vlibapi/api_helper_macros.h>

int
vnet_dns_response_to_reply (u8 * response,
			    vl_api_dns_resolve_name_reply_t * rmp,
			    u32 * min_ttlp);
int
vnet_dns_response_to_name (u8 * response,
			   vl_api_dns_resolve_ip_reply_t * rmp,
			   u32 * min_ttlp);
static u8 *
create_type_all_response (u8 *source_a, u8 *source_b)
{
  dns_header_t *h, *h_src;
  dns_query_t *qp;
  dns_rr_t *rr_src, *rr;
  u8 *pos, len, *rr_ptr;
  u8 *destination = NULL;
  u32 qp_offset;

  h_src = (dns_header_t *) source_a;
  pos = (u8 *) (h_src + 1);
  len = *pos;
  destination = vec_new (u8, 0);
  while (len)
    {
      vec_add1 (destination, len);
      pos++;
      len = *pos;
    }
  vec_add1 (destination, 0);

  while (*pos != 0xC0)
    {
      pos++;
    }
  /*0xC0 + 0x0C*/
  rr_src = (dns_rr_t *) (pos + 2);
  qp_offset = vec_len (destination);
  vec_validate (destination, qp_offset + sizeof (dns_query_t) - 1);

  qp = (dns_query_t *) (destination + qp_offset);
  qp->type = clib_host_to_net_u16 (DNS_TYPE_ALL);
  qp->class = clib_host_to_net_u16 (DNS_CLASS_IN);

  vec_insert (destination, sizeof (dns_header_t), 0);

  h = (dns_header_t *) destination;
  h->id = h_src->id;
  h->flags = h_src->flags;
  h->qdcount = clib_host_to_net_u16 (1);
  h->nscount = 0;
  h->arcount = 0;
  h->anscount = clib_host_to_net_u16 (2);

  vec_add1 (destination, 0xC0);
  vec_add1 (destination, 0x0C);

  vec_add2 (destination, rr_ptr, sizeof (*rr) + 4);
  rr = (dns_rr_t *) rr_ptr;
  rr->class = rr_src->class;
  rr->rdlength = rr_src->rdlength;
  rr->ttl = clib_host_to_net_u32 (300);
  rr->type = rr_src->type;
  clib_memcpy (rr->rdata, rr_src->rdata, 4);
  vec_add1 (destination, 0xC0);
  vec_add1 (destination, 0x0C);
  vec_add2 (destination, rr_ptr, sizeof (*rr) + 16);
  rr_src = (dns_rr_t *) ((source_b) + (((u8 *) rr_src) - source_a));
  rr = (dns_rr_t *) rr_ptr;
  rr->class = rr_src->class;
  rr->rdlength = rr_src->rdlength;
  rr->ttl = clib_host_to_net_u32 (300);
  rr->type = rr_src->type;
  clib_memcpy (rr->rdata, rr_src->rdata, 16);
  return destination;
}

static void
resolve_event (vlib_main_t * vm, dns_main_t * dm, f64 now, u8 * reply)
{
  dns_pending_request_t *pr;
  dns_header_t *d;
  dns_query_t *h;
  u32 pool_index;
  dns_cache_entry_t *ep;
  u32 min_ttl;
  u16 flags;
  u16 rcode;
  int i;
  int entry_was_valid;
  int remove_count;
  int rv = 0;
  u16 qtype, len;
  u8 *pos, *curpos;

  d = (dns_header_t *) reply;
  flags = clib_net_to_host_u16 (d->flags);
  rcode = flags & DNS_RCODE_MASK;
  curpos = (u8 *) (d + 1);
  pos = curpos;
  len = *pos++;

  while (len)
    {
      pos += len;
      len = *pos++;
    }
  curpos = pos;
  h = (dns_query_t *) curpos;
  qtype = clib_host_to_net_u16 (h->type);

  /* $$$ u16 limits cache to 65K entries, fix later multiple dst ports */
  pool_index = clib_net_to_host_u16 (d->id);
  dns_cache_lock (dm, 10);

  if (pool_is_free_index (dm->entries, pool_index))
    {
      vec_free (reply);
      if (0)
	clib_warning ("pool index %d is free", pool_index);
      vlib_node_increment_counter (vm, dns46_reply_node.index,
				   DNS46_REPLY_ERROR_NO_ELT, 1);
      dns_cache_unlock (dm);
      return;
    }

  ep = pool_elt_at_index (dm->entries, pool_index);

  if (qtype == DNS_TYPE_A)
    {
      if (ep->dns_a_response)
	vec_free (ep->dns_a_response);
    }
  else
    {
      if (ep->dns_aaaa_response)
	vec_free (ep->dns_aaaa_response);
    }
  /**
  if (ep->dns_response)
    vec_free (ep->dns_response);
**/
  /* Handle [sic] recursion AKA CNAME indirection */
  rv = vnet_dns_cname_indirection_nolock (vm, dm, pool_index, reply);

  /* CNAME found, further resolution pending, we're done here */
  if (rv > 0)
    {
      dns_cache_unlock (dm);
      return;
    }
  /* Server backfire: refused to answer, or sent zero replies */
  if (rv < 0)
    {
      /* Try a different server */
      if (ep->server_af /* ip6 */ )
	{
	  if (0)
	    clib_warning ("Server %U failed to resolve '%s'",
			  format_ip6_address,
			  dm->ip6_name_servers + ep->server_rotor, ep->name);
	  /* Any more servers to try? */
	  if (ep->server_fails > 1 || vec_len (dm->ip6_name_servers) <= 1)
	    {
	      /* No, tell the client to go away */
	      goto reply;
	    }
	  ep->retry_count = 0;
	  ep->server_rotor++;
	  ep->server_fails++;
	  if (ep->server_rotor >= vec_len (dm->ip6_name_servers))
	    ep->server_rotor = 0;
	  if (0)
	    clib_warning ("Try server %U", format_ip6_address,
			  dm->ip6_name_servers + ep->server_rotor);
	  vnet_dns_send_dns6_request
	    (vm, dm, ep, dm->ip6_name_servers + ep->server_rotor);
	}
      else
	{
	  if (0)
	    clib_warning ("Server %U failed to resolve '%s'",
			  format_ip4_address,
			  dm->ip4_name_servers + ep->server_rotor, ep->name);

	  if (ep->server_fails > 1 || vec_len (dm->ip4_name_servers) <= 1)
	    {
	      /* No, tell the client to go away */
	      goto reply;
	    }
	  ep->retry_count = 0;
	  ep->server_rotor++;
	  ep->server_fails++;
	  if (ep->server_rotor >= vec_len (dm->ip4_name_servers))
	    ep->server_rotor = 0;
	  if (0)
	    clib_warning ("Try server %U", format_ip4_address,
			  dm->ip4_name_servers + ep->server_rotor);
	  vnet_dns_send_dns4_request
	    (vm, dm, ep, dm->ip4_name_servers + ep->server_rotor);
	}
      dns_cache_unlock (dm);
      return;
    }

reply:
  /* Save the response */
  if (qtype == DNS_TYPE_A)
    {
      ep->dns_a_response = reply;
    }
  else
    {
      ep->dns_aaaa_response = reply;
    }
    ep->response_counter++;
  if (ep->response_counter < 2)
  {
    dns_cache_unlock(dm);
    return;
  }
 
  if (ep->dns_a_response == NULL  && ep->dns_aaaa_response == NULL)
    {
      //TODO: response without answers
    }
  else if (ep->dns_a_response == NULL || ep->dns_aaaa_response == NULL)
    {
      ep->dns_response = (ep->dns_a_response != NULL) 
                          ? ep->dns_a_response
                          : ep->dns_aaaa_response;
    }
  else{
    ep->dns_response =
    create_type_all_response (ep->dns_a_response, ep->dns_aaaa_response);
  }

  

  /*
   * Pick a sensible default cache entry expiration time.
   * We don't play the 10-second timeout game.
   */
  ep->expiration_time = now + 600.0;

  if (0)
    clib_warning ("resolving '%s', was %s valid",
		  ep->name, (ep->flags & DNS_CACHE_ENTRY_FLAG_VALID) ?
		  "already" : "not");
  /*
   * The world is a mess. A single DNS request sent to e.g. 8.8.8.8
   * may yield multiple, subtly different responses - all with the same
   * DNS protocol-level ID.
   *
   * Last response wins in terms of what ends up in the cache.
   * First response wins in terms of the response sent to the client.
   */

  /* Strong hint that we may not find a pending resolution entry */
  entry_was_valid = (ep->flags & DNS_CACHE_ENTRY_FLAG_VALID) ? 1 : 0;

  if (vec_len (ep->dns_response))
    ep->flags |= DNS_CACHE_ENTRY_FLAG_VALID;

  /* Most likely, send 1 message */
  for (i = 0; i < vec_len (ep->pending_requests); i++)
    {
      vl_api_registration_t *regp;

      pr = vec_elt_at_index (ep->pending_requests, i);

      switch (pr->request_type)
	{
	case DNS_API_PENDING_NAME_TO_IP:
	  {
	    vl_api_dns_resolve_name_reply_t *rmp;
	    regp = vl_api_client_index_to_registration (pr->client_index);
	    if (regp == 0)
	      continue;

	    rmp = vl_msg_api_alloc (sizeof (*rmp));
	    rmp->_vl_msg_id =
	      clib_host_to_net_u16 (VL_API_DNS_RESOLVE_NAME_REPLY
				    + dm->msg_id_base);
	    rmp->context = pr->client_context;
	    min_ttl = ~0;
	    rv = vnet_dns_response_to_reply (ep->dns_response, rmp, &min_ttl);
	    if (min_ttl != ~0)
	      ep->expiration_time = now + min_ttl;
	    rmp->retval = clib_host_to_net_u32 (rv);
	    vl_api_send_msg (regp, (u8 *) rmp);
	  }
	  break;

	case DNS_API_PENDING_IP_TO_NAME:
	  {
	    vl_api_dns_resolve_ip_reply_t *rmp;

	    regp = vl_api_client_index_to_registration (pr->client_index);
	    if (regp == 0)
	      continue;

	    rmp = vl_msg_api_alloc (sizeof (*rmp));
	    rmp->_vl_msg_id =
	      clib_host_to_net_u16 (VL_API_DNS_RESOLVE_IP_REPLY
				    + dm->msg_id_base);
	    rmp->context = pr->client_context;
	    min_ttl = ~0;
	    rv = vnet_dns_response_to_name (ep->dns_response, rmp, &min_ttl);
	    if (min_ttl != ~0)
	      ep->expiration_time = now + min_ttl;
	    rmp->retval = clib_host_to_net_u32 (rv);
	    vl_api_send_msg (regp, (u8 *) rmp);
	  }
	  break;

	case DNS_PEER_PENDING_IP_TO_NAME:
	case DNS_PEER_PENDING_NAME_TO_IP:
	  if (pr->is_ip6)
	    vnet_send_dns6_reply (vm, dm, pr, ep, 0 /* allocate a buffer */ );
	  else
	    vnet_send_dns4_reply (vm, dm, pr, ep, 0 /* allocate a buffer */ );
	  break;
	default:
	  clib_warning ("request type %d unknown", pr->request_type);
	  break;
	}
    }
  vec_free (ep->pending_requests);

  remove_count = 0;
  for (i = 0; i < vec_len (dm->unresolved_entries); i++)
    {
      if (dm->unresolved_entries[i] == pool_index)
	{
	  vec_delete (dm->unresolved_entries, 1, i);
	  remove_count++;
	  i--;
	}
    }
  /* See multiple response comment above... */
  if (remove_count == 0)
    {
      u32 error_code = entry_was_valid ? DNS46_REPLY_ERROR_MULTIPLE_REPLY :
	DNS46_REPLY_ERROR_NO_UNRESOLVED_ENTRY;

      vlib_node_increment_counter (vm, dns46_reply_node.index, error_code, 1);
      dns_cache_unlock (dm);
      return;
    }

  /* Deal with bogus names, server issues, etc. */
  switch (rcode)
    {
    default:
    case DNS_RCODE_NO_ERROR:
      break;

    case DNS_RCODE_SERVER_FAILURE:
    case DNS_RCODE_NOT_IMPLEMENTED:
    case DNS_RCODE_REFUSED:
      if (ep->server_af == 0)
	clib_warning ("name server %U can't resolve '%s'",
		      format_ip4_address,
		      dm->ip4_name_servers + ep->server_rotor, ep->name);
      else
	clib_warning ("name server %U can't resolve '%s'",
		      format_ip6_address,
		      dm->ip6_name_servers + ep->server_rotor, ep->name);
      /* FALLTHROUGH */
    case DNS_RCODE_NAME_ERROR:
    case DNS_RCODE_FORMAT_ERROR:
      /* remove trash from the cache... */
      vnet_dns_delete_entry_by_index_nolock (dm, ep - dm->entries);
      break;
    }


  dns_cache_unlock (dm);
  return;
}

static void
retry_scan (vlib_main_t * vm, dns_main_t * dm, f64 now)
{
  int i;
  dns_cache_entry_t *ep;

  for (i = 0; i < vec_len (dm->unresolved_entries); i++)
    {
      dns_cache_lock (dm, 11);
      ep = pool_elt_at_index (dm->entries, dm->unresolved_entries[i]);

      ASSERT ((ep->flags & DNS_CACHE_ENTRY_FLAG_VALID) == 0);
      vnet_send_dns_request (vm, dm, ep, DNS_TYPE_A);
      vnet_send_dns_request (vm, dm, ep, DNS_TYPE_AAAA);
      dns_cache_unlock (dm);
    }
}

static uword
dns_resolver_process (vlib_main_t * vm,
		      vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  dns_main_t *dm = &dns_main;
  f64 now;
  f64 timeout = 1000.0;
  uword *event_data = 0;
  uword event_type;
  int i;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);

      now = vlib_time_now (vm);

      event_type = vlib_process_get_events (vm, (uword **) & event_data);

      switch (event_type)
	{
	  /* Send one of these when a resolution is pending */
	case DNS_RESOLVER_EVENT_PENDING:
	  timeout = 2.0;
	  break;

	case DNS_RESOLVER_EVENT_RESOLVED:
	  for (i = 0; i < vec_len (event_data); i++)
	    resolve_event (vm, dm, now, (u8 *) event_data[i]);
	  break;

	case ~0:		/* timeout */
	  retry_scan (vm, dm, now);
	  break;
	}
      vec_reset_length (event_data);

      /* No work? Back to slow timeout mode... */
      if (vec_len (dm->unresolved_entries) == 0)
	timeout = 1000.0;
    }
  return 0;			/* or not */
}

void
vnet_dns_create_resolver_process (vlib_main_t * vm, dns_main_t * dm)
{
  /* Already created the resolver process? */
  if (dm->resolver_process_node_index > 0)
    return;

  /* No, create it now and make a note of the node index */
  dm->resolver_process_node_index = vlib_process_create
    (vm, "dns-resolver-process",
     dns_resolver_process, 16 /* log2_n_stack_bytes */ );
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
