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
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>

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

vlib_node_registration_t dns_resolver_node;

extern int
vnet_dns_response_to_reply (u8 * response,
			    vl_api_dns_resolve_name_reply_t * rmp,
			    u32 * min_ttlp);
extern int
vnet_dns_response_to_name (u8 * response,
			   vl_api_dns_resolve_ip_reply_t * rmp,
			   u32 * min_ttlp);

static void
resolve_event (dns_main_t * dm, f64 now, u8 * reply)
{
  vlib_main_t *vm = dm->vlib_main;
  dns_pending_request_t *pr;
  dns_header_t *d;
  u32 pool_index;
  dns_cache_entry_t *ep;
  u32 min_ttl;
  u16 flags;
  u16 rcode;
  int i;
  int rv = 0;

  d = (dns_header_t *) reply;
  flags = clib_net_to_host_u16 (d->flags);
  rcode = flags & DNS_RCODE_MASK;

  /* $$$ u16 limits cache to 65K entries, fix later multiple dst ports */
  pool_index = clib_net_to_host_u16 (d->id);
  dns_cache_lock (dm);

  if (pool_is_free_index (dm->entries, pool_index))
    {
      vec_free (reply);
      vlib_node_increment_counter (vm, dns46_reply_node.index,
				   DNS46_REPLY_ERROR_NO_ELT, 1);
      dns_cache_unlock (dm);
      return;
    }

  ep = pool_elt_at_index (dm->entries, pool_index);

  if (ep->dns_response)
    vec_free (ep->dns_response);

  /* Handle [sic] recursion AKA CNAME indirection */
  if (vnet_dns_cname_indirection_nolock (dm, pool_index, reply))
    {
      dns_cache_unlock (dm);
      return;
    }

  /* Save the response */
  ep->dns_response = reply;
  /* Pick some sensible default. */
  ep->expiration_time = now + 600.0;
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
	      clib_host_to_net_u16 (VL_API_DNS_RESOLVE_NAME_REPLY);
	    rmp->context = pr->client_context;
	    min_ttl = ~0;
	    rv = vnet_dns_response_to_reply (ep->dns_response, rmp, &min_ttl);
	    if (min_ttl != ~0)
	      ep->expiration_time = now + min_ttl;
	    rmp->retval = clib_host_to_net_u32 (rv);
	    vl_msg_api_send (regp, (u8 *) rmp);
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
	      clib_host_to_net_u16 (VL_API_DNS_RESOLVE_IP_REPLY);
	    rmp->context = pr->client_context;
	    min_ttl = ~0;
	    rv = vnet_dns_response_to_name (ep->dns_response, rmp, &min_ttl);
	    if (min_ttl != ~0)
	      ep->expiration_time = now + min_ttl;
	    rmp->retval = clib_host_to_net_u32 (rv);
	    vl_msg_api_send (regp, (u8 *) rmp);
	  }
	  break;

	case DNS_PEER_PENDING_IP_TO_NAME:
	case DNS_PEER_PENDING_NAME_TO_IP:
	  if (pr->is_ip6)
	    vnet_send_dns6_reply (dm, pr, ep, 0 /* allocate a buffer */ );
	  else
	    vnet_send_dns4_reply (dm, pr, ep, 0 /* allocate a buffer */ );
	  break;
	default:
	  clib_warning ("request type %d unknown", pr->request_type);
	  break;
	}
    }
  vec_free (ep->pending_requests);

  for (i = 0; i < vec_len (dm->unresolved_entries); i++)
    {
      if (dm->unresolved_entries[i] == pool_index)
	{
	  vec_delete (dm->unresolved_entries, 1, i);
	  goto found;
	}
    }
  clib_warning ("pool index %d AWOL from unresolved vector", pool_index);

found:
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
	clib_warning ("name server %U backfire",
		      format_ip4_address,
		      dm->ip4_name_servers + ep->server_rotor);
      else
	clib_warning ("name server %U backfire",
		      format_ip6_address,
		      dm->ip6_name_servers + ep->server_rotor);
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
retry_scan (dns_main_t * dm, f64 now)
{
  int i;
  dns_cache_entry_t *ep;

  for (i = 0; i < vec_len (dm->unresolved_entries); i++)
    {
      dns_cache_lock (dm);
      ep = pool_elt_at_index (dm->entries, dm->unresolved_entries[i]);

      ASSERT ((ep->flags & DNS_CACHE_ENTRY_FLAG_VALID) == 0);
      vnet_send_dns_request (dm, ep);
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
	    resolve_event (dm, now, (u8 *) event_data[i]);
	  break;

	case ~0:		/* timeout */
	  retry_scan (dm, now);
	  break;
	}
      vec_reset_length (event_data);

      /* No work? Back to slow timeout mode... */
      if (vec_len (dm->unresolved_entries) == 0)
	timeout = 1000.0;
    }
  return 0;			/* or not */
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dns_resolver_node) =
{
  .function = dns_resolver_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "dns-resolver-process",
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
