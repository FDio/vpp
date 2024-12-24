/*
 * Copyright (c) 2024 Cisco and/or its affiliates.
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
#include <dns/dns.h>
#include <vnet/ip/ip_sas.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

/* define message IDs */
#include <dns/dns.api_enum.h>
#include <dns/dns.api_types.h>

#define REPLY_MSG_ID_BASE dm->msg_id_base
#include <vlibapi/api_helper_macros.h>

void
vl_api_dns_resolve_name_t_handler (vl_api_want_dns_resolve_name_events_t *mp)
{
  dns_main_t *dm = &dns_main;
  vl_api_want_dns_resolve_name_events_reply_t *rmp;
  mp->name[ARRAY_LEN (mp->name) - 1] = 0;

  dns_cache_entry_t *ep = 0;
  dns_pending_request_t _t0 = { 0 }, *t0 = &_t0;
  int rv;
  dns_resolve_name_t rn;

  t0->request_type = DNS_API_PENDING_NAME_TO_IP;
  t0->client_index = mp->client_index;
  t0->client_context = mp->context;

  rv = dns_resolve_name (mp->name, &ep, t0, &rn);
  REPLY_MACRO (VL_API_WANT_DNS_RESOLVE_NAME_EVENTS_REPLY);
}

static void
vl_api_dns_resolve_ip_t_handler (vl_api_dns_resolve_name_t *mp)
{
  dns_main_t *dm = &dns_main;
  vl_api_dns_resolve_name_reply_t *rmp;
  dns_cache_entry_t *ep = 0;
  dns_pending_request_t _t0 = { 0 }, *t0 = &_t0;
  int rv;
  dns_resolve_name_t rn;

  /* Sanitize the name slightly */
  mp->name[ARRAY_LEN (mp->name) - 1] = 0;

  t0->request_type = DNS_API_PENDING_NAME_TO_IP;
  t0->client_index = mp->client_index;
  t0->client_context = mp->context;

  rv = dns_resolve_name (mp->name, &ep, t0, &rn);

  /* Error, e.g. not enabled? Tell the user */
  if (rv < 0)
    {
      REPLY_MACRO (VL_API_DNS_RESOLVE_NAME_REPLY);
      return;
    }

  /* Resolution pending? Don't reply... */
  if (ep == 0)
    return;

  REPLY_MACRO2 (VL_API_DNS_RESOLVE_NAME_REPLY, ({
		  ip_address_copy_addr (rmp->ip4_address, &rn.address);
		  if (ip_addr_version (&rn.address) == AF_IP4)
		    rmp->ip4_set = 1;
		  else
		    rmp->ip6_set = 1;
		}));
}

void
vl_api_want_dns_events_t_handler (vl_api_want_dns_resolve_ip_events_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  dns_main_t *dm = &dns_main;
  vl_api_want_dns_resolve_ip_events_reply_t *rmp;
  dns_cache_entry_t *ep;
  int rv;
  int i, len;
  u8 *lookup_name = 0;
  u8 digit, nybble;
  dns_pending_request_t _t0 = { 0 }, *t0 = &_t0;

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
  REPLY_MACRO (VL_API_WANT_DNS_RESOLVE_IP_EVENTS_REPLY);
}
