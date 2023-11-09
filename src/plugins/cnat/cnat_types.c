/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <cnat/cnat_types.h>
#include <cnat/cnat_inline.h>

cnat_main_t cnat_main;
cnat_timestamp_mpool_t cnat_timestamps;

char *cnat_error_strings[] = {
#define cnat_error(n,s) s,
#include <cnat/cnat_error.def>
#undef cnat_error
};

u8 *
format_cnat_5tuple (u8 *s, va_list *args)
{
  cnat_5tuple_t *tuple = va_arg (*args, cnat_5tuple_t *);

  if (tuple->af == AF_IP4)
    {
      s = format (s, "%U [%U;%u -> %U;%u]", format_ip_protocol, tuple->iproto, format_ip4_address,
		  &tuple->ip4[VLIB_RX], clib_net_to_host_u16 (tuple->port[VLIB_RX]),
		  format_ip4_address, &tuple->ip4[VLIB_TX],
		  clib_net_to_host_u16 (tuple->port[VLIB_TX]));
    }
  else
    {
      s = format (s, "%U [%U;%u -> %U;%u]", format_ip_protocol, tuple->iproto, format_ip6_address,
		  &tuple->ip6[VLIB_RX], clib_net_to_host_u16 (tuple->port[VLIB_RX]),
		  format_ip6_address, &tuple->ip6[VLIB_TX],
		  clib_net_to_host_u16 (tuple->port[VLIB_TX]));
    }
  return (s);
}

u8 *
format_cnat_rewrite (u8 *s, va_list *args)
{
  cnat_timestamp_rewrite_t *rw = va_arg (*args, cnat_timestamp_rewrite_t *);

  s = format (s, "%U node:%u lbi:%u fl:%u", format_cnat_5tuple, &rw->tuple, rw->cts_dpoi_next_node,
	      rw->cts_lbi, rw->cts_flags);

  return (s);
}

u8 *
format_cnat_rewrite_type (u8 *s, va_list *args)
{
  int rw_type = va_arg (*args, int);
  switch (rw_type)
    {
    case CNAT_LOCATION_INPUT:
      return format (s, " in ");
    case CNAT_LOCATION_OUTPUT:
      return format (s, " out");
    case CNAT_LOCATION_FIB:
      return format (s, " fib");
    case CNAT_LOCATION_INPUT + CNAT_IS_RETURN:
      return format (s, "rin ");
    case CNAT_LOCATION_OUTPUT + CNAT_IS_RETURN:
      return format (s, "rout");
    case CNAT_LOCATION_FIB + CNAT_IS_RETURN:
      return format (s, "rfib");
    default:
      return format (s, "unknown");
    }
}

u8
cnat_resolve_addr (u32 sw_if_index, ip_address_family_t af,
		   ip_address_t * addr)
{
  /* Tries to resolve IP from sw_if_index
   * returns 1 if we need to schedule DHCP */
  if (INDEX_INVALID == sw_if_index)
    return 0;
  if (af == AF_IP6)
    {
      ip6_address_t *ip6 = 0;
      ip6 = ip6_interface_first_address (&ip6_main, sw_if_index);
      if (ip6)
	{
	  ip_address_set (addr, ip6, AF_IP6);
	  return 0;
	}
      else
	return 1;
    }
  else
    {
      ip4_address_t *ip4 = 0;
      ip4 = ip4_interface_first_address (&ip4_main, sw_if_index, 0);
      if (ip4)
	{
	  ip_address_set (addr, ip4, AF_IP4);
	  return 0;
	}
      else
	return 1;
    }
}

u8
cnat_resolve_ep (cnat_endpoint_t * ep)
{
  int rv;
  rv = cnat_resolve_addr (ep->ce_sw_if_index, ep->ce_ip.version, &ep->ce_ip);
  if (0 == rv)
    ep->ce_flags |= CNAT_EP_FLAG_RESOLVED;
  return rv;
}

uword
unformat_cnat_ep (unformat_input_t * input, va_list * args)
{
  cnat_endpoint_t *a = va_arg (*args, cnat_endpoint_t *);
  vnet_main_t *vnm = vnet_get_main ();
  int port = 0;

  clib_memset (a, 0, sizeof (*a));
  a->ce_sw_if_index = INDEX_INVALID;
  if (unformat (input, "%U %d", unformat_ip_address, &a->ce_ip, &port))
    ;
  else if (unformat_user (input, unformat_ip_address, &a->ce_ip))
    ;
  else if (unformat (input, "%U v6 %d", unformat_vnet_sw_interface,
		     vnm, &a->ce_sw_if_index, &port))
    a->ce_ip.version = AF_IP6;
  else if (unformat (input, "%U v6", unformat_vnet_sw_interface,
		     vnm, &a->ce_sw_if_index))
    a->ce_ip.version = AF_IP6;
  else if (unformat (input, "%U %d", unformat_vnet_sw_interface,
		     vnm, &a->ce_sw_if_index, &port))
    a->ce_ip.version = AF_IP4;
  else if (unformat_user (input, unformat_vnet_sw_interface,
			  vnm, &a->ce_sw_if_index))
    a->ce_ip.version = AF_IP4;
  else if (unformat (input, "%d", &port))
    ;
  else
    return 0;
  a->ce_port = (u16) port;
  return 1;
}

uword
unformat_cnat_ep_flags (unformat_input_t *input, va_list *args)
{
  int *a = va_arg (*args, int *);
  if (unformat (input, ":nonat"))
    *a = CNAT_TRK_FLAG_NO_NAT;
  return 1;
}

uword
unformat_cnat_ep_tuple (unformat_input_t * input, va_list * args)
{
  cnat_endpoint_tuple_t *a = va_arg (*args, cnat_endpoint_tuple_t *);
  int flgs = 0;
  if (unformat (input, "%U->%U%U", unformat_cnat_ep, &a->src_ep,
		unformat_cnat_ep, &a->dst_ep, unformat_cnat_ep_flags, &flgs))
    a->ep_flags = flgs;
  else if (unformat (input, "->%U%U", unformat_cnat_ep, &a->dst_ep,
		     unformat_cnat_ep_flags, &flgs))
    a->ep_flags = flgs;
  else if (unformat (input, "%U->%U", unformat_cnat_ep, &a->src_ep,
		     unformat_cnat_ep_flags, &flgs))
    a->ep_flags = flgs;
  else
    return 0;
  return 1;
}

u8 *
format_cnat_endpoint (u8 * s, va_list * args)
{
  cnat_endpoint_t *cep = va_arg (*args, cnat_endpoint_t *);
  vnet_main_t *vnm = vnet_get_main ();
  if (INDEX_INVALID == cep->ce_sw_if_index)
    s = format (s, "%U;%d", format_ip_address, &cep->ce_ip, cep->ce_port);
  else
    {
      if (cep->ce_flags & CNAT_EP_FLAG_RESOLVED)
	s = format (s, "%U (%U);%d", format_vnet_sw_if_index_name, vnm,
		    cep->ce_sw_if_index, format_ip_address, &cep->ce_ip,
		    cep->ce_port);
      else
	s =
	  format (s, "%U (%U);%d", format_vnet_sw_if_index_name, vnm,
		  cep->ce_sw_if_index, format_ip_address_family,
		  cep->ce_ip.version, cep->ce_port);
    }
  return (s);
}

void
cnat_enable_disable_scanner (cnat_scanner_cmd_t event_type)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_process_signal_event (vm, cnat_main.scanner_node_index, event_type, 0);
}

void
cnat_lazy_init (void)
{
  cnat_timestamp_mpool_t *ctm = &cnat_timestamps;
  cnat_main_t *cm = &cnat_main;

  if (cm->lazy_init_done)
    return;

  clib_rwlock_init (&ctm->ts_lock);
  /* timestamp 0 is default */
  cnat_timestamp_alloc ();

  cnat_enable_disable_scanner (cm->default_scanner_state);

  cm->lazy_init_done = 1;
}

static clib_error_t *
cnat_config (vlib_main_t * vm, unformat_input_t * input)
{
  u32 log2_pool_sz = CNAT_DEFAULT_TS_LOG2_POOL_SZ;
  cnat_timestamp_mpool_t *ctm = &cnat_timestamps;
  u32 session_max = CNAT_MAX_SESSIONS;
  cnat_main_t *cm = &cnat_main;

  cm->translation_hash_memory = CNAT_DEFAULT_TRANSLATION_MEMORY;
  cm->translation_hash_buckets = CNAT_DEFAULT_TRANSLATION_BUCKETS;
  cm->client_hash_memory = CNAT_DEFAULT_CLIENT_MEMORY;
  cm->client_hash_buckets = CNAT_DEFAULT_CLIENT_BUCKETS;
  cm->snat_hash_memory = CNAT_DEFAULT_SNAT_MEMORY;
  cm->snat_hash_buckets = CNAT_DEFAULT_SNAT_BUCKETS;
  cm->snat_if_map_length = CNAT_DEFAULT_SNAT_IF_MAP_LEN;
  cm->scanner_timeout = CNAT_DEFAULT_SCANNER_TIMEOUT;
  cm->session_max_age = CNAT_DEFAULT_SESSION_MAX_AGE;
  cm->tcp_max_age = CNAT_DEFAULT_TCP_MAX_AGE;
  cm->default_scanner_state = CNAT_SCANNER_ON;
  cm->maglev_len = CNAT_DEFAULT_MAGLEV_LEN;
  cm->lazy_init_done = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "translation-db-buckets %u", &cm->translation_hash_buckets))
	;
      else if (unformat (input, "translation-db-memory %U",
			 unformat_memory_size, &cm->translation_hash_memory))
	;
      else if (unformat (input, "client-db-buckets %u",
			 &cm->client_hash_buckets))
	;
      else if (unformat (input, "client-db-memory %U", unformat_memory_size,
			 &cm->client_hash_memory))
	;
      else if (unformat (input, "snat-db-buckets %u", &cm->snat_hash_buckets))
	;
      else if (unformat (input, "snat-if-map-len %u", &cm->snat_if_map_length))
	;
      else if (unformat (input, "snat-db-memory %U",
			 unformat_memory_size, &cm->snat_hash_memory))
	;
      else if (unformat (input, "session-cleanup-timeout %f",
			 &cm->scanner_timeout))
	;
      else if (unformat (input, "scanner off"))
	cm->default_scanner_state = CNAT_SCANNER_OFF;
      else if (unformat (input, "scanner on"))
	cm->default_scanner_state = CNAT_SCANNER_ON;
      else if (unformat (input, "session-max-age %u", &cm->session_max_age))
	;
      else if (unformat (input, "tcp-max-age %u", &cm->tcp_max_age))
	;
      else if (unformat (input, "maglev-len %u", &cm->maglev_len))
	;
      else if (unformat (input, "session-log2-pool-size %u", &log2_pool_sz))
	;
      else if (unformat (input, "session-max %u", &session_max))
	{
	  if (session_max > CNAT_MAX_SESSIONS)
	    return clib_error_return (0, "cnat session-max %u > %u", session_max,
				      CNAT_MAX_SESSIONS);
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  /* session index is 32-bits and made of pool index + object index */
  u64 smax = session_max + (1ULL << log2_pool_sz) - 1;
  if (smax > CLIB_U32_MAX)
    return clib_error_return (0, "cnat session-max and session-log2-pool-size are incompatible");

  ctm->pool_max = smax >> log2_pool_sz;
  ctm->log2_pool_sz = log2_pool_sz;
  return 0;
}

cnat_main_t *
cnat_get_main ()
{
  return &cnat_main;
}

VLIB_EARLY_CONFIG_FUNCTION (cnat_config, "cnat");
