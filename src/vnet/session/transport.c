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

#include <vnet/session/transport_interface.h>
#include <vnet/session/session.h>
#include <vnet/fib/fib.h>

/**
 * Per-type vector of transport protocol virtual function tables
 */
transport_proto_vft_t *tp_vfts;

/*
 * Port allocator seed
 */
static u32 port_allocator_seed;

/*
 * Local endpoints table
 */
static transport_endpoint_table_t local_endpoints_table;

/*
 * Pool of local endpoints
 */
static transport_endpoint_t *local_endpoints;

/*
 * Local endpoints pool lock
 */
static clib_spinlock_t local_endpoints_lock;

/*
 * Period used by transport pacers. Initialized by session layer
 */
static double transport_pacer_period;

#define TRANSPORT_PACER_MIN_MSS 1460

u8 *
format_transport_proto (u8 * s, va_list * args)
{
  u32 transport_proto = va_arg (*args, u32);
  switch (transport_proto)
    {
    case TRANSPORT_PROTO_TCP:
      s = format (s, "TCP");
      break;
    case TRANSPORT_PROTO_UDP:
      s = format (s, "UDP");
      break;
    case TRANSPORT_PROTO_SCTP:
      s = format (s, "SCTP");
      break;
    case TRANSPORT_PROTO_UDPC:
      s = format (s, "UDPC");
      break;
    }
  return s;
}

u8 *
format_transport_proto_short (u8 * s, va_list * args)
{
  u32 transport_proto = va_arg (*args, u32);
  switch (transport_proto)
    {
    case TRANSPORT_PROTO_TCP:
      s = format (s, "T");
      break;
    case TRANSPORT_PROTO_UDP:
      s = format (s, "U");
      break;
    case TRANSPORT_PROTO_SCTP:
      s = format (s, "S");
      break;
    case TRANSPORT_PROTO_UDPC:
      s = format (s, "U");
      break;
    }
  return s;
}

u8 *
format_transport_connection (u8 * s, va_list * args)
{
  u32 transport_proto = va_arg (*args, u32);
  u32 conn_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  transport_proto_vft_t *tp_vft;
  transport_connection_t *tc;
  u32 indent;

  tp_vft = transport_protocol_get_vft (transport_proto);
  if (!tp_vft)
    return s;

  s = format (s, "%U", tp_vft->format_connection, conn_index, thread_index,
	      verbose);
  tc = tp_vft->get_connection (conn_index, thread_index);
  if (tc && transport_connection_is_tx_paced (tc) && verbose > 1)
    {
      indent = format_get_indent (s) + 1;
      s = format (s, "%Upacer: %U\n", format_white_space, indent,
		  format_transport_pacer, &tc->pacer);
    }
  return s;
}

u8 *
format_transport_listen_connection (u8 * s, va_list * args)
{
  u32 transport_proto = va_arg (*args, u32);
  u32 listen_index = va_arg (*args, u32);
  transport_proto_vft_t *tp_vft;

  tp_vft = transport_protocol_get_vft (transport_proto);
  if (!tp_vft)
    return s;

  s = format (s, "%U", tp_vft->format_listener, listen_index);
  return s;
}

u8 *
format_transport_half_open_connection (u8 * s, va_list * args)
{
  u32 transport_proto = va_arg (*args, u32);
  u32 listen_index = va_arg (*args, u32);
  transport_proto_vft_t *tp_vft;

  tp_vft = transport_protocol_get_vft (transport_proto);
  if (!tp_vft)
    return s;

  s = format (s, "%U", tp_vft->format_half_open, listen_index);
  return s;
}

uword
unformat_transport_proto (unformat_input_t * input, va_list * args)
{
  u32 *proto = va_arg (*args, u32 *);
  if (unformat (input, "tcp"))
    *proto = TRANSPORT_PROTO_TCP;
  else if (unformat (input, "TCP"))
    *proto = TRANSPORT_PROTO_TCP;
  else if (unformat (input, "udp"))
    *proto = TRANSPORT_PROTO_UDP;
  else if (unformat (input, "UDP"))
    *proto = TRANSPORT_PROTO_UDP;
  else if (unformat (input, "sctp"))
    *proto = TRANSPORT_PROTO_SCTP;
  else if (unformat (input, "SCTP"))
    *proto = TRANSPORT_PROTO_SCTP;
  else if (unformat (input, "tls"))
    *proto = TRANSPORT_PROTO_TLS;
  else if (unformat (input, "TLS"))
    *proto = TRANSPORT_PROTO_TLS;
  else if (unformat (input, "udpc"))
    *proto = TRANSPORT_PROTO_UDPC;
  else if (unformat (input, "UDPC"))
    *proto = TRANSPORT_PROTO_UDPC;
  else
    return 0;
  return 1;
}

u32
transport_endpoint_lookup (transport_endpoint_table_t * ht, u8 proto,
			   ip46_address_t * ip, u16 port)
{
  clib_bihash_kv_24_8_t kv;
  int rv;

  kv.key[0] = ip->as_u64[0];
  kv.key[1] = ip->as_u64[1];
  kv.key[2] = (u64) port << 8 | (u64) proto;

  rv = clib_bihash_search_inline_24_8 (ht, &kv);
  if (rv == 0)
    return kv.value;

  return ENDPOINT_INVALID_INDEX;
}

void
transport_endpoint_table_add (transport_endpoint_table_t * ht, u8 proto,
			      transport_endpoint_t * te, u32 value)
{
  clib_bihash_kv_24_8_t kv;

  kv.key[0] = te->ip.as_u64[0];
  kv.key[1] = te->ip.as_u64[1];
  kv.key[2] = (u64) te->port << 8 | (u64) proto;
  kv.value = value;

  clib_bihash_add_del_24_8 (ht, &kv, 1);
}

void
transport_endpoint_table_del (transport_endpoint_table_t * ht, u8 proto,
			      transport_endpoint_t * te)
{
  clib_bihash_kv_24_8_t kv;

  kv.key[0] = te->ip.as_u64[0];
  kv.key[1] = te->ip.as_u64[1];
  kv.key[2] = (u64) te->port << 8 | (u64) proto;

  clib_bihash_add_del_24_8 (ht, &kv, 0);
}

/**
 * Register transport virtual function table.
 *
 * @param transport_proto - transport protocol type (i.e., TCP, UDP ..)
 * @param vft - virtual function table for transport proto
 * @param fib_proto - network layer protocol
 * @param output_node - output node index that session layer will hand off
 * 			buffers to, for requested fib proto
 */
void
transport_register_protocol (transport_proto_t transport_proto,
			     const transport_proto_vft_t * vft,
			     fib_protocol_t fib_proto, u32 output_node)
{
  u8 is_ip4 = fib_proto == FIB_PROTOCOL_IP4;

  vec_validate (tp_vfts, transport_proto);
  tp_vfts[transport_proto] = *vft;

  session_register_transport (transport_proto, vft, is_ip4, output_node);
}

/**
 * Get transport virtual function table
 *
 * @param type - session type (not protocol type)
 */
transport_proto_vft_t *
transport_protocol_get_vft (transport_proto_t transport_proto)
{
  if (transport_proto >= vec_len (tp_vfts))
    return 0;
  return &tp_vfts[transport_proto];
}

transport_service_type_t
transport_protocol_service_type (transport_proto_t tp)
{
  return tp_vfts[tp].service_type;
}

transport_tx_fn_type_t
transport_protocol_tx_fn_type (transport_proto_t tp)
{
  return tp_vfts[tp].tx_type;
}

u8
transport_protocol_is_cl (transport_proto_t tp)
{
  return (tp_vfts[tp].service_type == TRANSPORT_SERVICE_CL);
}

#define PORT_MASK ((1 << 16)- 1)

void
transport_endpoint_del (u32 tepi)
{
  clib_spinlock_lock_if_init (&local_endpoints_lock);
  pool_put_index (local_endpoints, tepi);
  clib_spinlock_unlock_if_init (&local_endpoints_lock);
}

always_inline transport_endpoint_t *
transport_endpoint_new (void)
{
  transport_endpoint_t *tep;
  pool_get_zero (local_endpoints, tep);
  return tep;
}

void
transport_endpoint_cleanup (u8 proto, ip46_address_t * lcl_ip, u16 port)
{
  u32 tepi;
  transport_endpoint_t *tep;

  /* Cleanup local endpoint if this was an active connect */
  tepi = transport_endpoint_lookup (&local_endpoints_table, proto, lcl_ip,
				    clib_net_to_host_u16 (port));
  if (tepi != ENDPOINT_INVALID_INDEX)
    {
      tep = pool_elt_at_index (local_endpoints, tepi);
      transport_endpoint_table_del (&local_endpoints_table, proto, tep);
      transport_endpoint_del (tepi);
    }
}

static void
transport_endpoint_mark_used (u8 proto, ip46_address_t * ip, u16 port)
{
  transport_endpoint_t *tep;
  clib_spinlock_lock_if_init (&local_endpoints_lock);
  tep = transport_endpoint_new ();
  clib_memcpy (&tep->ip, ip, sizeof (*ip));
  tep->port = port;
  transport_endpoint_table_add (&local_endpoints_table, proto, tep,
				tep - local_endpoints);
  clib_spinlock_unlock_if_init (&local_endpoints_lock);
}

/**
 * Allocate local port and add if successful add entry to local endpoint
 * table to mark the pair as used.
 */
int
transport_alloc_local_port (u8 proto, ip46_address_t * ip)
{
  u16 min = 1024, max = 65535;	/* XXX configurable ? */
  int tries, limit;
  u32 tei;

  limit = max - min;

  /* Only support active opens from thread 0 */
  ASSERT (vlib_get_thread_index () == 0);

  /* Search for first free slot */
  for (tries = 0; tries < limit; tries++)
    {
      u16 port = 0;

      /* Find a port in the specified range */
      while (1)
	{
	  port = random_u32 (&port_allocator_seed) & PORT_MASK;
	  if (PREDICT_TRUE (port >= min && port < max))
	    break;
	}

      /* Look it up. If not found, we're done */
      tei = transport_endpoint_lookup (&local_endpoints_table, proto, ip,
				       port);
      if (tei == ENDPOINT_INVALID_INDEX)
	{
	  transport_endpoint_mark_used (proto, ip, port);
	  return port;
	}
    }
  return -1;
}

static clib_error_t *
transport_get_interface_ip (u32 sw_if_index, u8 is_ip4, ip46_address_t * addr)
{
  if (is_ip4)
    {
      ip4_address_t *ip4;
      ip4 = ip_interface_get_first_ip (sw_if_index, 1);
      if (!ip4)
	return clib_error_return (0, "no routable ip4 address on %U",
				  format_vnet_sw_if_index_name,
				  vnet_get_main (), sw_if_index);
      addr->ip4.as_u32 = ip4->as_u32;
    }
  else
    {
      ip6_address_t *ip6;
      ip6 = ip_interface_get_first_ip (sw_if_index, 0);
      if (ip6 == 0)
	return clib_error_return (0, "no routable ip6 addresses on %U",
				  format_vnet_sw_if_index_name,
				  vnet_get_main (), sw_if_index);
      clib_memcpy (&addr->ip6, ip6, sizeof (*ip6));
    }
  return 0;
}

static clib_error_t *
transport_find_local_ip_for_remote (u32 sw_if_index,
				    transport_endpoint_t * rmt,
				    ip46_address_t * lcl_addr)
{
  fib_node_index_t fei;
  fib_prefix_t prefix;

  if (sw_if_index == ENDPOINT_INVALID_INDEX)
    {
      /* Find a FIB path to the destination */
      clib_memcpy (&prefix.fp_addr, &rmt->ip, sizeof (rmt->ip));
      prefix.fp_proto = rmt->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
      prefix.fp_len = rmt->is_ip4 ? 32 : 128;

      ASSERT (rmt->fib_index != ENDPOINT_INVALID_INDEX);
      fei = fib_table_lookup (rmt->fib_index, &prefix);

      /* Couldn't find route to destination. Bail out. */
      if (fei == FIB_NODE_INDEX_INVALID)
	return clib_error_return (0, "no route to %U", format_ip46_address,
				  &rmt->ip, (rmt->is_ip4 == 0) + 1);

      sw_if_index = fib_entry_get_resolving_interface (fei);
      if (sw_if_index == ENDPOINT_INVALID_INDEX)
	return clib_error_return (0, "no resolving interface for %U",
				  format_ip46_address, &rmt->ip,
				  (rmt->is_ip4 == 0) + 1);
    }

  clib_memset (lcl_addr, 0, sizeof (*lcl_addr));
  return transport_get_interface_ip (sw_if_index, rmt->is_ip4, lcl_addr);
}

int
transport_alloc_local_endpoint (u8 proto, transport_endpoint_cfg_t * rmt_cfg,
				ip46_address_t * lcl_addr, u16 * lcl_port)
{
  transport_endpoint_t *rmt = (transport_endpoint_t *) rmt_cfg;
  clib_error_t *error;
  int port;
  u32 tei;

  /*
   * Find the local address
   */
  if (ip_is_zero (&rmt_cfg->peer.ip, rmt_cfg->peer.is_ip4))
    {
      error = transport_find_local_ip_for_remote (rmt_cfg->peer.sw_if_index,
						  rmt, lcl_addr);
      if (error)
	return -1;
    }
  else
    {
      /* Assume session layer vetted this address */
      clib_memcpy (lcl_addr, &rmt_cfg->peer.ip, sizeof (rmt_cfg->peer.ip));
    }

  /*
   * Allocate source port
   */
  if (rmt_cfg->peer.port == 0)
    {
      port = transport_alloc_local_port (proto, lcl_addr);
      if (port < 1)
	{
	  clib_warning ("Failed to allocate src port");
	  return -1;
	}
      *lcl_port = port;
    }
  else
    {
      port = clib_net_to_host_u16 (rmt_cfg->peer.port);
      tei = transport_endpoint_lookup (&local_endpoints_table, proto,
				       lcl_addr, port);
      if (tei != ENDPOINT_INVALID_INDEX)
	return -1;

      transport_endpoint_mark_used (proto, lcl_addr, port);
      *lcl_port = port;
    }

  return 0;
}

#define SPACER_CPU_TICKS_PER_PERIOD_SHIFT 10
#define SPACER_CPU_TICKS_PER_PERIOD (1 << SPACER_CPU_TICKS_PER_PERIOD_SHIFT)

u8 *
format_transport_pacer (u8 * s, va_list * args)
{
  spacer_t *pacer = va_arg (*args, spacer_t *);

  s = format (s, "bucket %u max_burst %u tokens/period %.3f last_update %x",
	      pacer->bucket, pacer->max_burst_size, pacer->tokens_per_period,
	      pacer->last_update);
  return s;
}

static inline u32
spacer_max_burst (spacer_t * pacer, u64 norm_time_now)
{
  u64 n_periods = norm_time_now - pacer->last_update;
  u64 inc;

  if (n_periods > 0 && (inc = n_periods * pacer->tokens_per_period) > 10)
    {
      pacer->last_update = norm_time_now;
      pacer->bucket += inc;
    }

  return clib_min (pacer->bucket, pacer->max_burst_size);
}

static inline void
spacer_update_bucket (spacer_t * pacer, u32 bytes)
{
  ASSERT (pacer->bucket >= bytes);
  if (pacer->bucket < bytes)
    os_panic ();
  pacer->bucket -= bytes;
}

static inline void
spacer_update_max_burst_size (spacer_t * pacer, u32 max_burst_bytes)
{
  pacer->max_burst_size = clib_max (max_burst_bytes, TRANSPORT_PACER_MIN_MSS);
}

static inline void
spacer_set_pace_rate (spacer_t * pacer, u64 rate_bytes_per_sec)
{
  ASSERT (rate_bytes_per_sec != 0);
  pacer->tokens_per_period = rate_bytes_per_sec / transport_pacer_period;
}

void
transport_connection_tx_pacer_reset (transport_connection_t * tc,
				     u32 rate_bytes_per_sec,
				     u32 start_bucket, u64 time_now)
{
  spacer_t *pacer = &tc->pacer;
  f64 dispatch_period;
  u32 burst_size;

  dispatch_period = transport_dispatch_period (tc->thread_index);
  burst_size = rate_bytes_per_sec * dispatch_period;
  spacer_update_max_burst_size (&tc->pacer, burst_size);
  spacer_set_pace_rate (&tc->pacer, rate_bytes_per_sec);
  pacer->last_update = time_now >> SPACER_CPU_TICKS_PER_PERIOD_SHIFT;
  pacer->bucket = start_bucket;
}

void
transport_connection_tx_pacer_init (transport_connection_t * tc,
				    u32 rate_bytes_per_sec,
				    u32 initial_bucket)
{
  vlib_main_t *vm = vlib_get_main ();
  tc->flags |= TRANSPORT_CONNECTION_F_IS_TX_PACED;
  transport_connection_tx_pacer_reset (tc, rate_bytes_per_sec,
				       initial_bucket,
				       vm->clib_time.last_cpu_time);
}

void
transport_connection_tx_pacer_update (transport_connection_t * tc,
				      u64 bytes_per_sec)
{
  u32 burst_size;

  burst_size = bytes_per_sec * transport_dispatch_period (tc->thread_index);
  spacer_set_pace_rate (&tc->pacer, bytes_per_sec);
  spacer_update_max_burst_size (&tc->pacer, burst_size);
}

u32
transport_connection_tx_pacer_burst (transport_connection_t * tc,
				     u64 time_now)
{
  time_now >>= SPACER_CPU_TICKS_PER_PERIOD_SHIFT;
  return spacer_max_burst (&tc->pacer, time_now);
}

u32
transport_connection_snd_space (transport_connection_t * tc, u64 time_now,
				u16 mss)
{
  u32 snd_space, max_paced_burst;

  snd_space = tp_vfts[tc->proto].send_space (tc);
  if (transport_connection_is_tx_paced (tc))
    {
      time_now >>= SPACER_CPU_TICKS_PER_PERIOD_SHIFT;
      max_paced_burst = spacer_max_burst (&tc->pacer, time_now);
      max_paced_burst = (max_paced_burst < mss) ? 0 : max_paced_burst;
      snd_space = clib_min (snd_space, max_paced_burst);
      snd_space = snd_space - snd_space % mss;
    }
  return snd_space;
}

void
transport_connection_update_tx_stats (transport_connection_t * tc, u32 bytes)
{
  tc->stats.tx_bytes += bytes;
  if (transport_connection_is_tx_paced (tc))
    spacer_update_bucket (&tc->pacer, bytes);
}

void
transport_connection_tx_pacer_update_bytes (transport_connection_t * tc,
					    u32 bytes)
{
  spacer_update_bucket (&tc->pacer, bytes);
}

void
transport_init_tx_pacers_period (void)
{
  f64 cpu_freq = os_cpu_clock_frequency ();
  transport_pacer_period = cpu_freq / SPACER_CPU_TICKS_PER_PERIOD;
}

void
transport_update_time (f64 time_now, u8 thread_index)
{
  transport_proto_vft_t *vft;
  vec_foreach (vft, tp_vfts)
  {
    if (vft->update_time)
      (vft->update_time) (time_now, thread_index);
  }
}

void
transport_enable_disable (vlib_main_t * vm, u8 is_en)
{
  transport_proto_vft_t *vft;
  vec_foreach (vft, tp_vfts)
  {
    if (vft->enable)
      (vft->enable) (vm, is_en);
  }
}

void
transport_init (void)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  u32 num_threads;

  if (smm->local_endpoints_table_buckets == 0)
    smm->local_endpoints_table_buckets = 250000;
  if (smm->local_endpoints_table_memory == 0)
    smm->local_endpoints_table_memory = 512 << 20;

  /* Initialize [port-allocator] random number seed */
  port_allocator_seed = (u32) clib_cpu_time_now ();

  clib_bihash_init_24_8 (&local_endpoints_table, "local endpoints table",
			 smm->local_endpoints_table_buckets,
			 smm->local_endpoints_table_memory);
  num_threads = 1 /* main thread */  + vtm->n_threads;
  if (num_threads > 1)
    clib_spinlock_init (&local_endpoints_lock);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
