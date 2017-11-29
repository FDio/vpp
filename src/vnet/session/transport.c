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
    }
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
 * @param type - session type (not protocol type)
 * @param vft - virtual function table
 */
void
transport_register_protocol (transport_proto_t transport_proto, u8 is_ip4,
			     const transport_proto_vft_t * vft)
{
  u8 session_type;
  session_type = session_type_from_proto_and_ip (transport_proto, is_ip4);

  vec_validate (tp_vfts, session_type);
  tp_vfts[session_type] = *vft;

  /* If an offset function is provided, then peek instead of dequeue */
  session_manager_set_transport_rx_fn (session_type,
				       vft->tx_fifo_offset != 0);
}

/**
 * Get transport virtual function table
 *
 * @param type - session type (not protocol type)
 */
transport_proto_vft_t *
transport_protocol_get_vft (u8 session_type)
{
  if (session_type >= vec_len (tp_vfts))
    return 0;
  return &tp_vfts[session_type];
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
  pool_get (local_endpoints, tep);
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

/**
 * Allocate local port and add if successful add entry to local endpoint
 * table to mark the pair as used.
 */
int
transport_alloc_local_port (u8 proto, ip46_address_t * ip)
{
  transport_endpoint_t *tep;
  u32 tei;
  u16 min = 1024, max = 65535;	/* XXX configurable ? */
  int tries, limit;

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
	  clib_spinlock_lock_if_init (&local_endpoints_lock);
	  tep = transport_endpoint_new ();
	  clib_memcpy (&tep->ip, ip, sizeof (*ip));
	  tep->port = port;
	  transport_endpoint_table_add (&local_endpoints_table, proto, tep,
					tep - local_endpoints);
	  clib_spinlock_unlock_if_init (&local_endpoints_lock);

	  return tep->port;
	}
    }
  return -1;
}

int
transport_alloc_local_endpoint (u8 proto, transport_endpoint_t * rmt,
				ip46_address_t * lcl_addr, u16 * lcl_port)
{
  fib_prefix_t prefix;
  fib_node_index_t fei;
  u32 sw_if_index;
  int port;

  /*
   * Find the local address and allocate port
   */

  /* Find a FIB path to the destination */
  clib_memcpy (&prefix.fp_addr, &rmt->ip, sizeof (rmt->ip));
  prefix.fp_proto = rmt->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  prefix.fp_len = rmt->is_ip4 ? 32 : 128;

  ASSERT (rmt->fib_index != ENDPOINT_INVALID_INDEX);
  fei = fib_table_lookup (rmt->fib_index, &prefix);

  /* Couldn't find route to destination. Bail out. */
  if (fei == FIB_NODE_INDEX_INVALID)
    {
      clib_warning ("no route to destination");
      return -1;
    }

  sw_if_index = rmt->sw_if_index;
  if (sw_if_index == ENDPOINT_INVALID_INDEX)
    sw_if_index = fib_entry_get_resolving_interface (fei);

  if (sw_if_index == ENDPOINT_INVALID_INDEX)
    {
      clib_warning ("no resolving interface for %U", format_ip46_address,
		    &rmt->ip, (rmt->is_ip4 == 0) + 1);
      return -1;
    }

  memset (lcl_addr, 0, sizeof (*lcl_addr));

  if (rmt->is_ip4)
    {
      ip4_address_t *ip4;
      ip4 = ip_interface_get_first_ip (sw_if_index, 1);
      lcl_addr->ip4.as_u32 = ip4->as_u32;
    }
  else
    {
      ip6_address_t *ip6;
      ip6 = ip_interface_get_first_ip (sw_if_index, 0);
      if (ip6 == 0)
	{
	  clib_warning ("no routable ip6 addresses on %U",
			format_vnet_sw_if_index_name, vnet_get_main (),
			sw_if_index);
	  return -1;
	}
      clib_memcpy (&lcl_addr->ip6, ip6, sizeof (*ip6));
    }

  /* Allocate source port */
  port = transport_alloc_local_port (proto, lcl_addr);
  if (port < 1)
    {
      clib_warning ("Failed to allocate src port");
      return -1;
    }
  *lcl_port = port;
  return 0;
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
