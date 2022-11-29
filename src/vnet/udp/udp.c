/*
 * Copyright (c) 2016-2020 Cisco and/or its affiliates.
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

#include <vnet/udp/udp.h>
#include <vnet/session/session.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>
#include <vppinfra/sparse_vec.h>

udp_main_t udp_main;

static void
udp_connection_register_port (u16 lcl_port, u8 is_ip4)
{
  udp_main_t *um = &udp_main;
  u16 *n;

  /* Setup udp protocol -> next index sparse vector mapping. Do not setup
   * udp_dst_port_info_t as that is used to distinguish between external
   * and transport consumed ports */

  if (is_ip4)
    n = sparse_vec_validate (um->next_by_dst_port4, lcl_port);
  else
    n = sparse_vec_validate (um->next_by_dst_port6, lcl_port);

  n[0] = um->local_to_input_edge[is_ip4];
}

static void
udp_connection_unregister_port (u16 lcl_port, u8 is_ip4)
{
  udp_main_t *um = &udp_main;
  u16 *n;

  if (is_ip4)
    n = sparse_vec_validate (um->next_by_dst_port4, lcl_port);
  else
    n = sparse_vec_validate (um->next_by_dst_port6, lcl_port);

  n[0] = UDP_NO_NODE_SET;
}

udp_connection_t *
udp_connection_alloc (u32 thread_index)
{
  udp_worker_t *wrk = udp_worker_get (thread_index);
  udp_connection_t *uc;

  pool_get_aligned_safe (wrk->connections, uc, CLIB_CACHE_LINE_BYTES);

  clib_memset (uc, 0, sizeof (*uc));
  uc->c_c_index = uc - wrk->connections;
  uc->c_thread_index = thread_index;
  uc->c_proto = TRANSPORT_PROTO_UDP;
  return uc;
}

void
udp_connection_free (udp_connection_t * uc)
{
  udp_worker_t *wrk = udp_worker_get (uc->c_thread_index);

  clib_spinlock_free (&uc->rx_lock);
  if (CLIB_DEBUG)
    clib_memset (uc, 0xFA, sizeof (*uc));
  pool_put (wrk->connections, uc);
}

static void
udp_connection_cleanup (udp_connection_t * uc)
{
  /* Unregister port from udp_local only if refcount went to zero */
  if (!transport_release_local_endpoint (TRANSPORT_PROTO_UDP, &uc->c_lcl_ip,
					 uc->c_lcl_port))
    udp_connection_unregister_port (uc->c_lcl_port, uc->c_is_ip4);
  udp_connection_free (uc);
}

void
udp_connection_delete (udp_connection_t * uc)
{
  session_transport_delete_notify (&uc->connection);
  udp_connection_cleanup (uc);
}

static void
udp_handle_cleanups (void *args)
{
  u32 thread_index = (u32) pointer_to_uword (args);
  udp_connection_t *uc;
  udp_worker_t *wrk;
  u32 *uc_index;

  wrk = udp_worker_get (thread_index);
  vec_foreach (uc_index, wrk->pending_cleanups)
    {
      uc = udp_connection_get (*uc_index, thread_index);
      udp_connection_delete (uc);
    }
  vec_reset_length (wrk->pending_cleanups);
}

static void
udp_connection_program_cleanup (udp_connection_t *uc)
{
  uword thread_index = uc->c_thread_index;
  udp_worker_t *wrk;

  wrk = udp_worker_get (uc->c_thread_index);
  vec_add1 (wrk->pending_cleanups, uc->c_c_index);

  if (vec_len (wrk->pending_cleanups) == 1)
    session_send_rpc_evt_to_thread_force (
      thread_index, udp_handle_cleanups,
      uword_to_pointer (thread_index, void *));
}

static u8
udp_connection_port_used_extern (u16 lcl_port, u8 is_ip4)
{
  udp_main_t *um = vnet_get_udp_main ();
  udp_dst_port_info_t *pi;

  pi = udp_get_dst_port_info (um, lcl_port, is_ip4);
  return (pi && udp_is_valid_dst_port (lcl_port, is_ip4));
}

static u16
udp_default_mtu (udp_main_t * um, u8 is_ip4)
{
  u16 ip_hlen = is_ip4 ? sizeof (ip4_header_t) : sizeof (ip6_header_t);
  return (um->default_mtu - sizeof (udp_header_t) - ip_hlen);
}

static u32
udp_session_bind (u32 session_index, transport_endpoint_cfg_t *lcl)
{
  udp_main_t *um = vnet_get_udp_main ();
  transport_endpoint_cfg_t *lcl_ext;
  udp_connection_t *listener;
  void *iface_ip;

  if (udp_connection_port_used_extern (clib_net_to_host_u16 (lcl->port),
				       lcl->is_ip4))
    {
      clib_warning ("port already used");
      return SESSION_E_PORTINUSE;
    }

  pool_get (um->listener_pool, listener);
  clib_memset (listener, 0, sizeof (udp_connection_t));

  listener->c_lcl_port = lcl->port;
  listener->c_c_index = listener - um->listener_pool;

  /* If we are provided a sw_if_index, bind using one of its ips */
  if (ip_is_zero (&lcl->ip, 1) && lcl->sw_if_index != ENDPOINT_INVALID_INDEX)
    {
      if ((iface_ip = ip_interface_get_first_ip (lcl->sw_if_index,
						 lcl->is_ip4)))
	ip_set (&lcl->ip, iface_ip, lcl->is_ip4);
    }
  ip_copy (&listener->c_lcl_ip, &lcl->ip, lcl->is_ip4);
  listener->c_is_ip4 = lcl->is_ip4;
  listener->c_proto = TRANSPORT_PROTO_UDP;
  listener->c_s_index = session_index;
  listener->c_fib_index = lcl->fib_index;
  listener->mss =
    lcl->mss ? lcl->mss : udp_default_mtu (um, listener->c_is_ip4);
  listener->flags |= UDP_CONN_F_OWNS_PORT | UDP_CONN_F_LISTEN;
  lcl_ext = (transport_endpoint_cfg_t *) lcl;
  if (lcl_ext->transport_flags & TRANSPORT_CFG_F_CONNECTED)
    listener->flags |= UDP_CONN_F_CONNECTED;
  else
    listener->c_flags |= TRANSPORT_CONNECTION_F_CLESS;
  clib_spinlock_init (&listener->rx_lock);
  if (!um->csum_offload)
    listener->cfg_flags |= UDP_CFG_F_NO_CSUM_OFFLOAD;

  udp_connection_register_port (listener->c_lcl_port, lcl->is_ip4);
  return listener->c_c_index;
}

static u32
udp_session_unbind (u32 listener_index)
{
  udp_main_t *um = &udp_main;
  udp_connection_t *listener;

  listener = udp_listener_get (listener_index);
  udp_connection_unregister_port (listener->c_lcl_port, listener->c_is_ip4);
  clib_spinlock_free (&listener->rx_lock);
  pool_put (um->listener_pool, listener);
  return 0;
}

static transport_connection_t *
udp_session_get_listener (u32 listener_index)
{
  udp_connection_t *us;

  us = udp_listener_get (listener_index);
  return &us->connection;
}

always_inline u32
udp_push_one_header (vlib_main_t *vm, udp_connection_t *uc, vlib_buffer_t *b)
{
  vlib_buffer_push_udp (b, uc->c_lcl_port, uc->c_rmt_port,
			udp_csum_offload (uc));
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  /* reuse tcp medatada for now */
  vnet_buffer (b)->tcp.connection_index = uc->c_c_index;

  return 0;
}

static u32
udp_push_header (transport_connection_t *tc, vlib_buffer_t **bs, u32 n_bufs)
{
  vlib_main_t *vm = vlib_get_main ();
  udp_connection_t *uc;

  uc = udp_connection_from_transport (tc);

  while (n_bufs >= 4)
    {
      vlib_prefetch_buffer_header (bs[2], STORE);
      vlib_prefetch_buffer_header (bs[3], STORE);

      udp_push_one_header (vm, uc, bs[0]);
      udp_push_one_header (vm, uc, bs[1]);

      n_bufs -= 2;
      bs += 2;
    }
  while (n_bufs)
    {
      if (n_bufs > 1)
	vlib_prefetch_buffer_header (bs[1], STORE);

      udp_push_one_header (vm, uc, bs[0]);

      n_bufs -= 1;
      bs += 1;
    }

  if (PREDICT_FALSE (uc->flags & UDP_CONN_F_CLOSING))
    {
      if (!transport_max_tx_dequeue (&uc->connection))
	udp_connection_program_cleanup (uc);
    }

  return 0;
}

static transport_connection_t *
udp_session_get (u32 connection_index, u32 thread_index)
{
  udp_connection_t *uc;
  uc = udp_connection_get (connection_index, thread_index);
  if (uc)
    return &uc->connection;
  return 0;
}

static void
udp_session_close (u32 connection_index, u32 thread_index)
{
  udp_connection_t *uc;

  uc = udp_connection_get (connection_index, thread_index);
  if (!uc || (uc->flags & UDP_CONN_F_MIGRATED))
    return;

  if (!transport_max_tx_dequeue (&uc->connection))
    udp_connection_program_cleanup (uc);
  else
    uc->flags |= UDP_CONN_F_CLOSING;
}

static void
udp_session_cleanup (u32 connection_index, u32 thread_index)
{
  udp_connection_t *uc;
  uc = udp_connection_get (connection_index, thread_index);
  if (!uc)
    return;
  if (uc->flags & UDP_CONN_F_MIGRATED)
    udp_connection_free (uc);
  else
    udp_connection_cleanup (uc);
}

static int
udp_session_send_params (transport_connection_t * tconn,
			 transport_send_params_t * sp)
{
  udp_connection_t *uc;

  uc = udp_connection_from_transport (tconn);

  /* No constraint on TX window */
  sp->snd_space = ~0;
  /* TODO figure out MTU of output interface */
  sp->snd_mss = uc->mss;
  sp->tx_offset = 0;
  sp->flags = 0;
  return 0;
}

static int
udp_open_connection (transport_endpoint_cfg_t * rmt)
{
  udp_main_t *um = &udp_main;
  ip46_address_t lcl_addr;
  udp_connection_t *uc;
  u32 thread_index;
  u16 lcl_port;
  int rv;

  rv = transport_alloc_local_endpoint (TRANSPORT_PROTO_UDP, rmt, &lcl_addr,
				       &lcl_port);
  if (rv)
    {
      if (rv != SESSION_E_PORTINUSE)
	return rv;

      if (udp_connection_port_used_extern (lcl_port, rmt->is_ip4))
	return SESSION_E_PORTINUSE;

      /* If port in use, check if 5-tuple is also in use */
      if (session_lookup_connection (rmt->fib_index, &lcl_addr, &rmt->ip,
				     lcl_port, rmt->port, TRANSPORT_PROTO_UDP,
				     rmt->is_ip4))
	return SESSION_E_PORTINUSE;

      /* 5-tuple is available so increase lcl endpoint refcount and proceed
       * with connection allocation */
      transport_share_local_endpoint (TRANSPORT_PROTO_UDP, &lcl_addr,
				      lcl_port);
      goto conn_alloc;
    }

  if (udp_is_valid_dst_port (lcl_port, rmt->is_ip4))
    {
      /* If specific source port was requested abort */
      if (rmt->peer.port)
	return SESSION_E_PORTINUSE;

      /* Try to find a port that's not used */
      while (udp_is_valid_dst_port (lcl_port, rmt->is_ip4))
	{
	  lcl_port = transport_alloc_local_port (TRANSPORT_PROTO_UDP,
						 &lcl_addr);
	  if (lcl_port < 1)
	    return SESSION_E_PORTINUSE;
	}
    }

conn_alloc:

  /* We don't poll main thread if we have workers */
  thread_index = transport_cl_thread ();

  uc = udp_connection_alloc (thread_index);
  ip_copy (&uc->c_rmt_ip, &rmt->ip, rmt->is_ip4);
  ip_copy (&uc->c_lcl_ip, &lcl_addr, rmt->is_ip4);
  uc->c_rmt_port = rmt->port;
  uc->c_lcl_port = clib_host_to_net_u16 (lcl_port);
  uc->c_is_ip4 = rmt->is_ip4;
  uc->c_proto = TRANSPORT_PROTO_UDP;
  uc->c_fib_index = rmt->fib_index;
  uc->c_dscp = rmt->dscp;
  uc->mss = rmt->mss ? rmt->mss : udp_default_mtu (um, uc->c_is_ip4);
  if (rmt->peer.sw_if_index != ENDPOINT_INVALID_INDEX)
    uc->sw_if_index = rmt->peer.sw_if_index;
  uc->flags |= UDP_CONN_F_OWNS_PORT;
  if (rmt->transport_flags & TRANSPORT_CFG_F_CONNECTED)
    {
      uc->flags |= UDP_CONN_F_CONNECTED;
    }
  else
    {
      clib_spinlock_init (&uc->rx_lock);
      uc->c_flags |= TRANSPORT_CONNECTION_F_CLESS;
    }
  if (!um->csum_offload)
    uc->cfg_flags |= UDP_CFG_F_NO_CSUM_OFFLOAD;
  uc->next_node_index = rmt->next_node_index;
  uc->next_node_opaque = rmt->next_node_opaque;

  udp_connection_register_port (uc->c_lcl_port, rmt->is_ip4);

  return uc->c_c_index;
}

static transport_connection_t *
udp_session_get_half_open (u32 conn_index)
{
  udp_connection_t *uc;
  u32 thread_index;

  /* We don't poll main thread if we have workers */
  thread_index = transport_cl_thread ();
  uc = udp_connection_get (conn_index, thread_index);
  if (!uc)
    return 0;
  return &uc->connection;
}

static u8 *
format_udp_session (u8 * s, va_list * args)
{
  u32 uci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  udp_connection_t *uc;

  uc = udp_connection_get (uci, thread_index);
  return format (s, "%U", format_udp_connection, uc, verbose);
}

static u8 *
format_udp_half_open_session (u8 * s, va_list * args)
{
  u32 __clib_unused tci = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  clib_warning ("BUG");
  return 0;
}

static u8 *
format_udp_listener_session (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  udp_connection_t *uc = udp_listener_get (tci);
  return format (s, "%U", format_udp_connection, uc, verbose);
}

static void
udp_realloc_ports_sv (u16 **ports_nh_svp)
{
  u16 port, port_no, *ports_nh_sv, *mc;
  u32 *ports = 0, *nh = 0, msum, i;
  sparse_vec_header_t *h;
  uword sv_index, *mb;

  ports_nh_sv = *ports_nh_svp;

  for (port = 1; port < 65535; port++)
    {
      port_no = clib_host_to_net_u16 (port);

      sv_index = sparse_vec_index (ports_nh_sv, port_no);
      if (sv_index != SPARSE_VEC_INVALID_INDEX)
	{
	  vec_add1 (ports, port_no);
	  vec_add1 (nh, ports_nh_sv[sv_index]);
	}
    }

  sparse_vec_free (ports_nh_sv);

  ports_nh_sv =
    sparse_vec_new (/* elt bytes */ sizeof (ports_nh_sv[0]),
		    /* bits in index */ BITS (((udp_header_t *) 0)->dst_port));

  vec_resize (ports_nh_sv, 65535);

  for (port = 1; port < 65535; port++)
    ports_nh_sv[port] = UDP_NO_NODE_SET;

  for (i = 0; i < vec_len (ports); i++)
    ports_nh_sv[ports[i]] = nh[i];

  h = sparse_vec_header (ports_nh_sv);
  vec_foreach (mb, h->is_member_bitmap)
    *mb = (uword) ~0;

  msum = 0;
  vec_foreach (mc, h->member_counts)
    {
      *mc = msum;
      msum += msum == 0 ? 63 : 64;
    }

  vec_free (ports);
  vec_free (nh);

  *ports_nh_svp = ports_nh_sv;
}

static clib_error_t *
udp_enable_disable (vlib_main_t *vm, u8 is_en)
{
  udp_main_t *um = &udp_main;

  /* Not ideal. The sparse vector used to map ports to next nodes assumes
   * only a few ports are ever used. When udp transport is enabled this does
   * not hold and, to make matters worse, ports are consumed in a random
   * order.
   *
   * This can lead to a lot of slow updates to internal data structures
   * which in turn can slow udp connection allocations until all ports are
   * eventually consumed.
   *
   * Consequently, reallocate sparse vector, preallocate all ports and have
   * them point to UDP_NO_NODE_SET. We could consider switching the sparse
   * vector to a preallocated vector but that would increase memory
   * consumption for vpp deployments that do not rely on host stack.
   */

  udp_realloc_ports_sv (&um->next_by_dst_port4);
  udp_realloc_ports_sv (&um->next_by_dst_port6);

  return 0;
}

static const transport_proto_vft_t udp_proto = {
  .enable = udp_enable_disable,
  .start_listen = udp_session_bind,
  .connect = udp_open_connection,
  .stop_listen = udp_session_unbind,
  .push_header = udp_push_header,
  .get_connection = udp_session_get,
  .get_listener = udp_session_get_listener,
  .get_half_open = udp_session_get_half_open,
  .close = udp_session_close,
  .cleanup = udp_session_cleanup,
  .send_params = udp_session_send_params,
  .format_connection = format_udp_session,
  .format_half_open = format_udp_half_open_session,
  .format_listener = format_udp_listener_session,
  .transport_options = {
    .name = "udp",
    .short_name = "U",
    .tx_type = TRANSPORT_TX_DGRAM,
    .service_type = TRANSPORT_SERVICE_CL,
  },
};

static clib_error_t *
udp_init (vlib_main_t * vm)
{
  udp_main_t *um = vnet_get_udp_main ();
  ip_main_t *im = &ip_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 num_threads;
  ip_protocol_info_t *pi;

  /*
   * Registrations
   */

  /* IP registration */
  pi = ip_get_protocol_info (im, IP_PROTOCOL_UDP);
  if (pi == 0)
    return clib_error_return (0, "UDP protocol info AWOL");
  pi->format_header = format_udp_header;
  pi->unformat_pg_edit = unformat_pg_udp_header;

  /* Register as transport with session layer */
  transport_register_protocol (TRANSPORT_PROTO_UDP, &udp_proto,
			       FIB_PROTOCOL_IP4, udp4_output_node.index);
  transport_register_protocol (TRANSPORT_PROTO_UDP, &udp_proto,
			       FIB_PROTOCOL_IP6, udp6_output_node.index);

  /*
   * Initialize data structures
   */

  num_threads = 1 /* main thread */  + tm->n_threads;
  vec_validate (um->wrk, num_threads - 1);

  um->local_to_input_edge[UDP_IP4] =
    vlib_node_add_next (vm, udp4_local_node.index, udp4_input_node.index);
  um->local_to_input_edge[UDP_IP6] =
    vlib_node_add_next (vm, udp6_local_node.index, udp6_input_node.index);

  um->default_mtu = 1500;
  um->csum_offload = 1;
  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (udp_init) =
{
  .runs_after = VLIB_INITS("ip_main_init", "ip4_lookup_init",
                           "ip6_lookup_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
