/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vnet/fib/fib_table.h>

#include <nat/lib/log.h>
#include <nat/lib/nat_inlines.h>
#include <nat/lib/ipfix_logging.h>

#include <nat/nat44-ei/nat44_ei.h>
#include <nat/nat44-ei/nat44_ei_ha.h>

u8 *
format_nat44_ei_session (u8 *s, va_list *args)
{
  nat44_ei_main_per_thread_data_t *tnm =
    va_arg (*args, nat44_ei_main_per_thread_data_t *);
  nat44_ei_session_t *sess = va_arg (*args, nat44_ei_session_t *);

  if (nat44_ei_is_unk_proto_session (sess))
    {
      s =
	format (s, "  i2o %U proto %u fib %u\n", format_ip4_address,
		&sess->in2out.addr, sess->in2out.port, sess->in2out.fib_index);
      s =
	format (s, "  o2i %U proto %u fib %u\n", format_ip4_address,
		&sess->out2in.addr, sess->out2in.port, sess->out2in.fib_index);
    }
  else
    {
      s = format (s, "  i2o %U proto %U port %d fib %d\n", format_ip4_address,
		  &sess->in2out.addr, format_nat_protocol, sess->nat_proto,
		  clib_net_to_host_u16 (sess->in2out.port),
		  sess->in2out.fib_index);
      s = format (s, "  o2i %U proto %U port %d fib %d\n", format_ip4_address,
		  &sess->out2in.addr, format_nat_protocol, sess->nat_proto,
		  clib_net_to_host_u16 (sess->out2in.port),
		  sess->out2in.fib_index);
    }

  s = format (s, "       index %llu\n", sess - tnm->sessions);
  s = format (s, "       last heard %.2f\n", sess->last_heard);
  s = format (s, "       total pkts %d, total bytes %lld\n", sess->total_pkts,
	      sess->total_bytes);
  if (nat44_ei_is_session_static (sess))
    s = format (s, "       static translation\n");
  else
    s = format (s, "       dynamic translation\n");

  return s;
}

u8 *
format_nat44_ei_user (u8 *s, va_list *args)
{
  nat44_ei_main_per_thread_data_t *tnm =
    va_arg (*args, nat44_ei_main_per_thread_data_t *);
  nat44_ei_user_t *u = va_arg (*args, nat44_ei_user_t *);
  int verbose = va_arg (*args, int);
  dlist_elt_t *head, *elt;
  u32 elt_index, head_index;
  u32 session_index;
  nat44_ei_session_t *sess;

  s = format (s, "%U: %d dynamic translations, %d static translations\n",
	      format_ip4_address, &u->addr, u->nsessions, u->nstaticsessions);

  if (verbose == 0)
    return s;

  if (u->nsessions || u->nstaticsessions)
    {
      head_index = u->sessions_per_user_list_head_index;
      head = pool_elt_at_index (tnm->list_pool, head_index);

      elt_index = head->next;
      elt = pool_elt_at_index (tnm->list_pool, elt_index);
      session_index = elt->value;

      while (session_index != ~0)
	{
	  sess = pool_elt_at_index (tnm->sessions, session_index);

	  s = format (s, "  %U\n", format_nat44_ei_session, tnm, sess);

	  elt_index = elt->next;
	  elt = pool_elt_at_index (tnm->list_pool, elt_index);
	  session_index = elt->value;
	}
    }

  return s;
}

u8 *
format_nat44_ei_static_mapping (u8 *s, va_list *args)
{
  nat44_ei_static_mapping_t *m = va_arg (*args, nat44_ei_static_mapping_t *);
  nat44_ei_lb_addr_port_t *local;

  if (nat44_ei_is_identity_static_mapping (m))
    {
      if (nat44_ei_is_addr_only_static_mapping (m))
	s = format (s, "identity mapping %U", format_ip4_address,
		    &m->local_addr);
      else
	s = format (s, "identity mapping %U %U:%d", format_nat_protocol,
		    m->proto, format_ip4_address, &m->local_addr,
		    clib_net_to_host_u16 (m->local_port));

      pool_foreach (local, m->locals)
	{
	  s = format (s, " vrf %d", local->vrf_id);
	}

      return s;
    }

  if (nat44_ei_is_addr_only_static_mapping (m))
    {
      s = format (s, "local %U external %U vrf %d", format_ip4_address,
		  &m->local_addr, format_ip4_address, &m->external_addr,
		  m->vrf_id);
    }
  else
    {
      s = format (s, "%U local %U:%d external %U:%d vrf %d",
		  format_nat_protocol, m->proto, format_ip4_address,
		  &m->local_addr, clib_net_to_host_u16 (m->local_port),
		  format_ip4_address, &m->external_addr,
		  clib_net_to_host_u16 (m->external_port), m->vrf_id);
    }
  return s;
}

u8 *
format_nat44_ei_static_map_to_resolve (u8 *s, va_list *args)
{
  nat44_ei_static_map_resolve_t *m =
    va_arg (*args, nat44_ei_static_map_resolve_t *);
  vnet_main_t *vnm = vnet_get_main ();

  if (m->addr_only)
    s =
      format (s, "local %U external %U vrf %d", format_ip4_address, &m->l_addr,
	      format_vnet_sw_if_index_name, vnm, m->sw_if_index, m->vrf_id);
  else
    s = format (s, "%U local %U:%d external %U:%d vrf %d", format_nat_protocol,
		m->proto, format_ip4_address, &m->l_addr,
		clib_net_to_host_u16 (m->l_port), format_vnet_sw_if_index_name,
		vnm, m->sw_if_index, clib_net_to_host_u16 (m->e_port),
		m->vrf_id);

  return s;
}

static clib_error_t *
nat44_ei_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  nat44_ei_config_t c = { 0 };
  u8 mode_set = 0;

  if (nm->enabled)
    return clib_error_return (0, "nat44 ei already enabled");

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      if (nat44_ei_plugin_enable (c) != 0)
	return clib_error_return (0, "nat44 ei enable failed");
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (!mode_set && unformat (line_input, "static-mapping-only"))
	{
	  mode_set = 1;
	  c.static_mapping_only = 1;
	  if (unformat (line_input, "connection-tracking"))
	    {
	      c.connection_tracking = 1;
	    }
	}
      else if (!mode_set && unformat (line_input, "out2in-dpo"))
	{
	  mode_set = 1;
	  c.out2in_dpo = 1;
	}
      else if (unformat (line_input, "inside-vrf %u", &c.inside_vrf))
	;
      else if (unformat (line_input, "outside-vrf %u", &c.outside_vrf))
	;
      else if (unformat (line_input, "users %u", &c.users))
	;
      else if (unformat (line_input, "sessions %u", &c.sessions))
	;
      else if (unformat (line_input, "user-sessions %u", &c.user_sessions))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!c.sessions)
    {
      error = clib_error_return (0, "number of sessions is required");
      goto done;
    }

  if (nat44_ei_plugin_enable (c) != 0)
    error = clib_error_return (0, "nat44 ei enable failed");
done:
  unformat_free (line_input);
  return error;
}

static clib_error_t *
nat44_ei_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  clib_error_t *error = 0;

  if (!nm->enabled)
    return clib_error_return (0, "nat44 ei already disabled");

  if (nat44_ei_plugin_disable () != 0)
    error = clib_error_return (0, "nat44 ei disable failed");

  return error;
}

static clib_error_t *
set_workers_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  uword *bitmap = 0;
  int rv = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_bitmap_list, &bitmap))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (bitmap == 0)
    {
      error = clib_error_return (0, "List of workers must be specified.");
      goto done;
    }

  rv = nat44_ei_set_workers (bitmap);

  clib_bitmap_free (bitmap);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_WORKER:
      error = clib_error_return (0, "Invalid worker(s).");
      goto done;
    case VNET_API_ERROR_FEATURE_DISABLED:
      error =
	clib_error_return (0, "Supported only if 2 or more workes available.");
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat_show_workers_commnad_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  u32 *worker;

  if (nm->num_workers > 1)
    {
      vlib_cli_output (vm, "%d workers", vec_len (nm->workers));
      vec_foreach (worker, nm->workers)
	{
	  vlib_worker_thread_t *w =
	    vlib_worker_threads + *worker + nm->first_worker_index;
	  vlib_cli_output (vm, "  %s", w->name);
	}
    }

  return 0;
}

static clib_error_t *
nat44_ei_set_log_level_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  nat44_ei_main_t *nm = &nat44_ei_main;
  u8 log_level = NAT_LOG_NONE;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat (line_input, "%d", &log_level))
    {
      error = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, line_input);
      goto done;
    }
  if (log_level > NAT_LOG_DEBUG)
    {
      error = clib_error_return (0, "unknown logging level '%d'", log_level);
      goto done;
    }
  nm->log_level = log_level;

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_ei_ipfix_logging_enable_disable_command_fn (vlib_main_t *vm,
						  unformat_input_t *input,
						  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 domain_id = 0;
  u32 src_port = 0;
  u8 enable = 1;
  int rv = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      rv =
	nat_ipfix_logging_enable_disable (enable, domain_id, (u16) src_port);
      if (rv)
	return clib_error_return (0, "ipfix logging enable failed");
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "domain %d", &domain_id))
	;
      else if (unformat (line_input, "src-port %d", &src_port))
	;
      else if (unformat (line_input, "disable"))
	enable = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = nat_ipfix_logging_enable_disable (enable, domain_id, (u16) src_port);

  if (rv)
    {
      error = clib_error_return (0, "ipfix logging enable failed");
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_ei_show_hash_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_main_per_thread_data_t *tnm;
  int i;
  int verbose = 0;

  if (unformat (input, "detail"))
    verbose = 1;
  else if (unformat (input, "verbose"))
    verbose = 2;

  vlib_cli_output (vm, "%U", format_bihash_8_8, &nm->static_mapping_by_local,
		   verbose);
  vlib_cli_output (vm, "%U", format_bihash_8_8,
		   &nm->static_mapping_by_external, verbose);
  vec_foreach_index (i, nm->per_thread_data)
    {
      tnm = vec_elt_at_index (nm->per_thread_data, i);
      vlib_cli_output (vm, "-------- thread %d %s --------\n", i,
		       vlib_worker_threads[i].name);

      vlib_cli_output (vm, "%U", format_bihash_8_8, &nm->in2out, verbose);
      vlib_cli_output (vm, "%U", format_bihash_8_8, &nm->out2in, verbose);
      vlib_cli_output (vm, "%U", format_bihash_8_8, &tnm->user_hash, verbose);
    }

  vlib_cli_output (vm, "-------- hash table parameters --------\n");
  vlib_cli_output (vm, "translation buckets: %u", nm->translation_buckets);
  vlib_cli_output (vm, "user buckets: %u", nm->user_buckets);
  return 0;
}

static clib_error_t *
nat44_ei_set_alloc_addr_and_port_alg_command_fn (vlib_main_t *vm,
						 unformat_input_t *input,
						 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 psid, psid_offset, psid_length, port_start, port_end;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "default"))
	nat44_ei_set_alloc_default ();
      else if (unformat (line_input,
			 "map-e psid %d psid-offset %d psid-len %d", &psid,
			 &psid_offset, &psid_length))
	nat44_ei_set_alloc_mape ((u16) psid, (u16) psid_offset,
				 (u16) psid_length);
      else if (unformat (line_input, "port-range %d - %d", &port_start,
			 &port_end))
	{
	  if (port_end <= port_start)
	    {
	      error = clib_error_return (
		0, "The end-port must be greater than start-port");
	      goto done;
	    }
	  nat44_ei_set_alloc_range ((u16) port_start, (u16) port_end);
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  unformat_free (line_input);

  return error;
};

u8 *
format_nat44_ei_addr_and_port_alloc_alg (u8 *s, va_list *args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v, N, s)                                                            \
  case NAT44_EI_ADDR_AND_PORT_ALLOC_ALG_##N:                                  \
    t = (u8 *) s;                                                             \
    break;
      foreach_nat44_ei_addr_and_port_alloc_alg
#undef _
	default : s = format (s, "unknown");
      return s;
    }
  s = format (s, "%s", t);
  return s;
}

static clib_error_t *
nat44_ei_show_alloc_addr_and_port_alg_command_fn (vlib_main_t *vm,
						  unformat_input_t *input,
						  vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;

  vlib_cli_output (vm, "NAT address and port: %U",
		   format_nat44_ei_addr_and_port_alloc_alg,
		   nm->addr_and_port_alloc_alg);
  switch (nm->addr_and_port_alloc_alg)
    {
    case NAT44_EI_ADDR_AND_PORT_ALLOC_ALG_MAPE:
      vlib_cli_output (vm, "  psid %d psid-offset %d psid-len %d", nm->psid,
		       nm->psid_offset, nm->psid_length);
      break;
    case NAT44_EI_ADDR_AND_PORT_ALLOC_ALG_RANGE:
      vlib_cli_output (vm, "  start-port %d end-port %d", nm->start_port,
		       nm->end_port);
      break;
    default:
      break;
    }

  return 0;
}

static clib_error_t *
nat_set_mss_clamping_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  nat44_ei_main_t *nm = &nat44_ei_main;
  clib_error_t *error = 0;
  u32 mss;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "disable"))
	nm->mss_clamping = 0;
      else if (unformat (line_input, "%d", &mss))
	nm->mss_clamping = (u16) mss;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat_show_mss_clamping_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;

  if (nm->mss_clamping)
    vlib_cli_output (vm, "mss-clamping %d", nm->mss_clamping);
  else
    vlib_cli_output (vm, "mss-clamping disabled");

  return 0;
}

static clib_error_t *
nat_ha_failover_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t addr;
  u32 port, session_refresh_interval = 10;
  int rv;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%u", unformat_ip4_address, &addr, &port))
	;
      else if (unformat (line_input, "refresh-interval %u",
			 &session_refresh_interval))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = nat_ha_set_failover (vm, &addr, (u16) port, session_refresh_interval);
  if (rv)
    error = clib_error_return (0, "set HA failover failed");

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat_ha_listener_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t addr;
  u32 port, path_mtu = 512;
  int rv;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%u", unformat_ip4_address, &addr, &port))
	;
      else if (unformat (line_input, "path-mtu %u", &path_mtu))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = nat_ha_set_listener (vm, &addr, (u16) port, path_mtu);
  if (rv)
    error = clib_error_return (0, "set HA listener failed");

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat_show_ha_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  ip4_address_t addr;
  u16 port;
  u32 path_mtu, session_refresh_interval, resync_ack_missed;
  u8 in_resync;

  nat_ha_get_listener (&addr, &port, &path_mtu);
  if (!port)
    {
      vlib_cli_output (vm, "NAT HA disabled\n");
      return 0;
    }

  vlib_cli_output (vm, "LISTENER:\n");
  vlib_cli_output (vm, "  %U:%u path-mtu %u\n", format_ip4_address, &addr,
		   port, path_mtu);

  nat_ha_get_failover (&addr, &port, &session_refresh_interval);
  vlib_cli_output (vm, "FAILOVER:\n");
  if (port)
    vlib_cli_output (vm, "  %U:%u refresh-interval %usec\n",
		     format_ip4_address, &addr, port,
		     session_refresh_interval);
  else
    vlib_cli_output (vm, "  NA\n");

  nat_ha_get_resync_status (&in_resync, &resync_ack_missed);
  vlib_cli_output (vm, "RESYNC:\n");
  if (in_resync)
    vlib_cli_output (vm, "  in progress\n");
  else
    vlib_cli_output (vm, "  completed (%d ACK missed)\n", resync_ack_missed);

  return 0;
}

static clib_error_t *
nat_ha_flush_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  nat_ha_flush (0);
  return 0;
}

static clib_error_t *
nat_ha_resync_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;

  if (nat_ha_resync (0, 0, 0))
    error = clib_error_return (0, "NAT HA resync already running");

  return error;
}

static clib_error_t *
add_address_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  nat44_ei_main_t *nm = &nat44_ei_main;
  ip4_address_t start_addr, end_addr, this_addr;
  u32 start_host_order, end_host_order;
  u32 vrf_id = ~0;
  int i, count;
  int is_add = 1;
  int rv = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U - %U", unformat_ip4_address, &start_addr,
		    unformat_ip4_address, &end_addr))
	;
      else if (unformat (line_input, "tenant-vrf %u", &vrf_id))
	;
      else if (unformat (line_input, "%U", unformat_ip4_address, &start_addr))
	end_addr = start_addr;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (nm->static_mapping_only)
    {
      error = clib_error_return (0, "static mapping only mode");
      goto done;
    }

  start_host_order = clib_host_to_net_u32 (start_addr.as_u32);
  end_host_order = clib_host_to_net_u32 (end_addr.as_u32);

  if (end_host_order < start_host_order)
    {
      error = clib_error_return (0, "end address less than start address");
      goto done;
    }

  count = (end_host_order - start_host_order) + 1;

  if (count > 1024)
    nat44_ei_log_info ("%U - %U, %d addresses...", format_ip4_address,
		       &start_addr, format_ip4_address, &end_addr, count);

  this_addr = start_addr;

  for (i = 0; i < count; i++)
    {
      if (is_add)
	rv = nat44_ei_add_address (nm, &this_addr, vrf_id);
      else
	rv = nat44_ei_del_address (nm, this_addr, 0);

      switch (rv)
	{
	case VNET_API_ERROR_VALUE_EXIST:
	  error = clib_error_return (0, "NAT address already in use.");
	  goto done;
	case VNET_API_ERROR_NO_SUCH_ENTRY:
	  error = clib_error_return (0, "NAT address not exist.");
	  goto done;
	case VNET_API_ERROR_UNSPECIFIED:
	  error = clib_error_return (0, "NAT address used in static mapping.");
	  goto done;
	case VNET_API_ERROR_FEATURE_DISABLED:
	  goto done;
	default:
	  break;
	}

      if (nm->out2in_dpo)
	nat44_ei_add_del_address_dpo (this_addr, is_add);

      increment_v4_address (&this_addr);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_ei_show_addresses_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_address_t *ap;

  vlib_cli_output (vm, "NAT44 pool addresses:");
  vec_foreach (ap, nm->addresses)
    {
      vlib_cli_output (vm, "%U", format_ip4_address, &ap->addr);
      if (ap->fib_index != ~0)
	vlib_cli_output (
	  vm, "  tenant VRF: %u",
	  fib_table_get (ap->fib_index, FIB_PROTOCOL_IP4)->ft_table_id);
      else
	vlib_cli_output (vm, "  tenant VRF independent");
#define _(N, i, n, s)                                                         \
  vlib_cli_output (vm, "  %d busy %s ports", ap->busy_##n##_ports, s);
      foreach_nat_protocol
#undef _
    }
  return 0;
}

static clib_error_t *
nat44_ei_feature_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;
  u32 *inside_sw_if_indices = 0;
  u32 *outside_sw_if_indices = 0;
  u8 is_output_feature = 0;
  int is_del = 0;
  int i;

  sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "in %U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	vec_add1 (inside_sw_if_indices, sw_if_index);
      else if (unformat (line_input, "out %U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	vec_add1 (outside_sw_if_indices, sw_if_index);
      else if (unformat (line_input, "output-feature"))
	is_output_feature = 1;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (vec_len (inside_sw_if_indices))
    {
      for (i = 0; i < vec_len (inside_sw_if_indices); i++)
	{
	  sw_if_index = inside_sw_if_indices[i];
	  if (is_output_feature)
	    {
	      if (nat44_ei_interface_add_del_output_feature (sw_if_index, 1,
							     is_del))
		{
		  error = clib_error_return (
		    0, "%s %U failed", is_del ? "del" : "add",
		    format_vnet_sw_if_index_name, vnm, sw_if_index);
		  goto done;
		}
	    }
	  else
	    {
	      if (nat44_ei_interface_add_del (sw_if_index, 1, is_del))
		{
		  error = clib_error_return (
		    0, "%s %U failed", is_del ? "del" : "add",
		    format_vnet_sw_if_index_name, vnm, sw_if_index);
		  goto done;
		}
	    }
	}
    }

  if (vec_len (outside_sw_if_indices))
    {
      for (i = 0; i < vec_len (outside_sw_if_indices); i++)
	{
	  sw_if_index = outside_sw_if_indices[i];
	  if (is_output_feature)
	    {
	      if (nat44_ei_interface_add_del_output_feature (sw_if_index, 0,
							     is_del))
		{
		  error = clib_error_return (
		    0, "%s %U failed", is_del ? "del" : "add",
		    format_vnet_sw_if_index_name, vnm, sw_if_index);
		  goto done;
		}
	    }
	  else
	    {
	      if (nat44_ei_interface_add_del (sw_if_index, 0, is_del))
		{
		  error = clib_error_return (
		    0, "%s %U failed", is_del ? "del" : "add",
		    format_vnet_sw_if_index_name, vnm, sw_if_index);
		  goto done;
		}
	    }
	}
    }

done:
  unformat_free (line_input);
  vec_free (inside_sw_if_indices);
  vec_free (outside_sw_if_indices);

  return error;
}

static clib_error_t *
nat44_ei_show_interfaces_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_interface_t *i;
  vnet_main_t *vnm = vnet_get_main ();

  vlib_cli_output (vm, "NAT44 interfaces:");
  pool_foreach (i, nm->interfaces)
    {
      vlib_cli_output (vm, " %U %s", format_vnet_sw_if_index_name, vnm,
		       i->sw_if_index,
		       (nat44_ei_interface_is_inside (i) &&
			nat44_ei_interface_is_outside (i)) ?
			 "in out" :
			 (nat44_ei_interface_is_inside (i) ? "in" : "out"));
    }

  pool_foreach (i, nm->output_feature_interfaces)
    {
      vlib_cli_output (vm, " %U output-feature %s",
		       format_vnet_sw_if_index_name, vnm, i->sw_if_index,
		       (nat44_ei_interface_is_inside (i) &&
			nat44_ei_interface_is_outside (i)) ?
			 "in out" :
			 (nat44_ei_interface_is_inside (i) ? "in" : "out"));
    }

  return 0;
}

static clib_error_t *
add_static_mapping_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  ip4_address_t l_addr, e_addr;
  u32 l_port = 0, e_port = 0, vrf_id = ~0;
  int is_add = 1, addr_only = 1, rv;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();
  nat_protocol_t proto = NAT_PROTOCOL_OTHER;
  u8 proto_set = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U %u", unformat_ip4_address, &l_addr,
		    &l_port))
	addr_only = 0;
      else if (unformat (line_input, "local %U", unformat_ip4_address,
			 &l_addr))
	;
      else if (unformat (line_input, "external %U %u", unformat_ip4_address,
			 &e_addr, &e_port))
	addr_only = 0;
      else if (unformat (line_input, "external %U", unformat_ip4_address,
			 &e_addr))
	;
      else if (unformat (line_input, "external %U %u",
			 unformat_vnet_sw_interface, vnm, &sw_if_index,
			 &e_port))
	addr_only = 0;
      else if (unformat (line_input, "external %U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	;
      else if (unformat (line_input, "vrf %u", &vrf_id))
	;
      else if (unformat (line_input, "%U", unformat_nat_protocol, &proto))
	proto_set = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (addr_only)
    {
      if (proto_set)
	{
	  error = clib_error_return (
	    0, "address only mapping doesn't support protocol");
	  goto done;
	}
    }
  else if (!proto_set)
    {
      error = clib_error_return (0, "protocol is required");
      goto done;
    }

  rv = nat44_ei_add_del_static_mapping (
    l_addr, e_addr, clib_host_to_net_u16 (l_port),
    clib_host_to_net_u16 (e_port), proto, sw_if_index, vrf_id, addr_only, 0, 0,
    is_add);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "External port already in use.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      if (is_add)
	error = clib_error_return (0, "External address must be allocated.");
      else
	error = clib_error_return (0, "Mapping not exist.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_FIB:
      error = clib_error_return (0, "No such VRF id.");
      goto done;
    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "Mapping already exist.");
      goto done;
    case VNET_API_ERROR_FEATURE_DISABLED:
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
add_identity_mapping_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 port = 0, vrf_id = ~0;
  ip4_address_t addr;
  int is_add = 1;
  int addr_only = 1;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();
  int rv;
  nat_protocol_t proto;

  addr.as_u32 = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip4_address, &addr))
	;
      else if (unformat (line_input, "external %U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	;
      else if (unformat (line_input, "vrf %u", &vrf_id))
	;
      else if (unformat (line_input, "%U %u", unformat_nat_protocol, &proto,
			 &port))
	addr_only = 0;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = nat44_ei_add_del_static_mapping (
    addr, addr, clib_host_to_net_u16 (port), clib_host_to_net_u16 (port),
    proto, sw_if_index, vrf_id, addr_only, 1, 0, is_add);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "External port already in use.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      if (is_add)
	error = clib_error_return (0, "External address must be allocated.");
      else
	error = clib_error_return (0, "Mapping not exist.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_FIB:
      error = clib_error_return (0, "No such VRF id.");
      goto done;
    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "Mapping already exist.");
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_ei_show_static_mappings_command_fn (vlib_main_t *vm,
					  unformat_input_t *input,
					  vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_static_mapping_t *m;
  nat44_ei_static_map_resolve_t *rp;

  vlib_cli_output (vm, "NAT44 static mappings:");
  pool_foreach (m, nm->static_mappings)
    {
      vlib_cli_output (vm, " %U", format_nat44_ei_static_mapping, m);
    }
  vec_foreach (rp, nm->to_resolve)
    vlib_cli_output (vm, " %U", format_nat44_ei_static_map_to_resolve, rp);

  return 0;
}

static clib_error_t *
nat44_ei_add_interface_address_command_fn (vlib_main_t *vm,
					   unformat_input_t *input,
					   vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index;
  int rv;
  int is_del = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    nm->vnet_main, &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = nat44_ei_add_interface_address (nm, sw_if_index, is_del);

  switch (rv)
    {
    case 0:
      break;

    default:
      error = clib_error_return (
	0, "nat44_ei_add_interface_address returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_ei_show_interface_address_command_fn (vlib_main_t *vm,
					    unformat_input_t *input,
					    vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 *sw_if_index;

  vlib_cli_output (vm, "NAT44 pool address interfaces:");
  vec_foreach (sw_if_index, nm->auto_add_sw_if_indices)
    {
      vlib_cli_output (vm, " %U", format_vnet_sw_if_index_name, vnm,
		       *sw_if_index);
    }
  return 0;
}

static clib_error_t *
nat44_ei_show_sessions_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  nat44_ei_main_per_thread_data_t *tnm;
  nat44_ei_main_t *nm = &nat44_ei_main;

  int detail = 0;
  int i = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    goto print;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "detail"))
	detail = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }
  unformat_free (line_input);

print:
  vlib_cli_output (vm, "NAT44 sessions:");

  vec_foreach_index (i, nm->per_thread_data)
    {
      tnm = vec_elt_at_index (nm->per_thread_data, i);

      vlib_cli_output (vm, "-------- thread %d %s: %d sessions --------\n", i,
		       vlib_worker_threads[i].name, pool_elts (tnm->sessions));

      nat44_ei_user_t *u;
      pool_foreach (u, tnm->users)
	{
	  vlib_cli_output (vm, "  %U", format_nat44_ei_user, tnm, u, detail);
	}
    }
  return error;
}

static clib_error_t *
nat44_ei_del_user_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  ip4_address_t addr;
  u32 fib_index = 0;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip4_address, &addr))
	;
      else if (unformat (line_input, "fib %u", &fib_index))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = nat44_ei_user_del (&addr, fib_index);

  if (!rv)
    {
      error = clib_error_return (0, "nat44_ei_user_del returned %d", rv);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_ei_clear_sessions_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  nat44_ei_sessions_clear ();
  return error;
}

static clib_error_t *
nat44_ei_del_session_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 port = 0, vrf_id = nm->outside_vrf_id;
  clib_error_t *error = 0;
  nat_protocol_t proto;
  ip4_address_t addr;
  int rv, is_in = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%u %U", unformat_ip4_address, &addr, &port,
		    unformat_nat_protocol, &proto))
	;
      else if (unformat (line_input, "in"))
	{
	  is_in = 1;
	  vrf_id = nm->inside_vrf_id;
	}
      else if (unformat (line_input, "out"))
	{
	  is_in = 0;
	  vrf_id = nm->outside_vrf_id;
	}
      else if (unformat (line_input, "vrf %u", &vrf_id))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = nat44_ei_del_session (nm, &addr, clib_host_to_net_u16 (port), proto,
			     vrf_id, is_in);

  switch (rv)
    {
    case 0:
      break;

    default:
      error = clib_error_return (0, "nat44_ei_del_session returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_ei_forwarding_set_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 forwarding_enable;
  u8 forwarding_enable_set = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "'enable' or 'disable' expected");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (!forwarding_enable_set && unformat (line_input, "enable"))
	{
	  forwarding_enable = 1;
	  forwarding_enable_set = 1;
	}
      else if (!forwarding_enable_set && unformat (line_input, "disable"))
	{
	  forwarding_enable = 0;
	  forwarding_enable_set = 1;
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!forwarding_enable_set)
    {
      error = clib_error_return (0, "'enable' or 'disable' expected");
      goto done;
    }

  nm->forwarding_enabled = forwarding_enable;

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
set_timeout_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "udp %u", &nm->timeouts.udp))
	;
      else if (unformat (line_input, "tcp-established %u",
			 &nm->timeouts.tcp.established))
	;
      else if (unformat (line_input, "tcp-transitory %u",
			 &nm->timeouts.tcp.transitory))
	;
      else if (unformat (line_input, "icmp %u", &nm->timeouts.icmp))
	;
      else if (unformat (line_input, "reset"))
	nat_reset_timeouts (&nm->timeouts);
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }
done:
  unformat_free (line_input);
  return error;
}

static clib_error_t *
nat_show_timeouts_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  nat44_ei_main_t *nm = &nat44_ei_main;

  // TODO: make format timeout function
  vlib_cli_output (vm, "udp timeout: %dsec", nm->timeouts.udp);
  vlib_cli_output (vm, "tcp-established timeout: %dsec",
		   nm->timeouts.tcp.established);
  vlib_cli_output (vm, "tcp-transitory timeout: %dsec",
		   nm->timeouts.tcp.transitory);
  vlib_cli_output (vm, "icmp timeout: %dsec", nm->timeouts.icmp);

  return 0;
}

/*?
 * @cliexpar
 * @cliexstart{nat44 ei enable}
 * Enable nat44 ei plugin
 * To enable nat44, use:
 *  vpp# nat44 ei enable sessions <n>
 * To enable nat44 ei static mapping only, use:
 *  vpp# nat44 ei enable sessions <n> static-mapping
 * To enable nat44 ei static mapping with connection tracking, use:
 *  vpp# nat44 ei enable sessions <n> static-mapping connection-tracking
 * To enable nat44 ei out2in dpo, use:
 *  vpp# nat44 ei enable sessions <n> out2in-dpo
 * To set inside-vrf outside-vrf, use:
 *  vpp# nat44 ei enable sessions <n> inside-vrf <id> outside-vrf <id>
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_enable_command, static) = {
  .path = "nat44 ei enable",
  .short_help =
    "nat44 ei enable sessions <max-number> [users <max-number>] "
    "[static-mappig-only [connection-tracking]|out2in-dpo] [inside-vrf "
    "<vrf-id>] [outside-vrf <vrf-id>] [user-sessions <max-number>]",
  .function = nat44_ei_enable_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei disable}
 * Disable nat44 ei plugin
 * To disable nat44, use:
 *  vpp# nat44 ei disable
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_disable_command, static) = {
  .path = "nat44 ei disable",
  .short_help = "nat44 ei disable",
  .function = nat44_ei_disable_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set snat44 ei workers}
 * Set NAT workers if 2 or more workers available, use:
 *  vpp# set snat44 ei workers 0-2,5
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_workers_command, static) = {
  .path = "set nat44 ei workers",
  .function = set_workers_command_fn,
  .short_help = "set nat44 ei workers <workers-list>",
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 ei workers}
 * Show NAT workers.
 *  vpp# show nat44 ei workers:
 *  2 workers
 *    vpp_wk_0
 *    vpp_wk_1
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_show_workers_command, static) = {
  .path = "show nat44 ei workers",
  .short_help = "show nat44 ei workers",
  .function = nat_show_workers_commnad_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set nat44 ei timeout}
 * Set values of timeouts for NAT sessions (in seconds), use:
 *  vpp# set nat44 ei timeout udp 120 tcp-established 7500 tcp-transitory 250
icmp 90
 * To reset default values use:
 *  vpp# set nat44 ei timeout reset
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_timeout_command, static) = {
  .path = "set nat44 ei timeout",
  .function = set_timeout_command_fn,
  .short_help = "set nat44 ei timeout [udp <sec> | tcp-established <sec> "
		"tcp-transitory <sec> | icmp <sec> | reset]",
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 ei timeouts}
 * Show values of timeouts for NAT sessions.
 * vpp# show nat44 ei timeouts
 * udp timeout: 300sec
 * tcp-established timeout: 7440sec
 * tcp-transitory timeout: 240sec
 * icmp timeout: 60sec
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_show_timeouts_command, static) = {
  .path = "show nat44 ei timeouts",
  .short_help = "show nat44 ei timeouts",
  .function = nat_show_timeouts_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei set logging level}
 * To set NAT logging level use:
 * Set nat44 ei logging level
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_set_log_level_command, static) = {
  .path = "nat44 ei set logging level",
  .function = nat44_ei_set_log_level_command_fn,
  .short_help = "nat44 ei set logging level <level>",
};

/*?
 * @cliexpar
 * @cliexstart{snat44 ei ipfix logging}
 * To enable NAT IPFIX logging use:
 *  vpp# nat44 ei ipfix logging
 * To set IPFIX exporter use:
 *  vpp# set ipfix exporter collector 10.10.10.3 src 10.10.10.1
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_ipfix_logging_enable_disable_command, static) = {
  .path = "nat44 ei ipfix logging",
  .function = nat44_ei_ipfix_logging_enable_disable_command_fn,
  .short_help =
    "nat44 ei ipfix logging [domain <domain-id>] [src-port <port>] [disable]",
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei addr-port-assignment-alg}
 * Set address and port assignment algorithm
 * For the MAP-E CE limit port choice based on PSID use:
 *  vpp# nat44 ei addr-port-assignment-alg map-e psid 10 psid-offset 6 psid-len
6
 * For port range use:
 *  vpp# nat44 ei addr-port-assignment-alg port-range <start-port> - <end-port>
 * To set standard (default) address and port assignment algorithm use:
 *  vpp# nat44 ei addr-port-assignment-alg default
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_set_alloc_addr_and_port_alg_command, static) = {
  .path = "nat44 ei addr-port-assignment-alg",
  .short_help = "nat44 ei addr-port-assignment-alg <alg-name> [<alg-params>]",
  .function = nat44_ei_set_alloc_addr_and_port_alg_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 ei addr-port-assignment-alg}
 * Show address and port assignment algorithm
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_show_alloc_addr_and_port_alg_command, static) = {
  .path = "show nat44 ei addr-port-assignment-alg",
  .short_help = "show nat44 ei addr-port-assignment-alg",
  .function = nat44_ei_show_alloc_addr_and_port_alg_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei mss-clamping}
 * Set TCP MSS rewriting configuration
 * To enable TCP MSS rewriting use:
 *  vpp# nat44 ei mss-clamping 1452
 * To disbale TCP MSS rewriting use:
 *  vpp# nat44 ei mss-clamping disable
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_set_mss_clamping_command, static) = {
  .path = "nat44 ei mss-clamping",
  .short_help = "nat44 ei mss-clamping <mss-value>|disable",
  .function = nat_set_mss_clamping_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 ei mss-clamping}
 * Show TCP MSS rewriting configuration
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_show_mss_clamping_command, static) = {
  .path = "show nat44 ei mss-clamping",
  .short_help = "show nat44 ei mss-clamping",
  .function = nat_show_mss_clamping_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei ha failover}
 * Set HA failover (remote settings)
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_ha_failover_command, static) = {
  .path = "nat44 ei ha failover",
  .short_help =
    "nat44 ei ha failover <ip4-address>:<port> [refresh-interval <sec>]",
  .function = nat_ha_failover_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei ha listener}
 * Set HA listener (local settings)
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_ha_listener_command, static) = {
  .path = "nat44 ei ha listener",
  .short_help =
    "nat44 ei ha listener <ip4-address>:<port> [path-mtu <path-mtu>]",
  .function = nat_ha_listener_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 ei ha}
 * Show HA configuration/status
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_show_ha_command, static) = {
  .path = "show nat44 ei ha",
  .short_help = "show nat44 ei ha",
  .function = nat_show_ha_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei ha flush}
 * Flush the current HA data (for testing)
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_ha_flush_command, static) = {
  .path = "nat44 ei ha flush",
  .short_help = "nat44 ei ha flush",
  .function = nat_ha_flush_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei ha resync}
 * Resync HA (resend existing sessions to new failover)
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_ha_resync_command, static) = {
  .path = "nat44 ei ha resync",
  .short_help = "nat44 ei ha resync",
  .function = nat_ha_resync_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 ei hash tables}
 * Show NAT44 hash tables
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_show_hash, static) = {
  .path = "show nat44 ei hash tables",
  .short_help = "show nat44 ei hash tables [detail|verbose]",
  .function = nat44_ei_show_hash_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei add address}
 * Add/delete NAT44 pool address.
 * To add NAT44 pool address use:
 *  vpp# nat44 ei add address 172.16.1.3
 *  vpp# nat44 ei add address 172.16.2.2 - 172.16.2.24
 * To add NAT44 pool address for specific tenant (identified by VRF id) use:
 *  vpp# nat44 ei add address 172.16.1.3 tenant-vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_address_command, static) = {
  .path = "nat44 ei add address",
  .short_help = "nat44 ei add address <ip4-range-start> [- <ip4-range-end>] "
		"[tenant-vrf <vrf-id>] [del]",
  .function = add_address_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 ei addresses}
 * Show NAT44 pool addresses.
 * vpp# show nat44 ei addresses
 * NAT44 pool addresses:
 * 172.16.2.2
 *   tenant VRF independent
 *   10 busy udp ports
 *   0 busy tcp ports
 *   0 busy icmp ports
 * 172.16.1.3
 *   tenant VRF: 10
 *   0 busy udp ports
 *   2 busy tcp ports
 *   0 busy icmp ports
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_show_addresses_command, static) = {
  .path = "show nat44 ei addresses",
  .short_help = "show nat44 ei addresses",
  .function = nat44_ei_show_addresses_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set interface nat44}
 * Enable/disable NAT44 feature on the interface.
 * To enable NAT44 feature with local network interface use:
 *  vpp# set interface nat44 ei in GigabitEthernet0/8/0
 * To enable NAT44 feature with external network interface use:
 *  vpp# set interface nat44 ei out GigabitEthernet0/a/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_interface_nat44_ei_command, static) = {
  .path = "set interface nat44 ei",
  .function = nat44_ei_feature_command_fn,
  .short_help =
    "set interface nat44 ei in <intfc> out <intfc> [output-feature] "
    "[del]",
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 ei interfaces}
 * Show interfaces with NAT44 feature.
 * vpp# show nat44 ei interfaces
 * NAT44 interfaces:
 *  GigabitEthernet0/8/0 in
 *  GigabitEthernet0/a/0 out
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_show_interfaces_command, static) = {
  .path = "show nat44 ei interfaces",
  .short_help = "show nat44 ei interfaces",
  .function = nat44_ei_show_interfaces_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei add static mapping}
 * Static mapping allows hosts on the external network to initiate connection
 * to to the local network host.
 * To create static mapping between local host address 10.0.0.3 port 6303 and
 * external address 4.4.4.4 port 3606 for TCP protocol use:
 *  vpp# nat44 ei add static mapping tcp local 10.0.0.3 6303 external 4.4.4.4
3606
 * If not runnig "static mapping only" NAT plugin mode use before:
 *  vpp# nat44 ei add address 4.4.4.4
 * To create address only static mapping between local and external address
use:
 *  vpp# nat44 ei add static mapping local 10.0.0.3 external 4.4.4.4
 * To create ICMP static mapping between local and external with ICMP echo
 * identifier 10 use:
 *  vpp# nat44 ei add static mapping icmp local 10.0.0.3 10 external 4.4.4.4 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_static_mapping_command, static) = {
  .path = "nat44 ei add static mapping",
  .function = add_static_mapping_command_fn,
  .short_help = "nat44 ei add static mapping tcp|udp|icmp local <addr> "
		"[<port|icmp-echo-id>] "
		"external <addr> [<port|icmp-echo-id>] [vrf <table-id>] [del]",
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei add identity mapping}
 * Identity mapping translate an IP address to itself.
 * To create identity mapping for address 10.0.0.3 port 6303 for TCP protocol
 * use:
 *  vpp# nat44 ei add identity mapping 10.0.0.3 tcp 6303
 * To create identity mapping for address 10.0.0.3 use:
 *  vpp# nat44 ei add identity mapping 10.0.0.3
 * To create identity mapping for DHCP addressed interface use:
 *  vpp# nat44 ei add identity mapping external GigabitEthernet0/a/0 tcp 3606
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_identity_mapping_command, static) = {
  .path = "nat44 ei add identity mapping",
  .function = add_identity_mapping_command_fn,
  .short_help =
    "nat44 ei add identity mapping <ip4-addr>|external <interface> "
    "[<protocol> <port>] [vrf <table-id>] [del]",
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 ei static mappings}
 * Show NAT44 static mappings.
 * vpp# show nat44 ei static mappings
 * NAT44 static mappings:
 *  local 10.0.0.3 external 4.4.4.4 vrf 0
 *  tcp local 192.168.0.4:6303 external 4.4.4.3:3606 vrf 0
 *  tcp vrf 0 external 1.2.3.4:80
 *   local 10.100.10.10:8080 probability 80
 *   local 10.100.10.20:8080 probability 20
 *  tcp local 10.0.0.10:3603 external GigabitEthernet0/a/0:6306 vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_show_static_mappings_command, static) = {
  .path = "show nat44 ei static mappings",
  .short_help = "show nat44 ei static mappings",
  .function = nat44_ei_show_static_mappings_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei add interface address}
 * Use NAT44 pool address from specific interfce
 * To add NAT44 pool address from specific interface use:
 *  vpp# nat44 ei add interface address GigabitEthernet0/8/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_add_interface_address_command, static) = {
  .path = "nat44 ei add interface address",
  .short_help = "nat44 ei add interface address <interface> [del]",
  .function = nat44_ei_add_interface_address_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 ei interface address}
 * Show NAT44 pool address interfaces
 * vpp# show nat44 ei interface address
 * NAT44 pool address interfaces:
 *  GigabitEthernet0/a/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_show_interface_address_command, static) = {
  .path = "show nat44 ei interface address",
  .short_help = "show nat44 ei interface address",
  .function = nat44_ei_show_interface_address_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 ei sessions}
 * Show NAT44 sessions.
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_show_sessions_command, static) = {
  .path = "show nat44 ei sessions",
  .short_help = "show nat44 ei sessions [detail|metrics]",
  .function = nat44_ei_show_sessions_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei del user}
 * To delete all NAT44 user sessions:
 *  vpp# nat44 ei del user 10.0.0.3
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_del_user_command, static) = {
  .path = "nat44 ei del user",
  .short_help = "nat44 ei del user <addr> [fib <index>]",
  .function = nat44_ei_del_user_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{clear nat44 ei sessions}
 * To clear all NAT44 sessions
 *  vpp# clear nat44 ei sessions
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_clear_sessions_command, static) = {
  .path = "clear nat44 ei sessions",
  .short_help = "clear nat44 ei sessions",
  .function = nat44_ei_clear_sessions_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei del session}
 * To administratively delete NAT44 session by inside address and port use:
 *  vpp# nat44 ei del session in 10.0.0.3:6303 tcp
 * To administratively delete NAT44 session by outside address and port use:
 *  vpp# nat44 ei del session out 1.0.0.3:6033 udp
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_del_session_command, static) = {
  .path = "nat44 ei del session",
  .short_help = "nat44 ei del session in|out <addr>:<port> tcp|udp|icmp [vrf "
		"<id>] [external-host <addr>:<port>]",
  .function = nat44_ei_del_session_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 ei forwarding}
 * Enable or disable forwarding
 * Forward packets which don't match existing translation
 * or static mapping instead of dropping them.
 * To enable forwarding, use:
 *  vpp# nat44 ei forwarding enable
 * To disable forwarding, use:
 *  vpp# nat44 ei forwarding disable
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ei_forwarding_set_command, static) = {
  .path = "nat44 ei forwarding",
  .short_help = "nat44 ei forwarding enable|disable",
  .function = nat44_ei_forwarding_set_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
