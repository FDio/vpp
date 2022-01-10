/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief NAT44 CLI
 */

#include <vnet/fib/fib_table.h>

#include <nat/lib/log.h>
#include <nat/lib/nat_inlines.h>
#include <nat/lib/ipfix_logging.h>

#include <nat/nat44-ed/nat44_ed.h>
#include <nat/nat44-ed/nat44_ed_inlines.h>
#include <nat/nat44-ed/nat44_ed_affinity.h>

#define NAT44_ED_EXPECTED_ARGUMENT "expected required argument(s)"

static clib_error_t *
nat44_ed_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  nat44_config_t c = { 0 };
  u8 enable_set = 0, enable = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "inside-vrf %u", &c.inside_vrf))
	;
      else if (unformat (line_input, "outside-vrf %u", &c.outside_vrf));
      else if (unformat (line_input, "sessions %u", &c.sessions));
      else if (!enable_set)
	{
	  enable_set = 1;
	  if (unformat (line_input, "disable"))
	    ;
	  else if (unformat (line_input, "enable"))
	    enable = 1;
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!enable_set)
    {
      error = clib_error_return (0, "expected enable | disable");
      goto done;
    }

  if (enable)
    {
      if (sm->enabled)
	{
	  error = clib_error_return (0, "already enabled");
	  goto done;
	}

      if (nat44_plugin_enable (c) != 0)
	error = clib_error_return (0, "enable failed");
    }
  else
    {
      if (!sm->enabled)
	{
	  error = clib_error_return (0, "already disabled");
	  goto done;
	}

      if (nat44_plugin_disable () != 0)
	error = clib_error_return (0, "disable failed");
    }

done:
  unformat_free (line_input);
  return error;
}

static clib_error_t *
set_workers_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  uword *bitmap = 0;
  int rv = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

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

  rv = snat_set_workers (bitmap);

  clib_bitmap_free (bitmap);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_WORKER:
      error = clib_error_return (0, "Invalid worker(s).");
      goto done;
    case VNET_API_ERROR_FEATURE_DISABLED:
      error = clib_error_return (0,
				 "Supported only if 2 or more workes available.");
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat_show_workers_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  snat_main_t *sm = &snat_main;
  u32 *worker;

  if (sm->num_workers > 1)
    {
      vlib_cli_output (vm, "%d workers", vec_len (sm->workers));
      vec_foreach (worker, sm->workers)
        {
          vlib_worker_thread_t *w =
            vlib_worker_threads + *worker + sm->first_worker_index;
          vlib_cli_output (vm, "  %s", w->name);
        }
    }

  return 0;
}

static clib_error_t *
snat_set_log_level_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snat_main_t *sm = &snat_main;
  u8 log_level = NAT_LOG_NONE;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

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
  sm->log_level = log_level;

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
snat_ipfix_logging_enable_disable_command_fn (vlib_main_t * vm,
					      unformat_input_t * input,
					      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  u32 domain_id = 0, src_port = 0;
  u8 enable_set = 0, enable = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "domain %d", &domain_id))
	;
      else if (unformat (line_input, "src-port %d", &src_port))
	;
      else if (!enable_set)
	{
	  enable_set = 1;
	  if (unformat (line_input, "disable"))
	    ;
	  else if (unformat (line_input, "enable"))
	    enable = 1;
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!enable_set)
    {
      error = clib_error_return (0, "expected enable | disable");
      goto done;
    }

  if (nat_ipfix_logging_enable_disable (enable, domain_id, (u16) src_port))
    {
      error = clib_error_return (0, "ipfix logging enable failed");
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_show_hash_command_fn (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  nat_affinity_main_t *nam = &nat_affinity_main;
  int i;
  int verbose = 0;

  if (unformat (input, "detail"))
    verbose = 1;
  else if (unformat (input, "verbose"))
    verbose = 2;

  vlib_cli_output (vm, "%U", format_bihash_16_8, &sm->flow_hash, verbose);
  vec_foreach_index (i, sm->per_thread_data)
  {
    vlib_cli_output (vm, "-------- thread %d %s --------\n",
		     i, vlib_worker_threads[i].name);
    vlib_cli_output (vm, "%U", format_bihash_16_8, &sm->flow_hash, verbose);
  }

  vlib_cli_output (vm, "%U", format_bihash_16_8, &nam->affinity_hash, verbose);

  vlib_cli_output (vm, "-------- hash table parameters --------\n");
  vlib_cli_output (vm, "translation buckets: %u", sm->translation_buckets);
  return 0;
}

static clib_error_t *
nat_set_mss_clamping_command_fn (vlib_main_t * vm, unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snat_main_t *sm = &snat_main;
  clib_error_t *error = 0;
  u32 mss;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "disable"))
	sm->mss_clamping = 0;
      else if (unformat (line_input, "%d", &mss))
	sm->mss_clamping = (u16) mss;
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
nat_show_mss_clamping_command_fn (vlib_main_t * vm, unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;

  if (sm->mss_clamping)
    vlib_cli_output (vm, "mss-clamping %d", sm->mss_clamping);
  else
    vlib_cli_output (vm, "mss-clamping disabled");

  return 0;
}

static clib_error_t *
add_address_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t start_addr, end_addr, this_addr;
  u32 start_host_order, end_host_order;
  u32 vrf_id = ~0;
  int i, count;
  int is_add = 1;
  int rv = 0;
  clib_error_t *error = 0;
  u8 twice_nat = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U - %U",
		    unformat_ip4_address, &start_addr,
		    unformat_ip4_address, &end_addr))
	;
      else if (unformat (line_input, "tenant-vrf %u", &vrf_id))
	;
      else if (unformat (line_input, "%U", unformat_ip4_address, &start_addr))
	end_addr = start_addr;
      else if (unformat (line_input, "twice-nat"))
	twice_nat = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
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
    nat_log_info ("%U - %U, %d addresses...",
		  format_ip4_address, &start_addr,
		  format_ip4_address, &end_addr, count);

  this_addr = start_addr;

  for (i = 0; i < count; i++)
    {
      if (is_add)
	{
	  rv = nat44_ed_add_address (&this_addr, vrf_id, twice_nat);
	}
      else
	{
	  rv = nat44_ed_del_address (this_addr, twice_nat);
	}

      switch (rv)
	{
	case VNET_API_ERROR_VALUE_EXIST:
	  error = clib_error_return (0, "NAT address already in use.");
	  goto done;
	case VNET_API_ERROR_NO_SUCH_ENTRY:
	  error = clib_error_return (0, "NAT address not exist.");
	  goto done;
	case VNET_API_ERROR_UNSPECIFIED:
	  error =
	    clib_error_return (0, "NAT address used in static mapping.");
	  goto done;
	default:
	  break;
	}

      increment_v4_address (&this_addr);
    }

done:
  unformat_free (line_input);

  return error;
}

static void
nat44_show_lru_summary (vlib_main_t * vm, snat_main_per_thread_data_t * tsm,
			u64 now, u64 sess_timeout_time)
{
  snat_main_t *sm = &snat_main;
  dlist_elt_t *oldest_elt;
  snat_session_t *s;
  u32 oldest_index;

  if (tsm->lru_pool)
    {
#define _(n, d)                                                               \
  oldest_index =                                                              \
    clib_dlist_remove_head (tsm->lru_pool, tsm->n##_lru_head_index);          \
  if (~0 != oldest_index)                                                     \
    {                                                                         \
      oldest_elt = pool_elt_at_index (tsm->lru_pool, oldest_index);           \
      s = pool_elt_at_index (tsm->sessions, oldest_elt->value);               \
      sess_timeout_time =                                                     \
	s->last_heard + (f64) nat44_session_get_timeout (sm, s);              \
      vlib_cli_output (vm, d " LRU min session timeout %llu (now %llu)",      \
		       sess_timeout_time, now);                               \
      clib_dlist_addhead (tsm->lru_pool, tsm->n##_lru_head_index,             \
			  oldest_index);                                      \
    }
      _ (tcp_estab, "established tcp");
      _ (tcp_trans, "transitory tcp");
      _ (udp, "udp");
      _ (unk_proto, "unknown protocol");
      _ (icmp, "icmp");
#undef _
    }
}

static clib_error_t *
nat44_show_summary_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  snat_main_per_thread_data_t *tsm;
  snat_main_t *sm = &snat_main;
  snat_session_t *s;

  u32 count = 0;

  u64 now = vlib_time_now (vm);
  u64 sess_timeout_time = 0;

  struct
  {
    u32 total;
    u32 timed_out;
  } udp = { 0 }, tcp = { 0 }, tcp_established = { 0 }, tcp_transitory = { 0 },
    icmp = { 0 }, other = { 0 };

  u32 fib;

  for (fib = 0; fib < vec_len (sm->max_translations_per_fib); fib++)
    vlib_cli_output (vm, "max translations per thread: %u fib %u",
		     sm->max_translations_per_fib[fib], fib);

  if (sm->num_workers > 1)
    {
      vec_foreach (tsm, sm->per_thread_data)
        {
          pool_foreach (s, tsm->sessions)
           {
	     sess_timeout_time =
	       s->last_heard + (f64) nat44_session_get_timeout (sm, s);

	     switch (s->proto)
	       {
	       case IP_PROTOCOL_ICMP:
		 ++icmp.total;
		 if (now >= sess_timeout_time)
		   ++icmp.timed_out;
		 break;
	       case IP_PROTOCOL_TCP:
		 ++tcp.total;
		 if (now >= sess_timeout_time)
		   ++tcp.timed_out;
		 if (NAT44_ED_TCP_STATE_ESTABLISHED == s->tcp_state)
		   {
		     ++tcp_established.total;
		     if (now >= sess_timeout_time)
		       ++tcp_established.timed_out;
		   }
		 else
		   {
		     ++tcp_transitory.total;
		     if (now >= sess_timeout_time)
		       ++tcp_transitory.timed_out;
		   }
		 break;
	       case IP_PROTOCOL_UDP:
		 ++udp.total;
		 if (now >= sess_timeout_time)
		   ++udp.timed_out;
		 break;
	       default:
		 ++other.total;
		 if (now >= sess_timeout_time)
		   ++other.timed_out;
		 break;
	       }
	   }
	  nat44_show_lru_summary (vm, tsm, now, sess_timeout_time);
	  count += pool_elts (tsm->sessions);
	}
    }
  else
    {
      tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);
      pool_foreach (s, tsm->sessions)
       {
        sess_timeout_time = s->last_heard +
	    (f64) nat44_session_get_timeout (sm, s);

	switch (s->proto)
	  {
	  case IP_PROTOCOL_ICMP:
	    ++icmp.total;
	    if (now >= sess_timeout_time)
	      ++icmp.timed_out;
	    break;
	  case IP_PROTOCOL_TCP:
	    ++tcp.total;
	    if (now >= sess_timeout_time)
	      ++tcp.timed_out;
	    if (NAT44_ED_TCP_STATE_ESTABLISHED == s->tcp_state)
	      {
		++tcp_established.total;
		if (now >= sess_timeout_time)
		  ++tcp_established.timed_out;
	      }
	    else
	      {
		++tcp_transitory.total;
		if (now >= sess_timeout_time)
		  ++tcp_transitory.timed_out;
	      }
	    break;
	  case IP_PROTOCOL_UDP:
	    ++udp.total;
	    if (now >= sess_timeout_time)
	      ++udp.timed_out;
	    break;
	  default:
	    ++other.total;
	    if (now >= sess_timeout_time)
	      ++other.timed_out;
	    break;
	  }
      }
      nat44_show_lru_summary (vm, tsm, now, sess_timeout_time);
      count = pool_elts (tsm->sessions);
    }

  u32 timed_out =
    tcp.timed_out + icmp.timed_out + udp.timed_out + other.timed_out;
  vlib_cli_output (vm, "total sessions: %u (timed out: %u)", count, timed_out);
  vlib_cli_output (vm, "tcp sessions:");
  vlib_cli_output (vm, "    total: %u (timed out: %u)", tcp.total,
		   tcp.timed_out);
  vlib_cli_output (vm, "        established: %u (timed out: %u)",
		   tcp_established.total, tcp_established.timed_out);
  vlib_cli_output (vm, "        transitory: %u (timed out: %u)",
		   tcp_transitory.total, tcp_transitory.timed_out);
  vlib_cli_output (vm, "udp sessions:");
  vlib_cli_output (vm, "    total: %u (timed out: %u)", udp.total,
		   udp.timed_out);
  vlib_cli_output (vm, "icmp sessions:");
  vlib_cli_output (vm, "    total: %u (timed out: %u)", icmp.total,
		   icmp.timed_out);
  vlib_cli_output (vm, "other sessions:");
  vlib_cli_output (vm, "    total: %u (timed out: %u)", other.total,
		   other.timed_out);
  return 0;
}

static clib_error_t *
nat44_show_addresses_command_fn (vlib_main_t * vm, unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  snat_address_t *ap;

  vlib_cli_output (vm, "NAT44 pool addresses:");
  vec_foreach (ap, sm->addresses)
    {
      vlib_cli_output (vm, "%U", format_ip4_address, &ap->addr);
      if (ap->fib_index != ~0)
	vlib_cli_output (
	  vm, "  tenant VRF: %u",
	  fib_table_get (ap->fib_index, FIB_PROTOCOL_IP4)->ft_table_id);
      else
        vlib_cli_output (vm, "  tenant VRF independent");

      if (ap->addr_len != ~0)
	vlib_cli_output (vm, "  synced with interface address");
    }
  vlib_cli_output (vm, "NAT44 twice-nat pool addresses:");
  vec_foreach (ap, sm->twice_nat_addresses)
    {
      vlib_cli_output (vm, "%U", format_ip4_address, &ap->addr);
      if (ap->fib_index != ~0)
          vlib_cli_output (vm, "  tenant VRF: %u",
            fib_table_get(ap->fib_index, FIB_PROTOCOL_IP4)->ft_table_id);
      else
        vlib_cli_output (vm, "  tenant VRF independent");

      if (ap->addr_len != ~0)
	vlib_cli_output (vm, "  synced with interface address");
    }
  return 0;
}

static clib_error_t *
snat_feature_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;
  u32 *inside_sw_if_indices = 0;
  u32 *outside_sw_if_indices = 0;
  u8 is_output_feature = 0;
  int i, rv, is_del = 0;

  sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "in %U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	vec_add1 (inside_sw_if_indices, sw_if_index);
      else if (unformat (line_input, "out %U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
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
	      if (is_del)
		{
		  rv = nat44_ed_del_output_interface (sw_if_index);
		}
	      else
		{
		  rv = nat44_ed_add_output_interface (sw_if_index);
		}
	      if (rv)
		{
		  error = clib_error_return (0, "%s %U failed",
					     is_del ? "del" : "add",
					     format_vnet_sw_if_index_name,
					     vnm, sw_if_index);
		  goto done;
		}
	    }
	  else
	    {
	      if (is_del)
		{
		  rv = nat44_ed_del_interface (sw_if_index, 1);
		}
	      else
		{
		  rv = nat44_ed_add_interface (sw_if_index, 1);
		}
	      if (rv)
		{
		  error = clib_error_return (0, "%s %U failed",
					     is_del ? "del" : "add",
					     format_vnet_sw_if_index_name,
					     vnm, sw_if_index);
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
	      if (is_del)
		{
		  rv = nat44_ed_del_output_interface (sw_if_index);
		}
	      else
		{
		  rv = nat44_ed_add_output_interface (sw_if_index);
		}
	      if (rv)
		{
		  error = clib_error_return (0, "%s %U failed",
					     is_del ? "del" : "add",
					     format_vnet_sw_if_index_name,
					     vnm, sw_if_index);
		  goto done;
		}
	    }
	  else
	    {
	      if (is_del)
		{
		  rv = nat44_ed_del_interface (sw_if_index, 0);
		}
	      else
		{
		  rv = nat44_ed_add_interface (sw_if_index, 0);
		}
	      if (rv)
		{
		  error = clib_error_return (0, "%s %U failed",
					     is_del ? "del" : "add",
					     format_vnet_sw_if_index_name,
					     vnm, sw_if_index);
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
nat44_show_interfaces_command_fn (vlib_main_t * vm, unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;
  vnet_main_t *vnm = vnet_get_main ();

  vlib_cli_output (vm, "NAT44 interfaces:");
  pool_foreach (i, sm->interfaces)
   {
     vlib_cli_output (vm, " %U %s", format_vnet_sw_if_index_name, vnm,
		      i->sw_if_index,
		      (nat44_ed_is_interface_inside (i) &&
		       nat44_ed_is_interface_outside (i)) ?
			"in out" :
			(nat44_ed_is_interface_inside (i) ? "in" : "out"));
  }

  pool_foreach (i, sm->output_feature_interfaces)
   {
     vlib_cli_output (vm, " %U output-feature %s",
		      format_vnet_sw_if_index_name, vnm, i->sw_if_index,
		      (nat44_ed_is_interface_inside (i) &&
		       nat44_ed_is_interface_outside (i)) ?
			"in out" :
			(nat44_ed_is_interface_inside (i) ? "in" : "out"));
  }

  return 0;
}

static clib_error_t *
add_static_mapping_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  ip4_address_t l_addr, e_addr, pool_addr;
  u32 l_port = 0, e_port = 0, vrf_id = ~0;
  u8 l_port_set = 0, e_port_set = 0;
  int is_add = 1, rv;
  u32 flags = 0;
  u32 sw_if_index = ~0;
  ip_protocol_t proto = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U %u", unformat_ip4_address, &l_addr,
		    &l_port))
	{
	  l_port_set = 1;
	}
      else
	if (unformat (line_input, "local %U", unformat_ip4_address, &l_addr))
	;
      else if (unformat (line_input, "external %U %u", unformat_ip4_address,
			 &e_addr, &e_port))
	{
	  e_port_set = 1;
	}
      else if (unformat (line_input, "external %U", unformat_ip4_address,
			 &e_addr))
	;
      else if (unformat (line_input, "external %U %u",
			 unformat_vnet_sw_interface, vnm, &sw_if_index,
			 &e_port))
	{
	  flags |= NAT_SM_FLAG_SWITCH_ADDRESS;
	  e_port_set = 1;
	}
      else if (unformat (line_input, "external %U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  flags |= NAT_SM_FLAG_SWITCH_ADDRESS;
	}
      else if (unformat (line_input, "exact %U", unformat_ip4_address,
			 &pool_addr))
	{
	  flags |= NAT_SM_FLAG_EXACT_ADDRESS;
	}
      else if (unformat (line_input, "vrf %u", &vrf_id))
	;
      else if (unformat (line_input, "%U", unformat_ip_protocol, &proto))
	;
      else if (unformat (line_input, "self-twice-nat"))
	{
	  flags |= NAT_SM_FLAG_SELF_TWICE_NAT;
	}
      else if (unformat (line_input, "twice-nat"))
	{
	  flags |= NAT_SM_FLAG_TWICE_NAT;
	}
      else if (unformat (line_input, "out2in-only"))
	{
	  flags |= NAT_SM_FLAG_OUT2IN_ONLY;
	}
      else if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else
	{
	  error = clib_error_return (0, "unknown input: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (l_port_set != e_port_set)
    {
      error = clib_error_return (0, "Either both ports are set or none.");
      goto done;
    }

  if (!l_port_set)
    {
      flags |= NAT_SM_FLAG_ADDR_ONLY;
    }
  else
    {
      l_port = clib_host_to_net_u16 (l_port);
      e_port = clib_host_to_net_u16 (e_port);
    }

  // TODO: specific pool_addr for both pool & twice nat pool ?

  if (is_add)
    {
      rv =
	nat44_ed_add_static_mapping (l_addr, e_addr, l_port, e_port, proto,
				     vrf_id, sw_if_index, flags, pool_addr, 0);
    }
  else
    {
      rv = nat44_ed_del_static_mapping (l_addr, e_addr, l_port, e_port, proto,
					vrf_id, sw_if_index, flags);
    }

  // TODO: fix returns

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

// TODO: either delete this bullshit or update it
static clib_error_t *
add_identity_mapping_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;

  int rv, is_add = 1, port_set = 0;
  u32 sw_if_index, port, flags, vrf_id = ~0;
  ip_protocol_t proto = 0;
  ip4_address_t addr;

  flags = NAT_SM_FLAG_IDENTITY_NAT;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip4_address, &addr))
	;
      else if (unformat (line_input, "external %U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  flags |= NAT_SM_FLAG_SWITCH_ADDRESS;
	}
      else if (unformat (line_input, "vrf %u", &vrf_id))
	;
      else if (unformat (line_input, "%U %u", unformat_ip_protocol, &proto,
			 &port))
	{
	  port_set = 1;
	}
      else if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else
	{
	  error = clib_error_return (0, "unknown input: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!port_set)
    {
      flags |= NAT_SM_FLAG_ADDR_ONLY;
    }
  else
    {
      port = clib_host_to_net_u16 (port);
    }

  if (is_add)
    {

      rv = nat44_ed_add_static_mapping (addr, addr, port, port, proto, vrf_id,
					sw_if_index, flags, addr, 0);
    }
  else
    {
      rv = nat44_ed_del_static_mapping (addr, addr, port, port, proto, vrf_id,
					sw_if_index, flags);
    }

  // TODO: fix returns

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
add_lb_static_mapping_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  ip4_address_t l_addr, e_addr;
  u32 l_port = 0, e_port = 0, vrf_id = 0, probability = 0, affinity = 0;
  u8 proto_set = 0;
  ip_protocol_t proto;
  nat44_lb_addr_port_t *locals = 0, local;
  int rv, is_add = 1;
  u32 flags = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U:%u probability %u",
		    unformat_ip4_address, &l_addr, &l_port, &probability))
	{
	  clib_memset (&local, 0, sizeof (local));
	  local.addr = l_addr;
	  local.port = (u16) l_port;
	  local.probability = (u8) probability;
	  vec_add1 (locals, local);
	}
      else if (unformat (line_input, "local %U:%u vrf %u probability %u",
			 unformat_ip4_address, &l_addr, &l_port, &vrf_id,
			 &probability))
	{
	  clib_memset (&local, 0, sizeof (local));
	  local.addr = l_addr;
	  local.port = (u16) l_port;
	  local.probability = (u8) probability;
	  local.vrf_id = vrf_id;
	  vec_add1 (locals, local);
	}
      else if (unformat (line_input, "external %U:%u", unformat_ip4_address,
			 &e_addr, &e_port))
	;
      else if (unformat (line_input, "protocol %U", unformat_ip_protocol,
			 &proto))
	{
	  proto_set = 1;
	}
      else if (unformat (line_input, "twice-nat"))
	{
	  flags |= NAT_SM_FLAG_TWICE_NAT;
	}
      else if (unformat (line_input, "self-twice-nat"))
	{
	  flags |= NAT_SM_FLAG_SELF_TWICE_NAT;
	}
      else if (unformat (line_input, "out2in-only"))
	{
	  flags |= NAT_SM_FLAG_OUT2IN_ONLY;
	}
      else if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (line_input, "affinity %u", &affinity))
	;
      else
	{
	  error = clib_error_return (0, "unknown input: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (vec_len (locals) < 2)
    {
      error = clib_error_return (0, "at least two local must be set");
      goto done;
    }

  if (!proto_set)
    {
      error = clib_error_return (0, "missing protocol");
      goto done;
    }

  if (is_add)
    {
      rv = nat44_ed_add_lb_static_mapping (e_addr, (u16) e_port, proto, locals,
					   flags, 0, affinity);
    }
  else
    {
      rv = nat44_ed_del_lb_static_mapping (e_addr, (u16) e_port, proto, flags);
    }

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
    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "Mapping already exist.");
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);
  vec_free (locals);

  return error;
}

static clib_error_t *
add_lb_backend_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  ip4_address_t l_addr, e_addr;
  u32 l_port = 0, e_port = 0, vrf_id = 0, probability = 0;
  int is_add = 1;
  int rv;
  ip_protocol_t proto;
  u8 proto_set = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U:%u probability %u",
		    unformat_ip4_address, &l_addr, &l_port, &probability))
	;
      else if (unformat (line_input, "local %U:%u vrf %u probability %u",
			 unformat_ip4_address, &l_addr, &l_port, &vrf_id,
			 &probability))
	;
      else if (unformat (line_input, "external %U:%u", unformat_ip4_address,
			 &e_addr, &e_port))
	;
      else if (unformat (line_input, "protocol %U", unformat_ip_protocol,
			 &proto))
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

  if (!l_port || !e_port)
    {
      error = clib_error_return (0, "local or external must be set");
      goto done;
    }

  if (!proto_set)
    {
      error = clib_error_return (0, "missing protocol");
      goto done;
    }

  rv = nat44_ed_add_del_lb_static_mapping_local (
    e_addr, (u16) e_port, l_addr, l_port, proto, vrf_id, probability, is_add);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "External is not load-balancing static "
				 "mapping.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "Mapping or back-end not exist.");
      goto done;
    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "Back-end already exist.");
      goto done;
    case VNET_API_ERROR_UNSPECIFIED:
      error = clib_error_return (0, "At least two back-ends must remain");
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_show_static_mappings_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  snat_static_mapping_resolve_t *rp;

  vlib_cli_output (vm, "NAT44 static mappings:");
  pool_foreach (m, sm->static_mappings)
   {
    vlib_cli_output (vm, " %U", format_snat_static_mapping, m);
  }
  vec_foreach (rp, sm->sm_to_resolve)
    vlib_cli_output (vm, " %U", format_snat_static_map_to_resolve, rp);

  return 0;
}

static clib_error_t *
snat_add_interface_address_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snat_main_t *sm = &snat_main;
  clib_error_t *error = 0;
  int rv, is_del = 0;
  u8 twice_nat = 0;
  u32 sw_if_index;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    sm->vnet_main, &sw_if_index))
	;
      else if (unformat (line_input, "twice-nat"))
	{
	  twice_nat = 1;
	}
      else if (unformat (line_input, "del"))
	{
	  is_del = 1;
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!is_del)
    {
      rv = nat44_ed_add_interface_address (sw_if_index, twice_nat);
      if (rv)
	{
	  error = clib_error_return (0, "add address returned %d", rv);
	}
    }
  else
    {
      rv = nat44_ed_del_interface_address (sw_if_index, twice_nat);
      if (rv)
	{
	  error = clib_error_return (0, "del address returned %d", rv);
	}
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_show_interface_address_command_fn (vlib_main_t * vm,
					 unformat_input_t * input,
					 vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  vnet_main_t *vnm = vnet_get_main ();
  snat_address_resolve_t *ap;

  vlib_cli_output (vm, "NAT44 pool address interfaces:");
  vec_foreach (ap, sm->addr_to_resolve)
    {
      vlib_cli_output (vm, " %U%s", format_vnet_sw_if_index_name, vnm,
		       ap->sw_if_index, ap->is_twice_nat ? " twice-nat" : "");
    }
  return 0;
}

static clib_error_t *
nat44_show_sessions_command_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  snat_main_per_thread_data_t *tsm;
  snat_main_t *sm = &snat_main;
  ip4_address_t i2o_sa, i2o_da, o2i_sa, o2i_da;
  u8 filter_i2o_sa = 0, filter_i2o_da = 0;
  u8 filter_o2i_sa = 0, filter_o2i_da = 0;
  u16 i2o_sp, i2o_dp, o2i_sp, o2i_dp;
  u8 filter_i2o_sp = 0, filter_i2o_dp = 0;
  u8 filter_o2i_sp = 0, filter_o2i_dp = 0;
  ip_protocol_t proto;
  u8 filter_proto = 0;
  u8 had_input = 1, filtering = 0;
  int i = 0, showed_sessions;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      had_input = 0;
      goto print;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "filter i2o saddr %U", unformat_ip4_address,
		    &i2o_sa))
	filter_i2o_sa = filtering = 1;
      else if (unformat (line_input, "filter i2o daddr %U",
			 unformat_ip4_address, &i2o_da))
	filter_i2o_da = filtering = 1;
      else if (unformat (line_input, "filter o2i saddr %U",
			 unformat_ip4_address, &o2i_sa))
	filter_o2i_sa = filtering = 1;
      else if (unformat (line_input, "filter o2i daddr %U",
			 unformat_ip4_address, &o2i_da))
	filter_o2i_da = filtering = 1;
      else if (unformat (line_input, "filter i2o sport %u", &i2o_sp))
	filter_i2o_sp = filtering = 1;
      else if (unformat (line_input, "filter i2o dport %u", &i2o_dp))
	filter_i2o_dp = filtering = 1;
      else if (unformat (line_input, "filter o2i sport %u", &o2i_sp))
	filter_o2i_sp = filtering = 1;
      else if (unformat (line_input, "filter o2i dport %u", &o2i_dp))
	filter_o2i_dp = filtering = 1;
      else if (unformat (line_input, "filter i2o proto %U",
			 unformat_ip_protocol, &proto))
	filter_proto = filtering = 1;
      else if (unformat (line_input, "filter o2i proto %U",
			 unformat_ip_protocol, &proto))
	filter_proto = filtering = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

print:
  vlib_cli_output (vm, "NAT44 ED sessions:");

  vec_foreach_index (i, sm->per_thread_data)
    {
      tsm = vec_elt_at_index (sm->per_thread_data, i);

      vlib_cli_output (vm, "-------- thread %d %s: %d sessions --------\n",
                       i, vlib_worker_threads[i].name,
                       pool_elts (tsm->sessions));

      showed_sessions = 0;
      snat_session_t *s;
      pool_foreach (s, tsm->sessions)
	{
	  if (filtering)
	    {
	      if (filter_i2o_sa && i2o_sa.as_u32 != s->i2o.match.saddr.as_u32)
		continue;
	      if (filter_i2o_da && i2o_da.as_u32 != s->i2o.match.daddr.as_u32)
		continue;
	      if (filter_o2i_sa && o2i_sa.as_u32 != s->o2i.match.saddr.as_u32)
		continue;
	      if (filter_o2i_da && o2i_da.as_u32 != s->o2i.match.daddr.as_u32)
		continue;
	      if (filter_i2o_sp &&
		  i2o_sp != clib_net_to_host_u16 (s->i2o.match.sport))
		continue;
	      if (filter_i2o_dp &&
		  i2o_dp != clib_net_to_host_u16 (s->i2o.match.dport))
		continue;
	      if (filter_o2i_sp &&
		  o2i_sp != clib_net_to_host_u16 (s->o2i.match.sport))
		continue;
	      if (filter_o2i_dp &&
		  o2i_dp != clib_net_to_host_u16 (s->o2i.match.dport))
		continue;
	      if (filter_proto && proto != s->proto)
		continue;
	      showed_sessions++;
	    }
	  vlib_cli_output (vm, "  %U\n", format_snat_session, sm, tsm, s,
			   vlib_time_now (vm));
	}
      if (filtering)
	{
	  vlib_cli_output (vm,
			   "Showed: %d, Filtered: %d of total %d "
			   "sessions of thread %d\n\n",
			   showed_sessions,
			   pool_elts (tsm->sessions) - showed_sessions,
			   pool_elts (tsm->sessions), i);
	}
    }

done:
  if (had_input)
    unformat_free (line_input);
  return error;
}

static clib_error_t *
nat44_set_session_limit_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  u32 session_limit = 0, vrf_id = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u", &session_limit))
	;
      else if (unformat (line_input, "vrf %u", &vrf_id))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!session_limit)
    error = clib_error_return (0, "missing value of session limit");
  else if (nat44_update_session_limit (session_limit, vrf_id))
    error = clib_error_return (0, "nat44_set_session_limit failed");

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_del_session_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 port = 0, eh_port = 0, vrf_id = sm->outside_vrf_id;
  clib_error_t *error = 0;
  ip4_address_t addr, eh_addr;
  ip_protocol_t proto;
  int is_in = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%u %U", unformat_ip4_address, &addr, &port,
		    unformat_ip_protocol, &proto))
	;
      else if (unformat (line_input, "in"))
	{
	  is_in = 1;
	  vrf_id = sm->inside_vrf_id;
	}
      else if (unformat (line_input, "out"))
	{
	  is_in = 0;
	  vrf_id = sm->outside_vrf_id;
	}
      else if (unformat (line_input, "vrf %u", &vrf_id))
	;
      else if (unformat (line_input, "external-host %U:%u",
			 unformat_ip4_address, &eh_addr, &eh_port))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = nat44_ed_del_session (sm, &addr, clib_host_to_net_u16 (port), &eh_addr,
			     clib_host_to_net_u16 (eh_port), proto, vrf_id,
			     is_in);

  switch (rv)
    {
    case 0:
      break;

    default:
      error = clib_error_return (0, "nat44_del_session returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
snat_forwarding_set_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  u8 enable_set = 0, enable = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (!enable_set)
	{
	  enable_set = 1;
	  if (unformat (line_input, "disable"))
	    ;
	  else if (unformat (line_input, "enable"))
	    enable = 1;
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!enable_set)
    error = clib_error_return (0, "expected enable | disable");
  else
    sm->forwarding_enabled = enable;

done:
  unformat_free (line_input);
  return error;
}

static clib_error_t *
set_timeout_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "udp %u", &sm->timeouts.udp));
      else if (unformat (line_input, "tcp-established %u",
			 &sm->timeouts.tcp.established));
      else if (unformat (line_input, "tcp-transitory %u",
			 &sm->timeouts.tcp.transitory));
      else if (unformat (line_input, "icmp %u", &sm->timeouts.icmp));
      else if (unformat (line_input, "reset"))
	nat_reset_timeouts (&sm->timeouts);
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
nat_show_timeouts_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;

  vlib_cli_output (vm, "udp timeout: %dsec", sm->timeouts.udp);
  vlib_cli_output (vm, "tcp-established timeout: %dsec",
		   sm->timeouts.tcp.established);
  vlib_cli_output (vm, "tcp-transitory timeout: %dsec",
		   sm->timeouts.tcp.transitory);
  vlib_cli_output (vm, "icmp timeout: %dsec", sm->timeouts.icmp);

  return 0;
}

static clib_error_t *
set_frame_queue_nelts_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 frame_queue_nelts = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT44_ED_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u", &frame_queue_nelts))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }
  if (!frame_queue_nelts)
    {
      error = clib_error_return (0, "frame_queue_nelts cannot be zero");
      goto done;
    }
  if (nat44_ed_set_frame_queue_nelts (frame_queue_nelts) != 0)
    {
      error = clib_error_return (0, "snat_set_frame_queue_nelts failed");
      goto done;
    }
done:
  unformat_free (line_input);
  return error;
}

/*?
 * @cliexpar
 * @cliexstart{nat44}
 * Enable nat44 plugin
 * To enable nat44-ed, use:
 *  vpp# nat44 enable
 * To disable nat44-ed, use:
 *  vpp# nat44 disable
 * To set inside-vrf outside-vrf, use:
 *  vpp# nat44 enable inside-vrf <id> outside-vrf <id>
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_ed_enable_disable_command, static) = {
  .path = "nat44",
  .short_help = "nat44 <enable [sessions <max-number>] [inside-vrf <vrf-id>] "
		"[outside-vrf <vrf-id>]>|disable",
  .function = nat44_ed_enable_disable_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set snat workers}
 * Set NAT workers if 2 or more workers available, use:
 *  vpp# set snat workers 0-2,5
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_workers_command, static) = {
  .path = "set nat workers",
  .function = set_workers_command_fn,
  .short_help = "set nat workers <workers-list>",
};

/*?
 * @cliexpar
 * @cliexstart{show nat workers}
 * Show NAT workers.
 *  vpp# show nat workers:
 *  2 workers
 *    vpp_wk_0
 *    vpp_wk_1
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_show_workers_command, static) = {
  .path = "show nat workers",
  .short_help = "show nat workers",
  .function = nat_show_workers_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set nat timeout}
 * Set values of timeouts for NAT sessions (in seconds), use:
 *  vpp# set nat timeout udp 120 tcp-established 7500 tcp-transitory 250 icmp 90
 * To reset default values use:
 *  vpp# set nat timeout reset
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_timeout_command, static) = {
  .path = "set nat timeout",
  .function = set_timeout_command_fn,
  .short_help =
    "set nat timeout [udp <sec> | tcp-established <sec> "
    "tcp-transitory <sec> | icmp <sec> | reset]",
};

/*?
 * @cliexpar
 * @cliexstart{show nat timeouts}
 * Show values of timeouts for NAT sessions.
 * vpp# show nat timeouts
 * udp timeout: 300sec
 * tcp-established timeout: 7440sec
 * tcp-transitory timeout: 240sec
 * icmp timeout: 60sec
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_show_timeouts_command, static) = {
  .path = "show nat timeouts",
  .short_help = "show nat timeouts",
  .function = nat_show_timeouts_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set nat frame-queue-nelts}
 * Set number of worker handoff frame queue elements.
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_frame_queue_nelts_command, static) = {
  .path = "set nat frame-queue-nelts",
  .function = set_frame_queue_nelts_command_fn,
  .short_help = "set nat frame-queue-nelts <number>",
};

/*?
 * @cliexpar
 * @cliexstart{nat set logging level}
 * To set NAT logging level use:
 * Set nat logging level
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_set_log_level_command, static) = {
  .path = "nat set logging level",
  .function = snat_set_log_level_command_fn,
  .short_help = "nat set logging level <level>",
};

/*?
 * @cliexpar
 * @cliexstart{snat ipfix logging}
 * To enable NAT IPFIX logging use:
 *  vpp# nat ipfix logging
 * To set IPFIX exporter use:
 *  vpp# set ipfix exporter collector 10.10.10.3 src 10.10.10.1
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_ipfix_logging_enable_disable_command, static) = {
  .path = "nat ipfix logging",
  .function = snat_ipfix_logging_enable_disable_command_fn,
  .short_help = "nat ipfix logging disable|<enable [domain <domain-id>] "
		"[src-port <port>]>",
};

/*?
 * @cliexpar
 * @cliexstart{nat mss-clamping}
 * Set TCP MSS rewriting configuration
 * To enable TCP MSS rewriting use:
 *  vpp# nat mss-clamping 1452
 * To disbale TCP MSS rewriting use:
 *  vpp# nat mss-clamping disable
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_set_mss_clamping_command, static) = {
    .path = "nat mss-clamping",
    .short_help = "nat mss-clamping <mss-value>|disable",
    .function = nat_set_mss_clamping_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat mss-clamping}
 * Show TCP MSS rewriting configuration
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_show_mss_clamping_command, static) = {
    .path = "show nat mss-clamping",
    .short_help = "show nat mss-clamping",
    .function = nat_show_mss_clamping_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 hash tables}
 * Show NAT44 hash tables
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_hash, static) = {
  .path = "show nat44 hash tables",
  .short_help = "show nat44 hash tables [detail|verbose]",
  .function = nat44_show_hash_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 add address}
 * Add/delete NAT44 pool address.
 * To add NAT44 pool address use:
 *  vpp# nat44 add address 172.16.1.3
 *  vpp# nat44 add address 172.16.2.2 - 172.16.2.24
 * To add NAT44 pool address for specific tenant (identified by VRF id) use:
 *  vpp# nat44 add address 172.16.1.3 tenant-vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_address_command, static) = {
  .path = "nat44 add address",
  .short_help = "nat44 add address <ip4-range-start> [- <ip4-range-end>] "
                "[tenant-vrf <vrf-id>] [twice-nat] [del]",
  .function = add_address_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 summary}
 * Show NAT44 summary
 * vpp# show nat44 summary
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_summary_command, static) = {
  .path = "show nat44 summary",
  .short_help = "show nat44 summary",
  .function = nat44_show_summary_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 addresses}
 * Show NAT44 pool addresses.
 * vpp# show nat44 addresses
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
 * NAT44 twice-nat pool addresses:
 * 10.20.30.72
 *   tenant VRF independent
 *   0 busy udp ports
 *   0 busy tcp ports
 *   0 busy icmp ports
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_addresses_command, static) = {
  .path = "show nat44 addresses",
  .short_help = "show nat44 addresses",
  .function = nat44_show_addresses_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set interface nat44}
 * Enable/disable NAT44 feature on the interface.
 * To enable NAT44 feature with local network interface use:
 *  vpp# set interface nat44 in GigabitEthernet0/8/0
 * To enable NAT44 feature with external network interface use:
 *  vpp# set interface nat44 out GigabitEthernet0/a/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_interface_snat_command, static) = {
  .path = "set interface nat44",
  .function = snat_feature_command_fn,
  .short_help = "set interface nat44 in <intfc> out <intfc> [output-feature] "
                "[del]",
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 interfaces}
 * Show interfaces with NAT44 feature.
 * vpp# show nat44 interfaces
 * NAT44 interfaces:
 *  GigabitEthernet0/8/0 in
 *  GigabitEthernet0/a/0 out
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_interfaces_command, static) = {
  .path = "show nat44 interfaces",
  .short_help = "show nat44 interfaces",
  .function = nat44_show_interfaces_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 add static mapping}
 * Static mapping allows hosts on the external network to initiate connection
 * to to the local network host.
 * To create static mapping between local host address 10.0.0.3 port 6303 and
 * external address 4.4.4.4 port 3606 for TCP protocol use:
 *  vpp# nat44 add static mapping tcp local 10.0.0.3 6303 external 4.4.4.4 3606
 * If not runnig "static mapping only" NAT plugin mode use before:
 *  vpp# nat44 add address 4.4.4.4
 * To create address only static mapping between local and external address use:
 *  vpp# nat44 add static mapping local 10.0.0.3 external 4.4.4.4
 * To create ICMP static mapping between local and external with ICMP echo
 * identifier 10 use:
 *  vpp# nat44 add static mapping icmp local 10.0.0.3 10 external 4.4.4.4 10
 * To force use of specific pool address, vrf independent
 *  vpp# nat44 add static mapping local 10.0.0.2 1234 external 10.0.2.2 1234 twice-nat exact 10.0.1.2
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_static_mapping_command, static) = {
  .path = "nat44 add static mapping",
  .function = add_static_mapping_command_fn,
  .short_help =
    "nat44 add static mapping tcp|udp|icmp local <addr> [<port|icmp-echo-id>] "
    "external <addr> [<port|icmp-echo-id>] [vrf <table-id>] [twice-nat|self-twice-nat] "
    "[out2in-only] [exact <pool-addr>] [del]",
};

/*?
 * @cliexpar
 * @cliexstart{nat44 add identity mapping}
 * Identity mapping translate an IP address to itself.
 * To create identity mapping for address 10.0.0.3 port 6303 for TCP protocol
 * use:
 *  vpp# nat44 add identity mapping 10.0.0.3 tcp 6303
 * To create identity mapping for address 10.0.0.3 use:
 *  vpp# nat44 add identity mapping 10.0.0.3
 * To create identity mapping for DHCP addressed interface use:
 *  vpp# nat44 add identity mapping external GigabitEthernet0/a/0 tcp 3606
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_identity_mapping_command, static) = {
  .path = "nat44 add identity mapping",
  .function = add_identity_mapping_command_fn,
  .short_help = "nat44 add identity mapping <ip4-addr>|external <interface> "
    "[<protocol> <port>] [vrf <table-id>] [del]",
};

/*?
 * @cliexpar
 * @cliexstart{nat44 add load-balancing static mapping}
 * Service load balancing using NAT44
 * To add static mapping with load balancing for service with external IP
 * address 1.2.3.4 and TCP port 80 and mapped to 2 local servers
 * 10.100.10.10:8080 and 10.100.10.20:8080 with probability 80% resp. 20% use:
 *  vpp# nat44 add load-balancing static mapping protocol tcp external 1.2.3.4:80 local 10.100.10.10:8080 probability 80 local 10.100.10.20:8080 probability 20
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_lb_static_mapping_command, static) = {
  .path = "nat44 add load-balancing static mapping",
  .function = add_lb_static_mapping_command_fn,
  .short_help =
    "nat44 add load-balancing static mapping protocol tcp|udp "
    "external <addr>:<port> local <addr>:<port> [vrf <table-id>] "
    "probability <n> [twice-nat|self-twice-nat] [out2in-only] "
    "[affinity <timeout-seconds>] [del]",
};

/*?
 * @cliexpar
 * @cliexstart{nat44 add load-balancing static mapping}
 * Modify service load balancing using NAT44
 * To add new back-end server 10.100.10.30:8080 for service load balancing
 * static mapping with external IP address 1.2.3.4 and TCP port 80 use:
 *  vpp# nat44 add load-balancing back-end protocol tcp external 1.2.3.4:80 local 10.100.10.30:8080 probability 25
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_lb_backend_command, static) = {
  .path = "nat44 add load-balancing back-end",
  .function = add_lb_backend_command_fn,
  .short_help =
    "nat44 add load-balancing back-end protocol tcp|udp "
    "external <addr>:<port> local <addr>:<port> [vrf <table-id>] "
    "probability <n> [del]",
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 static mappings}
 * Show NAT44 static mappings.
 * vpp# show nat44 static mappings
 * NAT44 static mappings:
 *  local 10.0.0.3 external 4.4.4.4 vrf 0
 *  tcp local 192.168.0.4:6303 external 4.4.4.3:3606 vrf 0
 *  tcp vrf 0 external 1.2.3.4:80  out2in-only
 *   local 10.100.10.10:8080 probability 80
 *   local 10.100.10.20:8080 probability 20
 *  tcp local 10.100.3.8:8080 external 169.10.10.1:80 vrf 0 twice-nat
 *  tcp local 10.0.0.10:3603 external GigabitEthernet0/a/0:6306 vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_static_mappings_command, static) = {
  .path = "show nat44 static mappings",
  .short_help = "show nat44 static mappings",
  .function = nat44_show_static_mappings_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 add interface address}
 * Use NAT44 pool address from specific interfce
 * To add NAT44 pool address from specific interface use:
 *  vpp# nat44 add interface address GigabitEthernet0/8/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_add_interface_address_command, static) = {
    .path = "nat44 add interface address",
    .short_help = "nat44 add interface address <interface> [twice-nat] [del]",
    .function = snat_add_interface_address_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 interface address}
 * Show NAT44 pool address interfaces
 * vpp# show nat44 interface address
 * NAT44 pool address interfaces:
 *  GigabitEthernet0/a/0
 * NAT44 twice-nat pool address interfaces:
 *  GigabitEthernet0/8/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_interface_address_command, static) = {
  .path = "show nat44 interface address",
  .short_help = "show nat44 interface address",
  .function = nat44_show_interface_address_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 sessions}
 * Show NAT44 sessions.
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_sessions_command, static) = {
  .path = "show nat44 sessions",
  .short_help = "show nat44 sessions [filter {i2o | o2i} {saddr <ip4-addr> "
		"| sport <n> | daddr <ip4-addr> | dport <n> | proto <proto>} "
		"[filter .. [..]]]",
  .function = nat44_show_sessions_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set nat44 session limit}
 * Set NAT44 session limit.
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_set_session_limit_command, static) = {
  .path = "set nat44 session limit",
  .short_help = "set nat44 session limit <limit> [vrf <table-id>]",
  .function = nat44_set_session_limit_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 del session}
 * To administratively delete NAT44 session by inside address and port use:
 *  vpp# nat44 del session in 10.0.0.3:6303 tcp
 * To administratively delete NAT44 session by outside address and port use:
 *  vpp# nat44 del session out 1.0.0.3:6033 udp
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_del_session_command, static) = {
    .path = "nat44 del session",
    .short_help = "nat44 del session in|out <addr>:<port> tcp|udp|icmp [vrf <id>] [external-host <addr>:<port>]",
    .function = nat44_del_session_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 forwarding}
 * Enable or disable forwarding
 * Forward packets which don't match existing translation
 * or static mapping instead of dropping them.
 * To enable forwarding, use:
 *  vpp# nat44 forwarding enable
 * To disable forwarding, use:
 *  vpp# nat44 forwarding disable
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_forwarding_set_command, static) = {
  .path = "nat44 forwarding",
  .short_help = "nat44 forwarding enable|disable",
  .function = snat_forwarding_set_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
