/*
 * det44.c - deterministic NAT
 *
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
/**
 * @file
 * @brief deterministic NAT (CGN)
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>

#include <nat/det44/det44.h>

det44_main_t det44_main;

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_det44_in2out, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "det44-in2out",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_det44_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "det44-out2in",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-sv-reassembly-feature",
                               "ip4-dhcp-client-detect"),
};
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Deterministic NAT (CGN)",
};
/* *INDENT-ON* */

void
det44_add_del_addr_to_fib (ip4_address_t * addr, u8 p_len, u32 sw_if_index,
			   int is_add)
{
  det44_main_t *dm = &det44_main;
  fib_prefix_t prefix = {
    .fp_len = p_len,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr = {
		.ip4.as_u32 = addr->as_u32,
		},
  };
  u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  if (is_add)
    {
      fib_table_entry_update_one_path (fib_index,
				       &prefix,
				       dm->fib_src_low,
				       (FIB_ENTRY_FLAG_CONNECTED |
					FIB_ENTRY_FLAG_LOCAL |
					FIB_ENTRY_FLAG_EXCLUSIVE),
				       DPO_PROTO_IP4,
				       NULL,
				       sw_if_index,
				       ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
    }
  else
    {
      fib_table_entry_delete (fib_index, &prefix, dm->fib_src_low);
    }
}

/**
 * @brief Add/delete deterministic NAT mapping.
 *
 * Create bijective mapping of inside address to outside address and port range
 * pairs, with the purpose of enabling deterministic NAT to reduce logging in
 * CGN deployments.
 *
 * @param in_addr  Inside network address.
 * @param in_plen  Inside network prefix length.
 * @param out_addr Outside network address.
 * @param out_plen Outside network prefix length.
 * @param is_add   If 0 delete, otherwise add.
 */
int
snat_det_add_map (ip4_address_t * in_addr, u8 in_plen,
		  ip4_address_t * out_addr, u8 out_plen, int is_add)
{
  static snat_det_session_t empty_snat_det_session = { 0 };
  det44_main_t *dm = &det44_main;
  ip4_address_t in_cmp, out_cmp;
  det44_interface_t *i;
  snat_det_map_t *mp;
  u8 found = 0;

  in_cmp.as_u32 = in_addr->as_u32 & ip4_main.fib_masks[in_plen];
  out_cmp.as_u32 = out_addr->as_u32 & ip4_main.fib_masks[out_plen];
  vec_foreach (mp, dm->det_maps)
  {
    /* Checking for overlapping addresses to be added here */
    if (mp->in_addr.as_u32 == in_cmp.as_u32 &&
	mp->in_plen == in_plen &&
	mp->out_addr.as_u32 == out_cmp.as_u32 && mp->out_plen == out_plen)
      {
	found = 1;
	break;
      }
  }

  /* If found, don't add again */
  if (found && is_add)
    return VNET_API_ERROR_VALUE_EXIST;

  /* If not found, don't delete */
  if (!found && !is_add)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (is_add)
    {
      pool_get (dm->det_maps, mp);
      clib_memset (mp, 0, sizeof (*mp));
      mp->in_addr.as_u32 = in_cmp.as_u32;
      mp->in_plen = in_plen;
      mp->out_addr.as_u32 = out_cmp.as_u32;
      mp->out_plen = out_plen;
      mp->sharing_ratio = (1 << (32 - in_plen)) / (1 << (32 - out_plen));
      mp->ports_per_host = (65535 - 1023) / mp->sharing_ratio;

      vec_validate_init_empty (mp->sessions,
			       DET44_SES_PER_USER * (1 << (32 - in_plen)) -
			       1, empty_snat_det_session);
    }
  else
    {
      vec_free (mp->sessions);
      vec_del1 (dm->det_maps, mp - dm->det_maps);
    }

  /* Add/del external address range to FIB */
  /* *INDENT-OFF* */
  pool_foreach (i, dm->interfaces, ({
    if (det44_interface_is_inside(i))
      continue;
    det44_add_del_addr_to_fib(out_addr, out_plen, i->sw_if_index, is_add);
    goto out;
  }));
  /* *INDENT-ON* */
out:
  return 0;
}

int
det44_set_timeouts (nat_timeouts_t * timeouts)
{
  det44_main_t *dm = &det44_main;
  if (timeouts->udp)
    dm->timeouts.udp = timeouts->udp;
  if (timeouts->tcp.established)
    dm->timeouts.tcp.established = timeouts->tcp.established;
  if (timeouts->tcp.transitory)
    dm->timeouts.tcp.transitory = timeouts->tcp.transitory;
  if (timeouts->icmp)
    dm->timeouts.icmp = timeouts->icmp;
  return 0;
}

nat_timeouts_t
det44_get_timeouts ()
{
  det44_main_t *dm = &det44_main;
  return dm->timeouts;
}

void
det44_reset_timeouts ()
{
  det44_main_t *dm = &det44_main;
  dm->timeouts.udp = 300;
  dm->timeouts.tcp.established = 7440;
  dm->timeouts.tcp.transitory = 240;
  dm->timeouts.icmp = 60;
}

int
det44_interface_add_del (u32 sw_if_index, u8 is_inside, int is_del)
{
  det44_main_t *dm = &det44_main;
  det44_interface_t *tmp, *i = 0;
  const char *feature_name;
  int rv;

  // TODO: if plugin is not enabled do not register nodes on interfaces
  // rather make a structure and when enable call is used
  // then register nodes

  /* *INDENT-OFF* */
  pool_foreach (tmp, dm->interfaces, ({
    if (tmp->sw_if_index == sw_if_index)
      {
        i = tmp;
        goto out;
      }
  }));
  /* *INDENT-ON* */
out:

  feature_name = is_inside ? "det44-in2out" : "det44-out2in";

  if (is_del)
    {
      if (!i)
	{
	  det44_log_err ("det44 is not enabled on this interface");
	  return VNET_API_ERROR_INVALID_VALUE;
	}

      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
      if (rv)
	return rv;

      rv = vnet_feature_enable_disable ("ip4-unicast", feature_name,
					sw_if_index, 1, 0, 0);
      if (rv)
	return rv;

      pool_put (dm->interfaces, i);
    }
  else
    {
      if (i)
	{
	  det44_log_err ("det44 is already enabled on this interface");
	  return VNET_API_ERROR_INVALID_VALUE;
	}

      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
      if (rv)
	return rv;

      rv = vnet_feature_enable_disable ("ip4-unicast", feature_name,
					sw_if_index, 1, 0, 0);
      if (rv)
	return rv;

      pool_get (dm->interfaces, i);
      clib_memset (i, 0, sizeof (*i));

      i->sw_if_index = sw_if_index;

      if (is_inside)
	i->flags |= DET44_INTERFACE_FLAG_IS_INSIDE;
      else
	i->flags |= DET44_INTERFACE_FLAG_IS_OUTSIDE;
    }

  if (!is_inside)
    {
      u32 fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
							   sw_if_index);
      // add/del outside interface fib to registry
      u8 found = 0;
      det44_fib_t *outside_fib;
      /* *INDENT-OFF* */
      vec_foreach (outside_fib, dm->outside_fibs)
        {
          if (outside_fib->fib_index == fib_index)
            {
              if (!is_del)
                {
                  outside_fib->refcount++;
                }
              else
                {
                  outside_fib->refcount--;
                  if (!outside_fib->refcount)
                    {
                      vec_del1 (dm->outside_fibs,
                                outside_fib - dm->outside_fibs);
                    }
                }
              found = 1;
              break;
            }
        }
      /* *INDENT-ON* */
      if (!is_del && !found)
	{
	  vec_add2 (dm->outside_fibs, outside_fib, 1);
	  outside_fib->fib_index = fib_index;
	  outside_fib->refcount = 1;
	}
      // add/del outside address to FIB
      snat_det_map_t *mp;
      /* *INDENT-OFF* */
      pool_foreach (mp, dm->det_maps, ({
        det44_add_del_addr_to_fib(&mp->out_addr,
                                  mp->out_plen, sw_if_index, !is_del);
      }));
      /* *INDENT-ON* */
    }
  return 0;
}

/**
 * @brief The 'det44-expire-walk' process's main loop.
 *
 * Check expire time for active sessions.
 */
static uword
det44_expire_walk_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
		      vlib_frame_t * f)
{
  det44_main_t *dm = &det44_main;
  snat_det_session_t *ses;
  snat_det_map_t *mp;

  vlib_process_wait_for_event_or_clock (vm, 10.0);
  vlib_process_get_events (vm, NULL);
  u32 now = (u32) vlib_time_now (vm);
  /* *INDENT-OFF* */
  pool_foreach (mp, dm->det_maps, ({
    vec_foreach(ses, mp->sessions)
      {
        /* Delete if session expired */
        if (ses->in_port && (ses->expire < now))
          snat_det_ses_close (mp, ses);
      }
  }));
  /* *INDENT-ON* */
  return 0;
}

void
det44_create_expire_walk_process ()
{
  det44_main_t *dm = &det44_main;

  if (dm->expire_walk_node_index)
    return;

  dm->expire_walk_node_index = vlib_process_create (vlib_get_main (),
						    "det44-expire-walk",
						    det44_expire_walk_fn,
						    16 /* stack_bytes */ );
}

int
det44_plugin_enable (det44_config_t c)
{
  det44_main_t *dm = &det44_main;

  if (plugin_enabled () == 1)
    {
      det44_log_err ("plugin already enabled!");
      return 1;
    }

  det44_log_err ("inside %u, outside %u", c.inside_vrf_id, c.outside_vrf_id);

  dm->outside_fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
							     c.outside_vrf_id,
							     dm->fib_src_hi);
  dm->inside_fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
							    c.inside_vrf_id,
							    dm->fib_src_hi);

  det44_create_expire_walk_process ();
  dm->mss_clamping = 0;
  dm->config = c;
  dm->enabled = 1;
  return 0;
}

int
det44_plugin_disable ()
{
  det44_main_t *dm = &det44_main;
  det44_interface_t *i, *interfaces;
  snat_det_map_t *mp;
  int rv = 0;

  if (plugin_enabled () == 0)
    {
      det44_log_err ("plugin already disabled!");
      return 1;
    }

  // DET44 cleanup (order dependent)
  // 1) remove interfaces (det44_interface_add_del) removes map ranges from fib
  // 2) free sessions
  // 3) free maps

  interfaces = vec_dup (dm->interfaces);
  vec_foreach (i, interfaces)
  {
    vnet_main_t *vnm = vnet_get_main ();

    if (i->flags & DET44_INTERFACE_FLAG_IS_INSIDE)
      {
	rv = det44_interface_add_del (i->sw_if_index, i->flags, 1);
	if (rv)
	  {
	    det44_log_err ("inside interface %U del failed",
			   unformat_vnet_sw_interface, vnm, i->sw_if_index);
	  }
      }

    if (i->flags & DET44_INTERFACE_FLAG_IS_OUTSIDE)
      {
	rv = det44_interface_add_del (i->sw_if_index, i->flags, 1);
	if (rv)
	  {
	    det44_log_err ("outside interface %U del failed",
			   unformat_vnet_sw_interface, vnm, i->sw_if_index);
	  }

      }
  }
  vec_free (interfaces);

  /* *INDENT-OFF* */
  pool_foreach (mp, dm->det_maps,
  ({
    vec_free (mp->sessions);
  }));
  /* *INDENT-ON* */

  det44_reset_timeouts ();
  dm->enabled = 0;

  pool_free (dm->interfaces);
  pool_free (dm->det_maps);

  return rv;
}

static void
det44_update_outside_fib (ip4_main_t * im,
			  uword opaque,
			  u32 sw_if_index, u32 new_fib_index,
			  u32 old_fib_index)
{
  det44_main_t *dm = &det44_main;

  det44_fib_t *outside_fib;
  det44_interface_t *i;

  u8 is_add = 1;
  u8 match = 0;

  if (plugin_enabled () == 0)
    return;

  if (new_fib_index == old_fib_index)
    return;

  if (!vec_len (dm->outside_fibs))
    return;

  /* *INDENT-OFF* */
  pool_foreach (i, dm->interfaces,
    ({
      if (i->sw_if_index == sw_if_index)
        {
          if (!(det44_interface_is_outside (i)))
	    return;
          match = 1;
        }
    }));
  /* *INDENT-ON* */

  if (!match)
    return;

  vec_foreach (outside_fib, dm->outside_fibs)
  {
    if (outside_fib->fib_index == old_fib_index)
      {
	outside_fib->refcount--;
	if (!outside_fib->refcount)
	  vec_del1 (dm->outside_fibs, outside_fib - dm->outside_fibs);
	break;
      }
  }

  vec_foreach (outside_fib, dm->outside_fibs)
  {
    if (outside_fib->fib_index == new_fib_index)
      {
	outside_fib->refcount++;
	is_add = 0;
	break;
      }
  }

  if (is_add)
    {
      vec_add2 (dm->outside_fibs, outside_fib, 1);
      outside_fib->refcount = 1;
      outside_fib->fib_index = new_fib_index;
    }
}

static clib_error_t *
det44_counters_init ()
{
  det44_main_t *dm = &det44_main;
  det44_counters_t *cnts = &dm->host_counters;
  clib_error_t *error = 0;

  u8 *name = format (0, "/nat44/det/inside-hosts");
  error = stat_segment_register_name_vector (name,
					     &cnts->stats_name_vector_index);
  vec_free (name);

  cnts->ses_per_host.name = "det NAT sessions per inside host";
  cnts->ses_per_host.stat_segment_name = "/nat44/det/sessions";
  vlib_validate_simple_counter (&cnts->ses_per_host, 0);

  cnts->max_ses_per_host.name = "det NAT max. sessions per inside host";
  cnts->max_ses_per_host.stat_segment_name = "/nat44/det/max-sessions";
  vlib_validate_simple_counter (&cnts->max_ses_per_host, 0);

  cnts->ports_per_host.name = "det NAT ports used per inside host";
  cnts->ports_per_host.stat_segment_name = "/nat44/det/ports";
  vlib_validate_simple_counter (&cnts->ports_per_host, 0);

  cnts->max_ports_per_host.name = "det NAT max. ports per inside host";
  cnts->max_ports_per_host.stat_segment_name = "/nat44/det/max-ports";
  vlib_validate_simple_counter (&cnts->max_ports_per_host, 0);

  clib_bihash_init_8_8 (&cnts->in_host,
			"deterministic NAT inside hosts", 1024, 128 << 20);

  clib_bihash_init_8_8 (&cnts->in_host_out_port,
			"deterministic NAT inside hosts & outside ports",
			1024, 128 << 20);

  return error;
}

static clib_error_t *
det44_init (vlib_main_t * vm)
{
  det44_main_t *dm = &det44_main;
  ip4_table_bind_callback_t cb;
  vlib_node_t *node;
  clib_error_t *error = 0;

  clib_memset (dm, 0, sizeof (*dm));

  dm->ip4_main = &ip4_main;
  dm->log_class = vlib_log_register_class ("det44", 0);

  node = vlib_get_node_by_name (vm, (u8 *) "det44-in2out");
  dm->in2out_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "det44-out2in");
  dm->out2in_node_index = node->index;

  dm->fib_src_hi = fib_source_allocate ("det44-hi",
					FIB_SOURCE_PRIORITY_HI,
					FIB_SOURCE_BH_SIMPLE);
  dm->fib_src_low = fib_source_allocate ("det44-low",
					 FIB_SOURCE_PRIORITY_LOW,
					 FIB_SOURCE_BH_SIMPLE);

  cb.function = det44_update_outside_fib;
  cb.function_opaque = 0;
  vec_add1 (dm->ip4_main->table_bind_callbacks, cb);

  det44_reset_timeouts ();
  error = det44_counters_init ();
  if (error)
    return error;
  return det44_api_hookup (vm);
}

VLIB_INIT_FUNCTION (det44_init);

static void
det44_update_host_port_counters (u32 cnt_index, ip4_address_t * in_addr,
				 u16 out_port, int is_add)
{
  det44_main_t *dm = &det44_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 thread_index = vm->thread_index;
  det44_counters_t *cnts = &dm->host_counters;
  clib_bihash_kv_8_8_t kv, kv_result;
  det44_port_counters_key_t key;
  u64 cnt_val;

  key.as_u64 = 0;
  key.addr = *in_addr;
  key.port = out_port;
  kv.key = key.as_u64;

  if (is_add)
    {
      if (clib_bihash_search_8_8 (&cnts->in_host_out_port, &kv, &kv_result))
	{
	  /* not found -> new combination, set in_host_out_port for
	   * given key to 1 and increment ports_per_host */
	  kv.value = 1;
	  clib_bihash_add_del_8_8 (&cnts->in_host_out_port, &kv, 1);

	  vlib_increment_simple_counter (&cnts->ports_per_host, thread_index,
					 cnt_index, 1);
	}
      else
	{
	  kv.value = kv_result.value + 1;
	  clib_bihash_add_del_8_8 (&cnts->in_host_out_port, &kv, 1);
	}
    }
  else
    {
      if (clib_bihash_search_8_8 (&cnts->in_host_out_port, &kv, &kv_result))
	ASSERT (0);		/* inconsistency! no track of the deleted session */

      if (kv_result.value == 1)
	{
	  clib_bihash_add_del_8_8 (&cnts->in_host_out_port, &kv, 0);

	  cnt_val =
	    vlib_get_simple_counter (&cnts->ports_per_host, cnt_index);
	  ASSERT (cnt_val > 0);

	  vlib_set_simple_counter (&cnts->ports_per_host, thread_index,
				   cnt_index, cnt_val - 1);
	}
      else
	{
	  kv.value = kv_result.value - 1;
	  clib_bihash_add_del_8_8 (&cnts->in_host_out_port, &kv, 1);
	}
    }
}

void
det44_update_host_counters (ip4_address_t * in_addr, u16 out_port,
			    u16 ports_per_host, int is_add)
{
  det44_main_t *dm = &det44_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 thread_index = vm->thread_index;
  det44_counters_t *cnts = &dm->host_counters;
  clib_bihash_kv_8_8_t kv, kv_result;
  u8 **name;
  u32 cnt_index;
  u64 cnt_val;

  kv.key = in_addr->as_u32;

  if (is_add)
    {
      if (clib_bihash_search_8_8 (&cnts->in_host, &kv, &kv_result))
	{
	  /* not found */
	  void *oldheap = stat_segment_prepare_name_vector (cnts->names);
	  pool_get (cnts->names, name);
	  *name = format (0, "%U", format_ip4_address, in_addr);
	  stat_segment_set_name_vector (cnts->stats_name_vector_index,
					cnts->names, oldheap);
	  cnt_index = name - cnts->names;
	  vlib_validate_simple_counter (&cnts->ses_per_host, cnt_index);
	  vlib_validate_simple_counter (&cnts->max_ses_per_host, cnt_index);
	  vlib_validate_simple_counter (&cnts->ports_per_host, cnt_index);
	  vlib_validate_simple_counter (&cnts->max_ports_per_host, cnt_index);
	  vlib_zero_simple_counter (&cnts->ses_per_host, cnt_index);
	  vlib_zero_simple_counter (&cnts->max_ses_per_host, cnt_index);
	  vlib_zero_simple_counter (&cnts->ports_per_host, cnt_index);
	  vlib_zero_simple_counter (&cnts->max_ports_per_host, cnt_index);
	  vlib_set_simple_counter (&cnts->ses_per_host, thread_index,
				   cnt_index, 1);
	  vlib_set_simple_counter (&cnts->max_ses_per_host, thread_index,
				   cnt_index, DET44_SES_PER_USER);
	  vlib_set_simple_counter (&cnts->max_ports_per_host, thread_index,
				   cnt_index, ports_per_host);
	  kv.value = cnt_index;
	  clib_bihash_add_del_8_8 (&cnts->in_host, &kv, 1);
	}
      else
	{
	  cnt_index = kv_result.value;
	  vlib_increment_simple_counter (&cnts->ses_per_host, thread_index,
					 cnt_index, 1);
	}
      det44_update_host_port_counters (cnt_index, in_addr, out_port, is_add);
    }
  else
    {
      if (clib_bihash_search_8_8 (&cnts->in_host, &kv, &kv_result))
	ASSERT (0);		/* inconsistency! no track of the deleted session */

      cnt_index = kv_result.value;
      cnt_val = vlib_get_simple_counter (&cnts->ses_per_host, cnt_index);

      if (cnt_val > 1)
	{
	  vlib_set_simple_counter (&cnts->ses_per_host, thread_index,
				   cnt_index, cnt_val - 1);
	  det44_update_host_port_counters (cnt_index, in_addr, out_port,
					   is_add);
	}
      else
	{
	  clib_bihash_add_del_8_8 (&cnts->in_host, &kv, 0);
	  name = pool_elt_at_index (cnts->names, cnt_index);
	  void *oldheap = stat_segment_prepare_name_vector (cnts->names);
	  pool_put (cnts->names, name);
	  vec_free (*name);
	  stat_segment_set_name_vector (cnts->stats_name_vector_index,
					cnts->names, oldheap);
	  vlib_zero_simple_counter (&cnts->ses_per_host, cnt_index);
	  vlib_zero_simple_counter (&cnts->max_ses_per_host, cnt_index);
	  vlib_zero_simple_counter (&cnts->ports_per_host, cnt_index);
	  vlib_zero_simple_counter (&cnts->max_ports_per_host, cnt_index);
	}
    }
}

u8 *
format_det44_session_state (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v, N, str) case DET44_SESSION_##N: t = (u8 *) str; break;
      foreach_det44_session_state
#undef _
    default:
      t = format (t, "unknown");
    }
  s = format (s, "%s", t);
  return s;
}

u8 *
format_det_map_ses (u8 * s, va_list * args)
{
  snat_det_map_t *det_map = va_arg (*args, snat_det_map_t *);
  ip4_address_t in_addr, out_addr;
  u32 in_offset, out_offset;
  snat_det_session_t *ses = va_arg (*args, snat_det_session_t *);
  u32 *i = va_arg (*args, u32 *);

  u32 user_index = *i / DET44_SES_PER_USER;
  in_addr.as_u32 =
    clib_host_to_net_u32 (clib_net_to_host_u32 (det_map->in_addr.as_u32) +
			  user_index);
  in_offset =
    clib_net_to_host_u32 (in_addr.as_u32) -
    clib_net_to_host_u32 (det_map->in_addr.as_u32);
  out_offset = in_offset / det_map->sharing_ratio;
  out_addr.as_u32 =
    clib_host_to_net_u32 (clib_net_to_host_u32 (det_map->out_addr.as_u32) +
			  out_offset);
  s =
    format (s,
	    "in %U:%d out %U:%d external host %U:%d state: %U expire: %d\n",
	    format_ip4_address, &in_addr, clib_net_to_host_u16 (ses->in_port),
	    format_ip4_address, &out_addr,
	    clib_net_to_host_u16 (ses->out.out_port), format_ip4_address,
	    &ses->out.ext_host_addr,
	    clib_net_to_host_u16 (ses->out.ext_host_port),
	    format_det44_session_state, ses->state, ses->expire);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
