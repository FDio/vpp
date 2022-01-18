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

u32
snat_det_close_ses_by_in (snat_det_map_t *dm, ip4_address_t *in_addr,
			  u16 in_port, snat_det_out_key_t out_key)
{
  u32 user_offset, count = 0;
  snat_det_session_t *ses;
  u16 i;

  user_offset =
    snat_det_user_ses_offset (dm->ses_per_user, in_addr, dm->in_plen);
  for (i = 0; i < dm->ses_per_user; i++)
    {
      ses = &dm->sessions[i + user_offset];
      if (ses->in_port == in_port &&
	  ses->out.ext_host_addr.as_u32 == out_key.ext_host_addr.as_u32 &&
	  ses->out.ext_host_port == out_key.ext_host_port)
	{
	  snat_det_ses_close (dm, ses);
	  count++;
	}
    }
  return count;
}

u32
snat_det_close_ses_by_out (snat_det_map_t *dm, ip4_address_t *in_addr,
			   u64 out_key)
{
  u32 user_offset, count = 0;
  snat_det_session_t *ses;
  u16 i;

  user_offset =
    snat_det_user_ses_offset (dm->ses_per_user, in_addr, dm->in_plen);
  for (i = 0; i < dm->ses_per_user; i++)
    {
      ses = &dm->sessions[i + user_offset];
      if (ses->out.as_u64 == out_key)
	{
	  snat_det_ses_close (dm, ses);
	  count++;
	}
    }
  return count;
}

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
snat_det_add_map (ip4_address_t *in_addr, u8 in_plen, ip4_address_t *out_addr,
		  u8 out_plen, u32 ses_per_user, u32 tcp_per_user,
		  u32 udp_per_user, u32 other_per_user, int is_add)
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

      if (~0 == ses_per_user)
	ses_per_user = DET44_SES_PER_USER;

      if (~0 == tcp_per_user)
	tcp_per_user = 0;

      if (~0 == udp_per_user)
	udp_per_user = 0;

      if (~0 == other_per_user)
	other_per_user = 0;

      if ((tcp_per_user + udp_per_user + other_per_user) > ses_per_user)
	{
	  return VNET_API_ERROR_INVALID_VALUE;
	}

      // number of inside addresses
      u32 num_in_addr = 1 << (32 - in_plen);

      // number of outside addresses
      u32 num_out_addr = 1 << (32 - out_plen);

      pool_get (dm->det_maps, mp);
      clib_memset (mp, 0, sizeof (*mp));

      u32 end = ses_per_user;

      mp->tcp_end = end;
      if (tcp_per_user > 0)
	{
	  end = end - tcp_per_user;
	  mp->tcp_start = end;
	}

      mp->udp_end = end;
      if (udp_per_user > 0)
	{
	  end = end - udp_per_user;
	  mp->udp_start = end;
	}

      mp->other_end = end;
      if (other_per_user > 0)
	{
	  end = end - other_per_user;
	  mp->other_start = end;
	}

      if (0 == tcp_per_user)
	mp->tcp_end = end;

      if (0 == udp_per_user)
	mp->udp_end = end;

      mp->ses_per_user = ses_per_user;
      // DET44_SES_PER_USER * (1 << (32 - in_plen)) - 1
      mp->ses_max = ses_per_user * num_in_addr;

      mp->in_addr.as_u32 = in_cmp.as_u32;
      mp->in_plen = in_plen;

      mp->out_addr.as_u32 = out_cmp.as_u32;
      mp->out_plen = out_plen;

      mp->sharing_ratio = num_in_addr / num_out_addr;
      mp->ports_per_host = (65535 - 1023) / mp->sharing_ratio;

      vec_validate_init_empty (mp->sessions, mp->ses_max,
			       empty_snat_det_session);
    }
  else
    {
      vec_free (mp->sessions);
      vec_del1 (dm->det_maps, mp - dm->det_maps);
    }

  /* Add/del external address range to FIB */
  /* *INDENT-OFF* */
  pool_foreach (i, dm->interfaces)  {
    if (det44_interface_is_inside(i))
      continue;
    det44_add_del_addr_to_fib(out_addr, out_plen, i->sw_if_index, is_add);
    goto out;
  }
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
  nat_reset_timeouts (&dm->timeouts);
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
  pool_foreach (tmp, dm->interfaces)  {
    if (tmp->sw_if_index == sw_if_index)
      {
        i = tmp;
        goto out;
      }
  }
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
      pool_foreach (mp, dm->det_maps)  {
        det44_add_del_addr_to_fib(&mp->out_addr,
                                  mp->out_plen, sw_if_index, !is_del);
      }
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

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 10.0);
      vlib_process_get_events (vm, NULL);
      u32 now = (u32) vlib_time_now (vm);

      if (!plugin_enabled ())
	{
	  continue;
	}

      pool_foreach (mp, dm->det_maps)
	{
	  vec_foreach (ses, mp->sessions)
	    {
	      // close expired sessions
	      if (ses->in_port && (ses->expire < now))
		{
		  snat_det_ses_close (mp, ses);
		}
	    }
	}
    }
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

  dm->mss_clamping = 0;
  dm->config = c;
  dm->enabled = 1;

  det44_create_expire_walk_process ();
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

  dm->enabled = 0;

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
  pool_foreach (mp, dm->det_maps)
   {
    vec_free (mp->sessions);
  }
  /* *INDENT-ON* */

  det44_reset_timeouts ();

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
  pool_foreach (i, dm->interfaces)
     {
      if (i->sw_if_index == sw_if_index)
        {
          if (!(det44_interface_is_outside (i)))
	    return;
          match = 1;
        }
    }
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
det44_init (vlib_main_t * vm)
{
  det44_main_t *dm = &det44_main;
  ip4_table_bind_callback_t cb;
  vlib_node_t *node;

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
  return det44_api_hookup (vm);
}

VLIB_INIT_FUNCTION (det44_init);

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
  s = format (
    s,
    "in %U:%d out %U:%d external host %U:%d proto: %U state: %U expire: %d\n",
    format_ip4_address, &in_addr, clib_net_to_host_u16 (ses->in_port),
    format_ip4_address, &out_addr, clib_net_to_host_u16 (ses->out.out_port),
    format_ip4_address, &ses->out.ext_host_addr,
    clib_net_to_host_u16 (ses->out.ext_host_port), format_ip_protocol,
    ses->proto, format_det44_session_state, ses->state, ses->expire);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
