/*
 * snat.c - simple nat plugin
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/plugin/plugin.h>
#include <nat/nat.h>
#include <nat/nat_dpo.h>
#include <nat/nat_ipfix_logging.h>
#include <nat/nat_det.h>
#include <nat/nat64.h>
#include <nat/nat66.h>
#include <nat/dslite.h>
#include <nat/nat_reass.h>
#include <nat/nat_inlines.h>
#include <nat/nat_affinity.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>

#include <vpp/app/version.h>

snat_main_t snat_main;

/* *INDENT-OFF* */

/* Hook up input features */
VNET_FEATURE_INIT (ip4_snat_in2out, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-in2out",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_snat_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-out2in",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_nat_classify, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-classify",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_snat_det_in2out, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-det-in2out",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_snat_det_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-det-out2in",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_nat_det_classify, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-det-classify",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_in2out, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ed-in2out",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ed-out2in",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_classify, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ed-classify",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_snat_in2out_worker_handoff, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-in2out-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_snat_out2in_worker_handoff, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-out2in-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_nat_handoff_classify, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-handoff-classify",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_snat_in2out_fast, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-in2out-fast",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_snat_out2in_fast, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-out2in-fast",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_snat_hairpin_dst, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-hairpin-dst",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_hairpin_dst, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ed-hairpin-dst",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};

/* Hook up output features */
VNET_FEATURE_INIT (ip4_snat_in2out_output, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-in2out-output",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_snat_in2out_output_worker_handoff, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-in2out-output-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_snat_hairpin_src, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-hairpin-src",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_in2out_output, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-ed-in2out-output",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_hairpin_src, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-ed-hairpin-src",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
};

/* Hook up ip4-local features */
VNET_FEATURE_INIT (ip4_nat_hairpinning, static) =
{
  .arc_name = "ip4-local",
  .node_name = "nat44-hairpinning",
  .runs_before = VNET_FEATURES("ip4-local-end-of-arc"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_hairpinning, static) =
{
  .arc_name = "ip4-local",
  .node_name = "nat44-ed-hairpinning",
  .runs_before = VNET_FEATURES("ip4-local-end-of-arc"),
};


VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Network Address Translation",
};
/* *INDENT-ON* */

void
nat_free_session_data (snat_main_t * sm, snat_session_t * s, u32 thread_index)
{
  snat_session_key_t key;
  clib_bihash_kv_8_8_t kv;
  nat_ed_ses_key_t ed_key;
  clib_bihash_kv_16_8_t ed_kv;
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_index);

  if (is_fwd_bypass_session (s))
    {
      ed_key.l_addr = s->in2out.addr;
      ed_key.r_addr = s->ext_host_addr;
      ed_key.l_port = s->in2out.port;
      ed_key.r_port = s->ext_host_port;
      ed_key.proto = snat_proto_to_ip_proto (s->in2out.protocol);
      ed_key.fib_index = 0;
      ed_kv.key[0] = ed_key.as_u64[0];
      ed_kv.key[1] = ed_key.as_u64[1];
      if (clib_bihash_add_del_16_8 (&tsm->in2out_ed, &ed_kv, 0))
	nat_log_warn ("in2out_ed key del failed");
      return;
    }

  /* session lookup tables */
  if (is_ed_session (s))
    {
      if (is_affinity_sessions (s))
	nat_affinity_unlock (s->ext_host_addr, s->out2in.addr,
			     s->in2out.protocol, s->out2in.port);
      ed_key.l_addr = s->out2in.addr;
      ed_key.r_addr = s->ext_host_addr;
      ed_key.fib_index = s->out2in.fib_index;
      if (snat_is_unk_proto_session (s))
	{
	  ed_key.proto = s->in2out.port;
	  ed_key.r_port = 0;
	  ed_key.l_port = 0;
	}
      else
	{
	  ed_key.proto = snat_proto_to_ip_proto (s->in2out.protocol);
	  ed_key.l_port = s->out2in.port;
	  ed_key.r_port = s->ext_host_port;
	}
      ed_kv.key[0] = ed_key.as_u64[0];
      ed_kv.key[1] = ed_key.as_u64[1];
      if (clib_bihash_add_del_16_8 (&tsm->out2in_ed, &ed_kv, 0))
	nat_log_warn ("out2in_ed key del failed");
      ed_key.l_addr = s->in2out.addr;
      ed_key.fib_index = s->in2out.fib_index;
      if (!snat_is_unk_proto_session (s))
	ed_key.l_port = s->in2out.port;
      if (is_twice_nat_session (s))
	{
	  ed_key.r_addr = s->ext_host_nat_addr;
	  ed_key.r_port = s->ext_host_nat_port;
	}
      ed_kv.key[0] = ed_key.as_u64[0];
      ed_kv.key[1] = ed_key.as_u64[1];
      if (clib_bihash_add_del_16_8 (&tsm->in2out_ed, &ed_kv, 0))
	nat_log_warn ("in2out_ed key del failed");
    }
  else
    {
      kv.key = s->in2out.as_u64;
      if (clib_bihash_add_del_8_8 (&tsm->in2out, &kv, 0))
	nat_log_warn ("in2out key del failed");
      kv.key = s->out2in.as_u64;
      if (clib_bihash_add_del_8_8 (&tsm->out2in, &kv, 0))
	nat_log_warn ("out2in key del failed");
    }

  if (snat_is_unk_proto_session (s))
    return;

  /* log NAT event */
  snat_ipfix_logging_nat44_ses_delete (s->in2out.addr.as_u32,
				       s->out2in.addr.as_u32,
				       s->in2out.protocol,
				       s->in2out.port,
				       s->out2in.port, s->in2out.fib_index);

  /* Twice NAT address and port for external host */
  if (is_twice_nat_session (s))
    {
      key.protocol = s->in2out.protocol;
      key.port = s->ext_host_nat_port;
      key.addr.as_u32 = s->ext_host_nat_addr.as_u32;
      snat_free_outside_address_and_port (sm->twice_nat_addresses,
					  thread_index, &key);
    }

  if (snat_is_session_static (s))
    return;

  snat_free_outside_address_and_port (sm->addresses, thread_index,
				      &s->out2in);
}

snat_user_t *
nat_user_get_or_create (snat_main_t * sm, ip4_address_t * addr, u32 fib_index,
			u32 thread_index)
{
  snat_user_t *u = 0;
  snat_user_key_t user_key;
  clib_bihash_kv_8_8_t kv, value;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  dlist_elt_t *per_user_list_head_elt;

  user_key.addr.as_u32 = addr->as_u32;
  user_key.fib_index = fib_index;
  kv.key = user_key.as_u64;

  /* Ever heard of the "user" = src ip4 address before? */
  if (clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
    {
      /* no, make a new one */
      pool_get (tsm->users, u);
      memset (u, 0, sizeof (*u));
      u->addr.as_u32 = addr->as_u32;
      u->fib_index = fib_index;

      pool_get (tsm->list_pool, per_user_list_head_elt);

      u->sessions_per_user_list_head_index = per_user_list_head_elt -
	tsm->list_pool;

      clib_dlist_init (tsm->list_pool, u->sessions_per_user_list_head_index);

      kv.value = u - tsm->users;

      /* add user */
      if (clib_bihash_add_del_8_8 (&tsm->user_hash, &kv, 1))
	nat_log_warn ("user_hash keay add failed");
    }
  else
    {
      u = pool_elt_at_index (tsm->users, value.value);
    }

  return u;
}

snat_session_t *
nat_session_alloc_or_recycle (snat_main_t * sm, snat_user_t * u,
			      u32 thread_index)
{
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  u32 oldest_per_user_translation_list_index, session_index;
  dlist_elt_t *oldest_per_user_translation_list_elt;
  dlist_elt_t *per_user_translation_list_elt;

  /* Over quota? Recycle the least recently used translation */
  if ((u->nsessions + u->nstaticsessions) >= sm->max_translations_per_user)
    {
      oldest_per_user_translation_list_index =
	clib_dlist_remove_head (tsm->list_pool,
				u->sessions_per_user_list_head_index);

      ASSERT (oldest_per_user_translation_list_index != ~0);

      /* Add it back to the end of the LRU list */
      clib_dlist_addtail (tsm->list_pool,
			  u->sessions_per_user_list_head_index,
			  oldest_per_user_translation_list_index);
      /* Get the list element */
      oldest_per_user_translation_list_elt =
	pool_elt_at_index (tsm->list_pool,
			   oldest_per_user_translation_list_index);

      /* Get the session index from the list element */
      session_index = oldest_per_user_translation_list_elt->value;

      /* Get the session */
      s = pool_elt_at_index (tsm->sessions, session_index);
      nat_free_session_data (sm, s, thread_index);
      if (snat_is_session_static (s))
	u->nstaticsessions--;
      else
	u->nsessions--;
      s->flags = 0;
      s->total_bytes = 0;
      s->total_pkts = 0;
      s->state = 0;
      s->ext_host_addr.as_u32 = 0;
      s->ext_host_port = 0;
      s->ext_host_nat_addr.as_u32 = 0;
      s->ext_host_nat_port = 0;
    }
  else
    {
      pool_get (tsm->sessions, s);
      memset (s, 0, sizeof (*s));

      /* Create list elts */
      pool_get (tsm->list_pool, per_user_translation_list_elt);
      clib_dlist_init (tsm->list_pool,
		       per_user_translation_list_elt - tsm->list_pool);

      per_user_translation_list_elt->value = s - tsm->sessions;
      s->per_user_index = per_user_translation_list_elt - tsm->list_pool;
      s->per_user_list_head_index = u->sessions_per_user_list_head_index;

      clib_dlist_addtail (tsm->list_pool,
			  s->per_user_list_head_index,
			  per_user_translation_list_elt - tsm->list_pool);
    }

  return s;
}

snat_session_t *
nat_ed_session_alloc (snat_main_t * sm, snat_user_t * u, u32 thread_index,
		      f64 now)
{
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  dlist_elt_t *per_user_translation_list_elt, *oldest_elt;
  u32 oldest_index;
  u64 sess_timeout_time;

  if ((u->nsessions + u->nstaticsessions) >= sm->max_translations_per_user)
    {
      oldest_index =
	clib_dlist_remove_head (tsm->list_pool,
				u->sessions_per_user_list_head_index);
      oldest_elt = pool_elt_at_index (tsm->list_pool, oldest_index);
      s = pool_elt_at_index (tsm->sessions, oldest_elt->value);
      sess_timeout_time =
	s->last_heard + (f64) nat44_session_get_timeout (sm, s);
      if (now >= sess_timeout_time)
	{
	  clib_dlist_addtail (tsm->list_pool,
			      u->sessions_per_user_list_head_index,
			      oldest_index);
	  nat_free_session_data (sm, s, thread_index);
	  if (snat_is_session_static (s))
	    u->nstaticsessions--;
	  else
	    u->nsessions--;
	  s->flags = 0;
	  s->total_bytes = 0;
	  s->total_pkts = 0;
	  s->state = 0;
	  s->ext_host_addr.as_u32 = 0;
	  s->ext_host_port = 0;
	  s->ext_host_nat_addr.as_u32 = 0;
	  s->ext_host_nat_port = 0;
	}
      else
	{
	  clib_dlist_addhead (tsm->list_pool,
			      u->sessions_per_user_list_head_index,
			      oldest_index);
	  nat_log_warn ("max translations per user %U", format_ip4_address,
			&u->addr);
	  snat_ipfix_logging_max_entries_per_user
	    (sm->max_translations_per_user, u->addr.as_u32);
	  return 0;
	}
    }
  else
    {
      pool_get (tsm->sessions, s);
      memset (s, 0, sizeof (*s));

      /* Create list elts */
      pool_get (tsm->list_pool, per_user_translation_list_elt);
      clib_dlist_init (tsm->list_pool,
		       per_user_translation_list_elt - tsm->list_pool);

      per_user_translation_list_elt->value = s - tsm->sessions;
      s->per_user_index = per_user_translation_list_elt - tsm->list_pool;
      s->per_user_list_head_index = u->sessions_per_user_list_head_index;

      clib_dlist_addtail (tsm->list_pool,
			  s->per_user_list_head_index,
			  per_user_translation_list_elt - tsm->list_pool);
    }
  return s;
}

void
snat_add_del_addr_to_fib (ip4_address_t * addr, u8 p_len, u32 sw_if_index,
			  int is_add)
{
  fib_prefix_t prefix = {
    .fp_len = p_len,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr = {
		.ip4.as_u32 = addr->as_u32,
		},
  };
  u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  if (is_add)
    fib_table_entry_update_one_path (fib_index,
				     &prefix,
				     FIB_SOURCE_PLUGIN_LOW,
				     (FIB_ENTRY_FLAG_CONNECTED |
				      FIB_ENTRY_FLAG_LOCAL |
				      FIB_ENTRY_FLAG_EXCLUSIVE),
				     DPO_PROTO_IP4,
				     NULL,
				     sw_if_index,
				     ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
  else
    fib_table_entry_delete (fib_index, &prefix, FIB_SOURCE_PLUGIN_LOW);
}

int
snat_add_address (snat_main_t * sm, ip4_address_t * addr, u32 vrf_id,
		  u8 twice_nat)
{
  snat_address_t *ap;
  snat_interface_t *i;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  if (twice_nat && !sm->endpoint_dependent)
    return VNET_API_ERROR_FEATURE_DISABLED;

  /* Check if address already exists */
  /* *INDENT-OFF* */
  vec_foreach (ap, twice_nat ? sm->twice_nat_addresses : sm->addresses)
    {
      if (ap->addr.as_u32 == addr->as_u32)
        return VNET_API_ERROR_VALUE_EXIST;
    }
  /* *INDENT-ON* */

  if (twice_nat)
    vec_add2 (sm->twice_nat_addresses, ap, 1);
  else
    vec_add2 (sm->addresses, ap, 1);

  ap->addr = *addr;
  if (vrf_id != ~0)
    ap->fib_index =
      fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id,
					 FIB_SOURCE_PLUGIN_LOW);
  else
    ap->fib_index = ~0;
#define _(N, i, n, s) \
  clib_bitmap_alloc (ap->busy_##n##_port_bitmap, 65535); \
  ap->busy_##n##_ports = 0; \
  ap->busy_##n##_ports_per_thread = 0;\
  vec_validate_init_empty (ap->busy_##n##_ports_per_thread, tm->n_vlib_mains - 1, 0);
  foreach_snat_protocol
#undef _
    if (twice_nat)
    return 0;

  /* Add external address to FIB */
  /* *INDENT-OFF* */
  pool_foreach (i, sm->interfaces,
  ({
    if (nat_interface_is_inside(i) || sm->out2in_dpo)
      continue;

    snat_add_del_addr_to_fib(addr, 32, i->sw_if_index, 1);
    break;
  }));
  pool_foreach (i, sm->output_feature_interfaces,
  ({
    if (nat_interface_is_inside(i) || sm->out2in_dpo)
      continue;

    snat_add_del_addr_to_fib(addr, 32, i->sw_if_index, 1);
    break;
  }));
  /* *INDENT-ON* */

  return 0;
}

static int
is_snat_address_used_in_static_mapping (snat_main_t * sm, ip4_address_t addr)
{
  snat_static_mapping_t *m;
  /* *INDENT-OFF* */
  pool_foreach (m, sm->static_mappings,
  ({
      if (m->external_addr.as_u32 == addr.as_u32)
        return 1;
  }));
  /* *INDENT-ON* */

  return 0;
}

void
increment_v4_address (ip4_address_t * a)
{
  u32 v;

  v = clib_net_to_host_u32 (a->as_u32) + 1;
  a->as_u32 = clib_host_to_net_u32 (v);
}

static void
snat_add_static_mapping_when_resolved (snat_main_t * sm,
				       ip4_address_t l_addr,
				       u16 l_port,
				       u32 sw_if_index,
				       u16 e_port,
				       u32 vrf_id,
				       snat_protocol_t proto,
				       int addr_only, int is_add, u8 * tag,
				       int twice_nat, int out2in_only,
				       int identity_nat)
{
  snat_static_map_resolve_t *rp;

  vec_add2 (sm->to_resolve, rp, 1);
  rp->l_addr.as_u32 = l_addr.as_u32;
  rp->l_port = l_port;
  rp->sw_if_index = sw_if_index;
  rp->e_port = e_port;
  rp->vrf_id = vrf_id;
  rp->proto = proto;
  rp->addr_only = addr_only;
  rp->is_add = is_add;
  rp->twice_nat = twice_nat;
  rp->out2in_only = out2in_only;
  rp->identity_nat = identity_nat;
  rp->tag = vec_dup (tag);
}

static u32
get_thread_idx_by_port (u16 e_port)
{
  snat_main_t *sm = &snat_main;
  u32 thread_idx = sm->num_workers;
  if (sm->num_workers > 1)
    {
      thread_idx =
	sm->first_worker_index +
	sm->workers[(e_port - 1024) / sm->port_per_thread];
    }
  return thread_idx;
}

int
snat_add_static_mapping (ip4_address_t l_addr, ip4_address_t e_addr,
			 u16 l_port, u16 e_port, u32 vrf_id, int addr_only,
			 u32 sw_if_index, snat_protocol_t proto, int is_add,
			 twice_nat_type_t twice_nat, u8 out2in_only, u8 * tag,
			 u8 identity_nat)
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  snat_session_key_t m_key;
  clib_bihash_kv_8_8_t kv, value;
  snat_address_t *a = 0;
  u32 fib_index = ~0;
  snat_interface_t *interface;
  int i;
  snat_main_per_thread_data_t *tsm;
  snat_user_key_t u_key;
  snat_user_t *u;
  dlist_elt_t *head, *elt;
  u32 elt_index, head_index;
  u32 ses_index;
  u64 user_index;
  snat_session_t *s;
  snat_static_map_resolve_t *rp, *rp_match = 0;
  nat44_lb_addr_port_t *local;
  u8 find = 0;

  if (!sm->endpoint_dependent)
    {
      if (twice_nat || out2in_only)
	return VNET_API_ERROR_FEATURE_DISABLED;
    }

  /* If the external address is a specific interface address */
  if (sw_if_index != ~0)
    {
      ip4_address_t *first_int_addr;

      for (i = 0; i < vec_len (sm->to_resolve); i++)
	{
	  rp = sm->to_resolve + i;
	  if (rp->sw_if_index != sw_if_index ||
	      rp->l_addr.as_u32 != l_addr.as_u32 ||
	      rp->vrf_id != vrf_id || rp->addr_only != addr_only)
	    continue;

	  if (!addr_only)
	    {
	      if (rp->l_port != l_port || rp->e_port != e_port
		  || rp->proto != proto)
		continue;
	    }

	  rp_match = rp;
	  break;
	}

      /* Might be already set... */
      first_int_addr = ip4_interface_first_address
	(sm->ip4_main, sw_if_index, 0 /* just want the address */ );

      if (is_add)
	{
	  if (rp_match)
	    return VNET_API_ERROR_VALUE_EXIST;

	  snat_add_static_mapping_when_resolved
	    (sm, l_addr, l_port, sw_if_index, e_port, vrf_id, proto,
	     addr_only, is_add, tag, twice_nat, out2in_only, identity_nat);

	  /* DHCP resolution required? */
	  if (first_int_addr == 0)
	    {
	      return 0;
	    }
	  else
	    {
	      e_addr.as_u32 = first_int_addr->as_u32;
	      /* Identity mapping? */
	      if (l_addr.as_u32 == 0)
		l_addr.as_u32 = e_addr.as_u32;
	    }
	}
      else
	{
	  if (!rp_match)
	    return VNET_API_ERROR_NO_SUCH_ENTRY;

	  vec_del1 (sm->to_resolve, i);

	  if (first_int_addr)
	    {
	      e_addr.as_u32 = first_int_addr->as_u32;
	      /* Identity mapping? */
	      if (l_addr.as_u32 == 0)
		l_addr.as_u32 = e_addr.as_u32;
	    }
	  else
	    return 0;
	}
    }

  m_key.addr = e_addr;
  m_key.port = addr_only ? 0 : e_port;
  m_key.protocol = addr_only ? 0 : proto;
  m_key.fib_index = 0;
  kv.key = m_key.as_u64;
  if (clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
    m = 0;
  else
    m = pool_elt_at_index (sm->static_mappings, value.value);

  if (is_add)
    {
      if (m)
	{
	  if (is_identity_static_mapping (m))
	    {
              /* *INDENT-OFF* */
              vec_foreach (local, m->locals)
                {
                  if (local->vrf_id == vrf_id)
                    return VNET_API_ERROR_VALUE_EXIST;
                }
              /* *INDENT-ON* */
	      vec_add2 (m->locals, local, 1);
	      local->vrf_id = vrf_id;
	      local->fib_index =
		fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id,
						   FIB_SOURCE_PLUGIN_LOW);
	      m_key.addr = m->local_addr;
	      m_key.port = m->local_port;
	      m_key.protocol = m->proto;
	      m_key.fib_index = local->fib_index;
	      kv.key = m_key.as_u64;
	      kv.value = m - sm->static_mappings;
	      clib_bihash_add_del_8_8 (&sm->static_mapping_by_local, &kv, 1);
	      return 0;
	    }
	  else
	    return VNET_API_ERROR_VALUE_EXIST;
	}

      if (twice_nat && addr_only)
	return VNET_API_ERROR_UNSUPPORTED;

      /* Convert VRF id to FIB index */
      if (vrf_id != ~0)
	fib_index =
	  fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id,
					     FIB_SOURCE_PLUGIN_LOW);
      /* If not specified use inside VRF id from SNAT plugin startup config */
      else
	{
	  fib_index = sm->inside_fib_index;
	  vrf_id = sm->inside_vrf_id;
	}

      if (!(out2in_only || identity_nat))
	{
	  m_key.addr = l_addr;
	  m_key.port = addr_only ? 0 : l_port;
	  m_key.protocol = addr_only ? 0 : proto;
	  m_key.fib_index = fib_index;
	  kv.key = m_key.as_u64;
	  if (!clib_bihash_search_8_8
	      (&sm->static_mapping_by_local, &kv, &value))
	    return VNET_API_ERROR_VALUE_EXIST;
	}

      /* Find external address in allocated addresses and reserve port for
         address and port pair mapping when dynamic translations enabled */
      if (!(addr_only || sm->static_mapping_only || out2in_only))
	{
	  for (i = 0; i < vec_len (sm->addresses); i++)
	    {
	      if (sm->addresses[i].addr.as_u32 == e_addr.as_u32)
		{
		  a = sm->addresses + i;
		  /* External port must be unused */
		  switch (proto)
		    {
#define _(N, j, n, s) \
                    case SNAT_PROTOCOL_##N: \
                      if (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, e_port)) \
                        return VNET_API_ERROR_INVALID_VALUE; \
                      clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, e_port, 1); \
                      if (e_port > 1024) \
                        { \
                          a->busy_##n##_ports++; \
                          a->busy_##n##_ports_per_thread[get_thread_idx_by_port(e_port)]++; \
                        } \
                      break;
		      foreach_snat_protocol
#undef _
		    default:
		      nat_log_info ("unknown protocol");
		      return VNET_API_ERROR_INVALID_VALUE_2;
		    }
		  break;
		}
	    }
	  /* External address must be allocated */
	  if (!a && (l_addr.as_u32 != e_addr.as_u32))
	    {
	      if (sw_if_index != ~0)
		{
		  for (i = 0; i < vec_len (sm->to_resolve); i++)
		    {
		      rp = sm->to_resolve + i;
		      if (rp->addr_only)
			continue;
		      if (rp->sw_if_index != sw_if_index &&
			  rp->l_addr.as_u32 != l_addr.as_u32 &&
			  rp->vrf_id != vrf_id && rp->l_port != l_port &&
			  rp->e_port != e_port && rp->proto != proto)
			continue;

		      vec_del1 (sm->to_resolve, i);
		      break;
		    }
		}
	      return VNET_API_ERROR_NO_SUCH_ENTRY;
	    }
	}

      pool_get (sm->static_mappings, m);
      memset (m, 0, sizeof (*m));
      m->tag = vec_dup (tag);
      m->local_addr = l_addr;
      m->external_addr = e_addr;
      m->twice_nat = twice_nat;
      if (out2in_only)
	m->flags |= NAT_STATIC_MAPPING_FLAG_OUT2IN_ONLY;
      if (addr_only)
	m->flags |= NAT_STATIC_MAPPING_FLAG_ADDR_ONLY;
      if (identity_nat)
	{
	  m->flags |= NAT_STATIC_MAPPING_FLAG_IDENTITY_NAT;
	  vec_add2 (m->locals, local, 1);
	  local->vrf_id = vrf_id;
	  local->fib_index = fib_index;
	}
      else
	{
	  m->vrf_id = vrf_id;
	  m->fib_index = fib_index;
	}
      if (!addr_only)
	{
	  m->local_port = l_port;
	  m->external_port = e_port;
	  m->proto = proto;
	}

      if (sm->num_workers > 1)
	{
	  ip4_header_t ip = {
	    .src_address = m->local_addr,
	  };
	  vec_add1 (m->workers, sm->worker_in2out_cb (&ip, m->fib_index));
	  tsm = vec_elt_at_index (sm->per_thread_data, m->workers[0]);
	}
      else
	tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

      m_key.addr = m->local_addr;
      m_key.port = m->local_port;
      m_key.protocol = m->proto;
      m_key.fib_index = fib_index;
      kv.key = m_key.as_u64;
      kv.value = m - sm->static_mappings;
      if (!out2in_only)
	clib_bihash_add_del_8_8 (&sm->static_mapping_by_local, &kv, 1);

      m_key.addr = m->external_addr;
      m_key.port = m->external_port;
      m_key.fib_index = 0;
      kv.key = m_key.as_u64;
      kv.value = m - sm->static_mappings;
      clib_bihash_add_del_8_8 (&sm->static_mapping_by_external, &kv, 1);

      /* Delete dynamic sessions matching local address (+ local port) */
      if (!(sm->static_mapping_only))
	{
	  u_key.addr = m->local_addr;
	  u_key.fib_index = m->fib_index;
	  kv.key = u_key.as_u64;
	  if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
	    {
	      user_index = value.value;
	      u = pool_elt_at_index (tsm->users, user_index);
	      if (u->nsessions)
		{
		  head_index = u->sessions_per_user_list_head_index;
		  head = pool_elt_at_index (tsm->list_pool, head_index);
		  elt_index = head->next;
		  elt = pool_elt_at_index (tsm->list_pool, elt_index);
		  ses_index = elt->value;
		  while (ses_index != ~0)
		    {
		      s = pool_elt_at_index (tsm->sessions, ses_index);
		      elt = pool_elt_at_index (tsm->list_pool, elt->next);
		      ses_index = elt->value;

		      if (snat_is_session_static (s))
			continue;

		      if (!addr_only
			  && (clib_net_to_host_u16 (s->in2out.port) !=
			      m->local_port))
			continue;

		      nat_free_session_data (sm, s,
					     tsm - sm->per_thread_data);
		      nat44_delete_session (sm, s, tsm - sm->per_thread_data);

		      if (!addr_only && !sm->endpoint_dependent)
			break;
		    }
		}
	    }
	}
    }
  else
    {
      if (!m)
	{
	  if (sw_if_index != ~0)
	    return 0;
	  else
	    return VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      if (identity_nat)
	{
	  for (i = 0; i < vec_len (m->locals); i++)
	    {
	      if (m->locals[i].vrf_id == vrf_id)
		{
		  find = 1;
		  break;
		}
	    }
	  if (!find)
	    return VNET_API_ERROR_NO_SUCH_ENTRY;

	  fib_index = m->locals[i].fib_index;
	  vec_del1 (m->locals, i);
	}
      else
	fib_index = m->fib_index;

      /* Free external address port */
      if (!(addr_only || sm->static_mapping_only || out2in_only))
	{
	  for (i = 0; i < vec_len (sm->addresses); i++)
	    {
	      if (sm->addresses[i].addr.as_u32 == e_addr.as_u32)
		{
		  a = sm->addresses + i;
		  switch (proto)
		    {
#define _(N, j, n, s) \
                    case SNAT_PROTOCOL_##N: \
                      clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, e_port, 0); \
                      if (e_port > 1024) \
                        { \
                          a->busy_##n##_ports--; \
                          a->busy_##n##_ports_per_thread[get_thread_idx_by_port(e_port)]--; \
                        } \
                      break;
		      foreach_snat_protocol
#undef _
		    default:
		      nat_log_info ("unknown protocol");
		      return VNET_API_ERROR_INVALID_VALUE_2;
		    }
		  break;
		}
	    }
	}

      if (sm->num_workers > 1)
	tsm = vec_elt_at_index (sm->per_thread_data, m->workers[0]);
      else
	tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

      m_key.addr = m->local_addr;
      m_key.port = m->local_port;
      m_key.protocol = m->proto;
      m_key.fib_index = fib_index;
      kv.key = m_key.as_u64;
      if (!out2in_only)
	clib_bihash_add_del_8_8 (&sm->static_mapping_by_local, &kv, 0);

      /* Delete session(s) for static mapping if exist */
      if (!(sm->static_mapping_only) ||
	  (sm->static_mapping_only && sm->static_mapping_connection_tracking))
	{
	  u_key.addr = m->local_addr;
	  u_key.fib_index = fib_index;
	  kv.key = u_key.as_u64;
	  if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
	    {
	      user_index = value.value;
	      u = pool_elt_at_index (tsm->users, user_index);
	      if (u->nstaticsessions)
		{
		  head_index = u->sessions_per_user_list_head_index;
		  head = pool_elt_at_index (tsm->list_pool, head_index);
		  elt_index = head->next;
		  elt = pool_elt_at_index (tsm->list_pool, elt_index);
		  ses_index = elt->value;
		  while (ses_index != ~0)
		    {
		      s = pool_elt_at_index (tsm->sessions, ses_index);
		      elt = pool_elt_at_index (tsm->list_pool, elt->next);
		      ses_index = elt->value;

		      if (!addr_only)
			{
			  if ((s->out2in.addr.as_u32 != e_addr.as_u32) ||
			      (clib_net_to_host_u16 (s->out2in.port) !=
			       e_port))
			    continue;
			}

		      if (is_lb_session (s))
			continue;

		      if (!snat_is_session_static (s))
			continue;

		      nat_free_session_data (sm, s,
					     tsm - sm->per_thread_data);
		      nat44_delete_session (sm, s, tsm - sm->per_thread_data);

		      if (!addr_only && !sm->endpoint_dependent)
			break;
		    }
		}
	    }
	}

      fib_table_unlock (fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_PLUGIN_LOW);
      if (vec_len (m->locals))
	return 0;

      m_key.addr = m->external_addr;
      m_key.port = m->external_port;
      m_key.fib_index = 0;
      kv.key = m_key.as_u64;
      clib_bihash_add_del_8_8 (&sm->static_mapping_by_external, &kv, 0);

      vec_free (m->tag);
      vec_free (m->workers);
      /* Delete static mapping from pool */
      pool_put (sm->static_mappings, m);
    }

  if (!addr_only || (l_addr.as_u32 == e_addr.as_u32))
    return 0;

  /* Add/delete external address to FIB */
  /* *INDENT-OFF* */
  pool_foreach (interface, sm->interfaces,
  ({
    if (nat_interface_is_inside(interface) || sm->out2in_dpo)
      continue;

    snat_add_del_addr_to_fib(&e_addr, 32, interface->sw_if_index, is_add);
    break;
  }));
  pool_foreach (interface, sm->output_feature_interfaces,
  ({
    if (nat_interface_is_inside(interface) || sm->out2in_dpo)
      continue;

    snat_add_del_addr_to_fib(&e_addr, 32, interface->sw_if_index, is_add);
    break;
  }));
  /* *INDENT-ON* */

  return 0;
}

int
nat44_add_del_lb_static_mapping (ip4_address_t e_addr, u16 e_port,
				 snat_protocol_t proto,
				 nat44_lb_addr_port_t * locals, u8 is_add,
				 twice_nat_type_t twice_nat, u8 out2in_only,
				 u8 * tag, u32 affinity)
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  snat_session_key_t m_key;
  clib_bihash_kv_8_8_t kv, value;
  snat_address_t *a = 0;
  int i;
  nat44_lb_addr_port_t *local;
  u32 elt_index, head_index, ses_index;
  snat_main_per_thread_data_t *tsm;
  snat_user_key_t u_key;
  snat_user_t *u;
  snat_session_t *s;
  dlist_elt_t *head, *elt;
  uword *bitmap = 0;

  if (!sm->endpoint_dependent)
    return VNET_API_ERROR_FEATURE_DISABLED;

  m_key.addr = e_addr;
  m_key.port = e_port;
  m_key.protocol = proto;
  m_key.fib_index = 0;
  kv.key = m_key.as_u64;
  if (clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
    m = 0;
  else
    m = pool_elt_at_index (sm->static_mappings, value.value);

  if (is_add)
    {
      if (m)
	return VNET_API_ERROR_VALUE_EXIST;

      if (vec_len (locals) < 2)
	return VNET_API_ERROR_INVALID_VALUE;

      /* Find external address in allocated addresses and reserve port for
         address and port pair mapping when dynamic translations enabled */
      if (!(sm->static_mapping_only || out2in_only))
	{
	  for (i = 0; i < vec_len (sm->addresses); i++)
	    {
	      if (sm->addresses[i].addr.as_u32 == e_addr.as_u32)
		{
		  a = sm->addresses + i;
		  /* External port must be unused */
		  switch (proto)
		    {
#define _(N, j, n, s) \
                    case SNAT_PROTOCOL_##N: \
                      if (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, e_port)) \
                        return VNET_API_ERROR_INVALID_VALUE; \
                      clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, e_port, 1); \
                      if (e_port > 1024) \
                        { \
                          a->busy_##n##_ports++; \
                          a->busy_##n##_ports_per_thread[get_thread_idx_by_port(e_port)]++; \
                        } \
                      break;
		      foreach_snat_protocol
#undef _
		    default:
		      nat_log_info ("unknown protocol");
		      return VNET_API_ERROR_INVALID_VALUE_2;
		    }
		  break;
		}
	    }
	  /* External address must be allocated */
	  if (!a)
	    return VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      pool_get (sm->static_mappings, m);
      memset (m, 0, sizeof (*m));
      m->tag = vec_dup (tag);
      m->external_addr = e_addr;
      m->external_port = e_port;
      m->proto = proto;
      m->twice_nat = twice_nat;
      m->flags |= NAT_STATIC_MAPPING_FLAG_LB;
      if (out2in_only)
	m->flags |= NAT_STATIC_MAPPING_FLAG_OUT2IN_ONLY;
      m->affinity = affinity;

      if (affinity)
	m->affinity_per_service_list_head_index =
	  nat_affinity_get_per_service_list_head_index ();
      else
	m->affinity_per_service_list_head_index = ~0;

      m_key.addr = m->external_addr;
      m_key.port = m->external_port;
      m_key.protocol = m->proto;
      m_key.fib_index = 0;
      kv.key = m_key.as_u64;
      kv.value = m - sm->static_mappings;
      if (clib_bihash_add_del_8_8 (&sm->static_mapping_by_external, &kv, 1))
	{
	  nat_log_err ("static_mapping_by_external key add failed");
	  return VNET_API_ERROR_UNSPECIFIED;
	}

      m_key.fib_index = m->fib_index;
      for (i = 0; i < vec_len (locals); i++)
	{
	  locals[i].fib_index =
	    fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
					       locals[i].vrf_id,
					       FIB_SOURCE_PLUGIN_LOW);
	  m_key.addr = locals[i].addr;
	  m_key.fib_index = locals[i].fib_index;
	  if (!out2in_only)
	    {
	      m_key.port = locals[i].port;
	      kv.key = m_key.as_u64;
	      kv.value = m - sm->static_mappings;
	      clib_bihash_add_del_8_8 (&sm->static_mapping_by_local, &kv, 1);
	    }
	  locals[i].prefix = (i == 0) ? locals[i].probability :
	    (locals[i - 1].prefix + locals[i].probability);
	  vec_add1 (m->locals, locals[i]);
	  if (sm->num_workers > 1)
	    {
	      ip4_header_t ip = {
		.src_address = locals[i].addr,
	      };
	      bitmap =
		clib_bitmap_set (bitmap,
				 sm->worker_in2out_cb (&ip, m->fib_index), 1);
	    }
	}

      /* Assign workers */
      if (sm->num_workers > 1)
	{
          /* *INDENT-OFF* */
          clib_bitmap_foreach (i, bitmap,
            ({
               vec_add1(m->workers, i);
            }));
          /* *INDENT-ON* */
	}
    }
  else
    {
      if (!m)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if (!is_lb_static_mapping (m))
	return VNET_API_ERROR_INVALID_VALUE;

      /* Free external address port */
      if (!(sm->static_mapping_only || out2in_only))
	{
	  for (i = 0; i < vec_len (sm->addresses); i++)
	    {
	      if (sm->addresses[i].addr.as_u32 == e_addr.as_u32)
		{
		  a = sm->addresses + i;
		  switch (proto)
		    {
#define _(N, j, n, s) \
                    case SNAT_PROTOCOL_##N: \
                      clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, e_port, 0); \
                      if (e_port > 1024) \
                        { \
                          a->busy_##n##_ports--; \
                          a->busy_##n##_ports_per_thread[get_thread_idx_by_port(e_port)]--; \
                        } \
                      break;
		      foreach_snat_protocol
#undef _
		    default:
		      nat_log_info ("unknown protocol");
		      return VNET_API_ERROR_INVALID_VALUE_2;
		    }
		  break;
		}
	    }
	}

      m_key.addr = m->external_addr;
      m_key.port = m->external_port;
      m_key.protocol = m->proto;
      m_key.fib_index = 0;
      kv.key = m_key.as_u64;
      if (clib_bihash_add_del_8_8 (&sm->static_mapping_by_external, &kv, 0))
	{
	  nat_log_err ("static_mapping_by_external key del failed");
	  return VNET_API_ERROR_UNSPECIFIED;
	}

      /* *INDENT-OFF* */
      vec_foreach (local, m->locals)
        {
          fib_table_unlock (local->fib_index, FIB_PROTOCOL_IP4,
                            FIB_SOURCE_PLUGIN_LOW);
          m_key.addr = local->addr;
          if (!out2in_only)
            {
              m_key.port = local->port;
              m_key.fib_index = local->fib_index;
              kv.key = m_key.as_u64;
              if (clib_bihash_add_del_8_8(&sm->static_mapping_by_local, &kv, 0))
                {
                  nat_log_err ("static_mapping_by_local key del failed");
                  return VNET_API_ERROR_UNSPECIFIED;
                }
            }

          if (sm->num_workers > 1)
            {
              ip4_header_t ip = {
                .src_address = local->addr,
              };
              tsm = vec_elt_at_index (sm->per_thread_data,
                                      sm->worker_in2out_cb (&ip, m->fib_index));
            }
          else
            tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

          /* Delete sessions */
          u_key.addr = local->addr;
          u_key.fib_index = m->fib_index;
          kv.key = u_key.as_u64;
          if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
            {
              u = pool_elt_at_index (tsm->users, value.value);
              if (u->nstaticsessions)
                {
                  head_index = u->sessions_per_user_list_head_index;
                  head = pool_elt_at_index (tsm->list_pool, head_index);
                  elt_index = head->next;
                  elt = pool_elt_at_index (tsm->list_pool, elt_index);
                  ses_index = elt->value;
                  while (ses_index != ~0)
                    {
                      s =  pool_elt_at_index (tsm->sessions, ses_index);
                      elt = pool_elt_at_index (tsm->list_pool, elt->next);
                      ses_index = elt->value;

                      if (!(is_lb_session (s)))
                        continue;

                      if ((s->in2out.addr.as_u32 != local->addr.as_u32) ||
                          (clib_net_to_host_u16 (s->in2out.port) != local->port))
                        continue;

                      nat_free_session_data (sm, s, tsm - sm->per_thread_data);
                      nat44_delete_session (sm, s, tsm - sm->per_thread_data);
                    }
                }
            }
        }
      /* *INDENT-ON* */
      if (m->affinity)
	nat_affinity_flush_service (m->affinity_per_service_list_head_index);
      vec_free (m->locals);
      vec_free (m->tag);
      vec_free (m->workers);

      pool_put (sm->static_mappings, m);
    }

  return 0;
}

int
snat_del_address (snat_main_t * sm, ip4_address_t addr, u8 delete_sm,
		  u8 twice_nat)
{
  snat_address_t *a = 0;
  snat_session_t *ses;
  u32 *ses_to_be_removed = 0, *ses_index;
  snat_main_per_thread_data_t *tsm;
  snat_static_mapping_t *m;
  snat_interface_t *interface;
  int i;
  snat_address_t *addresses =
    twice_nat ? sm->twice_nat_addresses : sm->addresses;

  /* Find SNAT address */
  for (i = 0; i < vec_len (addresses); i++)
    {
      if (addresses[i].addr.as_u32 == addr.as_u32)
	{
	  a = addresses + i;
	  break;
	}
    }
  if (!a)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (delete_sm)
    {
      /* *INDENT-OFF* */
      pool_foreach (m, sm->static_mappings,
      ({
          if (m->external_addr.as_u32 == addr.as_u32)
            (void) snat_add_static_mapping (m->local_addr, m->external_addr,
                                            m->local_port, m->external_port,
                                            m->vrf_id, is_addr_only_static_mapping(m), ~0,
                                            m->proto, 0, m->twice_nat,
                                            is_out2in_only_static_mapping(m), m->tag, is_identity_static_mapping(m));
      }));
      /* *INDENT-ON* */
    }
  else
    {
      /* Check if address is used in some static mapping */
      if (is_snat_address_used_in_static_mapping (sm, addr))
	{
	  nat_log_notice ("address used in static mapping");
	  return VNET_API_ERROR_UNSPECIFIED;
	}
    }

  if (a->fib_index != ~0)
    fib_table_unlock (a->fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_PLUGIN_LOW);

  /* Delete sessions using address */
  if (a->busy_tcp_ports || a->busy_udp_ports || a->busy_icmp_ports)
    {
      /* *INDENT-OFF* */
      vec_foreach (tsm, sm->per_thread_data)
        {
          pool_foreach (ses, tsm->sessions, ({
            if (ses->out2in.addr.as_u32 == addr.as_u32)
              {
                nat_free_session_data (sm, ses, tsm - sm->per_thread_data);
                vec_add1 (ses_to_be_removed, ses - tsm->sessions);
              }
          }));

          vec_foreach (ses_index, ses_to_be_removed)
            {
              ses = pool_elt_at_index (tsm->sessions, ses_index[0]);
              nat44_delete_session (sm, ses, tsm - sm->per_thread_data);
            }

          vec_free (ses_to_be_removed);
        }
      /* *INDENT-ON* */
    }

#define _(N, i, n, s) \
  clib_bitmap_free (a->busy_##n##_port_bitmap); \
  vec_free (a->busy_##n##_ports_per_thread);
  foreach_snat_protocol
#undef _
    if (twice_nat)
    {
      vec_del1 (sm->twice_nat_addresses, i);
      return 0;
    }
  else
    vec_del1 (sm->addresses, i);

  /* Delete external address from FIB */
  /* *INDENT-OFF* */
  pool_foreach (interface, sm->interfaces,
  ({
    if (nat_interface_is_inside(interface) || sm->out2in_dpo)
      continue;

    snat_add_del_addr_to_fib(&addr, 32, interface->sw_if_index, 0);
    break;
  }));
  pool_foreach (interface, sm->output_feature_interfaces,
  ({
    if (nat_interface_is_inside(interface) || sm->out2in_dpo)
      continue;

    snat_add_del_addr_to_fib(&addr, 32, interface->sw_if_index, 0);
    break;
  }));
  /* *INDENT-ON* */

  return 0;
}

int
snat_interface_add_del (u32 sw_if_index, u8 is_inside, int is_del)
{
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;
  const char *feature_name, *del_feature_name;
  snat_address_t *ap;
  snat_static_mapping_t *m;
  snat_det_map_t *dm;
  nat_outside_fib_t *outside_fib;
  u32 fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						       sw_if_index);

  if (sm->out2in_dpo && !is_inside)
    return VNET_API_ERROR_UNSUPPORTED;

  /* *INDENT-OFF* */
  pool_foreach (i, sm->output_feature_interfaces,
  ({
    if (i->sw_if_index == sw_if_index)
      return VNET_API_ERROR_VALUE_EXIST;
  }));
  /* *INDENT-ON* */

  if (sm->static_mapping_only && !(sm->static_mapping_connection_tracking))
    feature_name = is_inside ? "nat44-in2out-fast" : "nat44-out2in-fast";
  else
    {
      if (sm->num_workers > 1 && !sm->deterministic)
	feature_name =
	  is_inside ? "nat44-in2out-worker-handoff" :
	  "nat44-out2in-worker-handoff";
      else if (sm->deterministic)
	feature_name = is_inside ? "nat44-det-in2out" : "nat44-det-out2in";
      else if (sm->endpoint_dependent)
	feature_name = is_inside ? "nat44-ed-in2out" : "nat44-ed-out2in";
      else
	feature_name = is_inside ? "nat44-in2out" : "nat44-out2in";
    }

  if (sm->fq_in2out_index == ~0 && !sm->deterministic && sm->num_workers > 1)
    sm->fq_in2out_index = vlib_frame_queue_main_init (sm->in2out_node_index,
						      NAT_FQ_NELTS);

  if (sm->fq_out2in_index == ~0 && !sm->deterministic && sm->num_workers > 1)
    sm->fq_out2in_index = vlib_frame_queue_main_init (sm->out2in_node_index,
						      NAT_FQ_NELTS);

  if (!is_inside)
    {
      /* *INDENT-OFF* */
      vec_foreach (outside_fib, sm->outside_fibs)
        {
          if (outside_fib->fib_index == fib_index)
            {
              if (is_del)
                {
                  outside_fib->refcount--;
                  if (!outside_fib->refcount)
                    vec_del1 (sm->outside_fibs, outside_fib - sm->outside_fibs);
                }
              else
                outside_fib->refcount++;
              goto feature_set;
            }
        }
      /* *INDENT-ON* */
      if (!is_del)
	{
	  vec_add2 (sm->outside_fibs, outside_fib, 1);
	  outside_fib->refcount = 1;
	  outside_fib->fib_index = fib_index;
	}
    }
feature_set:
  /* *INDENT-OFF* */
  pool_foreach (i, sm->interfaces,
  ({
    if (i->sw_if_index == sw_if_index)
      {
        if (is_del)
          {
            if (nat_interface_is_inside(i) && nat_interface_is_outside(i))
              {
                if (is_inside)
                  i->flags &= ~NAT_INTERFACE_FLAG_IS_INSIDE;
                else
                  i->flags &= ~NAT_INTERFACE_FLAG_IS_OUTSIDE;

                if (sm->num_workers > 1 && !sm->deterministic)
                  {
                    del_feature_name = "nat44-handoff-classify";
                    feature_name = !is_inside ?  "nat44-in2out-worker-handoff" :
                                                 "nat44-out2in-worker-handoff";
                  }
                else if (sm->deterministic)
                  {
                    del_feature_name = "nat44-det-classify";
                    feature_name = !is_inside ?  "nat44-det-in2out" :
                                                 "nat44-det-out2in";
                  }
                else if (sm->endpoint_dependent)
                  {
                    del_feature_name = "nat44-ed-classify";
                    feature_name = !is_inside ?  "nat44-ed-in2out" :
                                                 "nat44-ed-out2in";
                  }
                else
                  {
                    del_feature_name = "nat44-classify";
                    feature_name = !is_inside ?  "nat44-in2out" : "nat44-out2in";
                  }

                vnet_feature_enable_disable ("ip4-unicast", del_feature_name,
                                             sw_if_index, 0, 0, 0);
                vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                             sw_if_index, 1, 0, 0);
                if (!is_inside)
                  {
                    if (sm->endpoint_dependent)
                      vnet_feature_enable_disable ("ip4-local",
                                                   "nat44-ed-hairpinning",
                                                   sw_if_index, 1, 0, 0);
                    else if (!sm->deterministic)
                      vnet_feature_enable_disable ("ip4-local",
                                                   "nat44-hairpinning",
                                                   sw_if_index, 1, 0, 0);
                  }
              }
            else
              {
                vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                             sw_if_index, 0, 0, 0);
                pool_put (sm->interfaces, i);
                if (is_inside)
                  {
                    if (sm->endpoint_dependent)
                      vnet_feature_enable_disable ("ip4-local",
                                                   "nat44-ed-hairpinning",
                                                   sw_if_index, 0, 0, 0);
                    else if (!sm->deterministic)
                      vnet_feature_enable_disable ("ip4-local",
                                                   "nat44-hairpinning",
                                                   sw_if_index, 0, 0, 0);
                  }
              }
          }
        else
          {
            if ((nat_interface_is_inside(i) && is_inside) ||
                (nat_interface_is_outside(i) && !is_inside))
              return 0;

            if (sm->num_workers > 1 && !sm->deterministic)
              {
                del_feature_name = !is_inside ?  "nat44-in2out-worker-handoff" :
                                                 "nat44-out2in-worker-handoff";
                feature_name = "nat44-handoff-classify";
              }
            else if (sm->deterministic)
              {
                del_feature_name = !is_inside ?  "nat44-det-in2out" :
                                                 "nat44-det-out2in";
                feature_name = "nat44-det-classify";
              }
            else if (sm->endpoint_dependent)
              {
                del_feature_name = !is_inside ?  "nat44-ed-in2out" :
                                                 "nat44-ed-out2in";
                feature_name = "nat44-ed-classify";
              }
            else
              {
                del_feature_name = !is_inside ?  "nat44-in2out" : "nat44-out2in";
                feature_name = "nat44-classify";
              }

            vnet_feature_enable_disable ("ip4-unicast", del_feature_name,
                                         sw_if_index, 0, 0, 0);
            vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                         sw_if_index, 1, 0, 0);
            if (!is_inside)
              {
                if (sm->endpoint_dependent)
                  vnet_feature_enable_disable ("ip4-local", "nat44-ed-hairpinning",
                                               sw_if_index, 0, 0, 0);
                else if (!sm->deterministic)
                  vnet_feature_enable_disable ("ip4-local", "nat44-hairpinning",
                                               sw_if_index, 0, 0, 0);
              }
            goto set_flags;
          }

        goto fib;
      }
  }));
  /* *INDENT-ON* */

  if (is_del)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pool_get (sm->interfaces, i);
  i->sw_if_index = sw_if_index;
  i->flags = 0;
  vnet_feature_enable_disable ("ip4-unicast", feature_name, sw_if_index, 1, 0,
			       0);

  if (is_inside && !sm->out2in_dpo)
    {
      if (sm->endpoint_dependent)
	vnet_feature_enable_disable ("ip4-local", "nat44-ed-hairpinning",
				     sw_if_index, 1, 0, 0);
      else if (!sm->deterministic)
	vnet_feature_enable_disable ("ip4-local", "nat44-hairpinning",
				     sw_if_index, 1, 0, 0);
    }

set_flags:
  if (is_inside)
    {
      i->flags |= NAT_INTERFACE_FLAG_IS_INSIDE;
      return 0;
    }
  else
    i->flags |= NAT_INTERFACE_FLAG_IS_OUTSIDE;

  /* Add/delete external addresses to FIB */
fib:
  /* *INDENT-OFF* */
  vec_foreach (ap, sm->addresses)
    snat_add_del_addr_to_fib(&ap->addr, 32, sw_if_index, !is_del);

  pool_foreach (m, sm->static_mappings,
  ({
    if (!(is_addr_only_static_mapping(m)) || (m->local_addr.as_u32 == m->external_addr.as_u32))
      continue;

    snat_add_del_addr_to_fib(&m->external_addr, 32, sw_if_index, !is_del);
  }));

  pool_foreach (dm, sm->det_maps,
  ({
    snat_add_del_addr_to_fib(&dm->out_addr, dm->out_plen, sw_if_index, !is_del);
  }));
  /* *INDENT-ON* */

  return 0;
}

int
snat_interface_add_del_output_feature (u32 sw_if_index,
				       u8 is_inside, int is_del)
{
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;
  snat_address_t *ap;
  snat_static_mapping_t *m;

  if (sm->deterministic ||
      (sm->static_mapping_only && !(sm->static_mapping_connection_tracking)))
    return VNET_API_ERROR_UNSUPPORTED;

  /* *INDENT-OFF* */
  pool_foreach (i, sm->interfaces,
  ({
    if (i->sw_if_index == sw_if_index)
      return VNET_API_ERROR_VALUE_EXIST;
  }));
  /* *INDENT-ON* */

  if (is_inside)
    {
      if (sm->endpoint_dependent)
	{
	  vnet_feature_enable_disable ("ip4-unicast", "nat44-ed-hairpin-dst",
				       sw_if_index, !is_del, 0, 0);
	  vnet_feature_enable_disable ("ip4-output", "nat44-ed-hairpin-src",
				       sw_if_index, !is_del, 0, 0);
	}
      else
	{
	  vnet_feature_enable_disable ("ip4-unicast", "nat44-hairpin-dst",
				       sw_if_index, !is_del, 0, 0);
	  vnet_feature_enable_disable ("ip4-output", "nat44-hairpin-src",
				       sw_if_index, !is_del, 0, 0);
	}
      goto fq;
    }

  if (sm->num_workers > 1)
    {
      vnet_feature_enable_disable ("ip4-unicast",
				   "nat44-out2in-worker-handoff",
				   sw_if_index, !is_del, 0, 0);
      vnet_feature_enable_disable ("ip4-output",
				   "nat44-in2out-output-worker-handoff",
				   sw_if_index, !is_del, 0, 0);
    }
  else
    {
      if (sm->endpoint_dependent)
	{
	  vnet_feature_enable_disable ("ip4-unicast", "nat44-ed-out2in",
				       sw_if_index, !is_del, 0, 0);
	  vnet_feature_enable_disable ("ip4-output", "nat44-ed-in2out-output",
				       sw_if_index, !is_del, 0, 0);
	}
      else
	{
	  vnet_feature_enable_disable ("ip4-unicast", "nat44-out2in",
				       sw_if_index, !is_del, 0, 0);
	  vnet_feature_enable_disable ("ip4-output", "nat44-in2out-output",
				       sw_if_index, !is_del, 0, 0);
	}
    }

fq:
  if (sm->fq_in2out_output_index == ~0 && sm->num_workers > 1)
    sm->fq_in2out_output_index =
      vlib_frame_queue_main_init (sm->in2out_output_node_index, 0);

  if (sm->fq_out2in_index == ~0 && sm->num_workers > 1)
    sm->fq_out2in_index =
      vlib_frame_queue_main_init (sm->out2in_node_index, 0);

  /* *INDENT-OFF* */
  pool_foreach (i, sm->output_feature_interfaces,
  ({
    if (i->sw_if_index == sw_if_index)
      {
        if (is_del)
          pool_put (sm->output_feature_interfaces, i);
        else
          return VNET_API_ERROR_VALUE_EXIST;

        goto fib;
      }
  }));
  /* *INDENT-ON* */

  if (is_del)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pool_get (sm->output_feature_interfaces, i);
  i->sw_if_index = sw_if_index;
  i->flags = 0;
  if (is_inside)
    i->flags |= NAT_INTERFACE_FLAG_IS_INSIDE;
  else
    i->flags |= NAT_INTERFACE_FLAG_IS_OUTSIDE;

  /* Add/delete external addresses to FIB */
fib:
  if (is_inside)
    return 0;

  /* *INDENT-OFF* */
  vec_foreach (ap, sm->addresses)
    snat_add_del_addr_to_fib(&ap->addr, 32, sw_if_index, !is_del);

  pool_foreach (m, sm->static_mappings,
  ({
    if (!((is_addr_only_static_mapping(m)))  || (m->local_addr.as_u32 == m->external_addr.as_u32))
      continue;

    snat_add_del_addr_to_fib(&m->external_addr, 32, sw_if_index, !is_del);
  }));
  /* *INDENT-ON* */

  return 0;
}

int
snat_set_workers (uword * bitmap)
{
  snat_main_t *sm = &snat_main;
  int i, j = 0;

  if (sm->num_workers < 2)
    return VNET_API_ERROR_FEATURE_DISABLED;

  if (clib_bitmap_last_set (bitmap) >= sm->num_workers)
    return VNET_API_ERROR_INVALID_WORKER;

  vec_free (sm->workers);
  /* *INDENT-OFF* */
  clib_bitmap_foreach (i, bitmap,
    ({
      vec_add1(sm->workers, i);
      sm->per_thread_data[sm->first_worker_index + i].snat_thread_index = j;
      j++;
    }));
  /* *INDENT-ON* */

  sm->port_per_thread = (0xffff - 1024) / _vec_len (sm->workers);
  sm->num_snat_thread = _vec_len (sm->workers);

  return 0;
}


static void
snat_ip4_add_del_interface_address_cb (ip4_main_t * im,
				       uword opaque,
				       u32 sw_if_index,
				       ip4_address_t * address,
				       u32 address_length,
				       u32 if_address_index, u32 is_delete);

static void
nat_ip4_add_del_addr_only_sm_cb (ip4_main_t * im,
				 uword opaque,
				 u32 sw_if_index,
				 ip4_address_t * address,
				 u32 address_length,
				 u32 if_address_index, u32 is_delete);

static int
nat_alloc_addr_and_port_default (snat_address_t * addresses,
				 u32 fib_index,
				 u32 thread_index,
				 snat_session_key_t * k,
				 u16 port_per_thread, u32 snat_thread_index);

static clib_error_t *
snat_init (vlib_main_t * vm)
{
  snat_main_t *sm = &snat_main;
  clib_error_t *error = 0;
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  uword *p;
  vlib_thread_registration_t *tr;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  uword *bitmap = 0;
  u32 i;
  ip4_add_del_interface_address_callback_t cb4;
  vlib_node_t *error_drop_node;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();
  sm->ip4_main = im;
  sm->ip4_lookup_main = lm;
  sm->api_main = &api_main;
  sm->first_worker_index = 0;
  sm->num_workers = 0;
  sm->num_snat_thread = 1;
  sm->workers = 0;
  sm->port_per_thread = 0xffff - 1024;
  sm->fq_in2out_index = ~0;
  sm->fq_out2in_index = ~0;
  sm->udp_timeout = SNAT_UDP_TIMEOUT;
  sm->tcp_established_timeout = SNAT_TCP_ESTABLISHED_TIMEOUT;
  sm->tcp_transitory_timeout = SNAT_TCP_TRANSITORY_TIMEOUT;
  sm->icmp_timeout = SNAT_ICMP_TIMEOUT;
  sm->alloc_addr_and_port = nat_alloc_addr_and_port_default;
  sm->addr_and_port_alloc_alg = NAT_ADDR_AND_PORT_ALLOC_ALG_DEFAULT;
  sm->forwarding_enabled = 0;
  sm->log_class = vlib_log_register_class ("nat", 0);
  error_drop_node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  sm->error_node_index = error_drop_node->index;
  sm->mss_clamping = 0;

  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  if (p)
    {
      tr = (vlib_thread_registration_t *) p[0];
      if (tr)
	{
	  sm->num_workers = tr->count;
	  sm->first_worker_index = tr->first_index;
	}
    }

  vec_validate (sm->per_thread_data, tm->n_vlib_mains - 1);

  /* Use all available workers by default */
  if (sm->num_workers > 1)
    {
      for (i = 0; i < sm->num_workers; i++)
	bitmap = clib_bitmap_set (bitmap, i, 1);
      snat_set_workers (bitmap);
      clib_bitmap_free (bitmap);
    }
  else
    {
      sm->per_thread_data[0].snat_thread_index = 0;
    }

  error = snat_api_init (vm, sm);
  if (error)
    return error;

  /* Set up the interface address add/del callback */
  cb4.function = snat_ip4_add_del_interface_address_cb;
  cb4.function_opaque = 0;

  vec_add1 (im->add_del_interface_address_callbacks, cb4);

  cb4.function = nat_ip4_add_del_addr_only_sm_cb;
  cb4.function_opaque = 0;

  vec_add1 (im->add_del_interface_address_callbacks, cb4);

  nat_dpo_module_init ();

  /* Init IPFIX logging */
  snat_ipfix_logging_init (vm);

  /* Init NAT64 */
  error = nat64_init (vm);
  if (error)
    return error;

  dslite_init (vm);

  nat66_init ();

  /* Init virtual fragmenentation reassembly */
  return nat_reass_init (vm);
}

VLIB_INIT_FUNCTION (snat_init);

void
snat_free_outside_address_and_port (snat_address_t * addresses,
				    u32 thread_index, snat_session_key_t * k)
{
  snat_address_t *a;
  u32 address_index;
  u16 port_host_byte_order = clib_net_to_host_u16 (k->port);

  for (address_index = 0; address_index < vec_len (addresses);
       address_index++)
    {
      if (addresses[address_index].addr.as_u32 == k->addr.as_u32)
	break;
    }

  ASSERT (address_index < vec_len (addresses));

  a = addresses + address_index;

  switch (k->protocol)
    {
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
      ASSERT (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, \
        port_host_byte_order) == 1); \
      clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, \
        port_host_byte_order, 0); \
      a->busy_##n##_ports--; \
      a->busy_##n##_ports_per_thread[thread_index]--; \
      break;
      foreach_snat_protocol
#undef _
    default:
      nat_log_info ("unknown protocol");
      return;
    }
}

int
snat_static_mapping_match (snat_main_t * sm,
			   snat_session_key_t match,
			   snat_session_key_t * mapping,
			   u8 by_external,
			   u8 * is_addr_only,
			   twice_nat_type_t * twice_nat,
			   lb_nat_type_t * lb, ip4_address_t * ext_host_addr,
			   u8 * is_identity_nat)
{
  clib_bihash_kv_8_8_t kv, value;
  snat_static_mapping_t *m;
  snat_session_key_t m_key;
  clib_bihash_8_8_t *mapping_hash = &sm->static_mapping_by_local;
  u32 rand, lo = 0, hi, mid;
  u8 backend_index;

  m_key.fib_index = match.fib_index;
  if (by_external)
    {
      mapping_hash = &sm->static_mapping_by_external;
      m_key.fib_index = 0;
    }

  m_key.addr = match.addr;
  m_key.port = clib_net_to_host_u16 (match.port);
  m_key.protocol = match.protocol;

  kv.key = m_key.as_u64;

  if (clib_bihash_search_8_8 (mapping_hash, &kv, &value))
    {
      /* Try address only mapping */
      m_key.port = 0;
      m_key.protocol = 0;
      kv.key = m_key.as_u64;
      if (clib_bihash_search_8_8 (mapping_hash, &kv, &value))
	return 1;
    }

  m = pool_elt_at_index (sm->static_mappings, value.value);

  if (by_external)
    {
      if (is_lb_static_mapping (m))
	{
	  if (PREDICT_FALSE (lb != 0))
	    *lb = m->affinity ? AFFINITY_LB_NAT : LB_NAT;
	  if (m->affinity)
	    {
	      if (nat_affinity_find_and_lock (ext_host_addr[0], match.addr,
					      match.protocol, match.port,
					      &backend_index))
		goto get_local;

	      mapping->addr = m->locals[backend_index].addr;
	      mapping->port =
		clib_host_to_net_u16 (m->locals[backend_index].port);
	      mapping->fib_index = m->locals[backend_index].fib_index;
	      goto end;
	    }
	get_local:
	  hi = vec_len (m->locals) - 1;
	  rand = 1 + (random_u32 (&sm->random_seed) % m->locals[hi].prefix);
	  while (lo < hi)
	    {
	      mid = ((hi - lo) >> 1) + lo;
	      (rand > m->locals[mid].prefix) ? (lo = mid + 1) : (hi = mid);
	    }
	  if (!(m->locals[lo].prefix >= rand))
	    return 1;
	  if (PREDICT_FALSE (sm->num_workers > 1))
	    {
	      ip4_header_t ip = {
		.src_address = m->locals[lo].addr,
	      };
	      if (sm->worker_in2out_cb (&ip, m->fib_index) !=
		  vlib_get_thread_index ())
		goto get_local;
	    }
	  mapping->addr = m->locals[lo].addr;
	  mapping->port = clib_host_to_net_u16 (m->locals[lo].port);
	  mapping->fib_index = m->locals[lo].fib_index;
	  if (m->affinity)
	    {
	      if (nat_affinity_create_and_lock (ext_host_addr[0], match.addr,
						match.protocol, match.port,
						lo, m->affinity,
						m->affinity_per_service_list_head_index))
		nat_log_info ("create affinity record failed");
	    }
	}
      else
	{
	  if (PREDICT_FALSE (lb != 0))
	    *lb = NO_LB_NAT;
	  mapping->fib_index = m->fib_index;
	  mapping->addr = m->local_addr;
	  /* Address only mapping doesn't change port */
	  mapping->port = is_addr_only_static_mapping (m) ? match.port
	    : clib_host_to_net_u16 (m->local_port);
	}
      mapping->protocol = m->proto;
    }
  else
    {
      mapping->addr = m->external_addr;
      /* Address only mapping doesn't change port */
      mapping->port = is_addr_only_static_mapping (m) ? match.port
	: clib_host_to_net_u16 (m->external_port);
      mapping->fib_index = sm->outside_fib_index;
    }

end:
  if (PREDICT_FALSE (is_addr_only != 0))
    *is_addr_only = is_addr_only_static_mapping (m);

  if (PREDICT_FALSE (twice_nat != 0))
    *twice_nat = m->twice_nat;

  if (PREDICT_FALSE (is_identity_nat != 0))
    *is_identity_nat = is_identity_static_mapping (m);

  return 0;
}

static_always_inline u16
snat_random_port (u16 min, u16 max)
{
  snat_main_t *sm = &snat_main;
  return min + random_u32 (&sm->random_seed) /
    (random_u32_max () / (max - min + 1) + 1);
}

int
snat_alloc_outside_address_and_port (snat_address_t * addresses,
				     u32 fib_index,
				     u32 thread_index,
				     snat_session_key_t * k,
				     u16 port_per_thread,
				     u32 snat_thread_index)
{
  snat_main_t *sm = &snat_main;

  return sm->alloc_addr_and_port (addresses, fib_index, thread_index, k,
				  port_per_thread, snat_thread_index);
}

static int
nat_alloc_addr_and_port_default (snat_address_t * addresses,
				 u32 fib_index,
				 u32 thread_index,
				 snat_session_key_t * k,
				 u16 port_per_thread, u32 snat_thread_index)
{
  int i;
  snat_address_t *a, *ga = 0;
  u32 portnum;

  for (i = 0; i < vec_len (addresses); i++)
    {
      a = addresses + i;
      switch (k->protocol)
	{
#define _(N, j, n, s) \
        case SNAT_PROTOCOL_##N: \
          if (a->busy_##n##_ports_per_thread[thread_index] < port_per_thread) \
            { \
              if (a->fib_index == fib_index) \
                { \
                  while (1) \
                    { \
                      portnum = (port_per_thread * \
                        snat_thread_index) + \
                        snat_random_port(1, port_per_thread) + 1024; \
                      if (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, portnum)) \
                        continue; \
                      clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, portnum, 1); \
                      a->busy_##n##_ports_per_thread[thread_index]++; \
                      a->busy_##n##_ports++; \
                      k->addr = a->addr; \
                      k->port = clib_host_to_net_u16(portnum); \
                      return 0; \
                    } \
                } \
              else if (a->fib_index == ~0) \
                { \
                  ga = a; \
                } \
            } \
          break;
	  foreach_snat_protocol
#undef _
	default:
	  nat_log_info ("unknown protocol");
	  return 1;
	}

    }

  if (ga)
    {
      a = ga;
      switch (k->protocol)
	{
#define _(N, j, n, s) \
        case SNAT_PROTOCOL_##N: \
          while (1) \
            { \
              portnum = (port_per_thread * \
                snat_thread_index) + \
                snat_random_port(1, port_per_thread) + 1024; \
              if (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, portnum)) \
                continue; \
              clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, portnum, 1); \
              a->busy_##n##_ports_per_thread[thread_index]++; \
              a->busy_##n##_ports++; \
              k->addr = a->addr; \
              k->port = clib_host_to_net_u16(portnum); \
              return 0; \
            }
	  break;
	  foreach_snat_protocol
#undef _
	default:
	  nat_log_info ("unknown protocol");
	  return 1;
	}
    }

  /* Totally out of translations to use... */
  snat_ipfix_logging_addresses_exhausted (0);
  return 1;
}

static int
nat_alloc_addr_and_port_mape (snat_address_t * addresses,
			      u32 fib_index,
			      u32 thread_index,
			      snat_session_key_t * k,
			      u16 port_per_thread, u32 snat_thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_address_t *a = addresses;
  u16 m, ports, portnum, A, j;
  m = 16 - (sm->psid_offset + sm->psid_length);
  ports = (1 << (16 - sm->psid_length)) - (1 << m);

  if (!vec_len (addresses))
    goto exhausted;

  switch (k->protocol)
    {
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
      if (a->busy_##n##_ports < ports) \
        { \
          while (1) \
            { \
              A = snat_random_port(1, pow2_mask(sm->psid_offset)); \
              j = snat_random_port(0, pow2_mask(m)); \
              portnum = A | (sm->psid << sm->psid_offset) | (j << (16 - m)); \
              if (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, portnum)) \
                continue; \
              clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, portnum, 1); \
              a->busy_##n##_ports++; \
              k->addr = a->addr; \
              k->port = clib_host_to_net_u16 (portnum); \
              return 0; \
            } \
        } \
      break;
      foreach_snat_protocol
#undef _
    default:
      nat_log_info ("unknown protocol");
      return 1;
    }

exhausted:
  /* Totally out of translations to use... */
  snat_ipfix_logging_addresses_exhausted (0);
  return 1;
}

static int
nat_alloc_addr_and_port_range (snat_address_t * addresses,
			       u32 fib_index,
			       u32 thread_index,
			       snat_session_key_t * k,
			       u16 port_per_thread, u32 snat_thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_address_t *a = addresses;
  u16 portnum, ports;

  ports = sm->end_port - sm->start_port + 1;

  if (!vec_len (addresses))
    goto exhausted;

  switch (k->protocol)
    {
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
      if (a->busy_##n##_ports < ports) \
        { \
          while (1) \
            { \
              portnum = snat_random_port(sm->start_port, sm->end_port); \
              if (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, portnum)) \
                continue; \
              clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, portnum, 1); \
              a->busy_##n##_ports++; \
              k->addr = a->addr; \
              k->port = clib_host_to_net_u16 (portnum); \
              return 0; \
            } \
        } \
      break;
      foreach_snat_protocol
#undef _
    default:
      nat_log_info ("unknown protocol");
      return 1;
    }

exhausted:
  /* Totally out of translations to use... */
  snat_ipfix_logging_addresses_exhausted (0);
  return 1;
}

void
nat44_add_del_address_dpo (ip4_address_t addr, u8 is_add)
{
  dpo_id_t dpo_v4 = DPO_INVALID;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr.ip4.as_u32 = addr.as_u32,
  };

  if (is_add)
    {
      nat_dpo_create (DPO_PROTO_IP4, 0, &dpo_v4);
      fib_table_entry_special_dpo_add (0, &pfx, FIB_SOURCE_PLUGIN_HI,
				       FIB_ENTRY_FLAG_EXCLUSIVE, &dpo_v4);
      dpo_reset (&dpo_v4);
    }
  else
    {
      fib_table_entry_special_remove (0, &pfx, FIB_SOURCE_PLUGIN_HI);
    }
}

u8 *
format_session_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);
  snat_session_key_t k;

  k.as_u64 = v->key;

  s = format (s, "%U session-index %llu", format_snat_key, &k, v->value);

  return s;
}

u8 *
format_static_mapping_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);
  snat_session_key_t k;

  k.as_u64 = v->key;

  s = format (s, "%U static-mapping-index %llu",
	      format_static_mapping_key, &k, v->value);

  return s;
}

u8 *
format_user_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);
  snat_user_key_t k;

  k.as_u64 = v->key;

  s = format (s, "%U fib %d user-index %llu", format_ip4_address, &k.addr,
	      k.fib_index, v->value);

  return s;
}

u8 *
format_ed_session_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_16_8_t *v = va_arg (*args, clib_bihash_kv_16_8_t *);
  nat_ed_ses_key_t k;

  k.as_u64[0] = v->key[0];
  k.as_u64[1] = v->key[1];

  s =
    format (s, "local %U:%d remote %U:%d proto %U fib %d session-index %llu",
	    format_ip4_address, &k.l_addr, clib_net_to_host_u16 (k.l_port),
	    format_ip4_address, &k.r_addr, clib_net_to_host_u16 (k.r_port),
	    format_ip_protocol, k.proto, k.fib_index, v->value);

  return s;
}

static u32
snat_get_worker_in2out_cb (ip4_header_t * ip0, u32 rx_fib_index0)
{
  snat_main_t *sm = &snat_main;
  u32 next_worker_index = 0;
  u32 hash;

  next_worker_index = sm->first_worker_index;
  hash = ip0->src_address.as_u32 + (ip0->src_address.as_u32 >> 8) +
    (ip0->src_address.as_u32 >> 16) + (ip0->src_address.as_u32 >> 24);

  if (PREDICT_TRUE (is_pow2 (_vec_len (sm->workers))))
    next_worker_index += sm->workers[hash & (_vec_len (sm->workers) - 1)];
  else
    next_worker_index += sm->workers[hash % _vec_len (sm->workers)];

  return next_worker_index;
}

static u32
snat_get_worker_out2in_cb (ip4_header_t * ip0, u32 rx_fib_index0)
{
  snat_main_t *sm = &snat_main;
  udp_header_t *udp;
  u16 port;
  snat_session_key_t m_key;
  clib_bihash_kv_8_8_t kv, value;
  snat_static_mapping_t *m;
  u32 proto;
  u32 next_worker_index = 0;

  /* first try static mappings without port */
  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
    {
      m_key.addr = ip0->dst_address;
      m_key.port = 0;
      m_key.protocol = 0;
      m_key.fib_index = rx_fib_index0;
      kv.key = m_key.as_u64;
      if (!clib_bihash_search_8_8
	  (&sm->static_mapping_by_external, &kv, &value))
	{
	  m = pool_elt_at_index (sm->static_mappings, value.value);
	  return m->workers[0];
	}
    }

  proto = ip_proto_to_snat_proto (ip0->protocol);
  udp = ip4_next_header (ip0);
  port = udp->dst_port;

  if (PREDICT_FALSE (ip4_is_fragment (ip0)))
    {
      if (PREDICT_FALSE (nat_reass_is_drop_frag (0)))
	return vlib_get_thread_index ();

      if (PREDICT_TRUE (!ip4_is_first_fragment (ip0)))
	{
	  nat_reass_ip4_t *reass;

	  reass = nat_ip4_reass_find (ip0->src_address, ip0->dst_address,
				      ip0->fragment_id, ip0->protocol);

	  if (reass && (reass->thread_index != (u32) ~ 0))
	    return reass->thread_index;
	  else
	    return vlib_get_thread_index ();
	}
    }

  /* unknown protocol */
  if (PREDICT_FALSE (proto == ~0))
    {
      /* use current thread */
      return vlib_get_thread_index ();
    }

  if (PREDICT_FALSE (ip0->protocol == IP_PROTOCOL_ICMP))
    {
      icmp46_header_t *icmp = (icmp46_header_t *) udp;
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      if (!icmp_is_error_message (icmp))
	port = echo->identifier;
      else
	{
	  ip4_header_t *inner_ip = (ip4_header_t *) (echo + 1);
	  proto = ip_proto_to_snat_proto (inner_ip->protocol);
	  void *l4_header = ip4_next_header (inner_ip);
	  switch (proto)
	    {
	    case SNAT_PROTOCOL_ICMP:
	      icmp = (icmp46_header_t *) l4_header;
	      echo = (icmp_echo_header_t *) (icmp + 1);
	      port = echo->identifier;
	      break;
	    case SNAT_PROTOCOL_UDP:
	    case SNAT_PROTOCOL_TCP:
	      port = ((tcp_udp_header_t *) l4_header)->src_port;
	      break;
	    default:
	      return vlib_get_thread_index ();
	    }
	}
    }

  /* try static mappings with port */
  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
    {
      m_key.addr = ip0->dst_address;
      m_key.port = clib_net_to_host_u16 (port);
      m_key.protocol = proto;
      m_key.fib_index = rx_fib_index0;
      kv.key = m_key.as_u64;
      if (!clib_bihash_search_8_8
	  (&sm->static_mapping_by_external, &kv, &value))
	{
	  m = pool_elt_at_index (sm->static_mappings, value.value);
	  return m->workers[0];
	}
    }

  /* worker by outside port */
  next_worker_index = sm->first_worker_index;
  next_worker_index +=
    sm->workers[(clib_net_to_host_u16 (port) - 1024) / sm->port_per_thread];
  return next_worker_index;
}

static u32
nat44_ed_get_worker_out2in_cb (ip4_header_t * ip, u32 rx_fib_index)
{
  snat_main_t *sm = &snat_main;
  clib_bihash_kv_8_8_t kv, value;
  u32 proto, next_worker_index = 0;
  udp_header_t *udp;
  u16 port;
  snat_static_mapping_t *m;
  u32 hash;

  /* first try static mappings without port */
  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
    {
      make_sm_kv (&kv, &ip->dst_address, 0, rx_fib_index, 0);
      if (!clib_bihash_search_8_8
	  (&sm->static_mapping_by_external, &kv, &value))
	{
	  m = pool_elt_at_index (sm->static_mappings, value.value);
	  return m->workers[0];
	}
    }

  proto = ip_proto_to_snat_proto (ip->protocol);

  /* unknown protocol */
  if (PREDICT_FALSE (proto == ~0))
    {
      /* use current thread */
      return vlib_get_thread_index ();
    }

  udp = ip4_next_header (ip);
  port = udp->dst_port;

  if (PREDICT_FALSE (ip->protocol == IP_PROTOCOL_ICMP))
    {
      icmp46_header_t *icmp = (icmp46_header_t *) udp;
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      if (!icmp_is_error_message (icmp))
	port = echo->identifier;
      else
	{
	  ip4_header_t *inner_ip = (ip4_header_t *) (echo + 1);
	  proto = ip_proto_to_snat_proto (inner_ip->protocol);
	  void *l4_header = ip4_next_header (inner_ip);
	  switch (proto)
	    {
	    case SNAT_PROTOCOL_ICMP:
	      icmp = (icmp46_header_t *) l4_header;
	      echo = (icmp_echo_header_t *) (icmp + 1);
	      port = echo->identifier;
	      break;
	    case SNAT_PROTOCOL_UDP:
	    case SNAT_PROTOCOL_TCP:
	      port = ((tcp_udp_header_t *) l4_header)->src_port;
	      break;
	    default:
	      return vlib_get_thread_index ();
	    }
	}
    }

  /* try static mappings with port */
  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
    {
      make_sm_kv (&kv, &ip->dst_address, proto, rx_fib_index,
		  clib_net_to_host_u16 (port));
      if (!clib_bihash_search_8_8
	  (&sm->static_mapping_by_external, &kv, &value))
	{
	  m = pool_elt_at_index (sm->static_mappings, value.value);
	  if (!is_lb_static_mapping (m))
	    return m->workers[0];

	  hash = ip->src_address.as_u32 + (ip->src_address.as_u32 >> 8) +
	    (ip->src_address.as_u32 >> 16) + (ip->src_address.as_u32 >> 24);

	  if (PREDICT_TRUE (is_pow2 (_vec_len (m->workers))))
	    return m->workers[hash & (_vec_len (m->workers) - 1)];
	  else
	    return m->workers[hash % _vec_len (m->workers)];
	}
    }

  /* worker by outside port */
  next_worker_index = sm->first_worker_index;
  next_worker_index +=
    sm->workers[(clib_net_to_host_u16 (port) - 1024) / sm->port_per_thread];

  return next_worker_index;
}

static clib_error_t *
snat_config (vlib_main_t * vm, unformat_input_t * input)
{
  snat_main_t *sm = &snat_main;
  nat66_main_t *nm = &nat66_main;
  u32 translation_buckets = 1024;
  u32 translation_memory_size = 128 << 20;
  u32 user_buckets = 128;
  u32 user_memory_size = 64 << 20;
  u32 max_translations_per_user = 100;
  u32 outside_vrf_id = 0;
  u32 outside_ip6_vrf_id = 0;
  u32 inside_vrf_id = 0;
  u32 static_mapping_buckets = 1024;
  u32 static_mapping_memory_size = 64 << 20;
  u32 nat64_bib_buckets = 1024;
  u32 nat64_bib_memory_size = 128 << 20;
  u32 nat64_st_buckets = 2048;
  u32 nat64_st_memory_size = 256 << 20;
  u8 static_mapping_only = 0;
  u8 static_mapping_connection_tracking = 0;
  snat_main_per_thread_data_t *tsm;
  dslite_main_t *dm = &dslite_main;

  sm->deterministic = 0;
  sm->out2in_dpo = 0;
  sm->endpoint_dependent = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "translation hash buckets %d", &translation_buckets))
	;
      else if (unformat (input, "translation hash memory %d",
			 &translation_memory_size));
      else if (unformat (input, "user hash buckets %d", &user_buckets))
	;
      else if (unformat (input, "user hash memory %d", &user_memory_size))
	;
      else if (unformat (input, "max translations per user %d",
			 &max_translations_per_user))
	;
      else if (unformat (input, "outside VRF id %d", &outside_vrf_id))
	;
      else if (unformat (input, "outside ip6 VRF id %d", &outside_ip6_vrf_id))
	;
      else if (unformat (input, "inside VRF id %d", &inside_vrf_id))
	;
      else if (unformat (input, "static mapping only"))
	{
	  static_mapping_only = 1;
	  if (unformat (input, "connection tracking"))
	    static_mapping_connection_tracking = 1;
	}
      else if (unformat (input, "deterministic"))
	sm->deterministic = 1;
      else if (unformat (input, "nat64 bib hash buckets %d",
			 &nat64_bib_buckets))
	;
      else if (unformat (input, "nat64 bib hash memory %d",
			 &nat64_bib_memory_size))
	;
      else
	if (unformat (input, "nat64 st hash buckets %d", &nat64_st_buckets))
	;
      else if (unformat (input, "nat64 st hash memory %d",
			 &nat64_st_memory_size))
	;
      else if (unformat (input, "out2in dpo"))
	sm->out2in_dpo = 1;
      else if (unformat (input, "dslite ce"))
	dslite_set_ce (dm, 1);
      else if (unformat (input, "endpoint-dependent"))
	sm->endpoint_dependent = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (sm->deterministic && sm->endpoint_dependent)
    return clib_error_return (0,
			      "deterministic and endpoint-dependent modes are mutually exclusive");

  if (static_mapping_only && (sm->deterministic || sm->endpoint_dependent))
    return clib_error_return (0,
			      "static mapping only mode available only for simple nat");

  if (sm->out2in_dpo && (sm->deterministic || sm->endpoint_dependent))
    return clib_error_return (0,
			      "out2in dpo mode available only for simple nat");

  /* for show commands, etc. */
  sm->translation_buckets = translation_buckets;
  sm->translation_memory_size = translation_memory_size;
  /* do not exceed load factor 10 */
  sm->max_translations = 10 * translation_buckets;
  sm->user_buckets = user_buckets;
  sm->user_memory_size = user_memory_size;
  sm->max_translations_per_user = max_translations_per_user;
  sm->outside_vrf_id = outside_vrf_id;
  sm->outside_fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
							     outside_vrf_id,
							     FIB_SOURCE_PLUGIN_HI);
  nm->outside_vrf_id = outside_ip6_vrf_id;
  nm->outside_fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6,
							     outside_ip6_vrf_id,
							     FIB_SOURCE_PLUGIN_HI);
  sm->inside_vrf_id = inside_vrf_id;
  sm->inside_fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
							    inside_vrf_id,
							    FIB_SOURCE_PLUGIN_HI);
  sm->static_mapping_only = static_mapping_only;
  sm->static_mapping_connection_tracking = static_mapping_connection_tracking;

  nat64_set_hash (nat64_bib_buckets, nat64_bib_memory_size, nat64_st_buckets,
		  nat64_st_memory_size);

  if (sm->deterministic)
    {
      sm->in2out_node_index = snat_det_in2out_node.index;
      sm->in2out_output_node_index = ~0;
      sm->out2in_node_index = snat_det_out2in_node.index;
      sm->icmp_match_in2out_cb = icmp_match_in2out_det;
      sm->icmp_match_out2in_cb = icmp_match_out2in_det;
    }
  else
    {
      if (sm->endpoint_dependent)
	{
	  sm->worker_in2out_cb = snat_get_worker_in2out_cb;
	  sm->worker_out2in_cb = nat44_ed_get_worker_out2in_cb;
	  sm->in2out_node_index = nat44_ed_in2out_node.index;
	  sm->in2out_output_node_index = nat44_ed_in2out_output_node.index;
	  sm->out2in_node_index = nat44_ed_out2in_node.index;
	  sm->icmp_match_in2out_cb = icmp_match_in2out_ed;
	  sm->icmp_match_out2in_cb = icmp_match_out2in_ed;
	  nat_affinity_init (vm);
	}
      else
	{
	  sm->worker_in2out_cb = snat_get_worker_in2out_cb;
	  sm->worker_out2in_cb = snat_get_worker_out2in_cb;
	  sm->in2out_node_index = snat_in2out_node.index;
	  sm->in2out_output_node_index = snat_in2out_output_node.index;
	  sm->out2in_node_index = snat_out2in_node.index;
	  sm->icmp_match_in2out_cb = icmp_match_in2out_slow;
	  sm->icmp_match_out2in_cb = icmp_match_out2in_slow;
	}
      if (!static_mapping_only ||
	  (static_mapping_only && static_mapping_connection_tracking))
	{
          /* *INDENT-OFF* */
          vec_foreach (tsm, sm->per_thread_data)
            {
              if (sm->endpoint_dependent)
                {
                  clib_bihash_init_16_8 (&tsm->in2out_ed, "in2out-ed",
                                         translation_buckets,
                                         translation_memory_size);
                  clib_bihash_set_kvp_format_fn_16_8 (&tsm->in2out_ed,
                                                      format_ed_session_kvp);

                  clib_bihash_init_16_8 (&tsm->out2in_ed, "out2in-ed",
                                         translation_buckets,
                                         translation_memory_size);
                  clib_bihash_set_kvp_format_fn_16_8 (&tsm->out2in_ed,
                                                      format_ed_session_kvp);
                }
              else
                {
                  clib_bihash_init_8_8 (&tsm->in2out, "in2out",
                                        translation_buckets,
                                        translation_memory_size);
                  clib_bihash_set_kvp_format_fn_8_8 (&tsm->in2out,
                                                     format_session_kvp);

                  clib_bihash_init_8_8 (&tsm->out2in, "out2in",
                                        translation_buckets,
                                        translation_memory_size);
                  clib_bihash_set_kvp_format_fn_8_8 (&tsm->out2in,
                                                     format_session_kvp);
                }

              clib_bihash_init_8_8 (&tsm->user_hash, "users", user_buckets,
                                    user_memory_size);
              clib_bihash_set_kvp_format_fn_8_8 (&tsm->user_hash,
                                                 format_user_kvp);
            }
          /* *INDENT-ON* */

	}
      else
	{
	  sm->icmp_match_in2out_cb = icmp_match_in2out_fast;
	  sm->icmp_match_out2in_cb = icmp_match_out2in_fast;
	}
      clib_bihash_init_8_8 (&sm->static_mapping_by_local,
			    "static_mapping_by_local", static_mapping_buckets,
			    static_mapping_memory_size);
      clib_bihash_set_kvp_format_fn_8_8 (&sm->static_mapping_by_local,
					 format_static_mapping_kvp);

      clib_bihash_init_8_8 (&sm->static_mapping_by_external,
			    "static_mapping_by_external",
			    static_mapping_buckets,
			    static_mapping_memory_size);
      clib_bihash_set_kvp_format_fn_8_8 (&sm->static_mapping_by_external,
					 format_static_mapping_kvp);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (snat_config, "nat");

static void
nat_ip4_add_del_addr_only_sm_cb (ip4_main_t * im,
				 uword opaque,
				 u32 sw_if_index,
				 ip4_address_t * address,
				 u32 address_length,
				 u32 if_address_index, u32 is_delete)
{
  snat_main_t *sm = &snat_main;
  snat_static_map_resolve_t *rp;
  snat_static_mapping_t *m;
  snat_session_key_t m_key;
  clib_bihash_kv_8_8_t kv, value;
  int i, rv;
  ip4_address_t l_addr;

  for (i = 0; i < vec_len (sm->to_resolve); i++)
    {
      rp = sm->to_resolve + i;
      if (rp->addr_only == 0)
	continue;
      if (rp->sw_if_index == sw_if_index)
	goto match;
    }

  return;

match:
  m_key.addr.as_u32 = address->as_u32;
  m_key.port = rp->addr_only ? 0 : rp->e_port;
  m_key.protocol = rp->addr_only ? 0 : rp->proto;
  m_key.fib_index = sm->outside_fib_index;
  kv.key = m_key.as_u64;
  if (clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
    m = 0;
  else
    m = pool_elt_at_index (sm->static_mappings, value.value);

  if (!is_delete)
    {
      /* Don't trip over lease renewal, static config */
      if (m)
	return;
    }
  else
    {
      if (!m)
	return;
    }

  /* Indetity mapping? */
  if (rp->l_addr.as_u32 == 0)
    l_addr.as_u32 = address[0].as_u32;
  else
    l_addr.as_u32 = rp->l_addr.as_u32;
  /* Add the static mapping */
  rv = snat_add_static_mapping (l_addr,
				address[0],
				rp->l_port,
				rp->e_port,
				rp->vrf_id,
				rp->addr_only, ~0 /* sw_if_index */ ,
				rp->proto, !is_delete, rp->twice_nat,
				rp->out2in_only, rp->tag, rp->identity_nat);
  if (rv)
    nat_log_notice ("snat_add_static_mapping returned %d", rv);
}

static void
snat_ip4_add_del_interface_address_cb (ip4_main_t * im,
				       uword opaque,
				       u32 sw_if_index,
				       ip4_address_t * address,
				       u32 address_length,
				       u32 if_address_index, u32 is_delete)
{
  snat_main_t *sm = &snat_main;
  snat_static_map_resolve_t *rp;
  ip4_address_t l_addr;
  int i, j;
  int rv;
  u8 twice_nat = 0;
  snat_address_t *addresses = sm->addresses;

  for (i = 0; i < vec_len (sm->auto_add_sw_if_indices); i++)
    {
      if (sw_if_index == sm->auto_add_sw_if_indices[i])
	goto match;
    }

  for (i = 0; i < vec_len (sm->auto_add_sw_if_indices_twice_nat); i++)
    {
      twice_nat = 1;
      addresses = sm->twice_nat_addresses;
      if (sw_if_index == sm->auto_add_sw_if_indices_twice_nat[i])
	goto match;
    }

  return;

match:
  if (!is_delete)
    {
      /* Don't trip over lease renewal, static config */
      for (j = 0; j < vec_len (addresses); j++)
	if (addresses[j].addr.as_u32 == address->as_u32)
	  return;

      (void) snat_add_address (sm, address, ~0, twice_nat);
      /* Scan static map resolution vector */
      for (j = 0; j < vec_len (sm->to_resolve); j++)
	{
	  rp = sm->to_resolve + j;
	  if (rp->addr_only)
	    continue;
	  /* On this interface? */
	  if (rp->sw_if_index == sw_if_index)
	    {
	      /* Indetity mapping? */
	      if (rp->l_addr.as_u32 == 0)
		l_addr.as_u32 = address[0].as_u32;
	      else
		l_addr.as_u32 = rp->l_addr.as_u32;
	      /* Add the static mapping */
	      rv = snat_add_static_mapping (l_addr,
					    address[0],
					    rp->l_port,
					    rp->e_port,
					    rp->vrf_id,
					    rp->addr_only,
					    ~0 /* sw_if_index */ ,
					    rp->proto,
					    rp->is_add, rp->twice_nat,
					    rp->out2in_only, rp->tag,
					    rp->identity_nat);
	      if (rv)
		nat_log_notice ("snat_add_static_mapping returned %d", rv);
	    }
	}
      return;
    }
  else
    {
      (void) snat_del_address (sm, address[0], 1, twice_nat);
      return;
    }
}


int
snat_add_interface_address (snat_main_t * sm, u32 sw_if_index, int is_del,
			    u8 twice_nat)
{
  ip4_main_t *ip4_main = sm->ip4_main;
  ip4_address_t *first_int_addr;
  snat_static_map_resolve_t *rp;
  u32 *indices_to_delete = 0;
  int i, j;
  u32 *auto_add_sw_if_indices =
    twice_nat ? sm->
    auto_add_sw_if_indices_twice_nat : sm->auto_add_sw_if_indices;

  first_int_addr = ip4_interface_first_address (ip4_main, sw_if_index, 0	/* just want the address */
    );

  for (i = 0; i < vec_len (auto_add_sw_if_indices); i++)
    {
      if (auto_add_sw_if_indices[i] == sw_if_index)
	{
	  if (is_del)
	    {
	      /* if have address remove it */
	      if (first_int_addr)
		(void) snat_del_address (sm, first_int_addr[0], 1, twice_nat);
	      else
		{
		  for (j = 0; j < vec_len (sm->to_resolve); j++)
		    {
		      rp = sm->to_resolve + j;
		      if (rp->sw_if_index == sw_if_index)
			vec_add1 (indices_to_delete, j);
		    }
		  if (vec_len (indices_to_delete))
		    {
		      for (j = vec_len (indices_to_delete) - 1; j >= 0; j--)
			vec_del1 (sm->to_resolve, j);
		      vec_free (indices_to_delete);
		    }
		}
	      if (twice_nat)
		vec_del1 (sm->auto_add_sw_if_indices_twice_nat, i);
	      else
		vec_del1 (sm->auto_add_sw_if_indices, i);
	    }
	  else
	    return VNET_API_ERROR_VALUE_EXIST;

	  return 0;
	}
    }

  if (is_del)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* add to the auto-address list */
  if (twice_nat)
    vec_add1 (sm->auto_add_sw_if_indices_twice_nat, sw_if_index);
  else
    vec_add1 (sm->auto_add_sw_if_indices, sw_if_index);

  /* If the address is already bound - or static - add it now */
  if (first_int_addr)
    (void) snat_add_address (sm, first_int_addr, ~0, twice_nat);

  return 0;
}

int
nat44_del_session (snat_main_t * sm, ip4_address_t * addr, u16 port,
		   snat_protocol_t proto, u32 vrf_id, int is_in)
{
  snat_main_per_thread_data_t *tsm;
  clib_bihash_kv_8_8_t kv, value;
  ip4_header_t ip;
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);
  snat_session_key_t key;
  snat_session_t *s;
  clib_bihash_8_8_t *t;

  if (sm->endpoint_dependent)
    return VNET_API_ERROR_UNSUPPORTED;

  ip.dst_address.as_u32 = ip.src_address.as_u32 = addr->as_u32;
  if (sm->num_workers > 1)
    tsm =
      vec_elt_at_index (sm->per_thread_data,
			sm->worker_in2out_cb (&ip, fib_index));
  else
    tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

  key.addr.as_u32 = addr->as_u32;
  key.port = clib_host_to_net_u16 (port);
  key.protocol = proto;
  key.fib_index = fib_index;
  kv.key = key.as_u64;
  t = is_in ? &tsm->in2out : &tsm->out2in;
  if (!clib_bihash_search_8_8 (t, &kv, &value))
    {
      if (pool_is_free_index (tsm->sessions, value.value))
	return VNET_API_ERROR_UNSPECIFIED;

      s = pool_elt_at_index (tsm->sessions, value.value);
      nat_free_session_data (sm, s, tsm - sm->per_thread_data);
      nat44_delete_session (sm, s, tsm - sm->per_thread_data);
      return 0;
    }

  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

int
nat44_del_ed_session (snat_main_t * sm, ip4_address_t * addr, u16 port,
		      ip4_address_t * eh_addr, u16 eh_port, u8 proto,
		      u32 vrf_id, int is_in)
{
  ip4_header_t ip;
  clib_bihash_16_8_t *t;
  nat_ed_ses_key_t key;
  clib_bihash_kv_16_8_t kv, value;
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm;

  if (!sm->endpoint_dependent)
    return VNET_API_ERROR_FEATURE_DISABLED;

  ip.dst_address.as_u32 = ip.src_address.as_u32 = addr->as_u32;
  if (sm->num_workers > 1)
    tsm =
      vec_elt_at_index (sm->per_thread_data,
			sm->worker_in2out_cb (&ip, fib_index));
  else
    tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

  t = is_in ? &tsm->in2out_ed : &tsm->out2in_ed;
  key.l_addr.as_u32 = addr->as_u32;
  key.r_addr.as_u32 = eh_addr->as_u32;
  key.l_port = clib_host_to_net_u16 (port);
  key.r_port = clib_host_to_net_u16 (eh_port);
  key.proto = proto;
  key.fib_index = fib_index;
  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];
  if (clib_bihash_search_16_8 (t, &kv, &value))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (pool_is_free_index (tsm->sessions, value.value))
    return VNET_API_ERROR_UNSPECIFIED;
  s = pool_elt_at_index (tsm->sessions, value.value);
  nat_free_session_data (sm, s, tsm - sm->per_thread_data);
  nat44_delete_session (sm, s, tsm - sm->per_thread_data);
  return 0;
}

void
nat_set_alloc_addr_and_port_mape (u16 psid, u16 psid_offset, u16 psid_length)
{
  snat_main_t *sm = &snat_main;

  sm->addr_and_port_alloc_alg = NAT_ADDR_AND_PORT_ALLOC_ALG_MAPE;
  sm->alloc_addr_and_port = nat_alloc_addr_and_port_mape;
  sm->psid = psid;
  sm->psid_offset = psid_offset;
  sm->psid_length = psid_length;
}

void
nat_set_alloc_addr_and_port_range (u16 start_port, u16 end_port)
{
  snat_main_t *sm = &snat_main;

  sm->addr_and_port_alloc_alg = NAT_ADDR_AND_PORT_ALLOC_ALG_RANGE;
  sm->alloc_addr_and_port = nat_alloc_addr_and_port_range;
  sm->start_port = start_port;
  sm->end_port = end_port;
}

void
nat_set_alloc_addr_and_port_default (void)
{
  snat_main_t *sm = &snat_main;

  sm->addr_and_port_alloc_alg = NAT_ADDR_AND_PORT_ALLOC_ALG_DEFAULT;
  sm->alloc_addr_and_port = nat_alloc_addr_and_port_default;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
