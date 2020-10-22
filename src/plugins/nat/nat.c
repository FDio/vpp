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
#include <nat/lib/ipfix_logging.h>
#include <nat/lib/nat_syslog.h>
#include <nat/nat_inlines.h>
#include <nat/nat44/inlines.h>
#include <nat/nat_affinity.h>
#include <nat/nat_ha.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vppinfra/bihash_16_8.h>
#include <nat/nat44/ed_inlines.h>
#include <vnet/ip/ip_table.h>

#include <vpp/app/version.h>

snat_main_t snat_main;

/* *INDENT-OFF* */
/* Hook up input features */
VNET_FEATURE_INIT (nat_pre_in2out, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat-pre-in2out",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (nat_pre_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat-pre-out2in",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-dhcp-client-detect",
			       "ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (snat_in2out_worker_handoff, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-in2out-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (snat_out2in_worker_handoff, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-out2in-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_snat_in2out, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-in2out",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa","ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_snat_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-out2in",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa","ip4-sv-reassembly-feature",
                               "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_nat_classify, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-classify",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa","ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_in2out, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ed-in2out",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa","ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ed-out2in",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa","ip4-sv-reassembly-feature",
                               "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_classify, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ed-classify",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa","ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_nat_handoff_classify, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-handoff-classify",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa","ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_snat_in2out_fast, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-in2out-fast",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa","ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_snat_out2in_fast, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-out2in-fast",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa","ip4-sv-reassembly-feature",
                               "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_snat_hairpin_dst, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-hairpin-dst",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa","ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_hairpin_dst, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ed-hairpin-dst",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa","ip4-sv-reassembly-feature"),
};

/* Hook up output features */
VNET_FEATURE_INIT (ip4_snat_in2out_output, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-in2out-output",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa","ip4-sv-reassembly-output-feature"),
};
VNET_FEATURE_INIT (ip4_snat_in2out_output_worker_handoff, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-in2out-output-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa","ip4-sv-reassembly-output-feature"),
};
VNET_FEATURE_INIT (ip4_snat_hairpin_src, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-hairpin-src",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa","ip4-sv-reassembly-output-feature"),
};
VNET_FEATURE_INIT (nat_pre_in2out_output, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat-pre-in2out-output",
  .runs_after = VNET_FEATURES ("ip4-sv-reassembly-output-feature"),
  .runs_before = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_in2out_output, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-ed-in2out-output",
  .runs_after = VNET_FEATURES ("ip4-sv-reassembly-output-feature"),
  .runs_before = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_nat44_ed_hairpin_src, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-ed-hairpin-src",
  .runs_after = VNET_FEATURES ("ip4-sv-reassembly-output-feature"),
  .runs_before = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
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
    .description = "Network Address Translation (NAT)",
};
/* *INDENT-ON* */

static u32
nat44_ed_get_worker_out2in_cb (vlib_buffer_t * b, ip4_header_t * ip,
			       u32 rx_fib_index, u8 is_output);

static u32
nat44_ed_get_worker_in2out_cb (ip4_header_t * ip, u32 rx_fib_index,
			       u8 is_output);

static u32
snat_get_worker_out2in_cb (vlib_buffer_t * b, ip4_header_t * ip0,
			   u32 rx_fib_index0, u8 is_output);

static u32
snat_get_worker_in2out_cb (ip4_header_t * ip0, u32 rx_fib_index0,
			   u8 is_output);

static u32 nat_calc_bihash_buckets (u32 n_elts);

u8 *
format_session_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);

  s = format (s, "%U session-index %llu", format_snat_key, v->key, v->value);

  return s;
}

u8 *
format_static_mapping_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);

  s = format (s, "%U static-mapping-index %llu",
	      format_snat_key, v->key, v->value);

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

  u8 proto;
  u16 r_port, l_port;
  ip4_address_t l_addr, r_addr;
  u32 fib_index;

  split_ed_kv (v, &l_addr, &r_addr, &proto, &fib_index, &l_port, &r_port);
  s =
    format (s,
	    "local %U:%d remote %U:%d proto %U fib %d thread-index %u session-index %u",
	    format_ip4_address, &l_addr, clib_net_to_host_u16 (l_port),
	    format_ip4_address, &r_addr, clib_net_to_host_u16 (r_port),
	    format_ip_protocol, proto, fib_index,
	    ed_value_get_session_index (v), ed_value_get_thread_index (v));

  return s;
}

void
nat44_ei_free_session_data (snat_main_t * sm, snat_session_t * s,
			    u32 thread_index, u8 is_ha)
{
  clib_bihash_kv_8_8_t kv;

  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_index);

  init_nat_i2o_k (&kv, s);
  if (clib_bihash_add_del_8_8 (&tsm->in2out, &kv, 0))
    nat_elog_warn ("in2out key del failed");

  init_nat_o2i_k (&kv, s);
  if (clib_bihash_add_del_8_8 (&tsm->out2in, &kv, 0))
    nat_elog_warn ("out2in key del failed");

  if (!is_ha)
    {
      nat_syslog_nat44_apmdel (s->user_index, s->in2out.fib_index,
			       &s->in2out.addr, s->in2out.port,
			       &s->out2in.addr, s->out2in.port, s->nat_proto);

      nat_ipfix_logging_nat44_ses_delete (thread_index,
					  s->in2out.addr.as_u32,
					  s->out2in.addr.as_u32,
					  s->nat_proto,
					  s->in2out.port,
					  s->out2in.port,
					  s->in2out.fib_index);

      nat_ha_sdel (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
		   s->ext_host_port, s->nat_proto, s->out2in.fib_index,
		   thread_index);

    }

  if (snat_is_session_static (s))
    return;

  snat_free_outside_address_and_port (sm->addresses, thread_index,
				      &s->out2in.addr, s->out2in.port,
				      s->nat_proto);
}

static_always_inline void
nat44_ei_user_del_sessions (snat_user_t * u, u32 thread_index)
{
  dlist_elt_t *elt;
  snat_session_t *s;

  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  // get head
  elt = pool_elt_at_index (tsm->list_pool,
			   u->sessions_per_user_list_head_index);
  // get first element
  elt = pool_elt_at_index (tsm->list_pool, elt->next);

  while (elt->value != ~0)
    {
      s = pool_elt_at_index (tsm->sessions, elt->value);
      elt = pool_elt_at_index (tsm->list_pool, elt->next);

      nat44_ei_free_session_data (sm, s, thread_index, 0);
      nat44_delete_session (sm, s, thread_index);
    }
}

int
nat44_ei_user_del (ip4_address_t * addr, u32 fib_index)
{
  int rv = 1;

  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;

  snat_user_key_t user_key;
  clib_bihash_kv_8_8_t kv, value;

  if (sm->endpoint_dependent)
    return rv;

  user_key.addr.as_u32 = addr->as_u32;
  user_key.fib_index = fib_index;
  kv.key = user_key.as_u64;

  if (sm->num_workers > 1)
    {
      /* *INDENT-OFF* */
      vec_foreach (tsm, sm->per_thread_data)
        {
          if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
            {
              nat44_ei_user_del_sessions (
                  pool_elt_at_index (tsm->users, value.value),
                  tsm->thread_index);
              rv = 0;
              break;
            }
        }
      /* *INDENT-ON* */
    }
  else
    {
      tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);
      if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
	{
	  nat44_ei_user_del_sessions (pool_elt_at_index
				      (tsm->users, value.value),
				      tsm->thread_index);
	  rv = 0;
	}
    }
  return rv;
}

void
nat_free_session_data (snat_main_t * sm, snat_session_t * s, u32 thread_index,
		       u8 is_ha)
{
  clib_bihash_kv_8_8_t kv;
  u8 proto;
  u16 r_port, l_port;
  ip4_address_t *l_addr, *r_addr;
  u32 fib_index = 0;
  clib_bihash_kv_16_8_t ed_kv;
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_index);

  if (is_ed_session (s))
    {
      per_vrf_sessions_unregister_session (s, thread_index);
    }

  if (is_fwd_bypass_session (s))
    {
      if (snat_is_unk_proto_session (s))
	{
	  init_ed_k (&ed_kv, s->in2out.addr, 0, s->ext_host_addr, 0, 0,
		     s->in2out.port);
	}
      else
	{
	  l_port = s->in2out.port;
	  r_port = s->ext_host_port;
	  l_addr = &s->in2out.addr;
	  r_addr = &s->ext_host_addr;
	  proto = nat_proto_to_ip_proto (s->nat_proto);
	  fib_index = s->in2out.fib_index;
	  init_ed_k (&ed_kv, *l_addr, l_port, *r_addr, r_port, fib_index,
		     proto);
	}
      if (clib_bihash_add_del_16_8 (&tsm->in2out_ed, &ed_kv, 0))
	nat_elog_warn ("in2out_ed key del failed");
      return;
    }

  /* session lookup tables */
  if (is_ed_session (s))
    {
      if (is_affinity_sessions (s))
	nat_affinity_unlock (s->ext_host_addr, s->out2in.addr,
			     s->nat_proto, s->out2in.port);
      l_addr = &s->out2in.addr;
      r_addr = &s->ext_host_addr;
      fib_index = s->out2in.fib_index;
      if (snat_is_unk_proto_session (s))
	{
	  proto = s->in2out.port;
	  r_port = 0;
	  l_port = 0;
	}
      else
	{
	  proto = nat_proto_to_ip_proto (s->nat_proto);
	  l_port = s->out2in.port;
	  r_port = s->ext_host_port;
	}
      init_ed_k (&ed_kv, *l_addr, l_port, *r_addr, r_port, fib_index, proto);
      if (clib_bihash_add_del_16_8 (&sm->out2in_ed, &ed_kv, 0))
	nat_elog_warn ("out2in_ed key del failed");
      l_addr = &s->in2out.addr;
      fib_index = s->in2out.fib_index;
      if (!snat_is_unk_proto_session (s))
	l_port = s->in2out.port;
      if (is_twice_nat_session (s))
	{
	  r_addr = &s->ext_host_nat_addr;
	  r_port = s->ext_host_nat_port;
	}
      init_ed_k (&ed_kv, *l_addr, l_port, *r_addr, r_port, fib_index, proto);
      if (clib_bihash_add_del_16_8 (&tsm->in2out_ed, &ed_kv, 0))
	nat_elog_warn ("in2out_ed key del failed");

      if (!is_ha)
	nat_syslog_nat44_sdel (s->user_index, s->in2out.fib_index,
			       &s->in2out.addr, s->in2out.port,
			       &s->ext_host_nat_addr, s->ext_host_nat_port,
			       &s->out2in.addr, s->out2in.port,
			       &s->ext_host_addr, s->ext_host_port,
			       s->nat_proto, is_twice_nat_session (s));
    }
  else
    {
      init_nat_i2o_k (&kv, s);
      if (clib_bihash_add_del_8_8 (&tsm->in2out, &kv, 0))
	nat_elog_warn ("in2out key del failed");
      init_nat_o2i_k (&kv, s);
      if (clib_bihash_add_del_8_8 (&tsm->out2in, &kv, 0))
	nat_elog_warn ("out2in key del failed");

      if (!is_ha)
	nat_syslog_nat44_apmdel (s->user_index, s->in2out.fib_index,
				 &s->in2out.addr, s->in2out.port,
				 &s->out2in.addr, s->out2in.port,
				 s->nat_proto);
    }

  if (snat_is_unk_proto_session (s))
    return;

  if (!is_ha)
    {
      /* log NAT event */
      nat_ipfix_logging_nat44_ses_delete (thread_index,
					  s->in2out.addr.as_u32,
					  s->out2in.addr.as_u32,
					  s->nat_proto,
					  s->in2out.port,
					  s->out2in.port,
					  s->in2out.fib_index);

      nat_ha_sdel (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
		   s->ext_host_port, s->nat_proto, s->out2in.fib_index,
		   thread_index);
    }

  /* Twice NAT address and port for external host */
  if (is_twice_nat_session (s))
    {
      snat_free_outside_address_and_port (sm->twice_nat_addresses,
					  thread_index,
					  &s->ext_host_nat_addr,
					  s->ext_host_nat_port, s->nat_proto);
    }

  if (snat_is_session_static (s))
    return;

  snat_free_outside_address_and_port (sm->addresses, thread_index,
				      &s->out2in.addr, s->out2in.port,
				      s->nat_proto);
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
      if (pool_elts (tsm->users) >= sm->max_users_per_thread)
	{
	  vlib_increment_simple_counter (&sm->user_limit_reached,
					 thread_index, 0, 1);
	  nat_elog_warn ("maximum user limit reached");
	  return NULL;
	}
      /* no, make a new one */
      pool_get (tsm->users, u);
      clib_memset (u, 0, sizeof (*u));

      u->addr.as_u32 = addr->as_u32;
      u->fib_index = fib_index;

      pool_get (tsm->list_pool, per_user_list_head_elt);

      u->sessions_per_user_list_head_index = per_user_list_head_elt -
	tsm->list_pool;

      clib_dlist_init (tsm->list_pool, u->sessions_per_user_list_head_index);

      kv.value = u - tsm->users;

      /* add user */
      if (clib_bihash_add_del_8_8 (&tsm->user_hash, &kv, 1))
	{
	  nat_elog_warn ("user_hash key add failed");
	  nat44_delete_user_with_no_session (sm, u, thread_index);
	  return NULL;
	}

      vlib_set_simple_counter (&sm->total_users, thread_index, 0,
			       pool_elts (tsm->users));
    }
  else
    {
      u = pool_elt_at_index (tsm->users, value.value);
    }

  return u;
}

// only NAT EI
snat_session_t *
nat_session_alloc_or_recycle (snat_main_t * sm, snat_user_t * u,
			      u32 thread_index, f64 now)
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

      // TODO: ONLY EI version should be called
      nat_free_session_data (sm, s, thread_index, 0);
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
      clib_memset (s, 0, sizeof (*s));

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

      s->user_index = u - tsm->users;
      vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			       pool_elts (tsm->sessions));
    }

  s->ha_last_refreshed = now;

  return s;
}

void
snat_add_del_addr_to_fib (ip4_address_t * addr, u8 p_len, u32 sw_if_index,
			  int is_add)
{
  snat_main_t *sm = &snat_main;
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
				     sm->fib_src_low,
				     (FIB_ENTRY_FLAG_CONNECTED |
				      FIB_ENTRY_FLAG_LOCAL |
				      FIB_ENTRY_FLAG_EXCLUSIVE),
				     DPO_PROTO_IP4,
				     NULL,
				     sw_if_index,
				     ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
  else
    fib_table_entry_delete (fib_index, &prefix, sm->fib_src_low);
}

int
snat_add_address (snat_main_t * sm, ip4_address_t * addr, u32 vrf_id,
		  u8 twice_nat)
{
  snat_address_t *ap;
  snat_interface_t *i;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  if (twice_nat && !sm->endpoint_dependent)
    {
      nat_log_err ("unsupported");
      return VNET_API_ERROR_UNSUPPORTED;
    }

  /* Check if address already exists */
  /* *INDENT-OFF* */
  vec_foreach (ap, twice_nat ? sm->twice_nat_addresses : sm->addresses)
    {
      if (ap->addr.as_u32 == addr->as_u32)
        {
          nat_log_err ("address exist");
          return VNET_API_ERROR_VALUE_EXIST;
        }
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
					 sm->fib_src_low);
  else
    ap->fib_index = ~0;

  /* *INDENT-OFF* */
  #define _(N, i, n, s) \
    clib_memset(ap->busy_##n##_port_refcounts, 0, sizeof(ap->busy_##n##_port_refcounts));\
    ap->busy_##n##_ports = 0; \
    ap->busy_##n##_ports_per_thread = 0;\
    vec_validate_init_empty (ap->busy_##n##_ports_per_thread, tm->n_vlib_mains - 1, 0);
    foreach_nat_protocol
  #undef _
  /* *INDENT-ON* */

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
      if (is_addr_only_static_mapping (m) ||
          is_out2in_only_static_mapping (m) ||
          is_identity_static_mapping (m))
        continue;
      if (m->external_addr.as_u32 == addr.as_u32)
        return 1;
  }));
  /* *INDENT-ON* */

  return 0;
}

static void
snat_add_static_mapping_when_resolved (snat_main_t * sm,
				       ip4_address_t l_addr,
				       u16 l_port,
				       u32 sw_if_index,
				       u16 e_port,
				       u32 vrf_id,
				       nat_protocol_t proto,
				       int addr_only, int is_add, u8 * tag,
				       int twice_nat, int out2in_only,
				       int identity_nat,
				       ip4_address_t pool_addr, int exact)
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
  rp->pool_addr = pool_addr;
  rp->exact = exact;
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

void
nat_ei_static_mapping_del_sessions (snat_main_t * sm,
				    snat_main_per_thread_data_t * tsm,
				    snat_user_key_t u_key, int addr_only,
				    ip4_address_t e_addr, u16 e_port)
{
  clib_bihash_kv_8_8_t kv, value;
  kv.key = u_key.as_u64;
  u64 user_index;
  dlist_elt_t *head, *elt;
  snat_user_t *u;
  snat_session_t *s;
  u32 elt_index, head_index, ses_index;

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
		      (s->out2in.port != e_port))
		    continue;
		}

	      if (is_lb_session (s))
		continue;

	      if (!snat_is_session_static (s))
		continue;

	      nat_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
	      nat44_delete_session (sm, s, tsm - sm->per_thread_data);

	      if (!addr_only)
		break;
	    }
	}
    }
}

void
nat_ed_static_mapping_del_sessions (snat_main_t * sm,
				    snat_main_per_thread_data_t * tsm,
				    ip4_address_t l_addr,
				    u16 l_port,
				    u8 protocol,
				    u32 fib_index, int addr_only,
				    ip4_address_t e_addr, u16 e_port)
{
  snat_session_t *s;
  u32 *indexes_to_free = NULL;
  /* *INDENT-OFF* */
  pool_foreach (s, tsm->sessions, {
    if (s->in2out.fib_index != fib_index ||
        s->in2out.addr.as_u32 != l_addr.as_u32)
      {
        continue;
      }
    if (!addr_only)
      {
        if ((s->out2in.addr.as_u32 != e_addr.as_u32) ||
            s->out2in.port != e_port ||
            s->in2out.port != l_port ||
            s->nat_proto != protocol)
          continue;
      }

    if (is_lb_session (s))
      continue;
    if (!snat_is_session_static (s))
      continue;
    nat_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
    vec_add1 (indexes_to_free, s - tsm->sessions);
    if (!addr_only)
      break;
  });
  /* *INDENT-ON* */
  u32 *ses_index;
  vec_foreach (ses_index, indexes_to_free)
  {
    s = pool_elt_at_index (tsm->sessions, *ses_index);
    nat_ed_session_delete (sm, s, tsm - sm->per_thread_data, 1);
  }
  vec_free (indexes_to_free);
}

int
snat_add_static_mapping (ip4_address_t l_addr, ip4_address_t e_addr,
			 u16 l_port, u16 e_port, u32 vrf_id, int addr_only,
			 u32 sw_if_index, nat_protocol_t proto, int is_add,
			 twice_nat_type_t twice_nat, u8 out2in_only, u8 * tag,
			 u8 identity_nat, ip4_address_t pool_addr, int exact)
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
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
  u32 find = ~0;

  if (!sm->endpoint_dependent)
    {
      if (twice_nat || out2in_only)
	return VNET_API_ERROR_UNSUPPORTED;
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
	      if ((rp->l_port != l_port && rp->e_port != e_port)
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
	     addr_only, is_add, tag, twice_nat, out2in_only,
	     identity_nat, pool_addr, exact);

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

  init_nat_k (&kv, e_addr, addr_only ? 0 : e_port, 0, addr_only ? 0 : proto);
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
              pool_foreach (local, m->locals,
              ({
                if (local->vrf_id == vrf_id)
                  return VNET_API_ERROR_VALUE_EXIST;
              }));
              /* *INDENT-ON* */
	      pool_get (m->locals, local);
	      local->vrf_id = vrf_id;
	      local->fib_index =
		fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id,
						   sm->fib_src_low);
	      init_nat_kv (&kv, m->local_addr, m->local_port,
			   local->fib_index, m->proto,
			   m - sm->static_mappings);
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
					     sm->fib_src_low);
      /* If not specified use inside VRF id from SNAT plugin startup config */
      else
	{
	  fib_index = sm->inside_fib_index;
	  vrf_id = sm->inside_vrf_id;
	  fib_table_lock (fib_index, FIB_PROTOCOL_IP4, sm->fib_src_low);
	}

      if (!(out2in_only || identity_nat))
	{
	  init_nat_k (&kv, l_addr, addr_only ? 0 : l_port, fib_index,
		      addr_only ? 0 : proto);
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
                    case NAT_PROTOCOL_##N: \
                      if (a->busy_##n##_port_refcounts[e_port]) \
                        return VNET_API_ERROR_INVALID_VALUE; \
                      ++a->busy_##n##_port_refcounts[e_port]; \
                      if (e_port > 1024) \
                        { \
                          a->busy_##n##_ports++; \
                          a->busy_##n##_ports_per_thread[get_thread_idx_by_port(e_port)]++; \
                        } \
                      break;
		      foreach_nat_protocol
#undef _
		    default:
		      nat_elog_info ("unknown protocol");
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
      clib_memset (m, 0, sizeof (*m));
      m->tag = vec_dup (tag);
      m->local_addr = l_addr;
      m->external_addr = e_addr;
      m->twice_nat = twice_nat;

      if (twice_nat == TWICE_NAT && exact)
	{
	  m->flags |= NAT_STATIC_MAPPING_FLAG_EXACT_ADDRESS;
	  m->pool_addr = pool_addr;
	}

      if (out2in_only)
	m->flags |= NAT_STATIC_MAPPING_FLAG_OUT2IN_ONLY;
      if (addr_only)
	m->flags |= NAT_STATIC_MAPPING_FLAG_ADDR_ONLY;
      if (identity_nat)
	{
	  m->flags |= NAT_STATIC_MAPPING_FLAG_IDENTITY_NAT;
	  pool_get (m->locals, local);
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
	  vec_add1 (m->workers, sm->worker_in2out_cb (&ip, m->fib_index, 0));
	  tsm = vec_elt_at_index (sm->per_thread_data, m->workers[0]);
	}
      else
	tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

      init_nat_kv (&kv, m->local_addr, m->local_port, fib_index, m->proto,
		   m - sm->static_mappings);
      if (!out2in_only)
	clib_bihash_add_del_8_8 (&sm->static_mapping_by_local, &kv, 1);

      init_nat_kv (&kv, m->external_addr, m->external_port, 0, m->proto,
		   m - sm->static_mappings);
      clib_bihash_add_del_8_8 (&sm->static_mapping_by_external, &kv, 1);

      /* Delete dynamic sessions matching local address (+ local port) */
      // TODO: based on type of NAT EI/ED
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

		      if (!addr_only && s->in2out.port != m->local_port)
			continue;

		      nat_free_session_data (sm, s,
					     tsm - sm->per_thread_data, 0);
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
	  if (vrf_id == ~0)
	    vrf_id = sm->inside_vrf_id;

          /* *INDENT-OFF* */
          pool_foreach (local, m->locals,
          ({
	    if (local->vrf_id == vrf_id)
              find = local - m->locals;
	  }));
          /* *INDENT-ON* */
	  if (find == ~0)
	    return VNET_API_ERROR_NO_SUCH_ENTRY;

	  local = pool_elt_at_index (m->locals, find);
	  fib_index = local->fib_index;
	  pool_put (m->locals, local);
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
                    case NAT_PROTOCOL_##N: \
                      --a->busy_##n##_port_refcounts[e_port]; \
                      if (e_port > 1024) \
                        { \
                          a->busy_##n##_ports--; \
                          a->busy_##n##_ports_per_thread[get_thread_idx_by_port(e_port)]--; \
                        } \
                      break;
		      foreach_nat_protocol
#undef _
		    default:
		      nat_elog_info ("unknown protocol");
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

      init_nat_k (&kv, m->local_addr, m->local_port, fib_index, m->proto);
      if (!out2in_only)
	clib_bihash_add_del_8_8 (&sm->static_mapping_by_local, &kv, 0);

      /* Delete session(s) for static mapping if exist */
      if (!(sm->static_mapping_only) ||
	  (sm->static_mapping_only && sm->static_mapping_connection_tracking))
	{
	  if (sm->endpoint_dependent)
	    {
	      nat_ed_static_mapping_del_sessions (sm, tsm, m->local_addr,
						  m->local_port, m->proto,
						  fib_index, addr_only,
						  e_addr, e_port);
	    }
	  else
	    {
	      u_key.addr = m->local_addr;
	      u_key.fib_index = fib_index;
	      kv.key = u_key.as_u64;
	      nat_ei_static_mapping_del_sessions (sm, tsm, u_key, addr_only,
						  e_addr, e_port);
	    }
	}

      fib_table_unlock (fib_index, FIB_PROTOCOL_IP4, sm->fib_src_low);
      if (pool_elts (m->locals))
	return 0;

      init_nat_k (&kv, m->external_addr, m->external_port, 0, m->proto);
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
				 nat_protocol_t proto,
				 nat44_lb_addr_port_t * locals, u8 is_add,
				 twice_nat_type_t twice_nat, u8 out2in_only,
				 u8 * tag, u32 affinity)
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  clib_bihash_kv_8_8_t kv, value;
  snat_address_t *a = 0;
  int i;
  nat44_lb_addr_port_t *local;
  snat_main_per_thread_data_t *tsm;
  snat_session_t *s;
  uword *bitmap = 0;

  if (!sm->endpoint_dependent)
    return VNET_API_ERROR_UNSUPPORTED;

  init_nat_k (&kv, e_addr, e_port, 0, proto);
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
                    case NAT_PROTOCOL_##N: \
                      if (a->busy_##n##_port_refcounts[e_port]) \
                        return VNET_API_ERROR_INVALID_VALUE; \
                      ++a->busy_##n##_port_refcounts[e_port]; \
                      if (e_port > 1024) \
                        { \
                          a->busy_##n##_ports++; \
                          a->busy_##n##_ports_per_thread[get_thread_idx_by_port(e_port)]++; \
                        } \
                      break;
		      foreach_nat_protocol
#undef _
		    default:
		      nat_elog_info ("unknown protocol");
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
      clib_memset (m, 0, sizeof (*m));
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

      init_nat_kv (&kv, m->external_addr, m->external_port, 0, m->proto,
		   m - sm->static_mappings);
      if (clib_bihash_add_del_8_8 (&sm->static_mapping_by_external, &kv, 1))
	{
	  nat_elog_err ("static_mapping_by_external key add failed");
	  return VNET_API_ERROR_UNSPECIFIED;
	}

      for (i = 0; i < vec_len (locals); i++)
	{
	  locals[i].fib_index =
	    fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
					       locals[i].vrf_id,
					       sm->fib_src_low);
	  if (!out2in_only)
	    {
	      init_nat_kv (&kv, locals[i].addr, locals[i].port,
			   locals[i].fib_index, m->proto,
			   m - sm->static_mappings);
	      clib_bihash_add_del_8_8 (&sm->static_mapping_by_local, &kv, 1);
	    }
	  locals[i].prefix = (i == 0) ? locals[i].probability :
	    (locals[i - 1].prefix + locals[i].probability);
	  pool_get (m->locals, local);
	  *local = locals[i];
	  if (sm->num_workers > 1)
	    {
	      ip4_header_t ip = {
		.src_address = locals[i].addr,
	      };
	      bitmap =
		clib_bitmap_set (bitmap,
				 sm->worker_in2out_cb (&ip, m->fib_index, 0),
				 1);
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
                    case NAT_PROTOCOL_##N: \
                      --a->busy_##n##_port_refcounts[e_port]; \
                      if (e_port > 1024) \
                        { \
                          a->busy_##n##_ports--; \
                          a->busy_##n##_ports_per_thread[get_thread_idx_by_port(e_port)]--; \
                        } \
                      break;
		      foreach_nat_protocol
#undef _
		    default:
		      nat_elog_info ("unknown protocol");
		      return VNET_API_ERROR_INVALID_VALUE_2;
		    }
		  break;
		}
	    }
	}

      init_nat_k (&kv, m->external_addr, m->external_port, 0, m->proto);
      if (clib_bihash_add_del_8_8 (&sm->static_mapping_by_external, &kv, 0))
	{
	  nat_elog_err ("static_mapping_by_external key del failed");
	  return VNET_API_ERROR_UNSPECIFIED;
	}

      /* *INDENT-OFF* */
      pool_foreach (local, m->locals,
      ({
          fib_table_unlock (local->fib_index, FIB_PROTOCOL_IP4,
                            sm->fib_src_low);
          if (!out2in_only)
            {
init_nat_k(&              kv, local->addr, local->port, local->fib_index, m->proto);
              if (clib_bihash_add_del_8_8(&sm->static_mapping_by_local, &kv, 0))
                {
                  nat_elog_err ("static_mapping_by_local key del failed");
                  return VNET_API_ERROR_UNSPECIFIED;
                }
            }

          if (sm->num_workers > 1)
            {
              ip4_header_t ip = {
                .src_address = local->addr,
              };
              tsm = vec_elt_at_index (sm->per_thread_data,
                                      sm->worker_in2out_cb (&ip, m->fib_index, 0));
            }
          else
            tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

          /* Delete sessions */
          pool_foreach (s, tsm->sessions, {
            if (!(is_lb_session (s)))
              continue;

            if ((s->in2out.addr.as_u32 != local->addr.as_u32) ||
                s->in2out.port != local->port)
              continue;

            nat_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
            nat_ed_session_delete (sm, s, tsm - sm->per_thread_data, 1);
          });
      }));
      /* *INDENT-ON* */
      if (m->affinity)
	nat_affinity_flush_service (m->affinity_per_service_list_head_index);
      pool_free (m->locals);
      vec_free (m->tag);
      vec_free (m->workers);

      pool_put (sm->static_mappings, m);
    }

  return 0;
}

int
nat44_lb_static_mapping_add_del_local (ip4_address_t e_addr, u16 e_port,
				       ip4_address_t l_addr, u16 l_port,
				       nat_protocol_t proto, u32 vrf_id,
				       u8 probability, u8 is_add)
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m = 0;
  clib_bihash_kv_8_8_t kv, value;
  nat44_lb_addr_port_t *local, *prev_local, *match_local = 0;
  snat_main_per_thread_data_t *tsm;
  snat_session_t *s;
  u32 *locals = 0;
  uword *bitmap = 0;
  int i;

  if (!sm->endpoint_dependent)
    return VNET_API_ERROR_FEATURE_DISABLED;

  init_nat_k (&kv, e_addr, e_port, 0, proto);
  if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
    m = pool_elt_at_index (sm->static_mappings, value.value);

  if (!m)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (!is_lb_static_mapping (m))
    return VNET_API_ERROR_INVALID_VALUE;

  /* *INDENT-OFF* */
  pool_foreach (local, m->locals,
  ({
    if ((local->addr.as_u32 == l_addr.as_u32) && (local->port == l_port) &&
        (local->vrf_id == vrf_id))
      {
        match_local = local;
        break;
      }
  }));
  /* *INDENT-ON* */

  if (is_add)
    {
      if (match_local)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (m->locals, local);
      clib_memset (local, 0, sizeof (*local));
      local->addr.as_u32 = l_addr.as_u32;
      local->port = l_port;
      local->probability = probability;
      local->vrf_id = vrf_id;
      local->fib_index =
	fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id,
					   sm->fib_src_low);

      if (!is_out2in_only_static_mapping (m))
	{
	  init_nat_kv (&kv, l_addr, l_port, local->fib_index, proto,
		       m - sm->static_mappings);
	  if (clib_bihash_add_del_8_8 (&sm->static_mapping_by_local, &kv, 1))
	    nat_elog_err ("static_mapping_by_local key add failed");
	}
    }
  else
    {
      if (!match_local)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if (pool_elts (m->locals) < 3)
	return VNET_API_ERROR_UNSPECIFIED;

      fib_table_unlock (match_local->fib_index, FIB_PROTOCOL_IP4,
			sm->fib_src_low);

      if (!is_out2in_only_static_mapping (m))
	{
	  init_nat_k (&kv, l_addr, l_port, match_local->fib_index, proto);
	  if (clib_bihash_add_del_8_8 (&sm->static_mapping_by_local, &kv, 0))
	    nat_elog_err ("static_mapping_by_local key del failed");
	}

      if (sm->num_workers > 1)
	{
	  ip4_header_t ip = {
	    .src_address = local->addr,
	  };
	  tsm = vec_elt_at_index (sm->per_thread_data,
				  sm->worker_in2out_cb (&ip, m->fib_index,
							0));
	}
      else
	tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

      /* Delete sessions */
      /* *INDENT-OFF* */
      pool_foreach (s, tsm->sessions, {
        if (!(is_lb_session (s)))
          continue;

        if ((s->in2out.addr.as_u32 != match_local->addr.as_u32) ||
            s->in2out.port != match_local->port)
          continue;

        nat_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
        nat_ed_session_delete (sm, s, tsm - sm->per_thread_data, 1);
      });
      /* *INDENT-ON* */

      pool_put (m->locals, match_local);
    }

  vec_free (m->workers);

  /* *INDENT-OFF* */
  pool_foreach (local, m->locals,
  ({
    vec_add1 (locals, local - m->locals);
    if (sm->num_workers > 1)
      {
        ip4_header_t ip;
        ip.src_address.as_u32 = local->addr.as_u32,
        bitmap = clib_bitmap_set (bitmap,
                                  sm->worker_in2out_cb (&ip, local->fib_index, 0),
                                  1);
      }
  }));
  /* *INDENT-ON* */

  ASSERT (vec_len (locals) > 1);

  local = pool_elt_at_index (m->locals, locals[0]);
  local->prefix = local->probability;
  for (i = 1; i < vec_len (locals); i++)
    {
      local = pool_elt_at_index (m->locals, locals[i]);
      prev_local = pool_elt_at_index (m->locals, locals[i - 1]);
      local->prefix = local->probability + prev_local->prefix;
    }

  /* Assign workers */
  if (sm->num_workers > 1)
    {
      /* *INDENT-OFF* */
      clib_bitmap_foreach (i, bitmap, ({ vec_add1(m->workers, i); }));
      /* *INDENT-ON* */
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
    {
      nat_log_err ("no such address");
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (delete_sm)
    {
      ip4_address_t pool_addr = { 0 };
      /* *INDENT-OFF* */
      pool_foreach (m, sm->static_mappings,
      ({
          if (m->external_addr.as_u32 == addr.as_u32)
            (void) snat_add_static_mapping (m->local_addr, m->external_addr,
                                            m->local_port, m->external_port,
                                            m->vrf_id,
                                            is_addr_only_static_mapping(m), ~0,
                                            m->proto, 0 /* is_add */,
                                            m->twice_nat,
                                            is_out2in_only_static_mapping(m),
                                            m->tag,
                                            is_identity_static_mapping(m),
                                            pool_addr, 0);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      /* Check if address is used in some static mapping */
      if (is_snat_address_used_in_static_mapping (sm, addr))
	{
	  nat_log_err ("address used in static mapping");
	  return VNET_API_ERROR_UNSPECIFIED;
	}
    }

  if (a->fib_index != ~0)
    fib_table_unlock (a->fib_index, FIB_PROTOCOL_IP4, sm->fib_src_low);

  /* Delete sessions using address */
  if (a->busy_tcp_ports || a->busy_udp_ports || a->busy_icmp_ports)
    {
      vec_foreach (tsm, sm->per_thread_data)
      {
        /* *INDENT-OFF* */
        pool_foreach (ses, tsm->sessions, ({
          if (ses->out2in.addr.as_u32 == addr.as_u32)
            {
              nat_free_session_data (sm, ses, tsm - sm->per_thread_data, 0);
              vec_add1 (ses_to_be_removed, ses - tsm->sessions);
            }
        }));
        /* *INDENT-ON* */

	if (sm->endpoint_dependent)
	  {
	    vec_foreach (ses_index, ses_to_be_removed)
	    {
	      ses = pool_elt_at_index (tsm->sessions, ses_index[0]);
	      nat_ed_session_delete (sm, ses, tsm - sm->per_thread_data, 1);
	    }
	  }
	else
	  {
	    vec_foreach (ses_index, ses_to_be_removed)
	    {
	      ses = pool_elt_at_index (tsm->sessions, ses_index[0]);
	      nat44_delete_session (sm, ses, tsm - sm->per_thread_data);
	    }
	  }

	vec_free (ses_to_be_removed);
      }
    }

#define _(N, i, n, s) \
  vec_free (a->busy_##n##_ports_per_thread);
  foreach_nat_protocol
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

static void
nat_validate_counters (snat_main_t * sm, u32 sw_if_index)
{
#define _(x)                                                                  \
  vlib_validate_simple_counter (&sm->counters.fastpath.in2out.x,              \
                                sw_if_index);                                 \
  vlib_zero_simple_counter (&sm->counters.fastpath.in2out.x, sw_if_index);    \
  vlib_validate_simple_counter (&sm->counters.fastpath.out2in.x,              \
                                sw_if_index);                                 \
  vlib_zero_simple_counter (&sm->counters.fastpath.out2in.x, sw_if_index);    \
  vlib_validate_simple_counter (&sm->counters.slowpath.in2out.x,              \
                                sw_if_index);                                 \
  vlib_zero_simple_counter (&sm->counters.slowpath.in2out.x, sw_if_index);    \
  vlib_validate_simple_counter (&sm->counters.slowpath.out2in.x,              \
                                sw_if_index);                                 \
  vlib_zero_simple_counter (&sm->counters.slowpath.out2in.x, sw_if_index);    \
  vlib_validate_simple_counter (&sm->counters.fastpath.in2out_ed.x,           \
                                sw_if_index);                                 \
  vlib_zero_simple_counter (&sm->counters.fastpath.in2out_ed.x, sw_if_index); \
  vlib_validate_simple_counter (&sm->counters.fastpath.out2in_ed.x,           \
                                sw_if_index);                                 \
  vlib_zero_simple_counter (&sm->counters.fastpath.out2in_ed.x, sw_if_index); \
  vlib_validate_simple_counter (&sm->counters.slowpath.in2out_ed.x,           \
                                sw_if_index);                                 \
  vlib_zero_simple_counter (&sm->counters.slowpath.in2out_ed.x, sw_if_index); \
  vlib_validate_simple_counter (&sm->counters.slowpath.out2in_ed.x,           \
                                sw_if_index);                                 \
  vlib_zero_simple_counter (&sm->counters.slowpath.out2in_ed.x, sw_if_index);
  foreach_nat_counter;
#undef _
  vlib_validate_simple_counter (&sm->counters.hairpinning, sw_if_index);
  vlib_zero_simple_counter (&sm->counters.hairpinning, sw_if_index);
}

void
expire_per_vrf_sessions (u32 fib_index)
{
  per_vrf_sessions_t *per_vrf_sessions;
  snat_main_per_thread_data_t *tsm;
  snat_main_t *sm = &snat_main;

  /* *INDENT-OFF* */
  vec_foreach (tsm, sm->per_thread_data)
    {
      vec_foreach (per_vrf_sessions, tsm->per_vrf_sessions_vec)
        {
          if ((per_vrf_sessions->rx_fib_index == fib_index) ||
              (per_vrf_sessions->tx_fib_index == fib_index))
            {
              per_vrf_sessions->expired = 1;
            }
        }
    }
  /* *INDENT-ON* */
}

void
update_per_vrf_sessions_vec (u32 fib_index, int is_del)
{
  snat_main_t *sm = &snat_main;
  nat_fib_t *fib;

  // we don't care if it is outside/inside fib
  // we just care about their ref_count
  // if it reaches 0 sessions should expire
  // because the fib isn't valid for NAT anymore

  vec_foreach (fib, sm->fibs)
  {
    if (fib->fib_index == fib_index)
      {
	if (is_del)
	  {
	    fib->ref_count--;
	    if (!fib->ref_count)
	      {
		vec_del1 (sm->fibs, fib - sm->fibs);
		expire_per_vrf_sessions (fib_index);
	      }
	    return;
	  }
	else
	  fib->ref_count++;
      }
  }
  if (!is_del)
    {
      vec_add2 (sm->fibs, fib, 1);
      fib->ref_count = 1;
      fib->fib_index = fib_index;
    }
}

int
snat_interface_add_del (u32 sw_if_index, u8 is_inside, int is_del)
{
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;
  const char *feature_name, *del_feature_name;
  snat_address_t *ap;
  snat_static_mapping_t *m;
  nat_outside_fib_t *outside_fib;
  u32 fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						       sw_if_index);

  if (!sm->enabled)
    {
      nat_log_err ("nat44 is disabled");
      return VNET_API_ERROR_UNSUPPORTED;
    }

  if (sm->out2in_dpo && !is_inside)
    {
      nat_log_err ("error unsupported");
      return VNET_API_ERROR_UNSUPPORTED;
    }

  /* *INDENT-OFF* */
  pool_foreach (i, sm->output_feature_interfaces,
  ({
    if (i->sw_if_index == sw_if_index)
      {
        nat_log_err ("error interface already configured");
        return VNET_API_ERROR_VALUE_EXIST;
      }
  }));
  /* *INDENT-ON* */

  if (sm->static_mapping_only && !(sm->static_mapping_connection_tracking))
    feature_name = is_inside ? "nat44-in2out-fast" : "nat44-out2in-fast";
  else
    {
      if (sm->num_workers > 1)
	feature_name =
	  is_inside ? "nat44-in2out-worker-handoff" :
	  "nat44-out2in-worker-handoff";
      else if (sm->endpoint_dependent)
	{
	  feature_name = is_inside ? "nat-pre-in2out" : "nat-pre-out2in";
	}
      else
	feature_name = is_inside ? "nat44-in2out" : "nat44-out2in";
    }

  if (sm->fq_in2out_index == ~0 && sm->num_workers > 1)
    sm->fq_in2out_index =
      vlib_frame_queue_main_init (sm->in2out_node_index, NAT_FQ_NELTS);

  if (sm->fq_out2in_index == ~0 && sm->num_workers > 1)
    sm->fq_out2in_index =
      vlib_frame_queue_main_init (sm->out2in_node_index, NAT_FQ_NELTS);

  if (sm->endpoint_dependent)
    update_per_vrf_sessions_vec (fib_index, is_del);

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

                if (sm->num_workers > 1)
                  {
                    del_feature_name = "nat44-handoff-classify";
                    feature_name = !is_inside ?  "nat44-in2out-worker-handoff" :
                                                 "nat44-out2in-worker-handoff";
                  }
                else if (sm->endpoint_dependent)
                  {
                    del_feature_name = "nat44-ed-classify";
                    feature_name = !is_inside ?  "nat-pre-in2out" :
                                                 "nat-pre-out2in";
                  }
                else
                  {
                    del_feature_name = "nat44-classify";
                    feature_name = !is_inside ?  "nat44-in2out" : "nat44-out2in";
                  }

		int rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
		if (rv)
		  return rv;
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
                    else
                      vnet_feature_enable_disable ("ip4-local",
                                                   "nat44-hairpinning",
                                                   sw_if_index, 1, 0, 0);
                  }
              }
            else
              {
		int rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
		if (rv)
		  return rv;
                vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                             sw_if_index, 0, 0, 0);
                pool_put (sm->interfaces, i);
                if (is_inside)
                  {
                    if (sm->endpoint_dependent)
                      vnet_feature_enable_disable ("ip4-local",
                                                   "nat44-ed-hairpinning",
                                                   sw_if_index, 0, 0, 0);
                    else
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

            if (sm->num_workers > 1)
              {
                del_feature_name = !is_inside ?  "nat44-in2out-worker-handoff" :
                                                 "nat44-out2in-worker-handoff";
                feature_name = "nat44-handoff-classify";
              }
            else if (sm->endpoint_dependent)
              {
                del_feature_name = !is_inside ?  "nat-pre-in2out" :
                                                 "nat-pre-out2in";

                feature_name = "nat44-ed-classify";
              }
            else
              {
                del_feature_name = !is_inside ?  "nat44-in2out" : "nat44-out2in";
                feature_name = "nat44-classify";
              }

	    int rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
	    if (rv)
	      return rv;
            vnet_feature_enable_disable ("ip4-unicast", del_feature_name,
                                         sw_if_index, 0, 0, 0);
            vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                         sw_if_index, 1, 0, 0);
            if (!is_inside)
              {
                if (sm->endpoint_dependent)
                  vnet_feature_enable_disable ("ip4-local", "nat44-ed-hairpinning",
                                               sw_if_index, 0, 0, 0);
                else
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
    {
      nat_log_err ("error interface couldn't be found");
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  pool_get (sm->interfaces, i);
  i->sw_if_index = sw_if_index;
  i->flags = 0;
  nat_validate_counters (sm, sw_if_index);

  vnet_feature_enable_disable ("ip4-unicast", feature_name, sw_if_index, 1, 0,
			       0);

  int rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
  if (rv)
    return rv;

  if (is_inside && !sm->out2in_dpo)
    {
      if (sm->endpoint_dependent)
	vnet_feature_enable_disable ("ip4-local", "nat44-ed-hairpinning",
				     sw_if_index, 1, 0, 0);
      else
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
  nat_outside_fib_t *outside_fib;
  u32 fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						       sw_if_index);

  if (!sm->enabled)
    {
      nat_log_err ("nat44 is disabled");
      return VNET_API_ERROR_UNSUPPORTED;
    }

  if (sm->static_mapping_only && !(sm->static_mapping_connection_tracking))
    {
      nat_log_err ("error unsupported");
      return VNET_API_ERROR_UNSUPPORTED;
    }

  /* *INDENT-OFF* */
  pool_foreach (i, sm->interfaces,
  ({
    if (i->sw_if_index == sw_if_index)
      {
        nat_log_err ("error interface already configured");
        return VNET_API_ERROR_VALUE_EXIST;
      }
  }));
  /* *INDENT-ON* */

  if (sm->endpoint_dependent)
    update_per_vrf_sessions_vec (fib_index, is_del);

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
  if (is_inside)
    {
      if (sm->endpoint_dependent)
	{
	  int rv =
	    ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, !is_del);
	  if (rv)
	    return rv;
	  rv =
	    ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index,
							    !is_del);
	  if (rv)
	    return rv;
	  vnet_feature_enable_disable ("ip4-unicast", "nat44-ed-hairpin-dst",
				       sw_if_index, !is_del, 0, 0);
	  vnet_feature_enable_disable ("ip4-output", "nat44-ed-hairpin-src",
				       sw_if_index, !is_del, 0, 0);
	}
      else
	{
	  int rv =
	    ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, !is_del);
	  if (rv)
	    return rv;
	  rv =
	    ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index,
							    !is_del);
	  if (rv)
	    return rv;
	  vnet_feature_enable_disable ("ip4-unicast", "nat44-hairpin-dst",
				       sw_if_index, !is_del, 0, 0);
	  vnet_feature_enable_disable ("ip4-output", "nat44-hairpin-src",
				       sw_if_index, !is_del, 0, 0);
	}
      goto fq;
    }

  if (sm->num_workers > 1)
    {
      int rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, !is_del);
      if (rv)
	return rv;
      rv =
	ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index, !is_del);
      if (rv)
	return rv;
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
	  int rv =
	    ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, !is_del);
	  if (rv)
	    return rv;
	  rv =
	    ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index,
							    !is_del);
	  if (rv)
	    return rv;
	  vnet_feature_enable_disable ("ip4-unicast", "nat-pre-out2in",
				       sw_if_index, !is_del, 0, 0);
	  vnet_feature_enable_disable ("ip4-output", "nat-pre-in2out-output",
				       sw_if_index, !is_del, 0, 0);
	}
      else
	{
	  int rv =
	    ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, !is_del);
	  if (rv)
	    return rv;
	  rv =
	    ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index,
							    !is_del);
	  if (rv)
	    return rv;
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
    {
      nat_log_err ("error interface couldn't be found");
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  pool_get (sm->output_feature_interfaces, i);
  i->sw_if_index = sw_if_index;
  i->flags = 0;
  nat_validate_counters (sm, sw_if_index);
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
      sm->per_thread_data[sm->first_worker_index + i].thread_index = i;
      j++;
    }));
  /* *INDENT-ON* */

  sm->port_per_thread = (0xffff - 1024) / _vec_len (sm->workers);

  return 0;
}

static void
snat_update_outside_fib (ip4_main_t * im, uword opaque,
			 u32 sw_if_index, u32 new_fib_index,
			 u32 old_fib_index)
{
  snat_main_t *sm = &snat_main;
  nat_outside_fib_t *outside_fib;
  snat_interface_t *i;
  u8 is_add = 1;
  u8 match = 0;

  if (!sm->enabled || (new_fib_index == old_fib_index)
      || (!vec_len (sm->outside_fibs)))
    {
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach (i, sm->interfaces,
    ({
      if (i->sw_if_index == sw_if_index)
        {
          if (!(nat_interface_is_outside (i)))
	    return;
          match = 1;
        }
    }));

  pool_foreach (i, sm->output_feature_interfaces,
    ({
      if (i->sw_if_index == sw_if_index)
        {
          if (!(nat_interface_is_outside (i)))
	    return;
          match = 1;
        }
    }));
  /* *INDENT-ON* */

  if (!match)
    return;

  vec_foreach (outside_fib, sm->outside_fibs)
  {
    if (outside_fib->fib_index == old_fib_index)
      {
	outside_fib->refcount--;
	if (!outside_fib->refcount)
	  vec_del1 (sm->outside_fibs, outside_fib - sm->outside_fibs);
	break;
      }
  }

  vec_foreach (outside_fib, sm->outside_fibs)
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
      vec_add2 (sm->outside_fibs, outside_fib, 1);
      outside_fib->refcount = 1;
      outside_fib->fib_index = new_fib_index;
    }
}

static void
snat_update_outside_fib (ip4_main_t * im, uword opaque,
			 u32 sw_if_index, u32 new_fib_index,
			 u32 old_fib_index);

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
nat_alloc_addr_and_port_default (snat_address_t * addresses, u32 fib_index,
				 u32 thread_index, nat_protocol_t proto,
				 ip4_address_t * addr, u16 * port,
				 u16 port_per_thread, u32 snat_thread_index);

void
test_key_calc_split ()
{
  ip4_address_t l_addr;
  l_addr.as_u8[0] = 1;
  l_addr.as_u8[1] = 1;
  l_addr.as_u8[2] = 1;
  l_addr.as_u8[3] = 1;
  ip4_address_t r_addr;
  r_addr.as_u8[0] = 2;
  r_addr.as_u8[1] = 2;
  r_addr.as_u8[2] = 2;
  r_addr.as_u8[3] = 2;
  u16 l_port = 40001;
  u16 r_port = 40301;
  u8 proto = 9;
  u32 fib_index = 9000001;
  u32 thread_index = 3000000001;
  u32 session_index = 3000000221;
  clib_bihash_kv_16_8_t kv;
  init_ed_kv (&kv, l_addr, l_port, r_addr, r_port, fib_index, proto,
	      thread_index, session_index);
  ip4_address_t l_addr2;
  ip4_address_t r_addr2;
  clib_memset (&l_addr2, 0, sizeof (l_addr2));
  clib_memset (&r_addr2, 0, sizeof (r_addr2));
  u16 l_port2 = 0;
  u16 r_port2 = 0;
  u8 proto2 = 0;
  u32 fib_index2 = 0;
  split_ed_kv (&kv, &l_addr2, &r_addr2, &proto2, &fib_index2, &l_port2,
	       &r_port2);
  ASSERT (l_addr.as_u32 == l_addr2.as_u32);
  ASSERT (r_addr.as_u32 == r_addr2.as_u32);
  ASSERT (l_port == l_port2);
  ASSERT (r_port == r_port2);
  ASSERT (proto == proto2);
  ASSERT (fib_index == fib_index2);
  ASSERT (thread_index == ed_value_get_thread_index (&kv));
  ASSERT (session_index == ed_value_get_session_index (&kv));

  fib_index = 7001;
  proto = 5;
  nat_protocol_t proto3 = ~0;
  u64 key = calc_nat_key (l_addr, l_port, fib_index, proto);
  split_nat_key (key, &l_addr2, &l_port2, &fib_index2, &proto3);
  ASSERT (l_addr.as_u32 == l_addr2.as_u32);
  ASSERT (l_port == l_port2);
  ASSERT (proto == proto3);
  ASSERT (fib_index == fib_index2);
}

static clib_error_t *
nat_ip_table_add_del (vnet_main_t * vnm, u32 table_id, u32 is_add)
{
  snat_main_t *sm = &snat_main;
  u32 fib_index;

  if (sm->endpoint_dependent)
    {
      // TODO: consider removing all NAT interfaces
      if (!is_add)
	{
	  fib_index = ip4_fib_index_from_table_id (table_id);
	  if (fib_index != ~0)
	    expire_per_vrf_sessions (fib_index);
	}
    }
  return 0;
}

VNET_IP_TABLE_ADD_DEL_FUNCTION (nat_ip_table_add_del);

void
nat44_set_node_indexes (snat_main_t * sm, vlib_main_t * vm)
{
  vlib_node_t *node;

  node = vlib_get_node_by_name (vm, (u8 *) "nat44-out2in");
  sm->ei_out2in_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-in2out");
  sm->ei_in2out_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-in2out-output");
  sm->ei_in2out_output_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ed-out2in");
  sm->ed_out2in_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ed-in2out");
  sm->ed_in2out_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ed-in2out-output");
  sm->ed_in2out_output_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  sm->error_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat-pre-in2out");
  sm->pre_in2out_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat-pre-out2in");
  sm->pre_out2in_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat-pre-in2out");
  sm->pre_in2out_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat-pre-out2in");
  sm->pre_out2in_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-in2out-fast");
  sm->in2out_fast_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-in2out-slowpath");
  sm->in2out_slowpath_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-in2out-output-slowpath");
  sm->in2out_slowpath_output_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ed-in2out-slowpath");
  sm->ed_in2out_slowpath_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-out2in-fast");
  sm->out2in_fast_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ed-out2in-slowpath");
  sm->ed_out2in_slowpath_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-hairpinning");
  sm->hairpinning_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-hairpin-dst");
  sm->hairpin_dst_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-hairpin-src");
  sm->hairpin_src_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ed-hairpinning");
  sm->ed_hairpinning_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ed-hairpin-dst");
  sm->ed_hairpin_dst_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ed-hairpin-src");
  sm->ed_hairpin_src_node_index = node->index;
}

#define nat_init_simple_counter(c, n, sn) \
do                                        \
  {                                       \
    c.name = n;                           \
    c.stat_segment_name = sn;             \
    vlib_validate_simple_counter (&c, 0); \
    vlib_zero_simple_counter (&c, 0);     \
  } while (0);

static clib_error_t *
nat_init (vlib_main_t * vm)
{
  snat_main_t *sm = &snat_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_thread_registration_t *tr;
  ip4_add_del_interface_address_callback_t cbi = { 0 };
  ip4_table_bind_callback_t cbt = { 0 };
  u32 i, num_threads = 0;
  uword *p, *bitmap = 0;

  clib_memset (sm, 0, sizeof (*sm));

  // required
  sm->vnet_main = vnet_get_main ();
  // convenience
  sm->ip4_main = &ip4_main;
  sm->api_main = vlibapi_get_main ();
  sm->ip4_lookup_main = &ip4_main.lookup_main;

  // frame queue indices used for handoff
  sm->fq_out2in_index = ~0;
  sm->fq_in2out_index = ~0;
  sm->fq_in2out_output_index = ~0;

  sm->log_level = SNAT_LOG_ERROR;

  nat44_set_node_indexes (sm, vm);
  sm->log_class = vlib_log_register_class ("nat", 0);
  nat_ipfix_logging_init (vm);

  nat_init_simple_counter (sm->total_users, "total-users",
			   "/nat44/total-users");
  nat_init_simple_counter (sm->total_sessions, "total-sessions",
			   "/nat44/total-sessions");
  nat_init_simple_counter (sm->user_limit_reached, "user-limit-reached",
			   "/nat44/user-limit-reached");

#define _(x)                                            \
  sm->counters.fastpath.in2out.x.name = #x;             \
  sm->counters.fastpath.in2out.x.stat_segment_name =    \
      "/nat44/in2out/fastpath/" #x;                     \
  sm->counters.slowpath.in2out.x.name = #x;             \
  sm->counters.slowpath.in2out.x.stat_segment_name =    \
      "/nat44/in2out/slowpath/" #x;                     \
  sm->counters.fastpath.out2in.x.name = #x;             \
  sm->counters.fastpath.out2in.x.stat_segment_name =    \
      "/nat44/out2in/fastpath/" #x;                     \
  sm->counters.slowpath.out2in.x.name = #x;             \
  sm->counters.slowpath.out2in.x.stat_segment_name =    \
      "/nat44/out2in/slowpath/" #x;                     \
  sm->counters.fastpath.in2out_ed.x.name = #x;          \
  sm->counters.fastpath.in2out_ed.x.stat_segment_name = \
      "/nat44/ed/in2out/fastpath/" #x;                  \
  sm->counters.slowpath.in2out_ed.x.name = #x;          \
  sm->counters.slowpath.in2out_ed.x.stat_segment_name = \
      "/nat44/ed/in2out/slowpath/" #x;                  \
  sm->counters.fastpath.out2in_ed.x.name = #x;          \
  sm->counters.fastpath.out2in_ed.x.stat_segment_name = \
      "/nat44/ed/out2in/fastpath/" #x;                  \
  sm->counters.slowpath.out2in_ed.x.name = #x;          \
  sm->counters.slowpath.out2in_ed.x.stat_segment_name = \
      "/nat44/ed/out2in/slowpath/" #x;
  foreach_nat_counter;
#undef _
  sm->counters.hairpinning.name = "hairpinning";
  sm->counters.hairpinning.stat_segment_name = "/nat44/hairpinning";

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
  num_threads = tm->n_vlib_mains - 1;
  sm->port_per_thread = 0xffff - 1024;
  vec_validate (sm->per_thread_data, num_threads);

  /* Use all available workers by default */
  if (sm->num_workers > 1)
    {

      for (i = 0; i < sm->num_workers; i++)
	bitmap = clib_bitmap_set (bitmap, i, 1);
      snat_set_workers (bitmap);
      clib_bitmap_free (bitmap);
    }
  else
    sm->per_thread_data[0].snat_thread_index = 0;

  /* callbacks to call when interface address changes. */
  cbi.function = snat_ip4_add_del_interface_address_cb;
  vec_add1 (sm->ip4_main->add_del_interface_address_callbacks, cbi);
  cbi.function = nat_ip4_add_del_addr_only_sm_cb;
  vec_add1 (sm->ip4_main->add_del_interface_address_callbacks, cbi);

  /* callbacks to call when interface to table biding changes */
  cbt.function = snat_update_outside_fib;
  vec_add1 (sm->ip4_main->table_bind_callbacks, cbt);

  sm->fib_src_low =
    fib_source_allocate ("nat-low", FIB_SOURCE_PRIORITY_LOW,
			 FIB_SOURCE_BH_SIMPLE);
  sm->fib_src_hi =
    fib_source_allocate ("nat-hi", FIB_SOURCE_PRIORITY_HI,
			 FIB_SOURCE_BH_SIMPLE);

  /* used only by out2in-dpo feature */
  nat_dpo_module_init ();

  nat_affinity_init (vm);
  nat_ha_init (vm, sm->num_workers, num_threads);

  test_key_calc_split ();
  return nat44_api_hookup (vm);
}

VLIB_INIT_FUNCTION (nat_init);

int
nat44_plugin_enable (nat44_config_t c)
{
  snat_main_t *sm = &snat_main;
  u32 static_mapping_buckets = 1024;
  u32 static_mapping_memory_size = 64 << 20;

  if (sm->enabled)
    {
      nat_log_err ("nat44 is enabled");
      return 1;
    }

  // c.static_mapping_only + c.connection_tracking
  //  - supported in NAT EI & NAT ED
  // c.out2in_dpo, c.static_mapping_only
  //  - supported in NAT EI

  if (c.endpoint_dependent)
    {
      if ((c.static_mapping_only && !c.connection_tracking) || c.out2in_dpo)
	{
	  nat_log_err ("unsupported combination of configuration");
	  return 1;
	}
      if (c.users || c.user_sessions)
	{
	  nat_log_err ("unsupported combination of configuration");
	  return 1;
	}
    }

  // reset to defaults:
  sm->alloc_addr_and_port = nat_alloc_addr_and_port_default;
  sm->addr_and_port_alloc_alg = NAT_ADDR_AND_PORT_ALLOC_ALG_DEFAULT;
  //
  nat_reset_timeouts (&sm->timeouts);

  // nat44 feature configuration
  sm->endpoint_dependent = c.endpoint_dependent;
  sm->static_mapping_only = c.static_mapping_only;
  sm->static_mapping_connection_tracking = c.connection_tracking;
  sm->forwarding_enabled = 0;
  sm->mss_clamping = 0;

  if (!c.users)
    c.users = 1024;

  sm->max_users_per_thread = c.users;
  sm->user_buckets = nat_calc_bihash_buckets (c.users);

  if (!c.sessions)
    c.sessions = 10 * 1024;

  sm->max_translations_per_thread = c.sessions;
  sm->translation_buckets = nat_calc_bihash_buckets (c.sessions);

  vec_add1 (sm->max_translations_per_fib, sm->max_translations_per_thread);
  sm->max_translations_per_user
    = c.user_sessions ? c.user_sessions : sm->max_translations_per_thread;

  sm->outside_vrf_id = c.outside_vrf;
  sm->outside_fib_index =
    fib_table_find_or_create_and_lock
    (FIB_PROTOCOL_IP4, c.outside_vrf, sm->fib_src_hi);

  sm->inside_vrf_id = c.inside_vrf;
  sm->inside_fib_index =
    fib_table_find_or_create_and_lock
    (FIB_PROTOCOL_IP4, c.inside_vrf, sm->fib_src_hi);

  if (c.endpoint_dependent)
    {
      sm->worker_out2in_cb = nat44_ed_get_worker_out2in_cb;
      sm->worker_in2out_cb = nat44_ed_get_worker_in2out_cb;
      sm->out2in_node_index = sm->ed_out2in_node_index;
      sm->in2out_node_index = sm->ed_in2out_node_index;
      sm->in2out_output_node_index = sm->ed_in2out_output_node_index;
      sm->icmp_match_out2in_cb = icmp_match_out2in_ed;
      sm->icmp_match_in2out_cb = icmp_match_in2out_ed;

      // try to move it into nat44_db_init,
      // consider static mapping requirements
      clib_bihash_init_16_8 (&sm->out2in_ed, "out2in-ed",
			     sm->translation_buckets, 0);
      clib_bihash_set_kvp_format_fn_16_8 (&sm->out2in_ed,
					  format_ed_session_kvp);


      nat_affinity_enable ();

      nat_ha_enable (nat_ha_sadd_ed_cb, nat_ha_sdel_ed_cb, nat_ha_sref_ed_cb);
    }
  else
    {
      sm->worker_out2in_cb = snat_get_worker_out2in_cb;
      sm->worker_in2out_cb = snat_get_worker_in2out_cb;
      sm->out2in_node_index = sm->ei_out2in_node_index;
      sm->in2out_node_index = sm->ei_in2out_node_index;
      sm->in2out_output_node_index = sm->ei_in2out_output_node_index;
      sm->icmp_match_out2in_cb = icmp_match_out2in_slow;
      sm->icmp_match_in2out_cb = icmp_match_in2out_slow;

      nat_ha_enable (nat_ha_sadd_cb, nat_ha_sdel_cb, nat_ha_sref_cb);
    }

  // c.static_mapping & c.connection_tracking require
  // session database
  if (!c.static_mapping_only
      || (c.static_mapping_only && c.connection_tracking))
    {
      snat_main_per_thread_data_t *tsm;
      /* *INDENT-OFF* */
      vec_foreach (tsm, sm->per_thread_data)
        {
          nat44_db_init (tsm);
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
			static_mapping_buckets, static_mapping_memory_size);
  clib_bihash_set_kvp_format_fn_8_8 (&sm->static_mapping_by_external,
				     format_static_mapping_kvp);

  // last: reset counters
  vlib_zero_simple_counter (&sm->total_users, 0);
  vlib_zero_simple_counter (&sm->total_sessions, 0);
  vlib_zero_simple_counter (&sm->user_limit_reached, 0);

  sm->enabled = 1;
  sm->rconfig = c;

  return 0;
}

void
nat44_addresses_free (snat_address_t ** addresses)
{
  snat_address_t *ap;
  /* *INDENT-OFF* */
  vec_foreach (ap, *addresses)
    {
    #define _(N, i, n, s) \
      vec_free (ap->busy_##n##_ports_per_thread);
      foreach_nat_protocol
    #undef _
    }
  /* *INDENT-ON* */
  vec_free (*addresses);
  *addresses = 0;
}

int
nat44_plugin_disable ()
{
  snat_main_t *sm = &snat_main;
  snat_interface_t *i, *vec;
  int error = 0;

  if (!sm->enabled)
    {
      nat_log_err ("nat44 is disabled");
      return 1;
    }

  nat_ha_disable ();

  // first unregister all nodes from interfaces
  vec = vec_dup (sm->interfaces);
  /* *INDENT-OFF* */
  vec_foreach (i, vec)
    {
      if (nat_interface_is_inside(i))
        error = snat_interface_add_del (i->sw_if_index, 1, 1);
      if (nat_interface_is_outside(i))
        error = snat_interface_add_del (i->sw_if_index, 0, 1);

      if (error)
        {
          nat_log_err ("error occurred while removing interface %u",
                       i->sw_if_index);
        }
    }
  /* *INDENT-ON* */
  vec_free (vec);
  sm->interfaces = 0;

  vec = vec_dup (sm->output_feature_interfaces);
  /* *INDENT-OFF* */
  vec_foreach (i, vec)
    {
      if (nat_interface_is_inside(i))
        error = snat_interface_add_del_output_feature (i->sw_if_index, 1, 1);
      if (nat_interface_is_outside(i))
        error = snat_interface_add_del_output_feature (i->sw_if_index, 0, 1);

      if (error)
        {
          nat_log_err ("error occurred while removing interface %u",
                       i->sw_if_index);
        }
    }
  /* *INDENT-ON* */
  vec_free (vec);
  sm->output_feature_interfaces = 0;

  vec_free (sm->max_translations_per_fib);

  if (sm->endpoint_dependent)
    {
      nat_affinity_disable ();
      clib_bihash_free_16_8 (&sm->out2in_ed);
    }

  clib_bihash_free_8_8 (&sm->static_mapping_by_local);
  clib_bihash_free_8_8 (&sm->static_mapping_by_external);

  if (!sm->static_mapping_only ||
      (sm->static_mapping_only && sm->static_mapping_connection_tracking))
    {
      snat_main_per_thread_data_t *tsm;
     /* *INDENT-OFF* */
      vec_foreach (tsm, sm->per_thread_data)
        {
          nat44_db_free (tsm);
        }
      /* *INDENT-ON* */
    }

  pool_free (sm->static_mappings);

  nat44_addresses_free (&sm->addresses);
  nat44_addresses_free (&sm->twice_nat_addresses);


  vec_free (sm->to_resolve);
  vec_free (sm->auto_add_sw_if_indices);
  vec_free (sm->auto_add_sw_if_indices_twice_nat);

  sm->to_resolve = 0;
  sm->auto_add_sw_if_indices = 0;
  sm->auto_add_sw_if_indices_twice_nat = 0;

  sm->forwarding_enabled = 0;

  sm->enabled = 0;
  clib_memset (&sm->rconfig, 0, sizeof (sm->rconfig));

  return 0;
}

void
snat_free_outside_address_and_port (snat_address_t * addresses,
				    u32 thread_index,
				    ip4_address_t * addr,
				    u16 port, nat_protocol_t protocol)
{
  snat_address_t *a;
  u32 address_index;
  u16 port_host_byte_order = clib_net_to_host_u16 (port);

  for (address_index = 0; address_index < vec_len (addresses);
       address_index++)
    {
      if (addresses[address_index].addr.as_u32 == addr->as_u32)
	break;
    }

  ASSERT (address_index < vec_len (addresses));

  a = addresses + address_index;

  switch (protocol)
    {
#define _(N, i, n, s) \
    case NAT_PROTOCOL_##N: \
      ASSERT (a->busy_##n##_port_refcounts[port_host_byte_order] >= 1); \
      --a->busy_##n##_port_refcounts[port_host_byte_order]; \
      a->busy_##n##_ports--; \
      a->busy_##n##_ports_per_thread[thread_index]--; \
      break;
      foreach_nat_protocol
#undef _
    default:
      nat_elog_info ("unknown protocol");
      return;
    }
}

static int
nat_set_outside_address_and_port (snat_address_t * addresses,
				  u32 thread_index, ip4_address_t addr,
				  u16 port, nat_protocol_t protocol)
{
  snat_address_t *a = 0;
  u32 address_index;
  u16 port_host_byte_order = clib_net_to_host_u16 (port);

  for (address_index = 0; address_index < vec_len (addresses);
       address_index++)
    {
      if (addresses[address_index].addr.as_u32 != addr.as_u32)
	continue;

      a = addresses + address_index;
      switch (protocol)
	{
#define _(N, j, n, s) \
        case NAT_PROTOCOL_##N: \
          if (a->busy_##n##_port_refcounts[port_host_byte_order]) \
            return VNET_API_ERROR_INSTANCE_IN_USE; \
	  ++a->busy_##n##_port_refcounts[port_host_byte_order]; \
          a->busy_##n##_ports_per_thread[thread_index]++; \
          a->busy_##n##_ports++; \
          return 0;
	  foreach_nat_protocol
#undef _
	default:
	  nat_elog_info ("unknown protocol");
	  return 1;
	}
    }

  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

int
snat_static_mapping_match (snat_main_t * sm,
			   ip4_address_t match_addr,
			   u16 match_port,
			   u32 match_fib_index,
			   nat_protocol_t match_protocol,
			   ip4_address_t * mapping_addr,
			   u16 * mapping_port,
			   u32 * mapping_fib_index,
			   u8 by_external,
			   u8 * is_addr_only,
			   twice_nat_type_t * twice_nat,
			   lb_nat_type_t * lb, ip4_address_t * ext_host_addr,
			   u8 * is_identity_nat, snat_static_mapping_t ** out)
{
  clib_bihash_kv_8_8_t kv, value;
  clib_bihash_8_8_t *mapping_hash;
  snat_static_mapping_t *m;
  u32 rand, lo = 0, hi, mid, *tmp = 0, i;
  nat44_lb_addr_port_t *local;
  u8 backend_index;

  if (!by_external)
    {
      mapping_hash = &sm->static_mapping_by_local;
      init_nat_k (&kv, match_addr, match_port, match_fib_index,
		  match_protocol);
      if (clib_bihash_search_8_8 (mapping_hash, &kv, &value))
	{
	  /* Try address only mapping */
	  init_nat_k (&kv, match_addr, 0, match_fib_index, 0);
	  if (clib_bihash_search_8_8 (mapping_hash, &kv, &value))
	    return 1;
	}
    }
  else
    {
      mapping_hash = &sm->static_mapping_by_external;
      init_nat_k (&kv, match_addr, match_port, 0, match_protocol);
      if (clib_bihash_search_8_8 (mapping_hash, &kv, &value))
	{
	  /* Try address only mapping */
	  init_nat_k (&kv, match_addr, 0, 0, 0);
	  if (clib_bihash_search_8_8 (mapping_hash, &kv, &value))
	    return 1;
	}
    }

  m = pool_elt_at_index (sm->static_mappings, value.value);

  if (by_external)
    {
      if (is_lb_static_mapping (m))
	{
	  if (PREDICT_FALSE (lb != 0))
	    *lb = m->affinity ? AFFINITY_LB_NAT : LB_NAT;
	  if (m->affinity && !nat_affinity_find_and_lock (ext_host_addr[0],
							  match_addr,
							  match_protocol,
							  match_port,
							  &backend_index))
	    {
	      local = pool_elt_at_index (m->locals, backend_index);
	      *mapping_addr = local->addr;
	      *mapping_port = local->port;
	      *mapping_fib_index = local->fib_index;
	      goto end;
	    }
	  // pick locals matching this worker
	  if (PREDICT_FALSE (sm->num_workers > 1))
	    {
	      u32 thread_index = vlib_get_thread_index ();
              /* *INDENT-OFF* */
              pool_foreach_index (i, m->locals,
              ({
                local = pool_elt_at_index (m->locals, i);

                ip4_header_t ip = {
		  .src_address = local->addr,
	        };

	        if (sm->worker_in2out_cb (&ip, m->fib_index, 0) ==
		    thread_index)
                  {
                    vec_add1 (tmp, i);
                  }
              }));
              /* *INDENT-ON* */
	      ASSERT (vec_len (tmp) != 0);
	    }
	  else
	    {
              /* *INDENT-OFF* */
              pool_foreach_index (i, m->locals,
              ({
                vec_add1 (tmp, i);
              }));
              /* *INDENT-ON* */
	    }
	  hi = vec_len (tmp) - 1;
	  local = pool_elt_at_index (m->locals, tmp[hi]);
	  rand = 1 + (random_u32 (&sm->random_seed) % local->prefix);
	  while (lo < hi)
	    {
	      mid = ((hi - lo) >> 1) + lo;
	      local = pool_elt_at_index (m->locals, tmp[mid]);
	      (rand > local->prefix) ? (lo = mid + 1) : (hi = mid);
	    }
	  local = pool_elt_at_index (m->locals, tmp[lo]);
	  if (!(local->prefix >= rand))
	    return 1;
	  *mapping_addr = local->addr;
	  *mapping_port = local->port;
	  *mapping_fib_index = local->fib_index;
	  if (m->affinity)
	    {
	      if (nat_affinity_create_and_lock (ext_host_addr[0], match_addr,
						match_protocol, match_port,
						tmp[lo], m->affinity,
						m->affinity_per_service_list_head_index))
		nat_elog_info ("create affinity record failed");
	    }
	  vec_free (tmp);
	}
      else
	{
	  if (PREDICT_FALSE (lb != 0))
	    *lb = NO_LB_NAT;
	  *mapping_fib_index = m->fib_index;
	  *mapping_addr = m->local_addr;
	  /* Address only mapping doesn't change port */
	  *mapping_port = is_addr_only_static_mapping (m) ? match_port
	    : m->local_port;
	}
    }
  else
    {
      *mapping_addr = m->external_addr;
      /* Address only mapping doesn't change port */
      *mapping_port = is_addr_only_static_mapping (m) ? match_port
	: m->external_port;
      *mapping_fib_index = sm->outside_fib_index;
    }

end:
  if (PREDICT_FALSE (is_addr_only != 0))
    *is_addr_only = is_addr_only_static_mapping (m);

  if (PREDICT_FALSE (twice_nat != 0))
    *twice_nat = m->twice_nat;

  if (PREDICT_FALSE (is_identity_nat != 0))
    *is_identity_nat = is_identity_static_mapping (m);

  if (out != 0)
    *out = m;

  return 0;
}

int
snat_alloc_outside_address_and_port (snat_address_t * addresses,
				     u32 fib_index,
				     u32 thread_index,
				     nat_protocol_t proto,
				     ip4_address_t * addr,
				     u16 * port,
				     u16 port_per_thread,
				     u32 snat_thread_index)
{
  snat_main_t *sm = &snat_main;

  return sm->alloc_addr_and_port (addresses, fib_index, thread_index, proto,
				  addr, port, port_per_thread,
				  snat_thread_index);
}

static int
nat_alloc_addr_and_port_default (snat_address_t * addresses,
				 u32 fib_index,
				 u32 thread_index,
				 nat_protocol_t proto,
				 ip4_address_t * addr,
				 u16 * port,
				 u16 port_per_thread, u32 snat_thread_index)
{
  int i;
  snat_address_t *a, *ga = 0;
  u32 portnum;

  for (i = 0; i < vec_len (addresses); i++)
    {
      a = addresses + i;
      switch (proto)
	{
#define _(N, j, n, s) \
        case NAT_PROTOCOL_##N: \
          if (a->busy_##n##_ports_per_thread[thread_index] < port_per_thread) \
            { \
              if (a->fib_index == fib_index) \
                { \
                  while (1) \
                    { \
                      portnum = (port_per_thread * \
                        snat_thread_index) + \
                        snat_random_port(0, port_per_thread - 1) + 1024; \
                      if (a->busy_##n##_port_refcounts[portnum]) \
                        continue; \
		      --a->busy_##n##_port_refcounts[portnum]; \
                      a->busy_##n##_ports_per_thread[thread_index]++; \
                      a->busy_##n##_ports++; \
                      *addr = a->addr; \
                      *port = clib_host_to_net_u16(portnum); \
                      return 0; \
                    } \
                } \
              else if (a->fib_index == ~0) \
                { \
                  ga = a; \
                } \
            } \
          break;
	  foreach_nat_protocol
#undef _
	default:
	  nat_elog_info ("unknown protocol");
	  return 1;
	}

    }

  if (ga)
    {
      a = ga;
      switch (proto)
	{
#define _(N, j, n, s) \
        case NAT_PROTOCOL_##N: \
          while (1) \
            { \
              portnum = (port_per_thread * \
                snat_thread_index) + \
                snat_random_port(0, port_per_thread - 1) + 1024; \
	      if (a->busy_##n##_port_refcounts[portnum]) \
                continue; \
	      ++a->busy_##n##_port_refcounts[portnum]; \
              a->busy_##n##_ports_per_thread[thread_index]++; \
              a->busy_##n##_ports++; \
              *addr = a->addr; \
              *port = clib_host_to_net_u16(portnum); \
              return 0; \
            }
	  break;
	  foreach_nat_protocol
#undef _
	default:
	  nat_elog_info ("unknown protocol");
	  return 1;
	}
    }

  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

static int
nat_alloc_addr_and_port_mape (snat_address_t * addresses, u32 fib_index,
			      u32 thread_index, nat_protocol_t proto,
			      ip4_address_t * addr, u16 * port,
			      u16 port_per_thread, u32 snat_thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_address_t *a = addresses;
  u16 m, ports, portnum, A, j;
  m = 16 - (sm->psid_offset + sm->psid_length);
  ports = (1 << (16 - sm->psid_length)) - (1 << m);

  if (!vec_len (addresses))
    goto exhausted;

  switch (proto)
    {
#define _(N, i, n, s) \
    case NAT_PROTOCOL_##N: \
      if (a->busy_##n##_ports < ports) \
        { \
          while (1) \
            { \
              A = snat_random_port(1, pow2_mask(sm->psid_offset)); \
              j = snat_random_port(0, pow2_mask(m)); \
              portnum = A | (sm->psid << sm->psid_offset) | (j << (16 - m)); \
	      if (a->busy_##n##_port_refcounts[portnum]) \
                continue; \
	      ++a->busy_##n##_port_refcounts[portnum]; \
              a->busy_##n##_ports++; \
              *addr = a->addr; \
              *port = clib_host_to_net_u16 (portnum); \
              return 0; \
            } \
        } \
      break;
      foreach_nat_protocol
#undef _
    default:
      nat_elog_info ("unknown protocol");
      return 1;
    }

exhausted:
  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

static int
nat_alloc_addr_and_port_range (snat_address_t * addresses, u32 fib_index,
			       u32 thread_index, nat_protocol_t proto,
			       ip4_address_t * addr, u16 * port,
			       u16 port_per_thread, u32 snat_thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_address_t *a = addresses;
  u16 portnum, ports;

  ports = sm->end_port - sm->start_port + 1;

  if (!vec_len (addresses))
    goto exhausted;

  switch (proto)
    {
#define _(N, i, n, s) \
    case NAT_PROTOCOL_##N: \
      if (a->busy_##n##_ports < ports) \
        { \
          while (1) \
            { \
              portnum = snat_random_port(sm->start_port, sm->end_port); \
	      if (a->busy_##n##_port_refcounts[portnum]) \
                continue; \
	      ++a->busy_##n##_port_refcounts[portnum]; \
              a->busy_##n##_ports++; \
              *addr = a->addr; \
              *port = clib_host_to_net_u16 (portnum); \
              return 0; \
            } \
        } \
      break;
      foreach_nat_protocol
#undef _
    default:
      nat_elog_info ("unknown protocol");
      return 1;
    }

exhausted:
  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

void
nat44_add_del_address_dpo (ip4_address_t addr, u8 is_add)
{
  snat_main_t *sm = &snat_main;
  dpo_id_t dpo_v4 = DPO_INVALID;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr.ip4.as_u32 = addr.as_u32,
  };

  if (is_add)
    {
      nat_dpo_create (DPO_PROTO_IP4, 0, &dpo_v4);
      fib_table_entry_special_dpo_add (0, &pfx, sm->fib_src_hi,
				       FIB_ENTRY_FLAG_EXCLUSIVE, &dpo_v4);
      dpo_reset (&dpo_v4);
    }
  else
    {
      fib_table_entry_special_remove (0, &pfx, sm->fib_src_hi);
    }
}

static u32
snat_get_worker_in2out_cb (ip4_header_t * ip0, u32 rx_fib_index0,
			   u8 is_output)
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
snat_get_worker_out2in_cb (vlib_buffer_t * b, ip4_header_t * ip0,
			   u32 rx_fib_index0, u8 is_output)
{
  snat_main_t *sm = &snat_main;
  udp_header_t *udp;
  u16 port;
  clib_bihash_kv_8_8_t kv, value;
  snat_static_mapping_t *m;
  u32 proto;
  u32 next_worker_index = 0;

  /* first try static mappings without port */
  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
    {
      init_nat_k (&kv, ip0->dst_address, 0, rx_fib_index0, 0);
      if (!clib_bihash_search_8_8
	  (&sm->static_mapping_by_external, &kv, &value))
	{
	  m = pool_elt_at_index (sm->static_mappings, value.value);
	  return m->workers[0];
	}
    }

  proto = ip_proto_to_nat_proto (ip0->protocol);
  udp = ip4_next_header (ip0);
  port = udp->dst_port;

  /* unknown protocol */
  if (PREDICT_FALSE (proto == NAT_PROTOCOL_OTHER))
    {
      /* use current thread */
      return vlib_get_thread_index ();
    }

  if (PREDICT_FALSE (ip0->protocol == IP_PROTOCOL_ICMP))
    {
      icmp46_header_t *icmp = (icmp46_header_t *) udp;
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      if (!icmp_type_is_error_message
	  (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags))
	port = vnet_buffer (b)->ip.reass.l4_src_port;
      else
	{
	  /* if error message, then it's not fragmented and we can access it */
	  ip4_header_t *inner_ip = (ip4_header_t *) (echo + 1);
	  proto = ip_proto_to_nat_proto (inner_ip->protocol);
	  void *l4_header = ip4_next_header (inner_ip);
	  switch (proto)
	    {
	    case NAT_PROTOCOL_ICMP:
	      icmp = (icmp46_header_t *) l4_header;
	      echo = (icmp_echo_header_t *) (icmp + 1);
	      port = echo->identifier;
	      break;
	    case NAT_PROTOCOL_UDP:
	    case NAT_PROTOCOL_TCP:
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
      init_nat_k (&kv, ip0->dst_address, port, rx_fib_index0, proto);
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
nat44_ed_get_worker_in2out_cb (ip4_header_t * ip, u32 rx_fib_index,
			       u8 is_output)
{
  snat_main_t *sm = &snat_main;
  u32 next_worker_index = sm->first_worker_index;
  u32 hash;

  clib_bihash_kv_16_8_t kv16, value16;
  snat_main_per_thread_data_t *tsm;
  udp_header_t *udp;

  if (PREDICT_FALSE (is_output))
    {
      u32 fib_index = sm->outside_fib_index;
      nat_outside_fib_t *outside_fib;
      fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
      fib_prefix_t pfx = {
	.fp_proto = FIB_PROTOCOL_IP4,
	.fp_len = 32,
	.fp_addr = {
		    .ip4.as_u32 = ip->dst_address.as_u32,
		    }
	,
      };

      udp = ip4_next_header (ip);

      switch (vec_len (sm->outside_fibs))
	{
	case 0:
	  fib_index = sm->outside_fib_index;
	  break;
	case 1:
	  fib_index = sm->outside_fibs[0].fib_index;
	  break;
	default:
            /* *INDENT-OFF* */
            vec_foreach (outside_fib, sm->outside_fibs)
              {
                fei = fib_table_lookup (outside_fib->fib_index, &pfx);
                if (FIB_NODE_INDEX_INVALID != fei)
                  {
                    if (fib_entry_get_resolving_interface (fei) != ~0)
                      {
                        fib_index = outside_fib->fib_index;
                        break;
                      }
                  }
              }
            /* *INDENT-ON* */
	  break;
	}

      init_ed_k (&kv16, ip->src_address, udp->src_port, ip->dst_address,
		 udp->dst_port, fib_index, ip->protocol);

      if (PREDICT_TRUE (!clib_bihash_search_16_8 (&sm->out2in_ed,
						  &kv16, &value16)))
	{
	  tsm =
	    vec_elt_at_index (sm->per_thread_data,
			      ed_value_get_thread_index (&value16));
	  next_worker_index += tsm->thread_index;

	  nat_elog_debug_handoff ("HANDOFF IN2OUT-OUTPUT-FEATURE (session)",
				  next_worker_index, fib_index,
				  clib_net_to_host_u32 (ip->
							src_address.as_u32),
				  clib_net_to_host_u32 (ip->
							dst_address.as_u32));

	  return next_worker_index;
	}
    }

  hash = ip->src_address.as_u32 + (ip->src_address.as_u32 >> 8) +
    (ip->src_address.as_u32 >> 16) + (ip->src_address.as_u32 >> 24);

  if (PREDICT_TRUE (is_pow2 (_vec_len (sm->workers))))
    next_worker_index += sm->workers[hash & (_vec_len (sm->workers) - 1)];
  else
    next_worker_index += sm->workers[hash % _vec_len (sm->workers)];

  if (PREDICT_TRUE (!is_output))
    {
      nat_elog_debug_handoff ("HANDOFF IN2OUT",
			      next_worker_index, rx_fib_index,
			      clib_net_to_host_u32 (ip->src_address.as_u32),
			      clib_net_to_host_u32 (ip->dst_address.as_u32));
    }
  else
    {
      nat_elog_debug_handoff ("HANDOFF IN2OUT-OUTPUT-FEATURE",
			      next_worker_index, rx_fib_index,
			      clib_net_to_host_u32 (ip->src_address.as_u32),
			      clib_net_to_host_u32 (ip->dst_address.as_u32));
    }

  return next_worker_index;
}

static u32
nat44_ed_get_worker_out2in_cb (vlib_buffer_t * b, ip4_header_t * ip,
			       u32 rx_fib_index, u8 is_output)
{
  snat_main_t *sm = &snat_main;
  clib_bihash_kv_8_8_t kv, value;
  clib_bihash_kv_16_8_t kv16, value16;
  snat_main_per_thread_data_t *tsm;

  u32 proto, next_worker_index = 0;
  udp_header_t *udp;
  u16 port;
  snat_static_mapping_t *m;
  u32 hash;

  proto = ip_proto_to_nat_proto (ip->protocol);

  if (PREDICT_TRUE (proto == NAT_PROTOCOL_UDP || proto == NAT_PROTOCOL_TCP))
    {
      udp = ip4_next_header (ip);

      init_ed_k (&kv16, ip->dst_address, udp->dst_port, ip->src_address,
		 udp->src_port, rx_fib_index, ip->protocol);

      if (PREDICT_TRUE (!clib_bihash_search_16_8 (&sm->out2in_ed,
						  &kv16, &value16)))
	{
	  tsm =
	    vec_elt_at_index (sm->per_thread_data,
			      ed_value_get_thread_index (&value16));
	  vnet_buffer2 (b)->nat.ed_out2in_nat_session_index =
	    ed_value_get_session_index (&value16);
	  next_worker_index = sm->first_worker_index + tsm->thread_index;
	  nat_elog_debug_handoff ("HANDOFF OUT2IN (session)",
				  next_worker_index, rx_fib_index,
				  clib_net_to_host_u32 (ip->
							src_address.as_u32),
				  clib_net_to_host_u32 (ip->
							dst_address.as_u32));
	  return next_worker_index;
	}
    }
  else if (proto == NAT_PROTOCOL_ICMP)
    {
      if (!get_icmp_o2i_ed_key (b, ip, rx_fib_index, ~0, ~0, 0, 0, 0, &kv16))
	{
	  if (PREDICT_TRUE (!clib_bihash_search_16_8 (&sm->out2in_ed,
						      &kv16, &value16)))
	    {
	      tsm =
		vec_elt_at_index (sm->per_thread_data,
				  ed_value_get_thread_index (&value16));
	      next_worker_index = sm->first_worker_index + tsm->thread_index;
	      nat_elog_debug_handoff ("HANDOFF OUT2IN (session)",
				      next_worker_index, rx_fib_index,
				      clib_net_to_host_u32 (ip->
							    src_address.as_u32),
				      clib_net_to_host_u32 (ip->
							    dst_address.as_u32));
	      return next_worker_index;
	    }
	}
    }

  /* first try static mappings without port */
  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
    {
      init_nat_k (&kv, ip->dst_address, 0, 0, 0);
      if (!clib_bihash_search_8_8
	  (&sm->static_mapping_by_external, &kv, &value))
	{
	  m = pool_elt_at_index (sm->static_mappings, value.value);
	  next_worker_index = m->workers[0];
	  goto done;
	}
    }

  /* unknown protocol */
  if (PREDICT_FALSE (proto == NAT_PROTOCOL_OTHER))
    {
      /* use current thread */
      next_worker_index = vlib_get_thread_index ();
      goto done;
    }

  udp = ip4_next_header (ip);
  port = udp->dst_port;

  if (PREDICT_FALSE (ip->protocol == IP_PROTOCOL_ICMP))
    {
      icmp46_header_t *icmp = (icmp46_header_t *) udp;
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      if (!icmp_type_is_error_message
	  (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags))
	port = vnet_buffer (b)->ip.reass.l4_src_port;
      else
	{
	  /* if error message, then it's not fragmented and we can access it */
	  ip4_header_t *inner_ip = (ip4_header_t *) (echo + 1);
	  proto = ip_proto_to_nat_proto (inner_ip->protocol);
	  void *l4_header = ip4_next_header (inner_ip);
	  switch (proto)
	    {
	    case NAT_PROTOCOL_ICMP:
	      icmp = (icmp46_header_t *) l4_header;
	      echo = (icmp_echo_header_t *) (icmp + 1);
	      port = echo->identifier;
	      break;
	    case NAT_PROTOCOL_UDP:
	    case NAT_PROTOCOL_TCP:
	      port = ((tcp_udp_header_t *) l4_header)->src_port;
	      break;
	    default:
	      next_worker_index = vlib_get_thread_index ();
	      goto done;
	    }
	}
    }

  /* try static mappings with port */
  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
    {
      init_nat_k (&kv, ip->dst_address, port, 0, proto);
      if (!clib_bihash_search_8_8
	  (&sm->static_mapping_by_external, &kv, &value))
	{
	  m = pool_elt_at_index (sm->static_mappings, value.value);
	  if (!is_lb_static_mapping (m))
	    {
	      next_worker_index = m->workers[0];
	      goto done;
	    }

	  hash = ip->src_address.as_u32 + (ip->src_address.as_u32 >> 8) +
	    (ip->src_address.as_u32 >> 16) + (ip->src_address.as_u32 >> 24);

	  if (PREDICT_TRUE (is_pow2 (_vec_len (m->workers))))
	    next_worker_index =
	      m->workers[hash & (_vec_len (m->workers) - 1)];
	  else
	    next_worker_index = m->workers[hash % _vec_len (m->workers)];
	  goto done;
	}
    }

  /* worker by outside port */
  next_worker_index = sm->first_worker_index;
  next_worker_index +=
    sm->workers[(clib_net_to_host_u16 (port) - 1024) / sm->port_per_thread];

done:
  nat_elog_debug_handoff ("HANDOFF OUT2IN", next_worker_index, rx_fib_index,
			  clib_net_to_host_u32 (ip->src_address.as_u32),
			  clib_net_to_host_u32 (ip->dst_address.as_u32));
  return next_worker_index;
}

void
nat_ha_sadd_cb (ip4_address_t * in_addr, u16 in_port,
		ip4_address_t * out_addr, u16 out_port,
		ip4_address_t * eh_addr, u16 eh_port,
		ip4_address_t * ehn_addr, u16 ehn_port, u8 proto,
		u32 fib_index, u16 flags, u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  snat_user_t *u;
  snat_session_t *s;
  clib_bihash_kv_8_8_t kv;
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);
  nat_outside_fib_t *outside_fib;
  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
		.ip4.as_u32 = eh_addr->as_u32,
		},
  };

  if (!(flags & SNAT_SESSION_FLAG_STATIC_MAPPING))
    {
      if (nat_set_outside_address_and_port
	  (sm->addresses, thread_index, *out_addr, out_port, proto))
	return;
    }

  u = nat_user_get_or_create (sm, in_addr, fib_index, thread_index);
  if (!u)
    return;

  s = nat_session_alloc_or_recycle (sm, u, thread_index, now);
  if (!s)
    return;

  if (sm->endpoint_dependent)
    {
      nat_ed_lru_insert (tsm, s, now, nat_proto_to_ip_proto (proto));
    }

  s->out2in.addr.as_u32 = out_addr->as_u32;
  s->out2in.port = out_port;
  s->nat_proto = proto;
  s->last_heard = now;
  s->flags = flags;
  s->ext_host_addr.as_u32 = eh_addr->as_u32;
  s->ext_host_port = eh_port;
  user_session_increment (sm, u, snat_is_session_static (s));
  switch (vec_len (sm->outside_fibs))
    {
    case 0:
      s->out2in.fib_index = sm->outside_fib_index;
      break;
    case 1:
      s->out2in.fib_index = sm->outside_fibs[0].fib_index;
      break;
    default:
      /* *INDENT-OFF* */
      vec_foreach (outside_fib, sm->outside_fibs)
        {
          fei = fib_table_lookup (outside_fib->fib_index, &pfx);
          if (FIB_NODE_INDEX_INVALID != fei)
            {
              if (fib_entry_get_resolving_interface (fei) != ~0)
                {
                  s->out2in.fib_index = outside_fib->fib_index;
                  break;
                }
            }
        }
      /* *INDENT-ON* */
      break;
    }
  init_nat_o2i_kv (&kv, s, s - tsm->sessions);
  if (clib_bihash_add_del_8_8 (&tsm->out2in, &kv, 1))
    nat_elog_warn ("out2in key add failed");

  s->in2out.addr.as_u32 = in_addr->as_u32;
  s->in2out.port = in_port;
  s->in2out.fib_index = fib_index;
  init_nat_i2o_kv (&kv, s, s - tsm->sessions);
  if (clib_bihash_add_del_8_8 (&tsm->in2out, &kv, 1))
    nat_elog_warn ("in2out key add failed");
}

void
nat_ha_sdel_cb (ip4_address_t * out_addr, u16 out_port,
		ip4_address_t * eh_addr, u16 eh_port, u8 proto, u32 fib_index,
		u32 ti)
{
  snat_main_t *sm = &snat_main;
  clib_bihash_kv_8_8_t kv, value;
  u32 thread_index;
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm;

  if (sm->num_workers > 1)
    thread_index =
      sm->first_worker_index +
      (sm->workers[(clib_net_to_host_u16 (out_port) -
		    1024) / sm->port_per_thread]);
  else
    thread_index = sm->num_workers;
  tsm = vec_elt_at_index (sm->per_thread_data, thread_index);

  init_nat_k (&kv, *out_addr, out_port, fib_index, proto);
  if (clib_bihash_search_8_8 (&tsm->out2in, &kv, &value))
    return;

  s = pool_elt_at_index (tsm->sessions, value.value);
  nat_free_session_data (sm, s, thread_index, 1);
  nat44_delete_session (sm, s, thread_index);
}

void
nat_ha_sref_cb (ip4_address_t * out_addr, u16 out_port,
		ip4_address_t * eh_addr, u16 eh_port, u8 proto, u32 fib_index,
		u32 total_pkts, u64 total_bytes, u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  clib_bihash_kv_8_8_t kv, value;
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm;

  tsm = vec_elt_at_index (sm->per_thread_data, thread_index);

  init_nat_k (&kv, *out_addr, out_port, fib_index, proto);
  if (clib_bihash_search_8_8 (&tsm->out2in, &kv, &value))
    return;

  s = pool_elt_at_index (tsm->sessions, value.value);
  s->total_pkts = total_pkts;
  s->total_bytes = total_bytes;
}

void
nat_ha_sadd_ed_cb (ip4_address_t * in_addr, u16 in_port,
		   ip4_address_t * out_addr, u16 out_port,
		   ip4_address_t * eh_addr, u16 eh_port,
		   ip4_address_t * ehn_addr, u16 ehn_port, u8 proto,
		   u32 fib_index, u16 flags, u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  snat_session_t *s;
  clib_bihash_kv_16_8_t kv;
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);
  nat_outside_fib_t *outside_fib;
  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
		.ip4.as_u32 = eh_addr->as_u32,
		},
  };


  if (!(flags & SNAT_SESSION_FLAG_STATIC_MAPPING))
    {
      if (nat_set_outside_address_and_port
	  (sm->addresses, thread_index, *out_addr, out_port, proto))
	return;
    }

  if (flags & SNAT_SESSION_FLAG_TWICE_NAT)
    {
      if (nat_set_outside_address_and_port
	  (sm->addresses, thread_index, *ehn_addr, ehn_port, proto))
	return;
    }

  s = nat_ed_session_alloc (sm, thread_index, now, proto);
  if (!s)
    return;

  s->last_heard = now;
  s->flags = flags;
  s->ext_host_nat_addr.as_u32 = s->ext_host_addr.as_u32 = eh_addr->as_u32;
  s->ext_host_nat_port = s->ext_host_port = eh_port;
  if (is_twice_nat_session (s))
    {
      s->ext_host_nat_addr.as_u32 = ehn_addr->as_u32;
      s->ext_host_nat_port = ehn_port;
    }
  switch (vec_len (sm->outside_fibs))
    {
    case 0:
      s->out2in.fib_index = sm->outside_fib_index;
      break;
    case 1:
      s->out2in.fib_index = sm->outside_fibs[0].fib_index;
      break;
    default:
      /* *INDENT-OFF* */
      vec_foreach (outside_fib, sm->outside_fibs)
        {
          fei = fib_table_lookup (outside_fib->fib_index, &pfx);
          if (FIB_NODE_INDEX_INVALID != fei)
            {
              if (fib_entry_get_resolving_interface (fei) != ~0)
                {
                  s->out2in.fib_index = outside_fib->fib_index;
                  break;
                }
            }
        }
      /* *INDENT-ON* */
      break;
    }
  s->nat_proto = proto;
  s->out2in.addr.as_u32 = out_addr->as_u32;
  s->out2in.port = out_port;

  s->in2out.addr.as_u32 = in_addr->as_u32;
  s->in2out.port = in_port;
  s->in2out.fib_index = fib_index;

  init_ed_kv (&kv, *in_addr, in_port, s->ext_host_nat_addr,
	      s->ext_host_nat_port, fib_index, nat_proto_to_ip_proto (proto),
	      thread_index, s - tsm->sessions);
  if (clib_bihash_add_del_16_8 (&tsm->in2out_ed, &kv, 1))
    nat_elog_warn ("in2out key add failed");

  init_ed_kv (&kv, *out_addr, out_port, *eh_addr, eh_port,
	      s->out2in.fib_index, nat_proto_to_ip_proto (proto),
	      thread_index, s - tsm->sessions);
  if (clib_bihash_add_del_16_8 (&sm->out2in_ed, &kv, 1))
    nat_elog_warn ("out2in key add failed");
}

void
nat_ha_sdel_ed_cb (ip4_address_t * out_addr, u16 out_port,
		   ip4_address_t * eh_addr, u16 eh_port, u8 proto,
		   u32 fib_index, u32 ti)
{
  snat_main_t *sm = &snat_main;
  clib_bihash_kv_16_8_t kv, value;
  u32 thread_index;
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm;

  if (sm->num_workers > 1)
    thread_index =
      sm->first_worker_index +
      (sm->workers[(clib_net_to_host_u16 (out_port) -
		    1024) / sm->port_per_thread]);
  else
    thread_index = sm->num_workers;
  tsm = vec_elt_at_index (sm->per_thread_data, thread_index);

  init_ed_k (&kv, *out_addr, out_port, *eh_addr, eh_port, fib_index, proto);
  if (clib_bihash_search_16_8 (&sm->out2in_ed, &kv, &value))
    return;

  s = pool_elt_at_index (tsm->sessions, ed_value_get_session_index (&value));
  nat_free_session_data (sm, s, thread_index, 1);
  nat44_delete_session (sm, s, thread_index);
}

void
nat_ha_sref_ed_cb (ip4_address_t * out_addr, u16 out_port,
		   ip4_address_t * eh_addr, u16 eh_port, u8 proto,
		   u32 fib_index, u32 total_pkts, u64 total_bytes,
		   u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  clib_bihash_kv_16_8_t kv, value;
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm;

  tsm = vec_elt_at_index (sm->per_thread_data, thread_index);

  init_ed_k (&kv, *out_addr, out_port, *eh_addr, eh_port, fib_index, proto);
  if (clib_bihash_search_16_8 (&sm->out2in_ed, &kv, &value))
    return;

  s = pool_elt_at_index (tsm->sessions, ed_value_get_session_index (&value));
  s->total_pkts = total_pkts;
  s->total_bytes = total_bytes;
}

static u32
nat_calc_bihash_buckets (u32 n_elts)
{
  n_elts = n_elts / 2.5;
  u64 lower_pow2 = 1;
  while (lower_pow2 * 2 < n_elts)
    {
      lower_pow2 = 2 * lower_pow2;
    }
  u64 upper_pow2 = 2 * lower_pow2;
  if ((upper_pow2 - n_elts) < (n_elts - lower_pow2))
    {
      if (upper_pow2 <= UINT32_MAX)
	{
	  return upper_pow2;
	}
    }
  return lower_pow2;
}

u32
nat44_get_max_session_limit ()
{
  snat_main_t *sm = &snat_main;
  u32 max_limit = 0, len = 0;

  for (; len < vec_len (sm->max_translations_per_fib); len++)
    {
      if (max_limit < sm->max_translations_per_fib[len])
	max_limit = sm->max_translations_per_fib[len];
    }
  return max_limit;
}

int
nat44_set_session_limit (u32 session_limit, u32 vrf_id)
{
  snat_main_t *sm = &snat_main;
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);
  u32 len = vec_len (sm->max_translations_per_fib);

  if (len <= fib_index)
    {
      vec_validate (sm->max_translations_per_fib, fib_index + 1);

      for (; len < vec_len (sm->max_translations_per_fib); len++)
	sm->max_translations_per_fib[len] = sm->max_translations_per_thread;
    }

  sm->max_translations_per_fib[fib_index] = session_limit;
  return 0;
}

int
nat44_update_session_limit (u32 session_limit, u32 vrf_id)
{
  snat_main_t *sm = &snat_main;

  if (nat44_set_session_limit (session_limit, vrf_id))
    return 1;
  sm->max_translations_per_thread = nat44_get_max_session_limit ();

  sm->translation_buckets =
    nat_calc_bihash_buckets (sm->max_translations_per_thread);

  nat44_sessions_clear ();
  return 0;
}

void
nat44_db_init (snat_main_per_thread_data_t * tsm)
{
  snat_main_t *sm = &snat_main;

  pool_alloc (tsm->sessions, sm->max_translations_per_thread);
  pool_alloc (tsm->lru_pool, sm->max_translations_per_thread);

  dlist_elt_t *head;

  pool_get (tsm->lru_pool, head);
  tsm->tcp_trans_lru_head_index = head - tsm->lru_pool;
  clib_dlist_init (tsm->lru_pool, tsm->tcp_trans_lru_head_index);

  pool_get (tsm->lru_pool, head);
  tsm->tcp_estab_lru_head_index = head - tsm->lru_pool;
  clib_dlist_init (tsm->lru_pool, tsm->tcp_estab_lru_head_index);

  pool_get (tsm->lru_pool, head);
  tsm->udp_lru_head_index = head - tsm->lru_pool;
  clib_dlist_init (tsm->lru_pool, tsm->udp_lru_head_index);

  pool_get (tsm->lru_pool, head);
  tsm->icmp_lru_head_index = head - tsm->lru_pool;
  clib_dlist_init (tsm->lru_pool, tsm->icmp_lru_head_index);

  pool_get (tsm->lru_pool, head);
  tsm->unk_proto_lru_head_index = head - tsm->lru_pool;
  clib_dlist_init (tsm->lru_pool, tsm->unk_proto_lru_head_index);

  if (sm->endpoint_dependent)
    {
      clib_bihash_init_16_8 (&tsm->in2out_ed, "in2out-ed",
			     sm->translation_buckets, 0);
      clib_bihash_set_kvp_format_fn_16_8 (&tsm->in2out_ed,
					  format_ed_session_kvp);
      /*
         clib_bihash_init_16_8 (&sm->out2in_ed, "out2in-ed",
         sm->translation_buckets, 0);
         clib_bihash_set_kvp_format_fn_16_8 (&sm->out2in_ed,
         format_ed_session_kvp); */
    }
  else
    {
      clib_bihash_init_8_8 (&tsm->in2out, "in2out", sm->translation_buckets,
			    0);
      clib_bihash_set_kvp_format_fn_8_8 (&tsm->in2out, format_session_kvp);
      clib_bihash_init_8_8 (&tsm->out2in, "out2in", sm->translation_buckets,
			    0);
      clib_bihash_set_kvp_format_fn_8_8 (&tsm->out2in, format_session_kvp);
    }

  // TODO: ED nat is not using these
  // before removal large refactor required
  pool_alloc (tsm->list_pool, sm->max_translations_per_thread);
  clib_bihash_init_8_8 (&tsm->user_hash, "users", sm->user_buckets, 0);
  clib_bihash_set_kvp_format_fn_8_8 (&tsm->user_hash, format_user_kvp);
}

void
nat44_db_free (snat_main_per_thread_data_t * tsm)
{
  snat_main_t *sm = &snat_main;

  pool_free (tsm->sessions);
  pool_free (tsm->lru_pool);

  if (sm->endpoint_dependent)
    {
      clib_bihash_free_16_8 (&tsm->in2out_ed);
      vec_free (tsm->per_vrf_sessions_vec);
    }
  else
    {
      clib_bihash_free_8_8 (&tsm->in2out);
      clib_bihash_free_8_8 (&tsm->out2in);
    }

  // TODO: resolve static mappings (put only to !ED)
  pool_free (tsm->users);
  pool_free (tsm->list_pool);
  clib_bihash_free_8_8 (&tsm->user_hash);
}

void
nat44_sessions_clear ()
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;

  if (sm->endpoint_dependent)
    {
      clib_bihash_free_16_8 (&sm->out2in_ed);
      clib_bihash_init_16_8 (&sm->out2in_ed, "out2in-ed",
			     clib_max (1,
				       sm->num_workers) *
			     sm->translation_buckets, 0);
      clib_bihash_set_kvp_format_fn_16_8 (&sm->out2in_ed,
					  format_ed_session_kvp);
    }

  /* *INDENT-OFF* */
  vec_foreach (tsm, sm->per_thread_data)
    {
      u32 ti;

      nat44_db_free (tsm);
      nat44_db_init (tsm);

      ti = tsm->snat_thread_index;
      vlib_set_simple_counter (&sm->total_users, ti, 0, 0);
      vlib_set_simple_counter (&sm->total_sessions, ti, 0, 0);
    }
  /* *INDENT-ON* */
}

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
  clib_bihash_kv_8_8_t kv, value;
  int i, rv;
  ip4_address_t l_addr;

  if (!sm->enabled)
    return;

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
  init_nat_k (&kv, *address, rp->addr_only ? 0 : rp->e_port,
	      sm->outside_fib_index, rp->addr_only ? 0 : rp->proto);
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
				rp->out2in_only, rp->tag, rp->identity_nat,
				rp->pool_addr, rp->exact);
  if (rv)
    nat_elog_notice_X1 ("snat_add_static_mapping returned %d", "i4", rv);
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

  if (!sm->enabled)
    return;

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
					    rp->identity_nat,
					    rp->pool_addr, rp->exact);
	      if (rv)
		nat_elog_notice_X1 ("snat_add_static_mapping returned %d",
				    "i4", rv);
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
		   nat_protocol_t proto, u32 vrf_id, int is_in)
{
  snat_main_per_thread_data_t *tsm;
  clib_bihash_kv_8_8_t kv, value;
  ip4_header_t ip;
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);
  snat_session_t *s;
  clib_bihash_8_8_t *t;

  if (sm->endpoint_dependent)
    return VNET_API_ERROR_UNSUPPORTED;

  ip.dst_address.as_u32 = ip.src_address.as_u32 = addr->as_u32;
  if (sm->num_workers > 1)
    tsm =
      vec_elt_at_index (sm->per_thread_data,
			sm->worker_in2out_cb (&ip, fib_index, 0));
  else
    tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

  init_nat_k (&kv, *addr, port, fib_index, proto);
  t = is_in ? &tsm->in2out : &tsm->out2in;
  if (!clib_bihash_search_8_8 (t, &kv, &value))
    {
      if (pool_is_free_index (tsm->sessions, value.value))
	return VNET_API_ERROR_UNSPECIFIED;

      s = pool_elt_at_index (tsm->sessions, value.value);
      nat_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
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
			sm->worker_in2out_cb (&ip, fib_index, 0));
  else
    tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

  t = is_in ? &tsm->in2out_ed : &sm->out2in_ed;
  init_ed_k (&kv, *addr, port, *eh_addr, eh_port, fib_index, proto);
  if (clib_bihash_search_16_8 (t, &kv, &value))
    {
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (pool_is_free_index (tsm->sessions, value.value))
    return VNET_API_ERROR_UNSPECIFIED;
  s = pool_elt_at_index (tsm->sessions, value.value);
  nat_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
  nat_ed_session_delete (sm, s, tsm - sm->per_thread_data, 1);
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

VLIB_NODE_FN (nat_default_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat_default_node) = {
  .name = "nat-default",
  .vector_size = sizeof (u32),
  .format_trace = 0,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = NAT_N_NEXT,
  .next_nodes = {
    [NAT_NEXT_DROP] = "error-drop",
    [NAT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [NAT_NEXT_IN2OUT_ED_FAST_PATH] = "nat44-ed-in2out",
    [NAT_NEXT_IN2OUT_ED_SLOW_PATH] = "nat44-ed-in2out-slowpath",
    [NAT_NEXT_IN2OUT_ED_OUTPUT_FAST_PATH] = "nat44-ed-in2out-output",
    [NAT_NEXT_IN2OUT_ED_OUTPUT_SLOW_PATH] = "nat44-ed-in2out-output-slowpath",
    [NAT_NEXT_OUT2IN_ED_FAST_PATH] = "nat44-ed-out2in",
    [NAT_NEXT_OUT2IN_ED_SLOW_PATH] = "nat44-ed-out2in-slowpath",
    [NAT_NEXT_OUT2IN_ED_HANDOFF] = "nat44-ed-out2in-handoff",
    [NAT_NEXT_IN2OUT_CLASSIFY] = "nat44-in2out-worker-handoff",
    [NAT_NEXT_OUT2IN_CLASSIFY] = "nat44-out2in-worker-handoff",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
