/*
 * nat44_ei.c - nat44 endpoint dependent plugin
 *
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip_table.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/plugin/plugin.h>

// nat lib
#include <nat/lib/log.h>
#include <nat/lib/nat_syslog.h>
#include <nat/lib/nat_inlines.h>
#include <nat/lib/ipfix_logging.h>

#include <nat/nat44-ei/nat44_ei_dpo.h>
#include <nat/nat44-ei/nat44_ei_inlines.h>
#include <nat/nat44-ei/nat44_ei.h>

nat44_ei_main_t nat44_ei_main;

extern vlib_node_registration_t nat44_ei_hairpinning_node;
extern vlib_node_registration_t nat44_ei_hairpin_dst_node;
extern vlib_node_registration_t
  nat44_ei_in2out_hairpinning_finish_ip4_lookup_node;
extern vlib_node_registration_t
  nat44_ei_in2out_hairpinning_finish_interface_output_node;

#define skip_if_disabled()                                                    \
  do                                                                          \
    {                                                                         \
      nat44_ei_main_t *nm = &nat44_ei_main;                                   \
      if (PREDICT_FALSE (!nm->enabled))                                       \
	return;                                                               \
    }                                                                         \
  while (0)

#define fail_if_enabled()                                                     \
  do                                                                          \
    {                                                                         \
      nat44_ei_main_t *nm = &nat44_ei_main;                                   \
      if (PREDICT_FALSE (nm->enabled))                                        \
	{                                                                     \
	  nat44_ei_log_err ("plugin enabled");                                \
	  return 1;                                                           \
	}                                                                     \
    }                                                                         \
  while (0)

#define fail_if_disabled()                                                    \
  do                                                                          \
    {                                                                         \
      nat44_ei_main_t *nm = &nat44_ei_main;                                   \
      if (PREDICT_FALSE (!nm->enabled))                                       \
	{                                                                     \
	  nat44_ei_log_err ("plugin disabled");                               \
	  return 1;                                                           \
	}                                                                     \
    }                                                                         \
  while (0)

/* Hook up input features */
VNET_FEATURE_INIT (ip4_nat_classify, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ei-classify",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_nat44_ei_in2out, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ei-in2out",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_nat44_ei_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ei-out2in",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature",
			       "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_nat44_ei_in2out_output, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-ei-in2out-output",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa",
			       "ip4-sv-reassembly-output-feature"),
};
VNET_FEATURE_INIT (ip4_nat44_ei_in2out_fast, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ei-in2out-fast",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_nat44_ei_out2in_fast, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ei-out2in-fast",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature",
			       "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_nat44_ei_hairpin_dst, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ei-hairpin-dst",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (ip4_nat44_ei_hairpin_src, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-ei-hairpin-src",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa",
			       "ip4-sv-reassembly-output-feature"),
};
VNET_FEATURE_INIT (ip4_nat44_ei_hairpinning, static) = {
  .arc_name = "ip4-local",
  .node_name = "nat44-ei-hairpinning",
  .runs_before = VNET_FEATURES ("ip4-local-end-of-arc"),
};
VNET_FEATURE_INIT (ip4_nat44_ei_in2out_worker_handoff, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ei-in2out-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_nat44_ei_out2in_worker_handoff, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-ei-out2in-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-dhcp-client-detect"),
};
VNET_FEATURE_INIT (ip4_nat44_ei_in2out_output_worker_handoff, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-ei-in2out-output-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa",
			       "ip4-sv-reassembly-output-feature"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "IPv4 Endpoint-Independent NAT (NAT44 EI)",
};

#define foreach_nat44_ei_classify_error                                       \
  _ (NEXT_IN2OUT, "next in2out")                                              \
  _ (NEXT_OUT2IN, "next out2in")                                              \
  _ (FRAG_CACHED, "fragment cached")

typedef enum
{
#define _(sym, str) NAT44_EI_CLASSIFY_ERROR_##sym,
  foreach_nat44_ei_classify_error
#undef _
    NAT44_EI_CLASSIFY_N_ERROR,
} nat44_ei_classify_error_t;

static char *nat44_ei_classify_error_strings[] = {
#define _(sym, string) string,
  foreach_nat44_ei_classify_error
#undef _
};

typedef enum
{
  NAT44_EI_CLASSIFY_NEXT_IN2OUT,
  NAT44_EI_CLASSIFY_NEXT_OUT2IN,
  NAT44_EI_CLASSIFY_NEXT_DROP,
  NAT44_EI_CLASSIFY_N_NEXT,
} nat44_ei_classify_next_t;

typedef struct
{
  u8 next_in2out;
  u8 cached;
} nat44_ei_classify_trace_t;

void nat44_ei_add_del_addr_to_fib (ip4_address_t *addr, u8 p_len,
				   u32 sw_if_index, int is_add);

static u8 *
format_nat44_ei_classify_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat44_ei_classify_trace_t *t = va_arg (*args, nat44_ei_classify_trace_t *);
  char *next;

  if (t->cached)
    s = format (s, "nat44-ei-classify: fragment cached");
  else
    {
      next = t->next_in2out ? "nat44-ei-in2out" : "nat44-ei-out2in";
      s = format (s, "nat44-ei-classify: next %s", next);
    }

  return s;
}

static void nat44_ei_db_free ();

static void nat44_ei_db_init (u32 translations, u32 translation_buckets,
			      u32 user_buckets);

static void nat44_ei_ip4_add_del_interface_address_cb (
  ip4_main_t *im, uword opaque, u32 sw_if_index, ip4_address_t *address,
  u32 address_length, u32 if_address_index, u32 is_delete);

static void nat44_ei_ip4_add_del_addr_only_sm_cb (
  ip4_main_t *im, uword opaque, u32 sw_if_index, ip4_address_t *address,
  u32 address_length, u32 if_address_index, u32 is_delete);

static void nat44_ei_update_outside_fib (ip4_main_t *im, uword opaque,
					 u32 sw_if_index, u32 new_fib_index,
					 u32 old_fib_index);

void
nat44_ei_set_node_indexes (nat44_ei_main_t *nm, vlib_main_t *vm)
{
  vlib_node_t *node;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ei-out2in");
  nm->out2in_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ei-in2out");
  nm->in2out_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ei-in2out-output");
  nm->in2out_output_node_index = node->index;
}

int
nat44_ei_set_workers (uword *bitmap)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  int i, j = 0;

  if (nm->num_workers < 2)
    return VNET_API_ERROR_FEATURE_DISABLED;

  if (clib_bitmap_last_set (bitmap) >= nm->num_workers)
    return VNET_API_ERROR_INVALID_WORKER;

  vec_free (nm->workers);
  clib_bitmap_foreach (i, bitmap)
    {
      vec_add1 (nm->workers, i);
      nm->per_thread_data[nm->first_worker_index + i].snat_thread_index = j;
      nm->per_thread_data[nm->first_worker_index + i].thread_index = i;
      j++;
    }

  nm->port_per_thread = (0xffff - 1024) / _vec_len (nm->workers);

  return 0;
}

#define nat_validate_simple_counter(c, i)                                     \
  do                                                                          \
    {                                                                         \
      vlib_validate_simple_counter (&c, i);                                   \
      vlib_zero_simple_counter (&c, i);                                       \
    }                                                                         \
  while (0);

#define nat_init_simple_counter(c, n, sn)                                     \
  do                                                                          \
    {                                                                         \
      c.name = n;                                                             \
      c.stat_segment_name = sn;                                               \
      nat_validate_simple_counter (c, 0);                                     \
    }                                                                         \
  while (0);

static_always_inline void
nat_validate_interface_counters (nat44_ei_main_t *nm, u32 sw_if_index)
{
#define _(x)                                                                  \
  nat_validate_simple_counter (nm->counters.fastpath.in2out.x, sw_if_index);  \
  nat_validate_simple_counter (nm->counters.fastpath.out2in.x, sw_if_index);  \
  nat_validate_simple_counter (nm->counters.slowpath.in2out.x, sw_if_index);  \
  nat_validate_simple_counter (nm->counters.slowpath.out2in.x, sw_if_index);
  foreach_nat_counter;
#undef _
  nat_validate_simple_counter (nm->counters.hairpinning, sw_if_index);
}

clib_error_t *
nat44_ei_init (vlib_main_t *vm)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_thread_registration_t *tr;
  ip4_add_del_interface_address_callback_t cbi = { 0 };
  ip4_table_bind_callback_t cbt = { 0 };
  u32 i, num_threads = 0;
  uword *p, *bitmap = 0;

  clib_memset (nm, 0, sizeof (*nm));

  // required
  nm->vnet_main = vnet_get_main ();
  // convenience
  nm->ip4_main = &ip4_main;
  nm->api_main = vlibapi_get_main ();
  nm->ip4_lookup_main = &ip4_main.lookup_main;

  // handoff stuff
  nm->fq_out2in_index = ~0;
  nm->fq_in2out_index = ~0;
  nm->fq_in2out_output_index = ~0;

  nm->log_level = NAT_LOG_ERROR;

  nat44_ei_set_node_indexes (nm, vm);
  nm->log_class = vlib_log_register_class ("nat44-ei", 0);

  nat_init_simple_counter (nm->total_users, "total-users",
			   "/nat44-ei/total-users");
  nat_init_simple_counter (nm->total_sessions, "total-sessions",
			   "/nat44-ei/total-sessions");
  nat_init_simple_counter (nm->user_limit_reached, "user-limit-reached",
			   "/nat44-ei/user-limit-reached");

#define _(x)                                                                  \
  nat_init_simple_counter (nm->counters.fastpath.in2out.x, #x,                \
			   "/nat44-ei/in2out/fastpath/" #x);                  \
  nat_init_simple_counter (nm->counters.fastpath.out2in.x, #x,                \
			   "/nat44-ei/out2in/fastpath/" #x);                  \
  nat_init_simple_counter (nm->counters.slowpath.in2out.x, #x,                \
			   "/nat44-ei/in2out/slowpath/" #x);                  \
  nat_init_simple_counter (nm->counters.slowpath.out2in.x, #x,                \
			   "/nat44-ei/out2in/slowpath/" #x);
  foreach_nat_counter;
#undef _
  nat_init_simple_counter (nm->counters.hairpinning, "hairpinning",
			   "/nat44-ei/hairpinning");

  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  if (p)
    {
      tr = (vlib_thread_registration_t *) p[0];
      if (tr)
	{
	  nm->num_workers = tr->count;
	  nm->first_worker_index = tr->first_index;
	}
    }
  num_threads = tm->n_vlib_mains - 1;
  nm->port_per_thread = 0xffff - 1024;
  vec_validate (nm->per_thread_data, num_threads);

  /* Use all available workers by default */
  if (nm->num_workers > 1)
    {

      for (i = 0; i < nm->num_workers; i++)
	bitmap = clib_bitmap_set (bitmap, i, 1);
      nat44_ei_set_workers (bitmap);
      clib_bitmap_free (bitmap);
    }
  else
    nm->per_thread_data[0].snat_thread_index = 0;

  /* callbacks to call when interface address changes. */
  cbi.function = nat44_ei_ip4_add_del_interface_address_cb;
  vec_add1 (nm->ip4_main->add_del_interface_address_callbacks, cbi);
  cbi.function = nat44_ei_ip4_add_del_addr_only_sm_cb;
  vec_add1 (nm->ip4_main->add_del_interface_address_callbacks, cbi);

  /* callbacks to call when interface to table biding changes */
  cbt.function = nat44_ei_update_outside_fib;
  vec_add1 (nm->ip4_main->table_bind_callbacks, cbt);

  nm->fib_src_low = fib_source_allocate (
    "nat44-ei-low", FIB_SOURCE_PRIORITY_LOW, FIB_SOURCE_BH_SIMPLE);
  nm->fib_src_hi = fib_source_allocate ("nat44-ei-hi", FIB_SOURCE_PRIORITY_HI,
					FIB_SOURCE_BH_SIMPLE);

  // used only by out2in-dpo feature
  nat_dpo_module_init ();
  nat_ha_init (vm, nm->num_workers, num_threads);

  nm->hairpinning_fq_index =
    vlib_frame_queue_main_init (nat44_ei_hairpinning_node.index, 0);
  nm->hairpin_dst_fq_index =
    vlib_frame_queue_main_init (nat44_ei_hairpin_dst_node.index, 0);
  nm->in2out_hairpinning_finish_ip4_lookup_node_fq_index =
    vlib_frame_queue_main_init (
      nat44_ei_in2out_hairpinning_finish_ip4_lookup_node.index, 0);
  nm->in2out_hairpinning_finish_interface_output_node_fq_index =
    vlib_frame_queue_main_init (
      nat44_ei_in2out_hairpinning_finish_interface_output_node.index, 0);
  return nat44_ei_api_hookup (vm);
}

VLIB_INIT_FUNCTION (nat44_ei_init);

int
nat44_ei_plugin_enable (nat44_ei_config_t c)
{
  nat44_ei_main_t *nm = &nat44_ei_main;

  fail_if_enabled ();

  if (!c.users)
    c.users = 1024;

  if (!c.sessions)
    c.sessions = 10 * 1024;

  nm->rconfig = c;

  if (!nm->frame_queue_nelts)
    nm->frame_queue_nelts = NAT_FQ_NELTS_DEFAULT;

  nm->translations = c.sessions;
  nm->translation_buckets = nat_calc_bihash_buckets (c.sessions);
  nm->user_buckets = nat_calc_bihash_buckets (c.users);

  nm->pat = (!c.static_mapping_only ||
	     (c.static_mapping_only && c.connection_tracking));

  nm->static_mapping_only = c.static_mapping_only;
  nm->static_mapping_connection_tracking = c.connection_tracking;
  nm->out2in_dpo = c.out2in_dpo;
  nm->forwarding_enabled = 0;
  nm->mss_clamping = 0;

  nm->max_users_per_thread = c.users;
  nm->max_translations_per_thread = c.sessions;
  nm->max_translations_per_user =
    c.user_sessions ? c.user_sessions : nm->max_translations_per_thread;

  nm->inside_vrf_id = c.inside_vrf;
  nm->inside_fib_index = fib_table_find_or_create_and_lock (
    FIB_PROTOCOL_IP4, c.inside_vrf, nm->fib_src_hi);

  nm->outside_vrf_id = c.outside_vrf;
  nm->outside_fib_index = fib_table_find_or_create_and_lock (
    FIB_PROTOCOL_IP4, c.outside_vrf, nm->fib_src_hi);

  nat_reset_timeouts (&nm->timeouts);
  nat44_ei_db_init (nm->translations, nm->translation_buckets,
		    nm->user_buckets);
  nat44_ei_set_alloc_default ();

  // TODO: zero simple counter for all counters missing

  vlib_zero_simple_counter (&nm->total_users, 0);
  vlib_zero_simple_counter (&nm->total_sessions, 0);
  vlib_zero_simple_counter (&nm->user_limit_reached, 0);

  nat_ha_enable ();
  nm->enabled = 1;

  return 0;
}

void
nat44_ei_addresses_free (nat44_ei_address_t **addresses)
{
  nat44_ei_address_t *ap;
  vec_foreach (ap, *addresses)
    {
#define _(N, i, n, s) vec_free (ap->busy_##n##_ports_per_thread);
      foreach_nat_protocol
#undef _
    }
  vec_free (*addresses);
  *addresses = 0;
}

int
nat44_ei_interface_add_del (u32 sw_if_index, u8 is_inside, int is_del)
{
  const char *feature_name, *del_feature_name;
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_interface_t *i;
  nat44_ei_address_t *ap;
  nat44_ei_static_mapping_t *m;
  nat44_ei_outside_fib_t *outside_fib;
  u32 fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);

  fail_if_disabled ();

  if (nm->out2in_dpo && !is_inside)
    {
      nat44_ei_log_err ("error unsupported");
      return VNET_API_ERROR_UNSUPPORTED;
    }

  pool_foreach (i, nm->output_feature_interfaces)
    {
      if (i->sw_if_index == sw_if_index)
	{
	  nat44_ei_log_err ("error interface already configured");
	  return VNET_API_ERROR_VALUE_EXIST;
	}
    }

  if (nm->static_mapping_only && !(nm->static_mapping_connection_tracking))
    feature_name = is_inside ? "nat44-ei-in2out-fast" : "nat44-ei-out2in-fast";
  else
    {
      if (nm->num_workers > 1)
	feature_name = is_inside ? "nat44-ei-in2out-worker-handoff" :
				   "nat44-ei-out2in-worker-handoff";
      else
	feature_name = is_inside ? "nat44-ei-in2out" : "nat44-ei-out2in";
    }

  if (nm->fq_in2out_index == ~0 && nm->num_workers > 1)
    nm->fq_in2out_index = vlib_frame_queue_main_init (nm->in2out_node_index,
						      nm->frame_queue_nelts);

  if (nm->fq_out2in_index == ~0 && nm->num_workers > 1)
    nm->fq_out2in_index = vlib_frame_queue_main_init (nm->out2in_node_index,
						      nm->frame_queue_nelts);

  if (!is_inside)
    {
      vec_foreach (outside_fib, nm->outside_fibs)
	{
	  if (outside_fib->fib_index == fib_index)
	    {
	      if (is_del)
		{
		  outside_fib->refcount--;
		  if (!outside_fib->refcount)
		    vec_del1 (nm->outside_fibs,
			      outside_fib - nm->outside_fibs);
		}
	      else
		outside_fib->refcount++;
	      goto feature_set;
	    }
	}
      if (!is_del)
	{
	  vec_add2 (nm->outside_fibs, outside_fib, 1);
	  outside_fib->refcount = 1;
	  outside_fib->fib_index = fib_index;
	}
    }

feature_set:
  pool_foreach (i, nm->interfaces)
    {
      if (i->sw_if_index == sw_if_index)
	{
	  if (is_del)
	    {
	      if (nat44_ei_interface_is_inside (i) &&
		  nat44_ei_interface_is_outside (i))
		{
		  if (is_inside)
		    i->flags &= ~NAT44_EI_INTERFACE_FLAG_IS_INSIDE;
		  else
		    i->flags &= ~NAT44_EI_INTERFACE_FLAG_IS_OUTSIDE;

		  if (nm->num_workers > 1)
		    {
		      del_feature_name = "nat44-handoff-classify";
		      feature_name = !is_inside ?
				       "nat44-ei-in2out-worker-handoff" :
				       "nat44-ei-out2in-worker-handoff";
		    }
		  else
		    {
		      del_feature_name = "nat44-ei-classify";
		      feature_name =
			!is_inside ? "nat44-ei-in2out" : "nat44-ei-out2in";
		    }

		  int rv =
		    ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
		  if (rv)
		    return rv;
		  vnet_feature_enable_disable ("ip4-unicast", del_feature_name,
					       sw_if_index, 0, 0, 0);
		  vnet_feature_enable_disable ("ip4-unicast", feature_name,
					       sw_if_index, 1, 0, 0);
		  if (!is_inside)
		    {
		      vnet_feature_enable_disable ("ip4-local",
						   "nat44-ei-hairpinning",
						   sw_if_index, 1, 0, 0);
		    }
		}
	      else
		{
		  int rv =
		    ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
		  if (rv)
		    return rv;
		  vnet_feature_enable_disable ("ip4-unicast", feature_name,
					       sw_if_index, 0, 0, 0);
		  pool_put (nm->interfaces, i);
		  if (is_inside)
		    {
		      vnet_feature_enable_disable ("ip4-local",
						   "nat44-ei-hairpinning",
						   sw_if_index, 0, 0, 0);
		    }
		}
	    }
	  else
	    {
	      if ((nat44_ei_interface_is_inside (i) && is_inside) ||
		  (nat44_ei_interface_is_outside (i) && !is_inside))
		return 0;

	      if (nm->num_workers > 1)
		{
		  del_feature_name = !is_inside ?
				       "nat44-ei-in2out-worker-handoff" :
				       "nat44-ei-out2in-worker-handoff";
		  feature_name = "nat44-handoff-classify";
		}
	      else
		{
		  del_feature_name =
		    !is_inside ? "nat44-ei-in2out" : "nat44-ei-out2in";
		  feature_name = "nat44-ei-classify";
		}

	      int rv =
		ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
	      if (rv)
		return rv;
	      vnet_feature_enable_disable ("ip4-unicast", del_feature_name,
					   sw_if_index, 0, 0, 0);
	      vnet_feature_enable_disable ("ip4-unicast", feature_name,
					   sw_if_index, 1, 0, 0);
	      if (!is_inside)
		{
		  vnet_feature_enable_disable (
		    "ip4-local", "nat44-ei-hairpinning", sw_if_index, 0, 0, 0);
		}
	      goto set_flags;
	    }

	  goto fib;
	}
    }

  if (is_del)
    {
      nat44_ei_log_err ("error interface couldn't be found");
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  pool_get (nm->interfaces, i);
  i->sw_if_index = sw_if_index;
  i->flags = 0;
  nat_validate_interface_counters (nm, sw_if_index);

  vnet_feature_enable_disable ("ip4-unicast", feature_name, sw_if_index, 1, 0,
			       0);

  int rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
  if (rv)
    return rv;

  if (is_inside && !nm->out2in_dpo)
    {
      vnet_feature_enable_disable ("ip4-local", "nat44-ei-hairpinning",
				   sw_if_index, 1, 0, 0);
    }

set_flags:
  if (is_inside)
    {
      i->flags |= NAT44_EI_INTERFACE_FLAG_IS_INSIDE;
      return 0;
    }
  else
    i->flags |= NAT44_EI_INTERFACE_FLAG_IS_OUTSIDE;

  /* Add/delete external addresses to FIB */
fib:
  vec_foreach (ap, nm->addresses)
    nat44_ei_add_del_addr_to_fib (&ap->addr, 32, sw_if_index, !is_del);

  pool_foreach (m, nm->static_mappings)
    {
      if (!(nat44_ei_is_addr_only_static_mapping (m)) ||
	  (m->local_addr.as_u32 == m->external_addr.as_u32))
	continue;

      nat44_ei_add_del_addr_to_fib (&m->external_addr, 32, sw_if_index,
				    !is_del);
    }

  return 0;
}

int
nat44_ei_interface_add_del_output_feature (u32 sw_if_index, u8 is_inside,
					   int is_del)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_interface_t *i;
  nat44_ei_address_t *ap;
  nat44_ei_static_mapping_t *m;
  nat44_ei_outside_fib_t *outside_fib;
  u32 fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);

  fail_if_disabled ();

  if (nm->static_mapping_only && !(nm->static_mapping_connection_tracking))
    {
      nat44_ei_log_err ("error unsupported");
      return VNET_API_ERROR_UNSUPPORTED;
    }

  pool_foreach (i, nm->interfaces)
    {
      if (i->sw_if_index == sw_if_index)
	{
	  nat44_ei_log_err ("error interface already configured");
	  return VNET_API_ERROR_VALUE_EXIST;
	}
    }

  if (!is_inside)
    {
      vec_foreach (outside_fib, nm->outside_fibs)
	{
	  if (outside_fib->fib_index == fib_index)
	    {
	      if (is_del)
		{
		  outside_fib->refcount--;
		  if (!outside_fib->refcount)
		    vec_del1 (nm->outside_fibs,
			      outside_fib - nm->outside_fibs);
		}
	      else
		outside_fib->refcount++;
	      goto feature_set;
	    }
	}
      if (!is_del)
	{
	  vec_add2 (nm->outside_fibs, outside_fib, 1);
	  outside_fib->refcount = 1;
	  outside_fib->fib_index = fib_index;
	}
    }

feature_set:
  if (is_inside)
    {
      int rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, !is_del);
      if (rv)
	return rv;
      rv =
	ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index, !is_del);
      if (rv)
	return rv;
      vnet_feature_enable_disable ("ip4-unicast", "nat44-ei-hairpin-dst",
				   sw_if_index, !is_del, 0, 0);
      vnet_feature_enable_disable ("ip4-output", "nat44-ei-hairpin-src",
				   sw_if_index, !is_del, 0, 0);
      goto fq;
    }

  if (nm->num_workers > 1)
    {
      int rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, !is_del);
      if (rv)
	return rv;
      rv =
	ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index, !is_del);
      if (rv)
	return rv;
      vnet_feature_enable_disable ("ip4-unicast",
				   "nat44-ei-out2in-worker-handoff",
				   sw_if_index, !is_del, 0, 0);
      vnet_feature_enable_disable ("ip4-output",
				   "nat44-ei-in2out-output-worker-handoff",
				   sw_if_index, !is_del, 0, 0);
    }
  else
    {
      int rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, !is_del);
      if (rv)
	return rv;
      rv =
	ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index, !is_del);
      if (rv)
	return rv;
      vnet_feature_enable_disable ("ip4-unicast", "nat44-ei-out2in",
				   sw_if_index, !is_del, 0, 0);
      vnet_feature_enable_disable ("ip4-output", "nat44-ei-in2out-output",
				   sw_if_index, !is_del, 0, 0);
    }

fq:
  if (nm->fq_in2out_output_index == ~0 && nm->num_workers > 1)
    nm->fq_in2out_output_index =
      vlib_frame_queue_main_init (nm->in2out_output_node_index, 0);

  if (nm->fq_out2in_index == ~0 && nm->num_workers > 1)
    nm->fq_out2in_index =
      vlib_frame_queue_main_init (nm->out2in_node_index, 0);

  pool_foreach (i, nm->output_feature_interfaces)
    {
      if (i->sw_if_index == sw_if_index)
	{
	  if (is_del)
	    pool_put (nm->output_feature_interfaces, i);
	  else
	    return VNET_API_ERROR_VALUE_EXIST;

	  goto fib;
	}
    }

  if (is_del)
    {
      nat44_ei_log_err ("error interface couldn't be found");
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  pool_get (nm->output_feature_interfaces, i);
  i->sw_if_index = sw_if_index;
  i->flags = 0;
  nat_validate_interface_counters (nm, sw_if_index);
  if (is_inside)
    i->flags |= NAT44_EI_INTERFACE_FLAG_IS_INSIDE;
  else
    i->flags |= NAT44_EI_INTERFACE_FLAG_IS_OUTSIDE;

  /* Add/delete external addresses to FIB */
fib:
  if (is_inside)
    return 0;

  vec_foreach (ap, nm->addresses)
    nat44_ei_add_del_addr_to_fib (&ap->addr, 32, sw_if_index, !is_del);

  pool_foreach (m, nm->static_mappings)
    {
      if (!((nat44_ei_is_addr_only_static_mapping (m))) ||
	  (m->local_addr.as_u32 == m->external_addr.as_u32))
	continue;

      nat44_ei_add_del_addr_to_fib (&m->external_addr, 32, sw_if_index,
				    !is_del);
    }

  return 0;
}

int
nat44_ei_plugin_disable ()
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_interface_t *i, *vec;
  int error = 0;

  // first unregister all nodes from interfaces
  vec = vec_dup (nm->interfaces);
  vec_foreach (i, vec)
    {
      if (nat44_ei_interface_is_inside (i))
	error = nat44_ei_interface_add_del (i->sw_if_index, 1, 1);
      if (nat44_ei_interface_is_outside (i))
	error = nat44_ei_interface_add_del (i->sw_if_index, 0, 1);

      if (error)
	{
	  nat44_ei_log_err ("error occurred while removing interface %u",
			    i->sw_if_index);
	}
    }
  vec_free (vec);
  nm->interfaces = 0;

  vec = vec_dup (nm->output_feature_interfaces);
  vec_foreach (i, vec)
    {
      if (nat44_ei_interface_is_inside (i))
	error =
	  nat44_ei_interface_add_del_output_feature (i->sw_if_index, 1, 1);
      if (nat44_ei_interface_is_outside (i))
	error =
	  nat44_ei_interface_add_del_output_feature (i->sw_if_index, 0, 1);

      if (error)
	{
	  nat44_ei_log_err ("error occurred while removing interface %u",
			    i->sw_if_index);
	}
    }
  vec_free (vec);
  nm->output_feature_interfaces = 0;

  nat_ha_disable ();
  nat44_ei_db_free ();

  nat44_ei_addresses_free (&nm->addresses);

  vec_free (nm->to_resolve);
  vec_free (nm->auto_add_sw_if_indices);

  nm->to_resolve = 0;
  nm->auto_add_sw_if_indices = 0;

  nm->forwarding_enabled = 0;

  nm->enabled = 0;
  clib_memset (&nm->rconfig, 0, sizeof (nm->rconfig));

  return error;
}

int
nat44_ei_set_outside_address_and_port (nat44_ei_address_t *addresses,
				       u32 thread_index, ip4_address_t addr,
				       u16 port, nat_protocol_t protocol)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_address_t *a = 0;
  u32 address_index;
  u16 port_host_byte_order = clib_net_to_host_u16 (port);

  for (address_index = 0; address_index < vec_len (addresses); address_index++)
    {
      if (addresses[address_index].addr.as_u32 != addr.as_u32)
	continue;

      a = addresses + address_index;
      switch (protocol)
	{
#define _(N, j, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    if (a->busy_##n##_port_refcounts[port_host_byte_order])                   \
      return VNET_API_ERROR_INSTANCE_IN_USE;                                  \
    ++a->busy_##n##_port_refcounts[port_host_byte_order];                     \
    a->busy_##n##_ports_per_thread[thread_index]++;                           \
    a->busy_##n##_ports++;                                                    \
    return 0;
	  foreach_nat_protocol
#undef _
	    default : nat_elog_info (nm, "unknown protocol");
	  return 1;
	}
    }

  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

void
nat44_ei_add_del_address_dpo (ip4_address_t addr, u8 is_add)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  dpo_id_t dpo_v4 = DPO_INVALID;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr.ip4.as_u32 = addr.as_u32,
  };

  if (is_add)
    {
      nat_dpo_create (DPO_PROTO_IP4, 0, &dpo_v4);
      fib_table_entry_special_dpo_add (0, &pfx, nm->fib_src_hi,
				       FIB_ENTRY_FLAG_EXCLUSIVE, &dpo_v4);
      dpo_reset (&dpo_v4);
    }
  else
    {
      fib_table_entry_special_remove (0, &pfx, nm->fib_src_hi);
    }
}

void
nat44_ei_free_outside_address_and_port (nat44_ei_address_t *addresses,
					u32 thread_index, ip4_address_t *addr,
					u16 port, nat_protocol_t protocol)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_address_t *a;
  u32 address_index;
  u16 port_host_byte_order = clib_net_to_host_u16 (port);

  for (address_index = 0; address_index < vec_len (addresses); address_index++)
    {
      if (addresses[address_index].addr.as_u32 == addr->as_u32)
	break;
    }

  ASSERT (address_index < vec_len (addresses));

  a = addresses + address_index;

  switch (protocol)
    {
#define _(N, i, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    ASSERT (a->busy_##n##_port_refcounts[port_host_byte_order] >= 1);         \
    --a->busy_##n##_port_refcounts[port_host_byte_order];                     \
    a->busy_##n##_ports--;                                                    \
    a->busy_##n##_ports_per_thread[thread_index]--;                           \
    break;
      foreach_nat_protocol
#undef _
	default : nat_elog_info (nm, "unknown protocol");
      return;
    }
}

void
nat44_ei_free_session_data_v2 (nat44_ei_main_t *nm, nat44_ei_session_t *s,
			       u32 thread_index, u8 is_ha)
{
  clib_bihash_kv_8_8_t kv;

  /* session lookup tables */
  init_nat_i2o_k (&kv, s);
  if (clib_bihash_add_del_8_8 (&nm->in2out, &kv, 0))
    nat_elog_warn (nm, "in2out key del failed");
  init_nat_o2i_k (&kv, s);
  if (clib_bihash_add_del_8_8 (&nm->out2in, &kv, 0))
    nat_elog_warn (nm, "out2in key del failed");

  if (!is_ha)
    nat_syslog_nat44_apmdel (s->user_index, s->in2out.fib_index,
			     &s->in2out.addr, s->in2out.port, &s->out2in.addr,
			     s->out2in.port, s->nat_proto);

  if (nat44_ei_is_unk_proto_session (s))
    return;

  if (!is_ha)
    {
      /* log NAT event */
      nat_ipfix_logging_nat44_ses_delete (
	thread_index, s->in2out.addr.as_u32, s->out2in.addr.as_u32,
	s->nat_proto, s->in2out.port, s->out2in.port, s->in2out.fib_index);

      nat_ha_sdel (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
		   s->ext_host_port, s->nat_proto, s->out2in.fib_index,
		   thread_index);
    }

  if (nat44_ei_is_session_static (s))
    return;

  nat44_ei_free_outside_address_and_port (nm->addresses, thread_index,
					  &s->out2in.addr, s->out2in.port,
					  s->nat_proto);
}

nat44_ei_user_t *
nat44_ei_user_get_or_create (nat44_ei_main_t *nm, ip4_address_t *addr,
			     u32 fib_index, u32 thread_index)
{
  nat44_ei_user_t *u = 0;
  nat44_ei_user_key_t user_key;
  clib_bihash_kv_8_8_t kv, value;
  nat44_ei_main_per_thread_data_t *tnm = &nm->per_thread_data[thread_index];
  dlist_elt_t *per_user_list_head_elt;

  user_key.addr.as_u32 = addr->as_u32;
  user_key.fib_index = fib_index;
  kv.key = user_key.as_u64;

  /* Ever heard of the "user" = src ip4 address before? */
  if (clib_bihash_search_8_8 (&tnm->user_hash, &kv, &value))
    {
      if (pool_elts (tnm->users) >= nm->max_users_per_thread)
	{
	  vlib_increment_simple_counter (&nm->user_limit_reached, thread_index,
					 0, 1);
	  nat_elog_warn (nm, "maximum user limit reached");
	  return NULL;
	}
      /* no, make a new one */
      pool_get (tnm->users, u);
      clib_memset (u, 0, sizeof (*u));

      u->addr.as_u32 = addr->as_u32;
      u->fib_index = fib_index;

      pool_get (tnm->list_pool, per_user_list_head_elt);

      u->sessions_per_user_list_head_index =
	per_user_list_head_elt - tnm->list_pool;

      clib_dlist_init (tnm->list_pool, u->sessions_per_user_list_head_index);

      kv.value = u - tnm->users;

      /* add user */
      if (clib_bihash_add_del_8_8 (&tnm->user_hash, &kv, 1))
	{
	  nat_elog_warn (nm, "user_hash key add failed");
	  nat44_ei_delete_user_with_no_session (nm, u, thread_index);
	  return NULL;
	}

      vlib_set_simple_counter (&nm->total_users, thread_index, 0,
			       pool_elts (tnm->users));
    }
  else
    {
      u = pool_elt_at_index (tnm->users, value.value);
    }

  return u;
}

nat44_ei_session_t *
nat44_ei_session_alloc_or_recycle (nat44_ei_main_t *nm, nat44_ei_user_t *u,
				   u32 thread_index, f64 now)
{
  nat44_ei_session_t *s;
  nat44_ei_main_per_thread_data_t *tnm = &nm->per_thread_data[thread_index];
  u32 oldest_per_user_translation_list_index, session_index;
  dlist_elt_t *oldest_per_user_translation_list_elt;
  dlist_elt_t *per_user_translation_list_elt;

  /* Over quota? Recycle the least recently used translation */
  if ((u->nsessions + u->nstaticsessions) >= nm->max_translations_per_user)
    {
      oldest_per_user_translation_list_index = clib_dlist_remove_head (
	tnm->list_pool, u->sessions_per_user_list_head_index);

      ASSERT (oldest_per_user_translation_list_index != ~0);

      /* Add it back to the end of the LRU list */
      clib_dlist_addtail (tnm->list_pool, u->sessions_per_user_list_head_index,
			  oldest_per_user_translation_list_index);
      /* Get the list element */
      oldest_per_user_translation_list_elt = pool_elt_at_index (
	tnm->list_pool, oldest_per_user_translation_list_index);

      /* Get the session index from the list element */
      session_index = oldest_per_user_translation_list_elt->value;

      /* Get the session */
      s = pool_elt_at_index (tnm->sessions, session_index);

      nat44_ei_free_session_data_v2 (nm, s, thread_index, 0);
      if (nat44_ei_is_session_static (s))
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
      pool_get (tnm->sessions, s);
      clib_memset (s, 0, sizeof (*s));

      /* Create list elts */
      pool_get (tnm->list_pool, per_user_translation_list_elt);
      clib_dlist_init (tnm->list_pool,
		       per_user_translation_list_elt - tnm->list_pool);

      per_user_translation_list_elt->value = s - tnm->sessions;
      s->per_user_index = per_user_translation_list_elt - tnm->list_pool;
      s->per_user_list_head_index = u->sessions_per_user_list_head_index;

      clib_dlist_addtail (tnm->list_pool, s->per_user_list_head_index,
			  per_user_translation_list_elt - tnm->list_pool);

      s->user_index = u - tnm->users;
      vlib_set_simple_counter (&nm->total_sessions, thread_index, 0,
			       pool_elts (tnm->sessions));
    }

  s->ha_last_refreshed = now;

  return s;
}

void
nat44_ei_free_session_data (nat44_ei_main_t *nm, nat44_ei_session_t *s,
			    u32 thread_index, u8 is_ha)
{
  clib_bihash_kv_8_8_t kv;

  init_nat_i2o_k (&kv, s);
  if (clib_bihash_add_del_8_8 (&nm->in2out, &kv, 0))
    nat_elog_warn (nm, "in2out key del failed");

  init_nat_o2i_k (&kv, s);
  if (clib_bihash_add_del_8_8 (&nm->out2in, &kv, 0))
    nat_elog_warn (nm, "out2in key del failed");

  if (!is_ha)
    {
      nat_syslog_nat44_apmdel (s->user_index, s->in2out.fib_index,
			       &s->in2out.addr, s->in2out.port,
			       &s->out2in.addr, s->out2in.port, s->nat_proto);

      nat_ipfix_logging_nat44_ses_delete (
	thread_index, s->in2out.addr.as_u32, s->out2in.addr.as_u32,
	s->nat_proto, s->in2out.port, s->out2in.port, s->in2out.fib_index);

      nat_ha_sdel (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
		   s->ext_host_port, s->nat_proto, s->out2in.fib_index,
		   thread_index);
    }

  if (nat44_ei_is_session_static (s))
    return;

  nat44_ei_free_outside_address_and_port (nm->addresses, thread_index,
					  &s->out2in.addr, s->out2in.port,
					  s->nat_proto);
}

static_always_inline void
nat44_ei_user_del_sessions (nat44_ei_user_t *u, u32 thread_index)
{
  dlist_elt_t *elt;
  nat44_ei_session_t *s;

  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_main_per_thread_data_t *tnm = &nm->per_thread_data[thread_index];

  // get head
  elt =
    pool_elt_at_index (tnm->list_pool, u->sessions_per_user_list_head_index);
  // get first element
  elt = pool_elt_at_index (tnm->list_pool, elt->next);

  while (elt->value != ~0)
    {
      s = pool_elt_at_index (tnm->sessions, elt->value);
      elt = pool_elt_at_index (tnm->list_pool, elt->next);

      nat44_ei_free_session_data (nm, s, thread_index, 0);
      nat44_ei_delete_session (nm, s, thread_index);
    }
}

int
nat44_ei_user_del (ip4_address_t *addr, u32 fib_index)
{
  int rv = 1;

  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_main_per_thread_data_t *tnm;

  nat44_ei_user_key_t user_key;
  clib_bihash_kv_8_8_t kv, value;

  user_key.addr.as_u32 = addr->as_u32;
  user_key.fib_index = fib_index;
  kv.key = user_key.as_u64;

  if (nm->num_workers > 1)
    {
      vec_foreach (tnm, nm->per_thread_data)
	{
	  if (!clib_bihash_search_8_8 (&tnm->user_hash, &kv, &value))
	    {
	      nat44_ei_user_del_sessions (
		pool_elt_at_index (tnm->users, value.value),
		tnm->thread_index);
	      rv = 0;
	      break;
	    }
	}
    }
  else
    {
      tnm = vec_elt_at_index (nm->per_thread_data, nm->num_workers);
      if (!clib_bihash_search_8_8 (&tnm->user_hash, &kv, &value))
	{
	  nat44_ei_user_del_sessions (
	    pool_elt_at_index (tnm->users, value.value), tnm->thread_index);
	  rv = 0;
	}
    }
  return rv;
}

void
nat44_ei_static_mapping_del_sessions (nat44_ei_main_t *nm,
				      nat44_ei_main_per_thread_data_t *tnm,
				      nat44_ei_user_key_t u_key, int addr_only,
				      ip4_address_t e_addr, u16 e_port)
{
  clib_bihash_kv_8_8_t kv, value;
  kv.key = u_key.as_u64;
  u64 user_index;
  dlist_elt_t *head, *elt;
  nat44_ei_user_t *u;
  nat44_ei_session_t *s;
  u32 elt_index, head_index, ses_index;

  if (!clib_bihash_search_8_8 (&tnm->user_hash, &kv, &value))
    {
      user_index = value.value;
      u = pool_elt_at_index (tnm->users, user_index);
      if (u->nstaticsessions)
	{
	  head_index = u->sessions_per_user_list_head_index;
	  head = pool_elt_at_index (tnm->list_pool, head_index);
	  elt_index = head->next;
	  elt = pool_elt_at_index (tnm->list_pool, elt_index);
	  ses_index = elt->value;
	  while (ses_index != ~0)
	    {
	      s = pool_elt_at_index (tnm->sessions, ses_index);
	      elt = pool_elt_at_index (tnm->list_pool, elt->next);
	      ses_index = elt->value;

	      if (!addr_only)
		{
		  if ((s->out2in.addr.as_u32 != e_addr.as_u32) ||
		      (s->out2in.port != e_port))
		    continue;
		}

	      if (!nat44_ei_is_session_static (s))
		continue;

	      nat44_ei_free_session_data_v2 (nm, s, tnm - nm->per_thread_data,
					     0);
	      nat44_ei_delete_session (nm, s, tnm - nm->per_thread_data);

	      if (!addr_only)
		break;
	    }
	}
    }
}

u32
nat44_ei_get_in2out_worker_index (ip4_header_t *ip0, u32 rx_fib_index0,
				  u8 is_output)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  u32 next_worker_index = 0;
  u32 hash;

  next_worker_index = nm->first_worker_index;
  hash = ip0->src_address.as_u32 + (ip0->src_address.as_u32 >> 8) +
	 (ip0->src_address.as_u32 >> 16) + (ip0->src_address.as_u32 >> 24);

  if (PREDICT_TRUE (is_pow2 (_vec_len (nm->workers))))
    next_worker_index += nm->workers[hash & (_vec_len (nm->workers) - 1)];
  else
    next_worker_index += nm->workers[hash % _vec_len (nm->workers)];

  return next_worker_index;
}

u32
nat44_ei_get_out2in_worker_index (vlib_buffer_t *b, ip4_header_t *ip0,
				  u32 rx_fib_index0, u8 is_output)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  udp_header_t *udp;
  u16 port;
  clib_bihash_kv_8_8_t kv, value;
  nat44_ei_static_mapping_t *m;
  u32 proto;
  u32 next_worker_index = 0;

  /* first try static mappings without port */
  if (PREDICT_FALSE (pool_elts (nm->static_mappings)))
    {
      init_nat_k (&kv, ip0->dst_address, 0, rx_fib_index0, 0);
      if (!clib_bihash_search_8_8 (&nm->static_mapping_by_external, &kv,
				   &value))
	{
	  m = pool_elt_at_index (nm->static_mappings, value.value);
	  return m->workers[0];
	}
    }

  proto = ip_proto_to_nat_proto (ip0->protocol);
  udp = ip4_next_header (ip0);
  port = vnet_buffer (b)->ip.reass.l4_dst_port;

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
      if (!icmp_type_is_error_message (
	    vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags))
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
  if (PREDICT_FALSE (pool_elts (nm->static_mappings)))
    {
      init_nat_k (&kv, ip0->dst_address, port, rx_fib_index0, proto);
      if (!clib_bihash_search_8_8 (&nm->static_mapping_by_external, &kv,
				   &value))
	{
	  m = pool_elt_at_index (nm->static_mappings, value.value);
	  return m->workers[0];
	}
    }

  /* worker by outside port */
  next_worker_index = nm->first_worker_index;
  next_worker_index +=
    nm->workers[(clib_net_to_host_u16 (port) - 1024) / nm->port_per_thread];
  return next_worker_index;
}

static int
nat44_ei_alloc_default_cb (nat44_ei_address_t *addresses, u32 fib_index,
			   u32 thread_index, nat_protocol_t proto,
			   ip4_address_t s_addr, ip4_address_t *addr,
			   u16 *port, u16 port_per_thread,
			   u32 snat_thread_index)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_address_t *a, *ga = 0;
  u32 portnum;
  int i;

  if (vec_len (addresses) > 0)
    {

      int s_addr_offset = s_addr.as_u32 % vec_len (addresses);

      for (i = s_addr_offset; i < vec_len (addresses); ++i)
	{
	  a = addresses + i;
	  switch (proto)
	    {
#define _(N, j, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    if (a->busy_##n##_ports_per_thread[thread_index] < port_per_thread)       \
      {                                                                       \
	if (a->fib_index == fib_index)                                        \
	  {                                                                   \
	    while (1)                                                         \
	      {                                                               \
		portnum = (port_per_thread * snat_thread_index) +             \
			  nat_random_port (&nm->random_seed, 0,               \
					   port_per_thread - 1) +             \
			  1024;                                               \
		if (a->busy_##n##_port_refcounts[portnum])                    \
		  continue;                                                   \
		--a->busy_##n##_port_refcounts[portnum];                      \
		a->busy_##n##_ports_per_thread[thread_index]++;               \
		a->busy_##n##_ports++;                                        \
		*addr = a->addr;                                              \
		*port = clib_host_to_net_u16 (portnum);                       \
		return 0;                                                     \
	      }                                                               \
	  }                                                                   \
	else if (a->fib_index == ~0)                                          \
	  {                                                                   \
	    ga = a;                                                           \
	  }                                                                   \
      }                                                                       \
    break;
	      foreach_nat_protocol;
	    default:
	      nat_elog_info (nm, "unknown protocol");
	      return 1;
	    }
	}

      for (i = 0; i < s_addr_offset; ++i)
	{
	  a = addresses + i;
	  switch (proto)
	    {
	      foreach_nat_protocol;
	    default:
	      nat_elog_info (nm, "unknown protocol");
	      return 1;
	    }
	}
  if (ga)
    {
      a = ga;
      // fake fib index to reuse macro
      fib_index = ~0;
      switch (proto)
	{
	  foreach_nat_protocol;
	    default : nat_elog_info (nm, "unknown protocol");
	  return 1;
	}
    }
    }

#undef _

  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

static int
nat44_ei_alloc_range_cb (nat44_ei_address_t *addresses, u32 fib_index,
			 u32 thread_index, nat_protocol_t proto,
			 ip4_address_t s_addr, ip4_address_t *addr, u16 *port,
			 u16 port_per_thread, u32 snat_thread_index)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_address_t *a = addresses;
  u16 portnum, ports;

  ports = nm->end_port - nm->start_port + 1;

  if (!vec_len (addresses))
    goto exhausted;

  switch (proto)
    {
#define _(N, i, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    if (a->busy_##n##_ports < ports)                                          \
      {                                                                       \
	while (1)                                                             \
	  {                                                                   \
	    portnum = nat_random_port (&nm->random_seed, nm->start_port,      \
				       nm->end_port);                         \
	    if (a->busy_##n##_port_refcounts[portnum])                        \
	      continue;                                                       \
	    ++a->busy_##n##_port_refcounts[portnum];                          \
	    a->busy_##n##_ports++;                                            \
	    *addr = a->addr;                                                  \
	    *port = clib_host_to_net_u16 (portnum);                           \
	    return 0;                                                         \
	  }                                                                   \
      }                                                                       \
    break;
      foreach_nat_protocol
#undef _
	default : nat_elog_info (nm, "unknown protocol");
      return 1;
    }

exhausted:
  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

static int
nat44_ei_alloc_mape_cb (nat44_ei_address_t *addresses, u32 fib_index,
			u32 thread_index, nat_protocol_t proto,
			ip4_address_t s_addr, ip4_address_t *addr, u16 *port,
			u16 port_per_thread, u32 snat_thread_index)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_address_t *a = addresses;
  u16 m, ports, portnum, A, j;
  m = 16 - (nm->psid_offset + nm->psid_length);
  ports = (1 << (16 - nm->psid_length)) - (1 << m);

  if (!vec_len (addresses))
    goto exhausted;

  switch (proto)
    {
#define _(N, i, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    if (a->busy_##n##_ports < ports)                                          \
      {                                                                       \
	while (1)                                                             \
	  {                                                                   \
	    A = nat_random_port (&nm->random_seed, 1,                         \
				 pow2_mask (nm->psid_offset));                \
	    j = nat_random_port (&nm->random_seed, 0, pow2_mask (m));         \
	    portnum = A | (nm->psid << nm->psid_offset) | (j << (16 - m));    \
	    if (a->busy_##n##_port_refcounts[portnum])                        \
	      continue;                                                       \
	    ++a->busy_##n##_port_refcounts[portnum];                          \
	    a->busy_##n##_ports++;                                            \
	    *addr = a->addr;                                                  \
	    *port = clib_host_to_net_u16 (portnum);                           \
	    return 0;                                                         \
	  }                                                                   \
      }                                                                       \
    break;
      foreach_nat_protocol
#undef _
	default : nat_elog_info (nm, "unknown protocol");
      return 1;
    }

exhausted:
  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

void
nat44_ei_set_alloc_default ()
{
  nat44_ei_main_t *nm = &nat44_ei_main;

  nm->addr_and_port_alloc_alg = NAT44_EI_ADDR_AND_PORT_ALLOC_ALG_DEFAULT;
  nm->alloc_addr_and_port = nat44_ei_alloc_default_cb;
}

void
nat44_ei_set_alloc_range (u16 start_port, u16 end_port)
{
  nat44_ei_main_t *nm = &nat44_ei_main;

  nm->addr_and_port_alloc_alg = NAT44_EI_ADDR_AND_PORT_ALLOC_ALG_RANGE;
  nm->alloc_addr_and_port = nat44_ei_alloc_range_cb;
  nm->start_port = start_port;
  nm->end_port = end_port;
}

void
nat44_ei_set_alloc_mape (u16 psid, u16 psid_offset, u16 psid_length)
{
  nat44_ei_main_t *nm = &nat44_ei_main;

  nm->addr_and_port_alloc_alg = NAT44_EI_ADDR_AND_PORT_ALLOC_ALG_MAPE;
  nm->alloc_addr_and_port = nat44_ei_alloc_mape_cb;
  nm->psid = psid;
  nm->psid_offset = psid_offset;
  nm->psid_length = psid_length;
}

static void
nat44_ei_add_static_mapping_when_resolved (ip4_address_t l_addr, u16 l_port,
					   u16 e_port, nat_protocol_t proto,
					   u32 sw_if_index, u32 vrf_id,
					   int addr_only, int identity_nat,
					   u8 *tag)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_static_map_resolve_t *rp;

  vec_add2 (nm->to_resolve, rp, 1);
  clib_memset (rp, 0, sizeof (*rp));

  rp->l_addr.as_u32 = l_addr.as_u32;
  rp->l_port = l_port;
  rp->e_port = e_port;
  rp->sw_if_index = sw_if_index;
  rp->vrf_id = vrf_id;
  rp->proto = proto;
  rp->addr_only = addr_only;
  rp->identity_nat = identity_nat;
  rp->tag = vec_dup (tag);
}

void
nat44_ei_delete_session (nat44_ei_main_t *nm, nat44_ei_session_t *ses,
			 u32 thread_index)
{
  nat44_ei_main_per_thread_data_t *tnm =
    vec_elt_at_index (nm->per_thread_data, thread_index);
  clib_bihash_kv_8_8_t kv, value;
  nat44_ei_user_t *u;
  const nat44_ei_user_key_t u_key = { .addr = ses->in2out.addr,
				      .fib_index = ses->in2out.fib_index };
  const u8 u_static = nat44_ei_is_session_static (ses);

  clib_dlist_remove (tnm->list_pool, ses->per_user_index);
  pool_put_index (tnm->list_pool, ses->per_user_index);

  pool_put (tnm->sessions, ses);
  vlib_set_simple_counter (&nm->total_sessions, thread_index, 0,
			   pool_elts (tnm->sessions));

  kv.key = u_key.as_u64;
  if (!clib_bihash_search_8_8 (&tnm->user_hash, &kv, &value))
    {
      u = pool_elt_at_index (tnm->users, value.value);
      if (u_static)
	u->nstaticsessions--;
      else
	u->nsessions--;

      nat44_ei_delete_user_with_no_session (nm, u, thread_index);
    }
}

int
nat44_ei_del_session (nat44_ei_main_t *nm, ip4_address_t *addr, u16 port,
		      nat_protocol_t proto, u32 vrf_id, int is_in)
{
  nat44_ei_main_per_thread_data_t *tnm;
  clib_bihash_kv_8_8_t kv, value;
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);
  nat44_ei_session_t *s;
  clib_bihash_8_8_t *t;

  init_nat_k (&kv, *addr, port, fib_index, proto);
  t = is_in ? &nm->in2out : &nm->out2in;
  if (!clib_bihash_search_8_8 (t, &kv, &value))
    {
      // world is stopped here - can manipulate per-thread data with no risks
      u32 thread_index = nat_value_get_thread_index (&value);
      tnm = vec_elt_at_index (nm->per_thread_data, thread_index);
      u32 session_index = nat_value_get_session_index (&value);
      if (pool_is_free_index (tnm->sessions, session_index))
	return VNET_API_ERROR_UNSPECIFIED;

      s = pool_elt_at_index (tnm->sessions, session_index);
      nat44_ei_free_session_data_v2 (nm, s, tnm - nm->per_thread_data, 0);
      nat44_ei_delete_session (nm, s, tnm - nm->per_thread_data);
      return 0;
    }

  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

u32
nat44_ei_get_thread_idx_by_port (u16 e_port)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  u32 thread_idx = nm->num_workers;
  if (nm->num_workers > 1)
    {
      thread_idx = nm->first_worker_index +
		   nm->workers[(e_port - 1024) / nm->port_per_thread];
    }
  return thread_idx;
}

void
nat44_ei_add_del_addr_to_fib (ip4_address_t *addr, u8 p_len, u32 sw_if_index,
			      int is_add)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  fib_prefix_t prefix = {
    .fp_len = p_len,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr = {
		.ip4.as_u32 = addr->as_u32,
		},
  };
  u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  if (is_add)
    fib_table_entry_update_one_path (
      fib_index, &prefix, nm->fib_src_low,
      (FIB_ENTRY_FLAG_CONNECTED | FIB_ENTRY_FLAG_LOCAL |
       FIB_ENTRY_FLAG_EXCLUSIVE),
      DPO_PROTO_IP4, NULL, sw_if_index, ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
  else
    fib_table_entry_delete (fib_index, &prefix, nm->fib_src_low);
}

int
nat44_ei_add_del_static_mapping (ip4_address_t l_addr, ip4_address_t e_addr,
				 u16 l_port, u16 e_port, nat_protocol_t proto,
				 u32 sw_if_index, u32 vrf_id, u8 addr_only,
				 u8 identity_nat, u8 *tag, u8 is_add)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_static_mapping_t *m = 0;
  clib_bihash_kv_8_8_t kv, value;
  nat44_ei_address_t *a = 0;
  u32 fib_index = ~0;
  nat44_ei_interface_t *interface;
  nat44_ei_main_per_thread_data_t *tnm;
  nat44_ei_user_key_t u_key;
  nat44_ei_user_t *u;
  dlist_elt_t *head, *elt;
  u32 elt_index, head_index;
  u32 ses_index;
  u64 user_index;
  nat44_ei_session_t *s;
  nat44_ei_static_map_resolve_t *rp, *rp_match = 0;
  nat44_ei_lb_addr_port_t *local;
  u32 find = ~0;
  int i;

  if (sw_if_index != ~0)
    {
      ip4_address_t *first_int_addr;

      for (i = 0; i < vec_len (nm->to_resolve); i++)
	{
	  rp = nm->to_resolve + i;
	  if (rp->sw_if_index != sw_if_index ||
	      rp->l_addr.as_u32 != l_addr.as_u32 || rp->vrf_id != vrf_id ||
	      rp->addr_only != addr_only)
	    continue;

	  if (!addr_only)
	    {
	      if ((rp->l_port != l_port && rp->e_port != e_port) ||
		  rp->proto != proto)
		continue;
	    }

	  rp_match = rp;
	  break;
	}

      /* Might be already set... */
      first_int_addr = ip4_interface_first_address (
	nm->ip4_main, sw_if_index, 0 /* just want the address */);

      if (is_add)
	{
	  if (rp_match)
	    return VNET_API_ERROR_VALUE_EXIST;

	  nat44_ei_add_static_mapping_when_resolved (
	    l_addr, l_port, e_port, proto, sw_if_index, vrf_id, addr_only,
	    identity_nat, tag);

	  /* DHCP resolution required? */
	  if (!first_int_addr)
	    return 0;

	  e_addr.as_u32 = first_int_addr->as_u32;
	  /* Identity mapping? */
	  if (l_addr.as_u32 == 0)
	    l_addr.as_u32 = e_addr.as_u32;
	}
      else
	{
	  if (!rp_match)
	    return VNET_API_ERROR_NO_SUCH_ENTRY;

	  vec_del1 (nm->to_resolve, i);

	  if (!first_int_addr)
	    return 0;

	  e_addr.as_u32 = first_int_addr->as_u32;
	  /* Identity mapping? */
	  if (l_addr.as_u32 == 0)
	    l_addr.as_u32 = e_addr.as_u32;
	}
    }

  init_nat_k (&kv, e_addr, addr_only ? 0 : e_port, 0, addr_only ? 0 : proto);
  if (!clib_bihash_search_8_8 (&nm->static_mapping_by_external, &kv, &value))
    m = pool_elt_at_index (nm->static_mappings, value.value);

  if (is_add)
    {
      if (m)
	{
	  // identity mapping for second vrf
	  if (nat44_ei_is_identity_static_mapping (m))
	    {
	      pool_foreach (local, m->locals)
		{
		  if (local->vrf_id == vrf_id)
		    return VNET_API_ERROR_VALUE_EXIST;
		}
	      pool_get (m->locals, local);
	      local->vrf_id = vrf_id;
	      local->fib_index = fib_table_find_or_create_and_lock (
		FIB_PROTOCOL_IP4, vrf_id, nm->fib_src_low);
	      init_nat_kv (&kv, m->local_addr, m->local_port, local->fib_index,
			   m->proto, 0, m - nm->static_mappings);
	      clib_bihash_add_del_8_8 (&nm->static_mapping_by_local, &kv, 1);
	      return 0;
	    }
	  return VNET_API_ERROR_VALUE_EXIST;
	}

      /* Convert VRF id to FIB index */
      if (vrf_id != ~0)
	{
	  fib_index = fib_table_find_or_create_and_lock (
	    FIB_PROTOCOL_IP4, vrf_id, nm->fib_src_low);
	}
      /* If not specified use inside VRF id from NAT44 plugin config */
      else
	{
	  fib_index = nm->inside_fib_index;
	  vrf_id = nm->inside_vrf_id;
	  fib_table_lock (fib_index, FIB_PROTOCOL_IP4, nm->fib_src_low);
	}

      if (!identity_nat)
	{
	  init_nat_k (&kv, l_addr, addr_only ? 0 : l_port, fib_index,
		      addr_only ? 0 : proto);
	  if (!clib_bihash_search_8_8 (&nm->static_mapping_by_local, &kv,
				       &value))
	    return VNET_API_ERROR_VALUE_EXIST;
	}

      /* Find external address in allocated addresses and reserve port for
	 address and port pair mapping when dynamic translations enabled */
      if (!(addr_only || nm->static_mapping_only))
	{
	  for (i = 0; i < vec_len (nm->addresses); i++)
	    {
	      if (nm->addresses[i].addr.as_u32 == e_addr.as_u32)
		{
		  a = nm->addresses + i;
		  /* External port must be unused */
		  switch (proto)
		    {
#define _(N, j, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    if (a->busy_##n##_port_refcounts[e_port])                                 \
      return VNET_API_ERROR_INVALID_VALUE;                                    \
    ++a->busy_##n##_port_refcounts[e_port];                                   \
    if (e_port > 1024)                                                        \
      {                                                                       \
	a->busy_##n##_ports++;                                                \
	a->busy_##n##_ports_per_thread[nat44_ei_get_thread_idx_by_port (      \
	  e_port)]++;                                                         \
      }                                                                       \
    break;
		      foreach_nat_protocol
#undef _
			default : nat_elog_info (nm, "unknown protocol");
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
		  for (i = 0; i < vec_len (nm->to_resolve); i++)
		    {
		      rp = nm->to_resolve + i;
		      if (rp->addr_only)
			continue;
		      if (rp->sw_if_index != sw_if_index &&
			  rp->l_addr.as_u32 != l_addr.as_u32 &&
			  rp->vrf_id != vrf_id && rp->l_port != l_port &&
			  rp->e_port != e_port && rp->proto != proto)
			continue;

		      vec_del1 (nm->to_resolve, i);
		      break;
		    }
		}
	      return VNET_API_ERROR_NO_SUCH_ENTRY;
	    }
	}

      pool_get (nm->static_mappings, m);
      clib_memset (m, 0, sizeof (*m));
      m->tag = vec_dup (tag);
      m->local_addr = l_addr;
      m->external_addr = e_addr;

      if (addr_only)
	m->flags |= NAT44_EI_STATIC_MAPPING_FLAG_ADDR_ONLY;
      else
	{
	  m->local_port = l_port;
	  m->external_port = e_port;
	  m->proto = proto;
	}

      if (identity_nat)
	{
	  m->flags |= NAT44_EI_STATIC_MAPPING_FLAG_IDENTITY_NAT;
	  pool_get (m->locals, local);
	  local->vrf_id = vrf_id;
	  local->fib_index = fib_index;
	}
      else
	{
	  m->vrf_id = vrf_id;
	  m->fib_index = fib_index;
	}

      if (nm->num_workers > 1)
	{
	  ip4_header_t ip = {
	    .src_address = m->local_addr,
	  };
	  vec_add1 (m->workers,
		    nat44_ei_get_in2out_worker_index (&ip, m->fib_index, 0));
	  tnm = vec_elt_at_index (nm->per_thread_data, m->workers[0]);
	}
      else
	tnm = vec_elt_at_index (nm->per_thread_data, nm->num_workers);

      init_nat_kv (&kv, m->local_addr, m->local_port, fib_index, m->proto, 0,
		   m - nm->static_mappings);
      clib_bihash_add_del_8_8 (&nm->static_mapping_by_local, &kv, 1);

      init_nat_kv (&kv, m->external_addr, m->external_port, 0, m->proto, 0,
		   m - nm->static_mappings);
      clib_bihash_add_del_8_8 (&nm->static_mapping_by_external, &kv, 1);

      /* Delete dynamic sessions matching local address (+ local port) */
      // TODO: based on type of NAT EI/ED
      if (!(nm->static_mapping_only))
	{
	  u_key.addr = m->local_addr;
	  u_key.fib_index = m->fib_index;
	  kv.key = u_key.as_u64;
	  if (!clib_bihash_search_8_8 (&tnm->user_hash, &kv, &value))
	    {
	      user_index = value.value;
	      u = pool_elt_at_index (tnm->users, user_index);
	      if (u->nsessions)
		{
		  head_index = u->sessions_per_user_list_head_index;
		  head = pool_elt_at_index (tnm->list_pool, head_index);
		  elt_index = head->next;
		  elt = pool_elt_at_index (tnm->list_pool, elt_index);
		  ses_index = elt->value;
		  while (ses_index != ~0)
		    {
		      s = pool_elt_at_index (tnm->sessions, ses_index);
		      elt = pool_elt_at_index (tnm->list_pool, elt->next);
		      ses_index = elt->value;

		      if (nat44_ei_is_session_static (s))
			continue;

		      if (!addr_only && s->in2out.port != m->local_port)
			continue;

		      nat44_ei_free_session_data_v2 (
			nm, s, tnm - nm->per_thread_data, 0);
		      nat44_ei_delete_session (nm, s,
					       tnm - nm->per_thread_data);

		      if (!addr_only)
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
	    vrf_id = nm->inside_vrf_id;

	  pool_foreach (local, m->locals)
	    {
	      if (local->vrf_id == vrf_id)
		find = local - m->locals;
	    }
	  if (find == ~0)
	    return VNET_API_ERROR_NO_SUCH_ENTRY;

	  local = pool_elt_at_index (m->locals, find);
	  fib_index = local->fib_index;
	  pool_put (m->locals, local);
	}
      else
	fib_index = m->fib_index;

      /* Free external address port */
      if (!(addr_only || nm->static_mapping_only))
	{
	  for (i = 0; i < vec_len (nm->addresses); i++)
	    {
	      if (nm->addresses[i].addr.as_u32 == e_addr.as_u32)
		{
		  a = nm->addresses + i;
		  switch (proto)
		    {
#define _(N, j, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    --a->busy_##n##_port_refcounts[e_port];                                   \
    if (e_port > 1024)                                                        \
      {                                                                       \
	a->busy_##n##_ports--;                                                \
	a->busy_##n##_ports_per_thread[nat44_ei_get_thread_idx_by_port (      \
	  e_port)]--;                                                         \
      }                                                                       \
    break;
		      foreach_nat_protocol
#undef _
			default : return VNET_API_ERROR_INVALID_VALUE_2;
		    }
		  break;
		}
	    }
	}

      if (nm->num_workers > 1)
	tnm = vec_elt_at_index (nm->per_thread_data, m->workers[0]);
      else
	tnm = vec_elt_at_index (nm->per_thread_data, nm->num_workers);

      init_nat_k (&kv, m->local_addr, m->local_port, fib_index, m->proto);
      clib_bihash_add_del_8_8 (&nm->static_mapping_by_local, &kv, 0);

      /* Delete session(s) for static mapping if exist */
      if (!(nm->static_mapping_only) ||
	  (nm->static_mapping_only && nm->static_mapping_connection_tracking))
	{
	  u_key.addr = m->local_addr;
	  u_key.fib_index = fib_index;
	  kv.key = u_key.as_u64;
	  nat44_ei_static_mapping_del_sessions (nm, tnm, u_key, addr_only,
						e_addr, e_port);
	}

      fib_table_unlock (fib_index, FIB_PROTOCOL_IP4, nm->fib_src_low);
      if (pool_elts (m->locals))
	return 0;

      init_nat_k (&kv, m->external_addr, m->external_port, 0, m->proto);
      clib_bihash_add_del_8_8 (&nm->static_mapping_by_external, &kv, 0);

      vec_free (m->tag);
      vec_free (m->workers);
      /* Delete static mapping from pool */
      pool_put (nm->static_mappings, m);
    }

  if (!addr_only || (l_addr.as_u32 == e_addr.as_u32))
    return 0;

  /* Add/delete external address to FIB */
  pool_foreach (interface, nm->interfaces)
    {
      if (nat44_ei_interface_is_inside (interface) || nm->out2in_dpo)
	continue;

      nat44_ei_add_del_addr_to_fib (&e_addr, 32, interface->sw_if_index,
				    is_add);
      break;
    }
  pool_foreach (interface, nm->output_feature_interfaces)
    {
      if (nat44_ei_interface_is_inside (interface) || nm->out2in_dpo)
	continue;

      nat44_ei_add_del_addr_to_fib (&e_addr, 32, interface->sw_if_index,
				    is_add);
      break;
    }
  return 0;
}

int
nat44_ei_static_mapping_match (ip4_address_t match_addr, u16 match_port,
			       u32 match_fib_index,
			       nat_protocol_t match_protocol,
			       ip4_address_t *mapping_addr, u16 *mapping_port,
			       u32 *mapping_fib_index, u8 by_external,
			       u8 *is_addr_only, u8 *is_identity_nat)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  clib_bihash_kv_8_8_t kv, value;
  nat44_ei_static_mapping_t *m;
  u16 port;

  if (by_external)
    {
      init_nat_k (&kv, match_addr, match_port, 0, match_protocol);
      if (clib_bihash_search_8_8 (&nm->static_mapping_by_external, &kv,
				  &value))
	{
	  /* Try address only mapping */
	  init_nat_k (&kv, match_addr, 0, 0, 0);
	  if (clib_bihash_search_8_8 (&nm->static_mapping_by_external, &kv,
				      &value))
	    return 1;
	}
      m = pool_elt_at_index (nm->static_mappings, value.value);

      *mapping_fib_index = m->fib_index;
      *mapping_addr = m->local_addr;
      port = m->local_port;
    }
  else
    {
      init_nat_k (&kv, match_addr, match_port, match_fib_index,
		  match_protocol);
      if (clib_bihash_search_8_8 (&nm->static_mapping_by_local, &kv, &value))
	{
	  /* Try address only mapping */
	  init_nat_k (&kv, match_addr, 0, match_fib_index, 0);
	  if (clib_bihash_search_8_8 (&nm->static_mapping_by_local, &kv,
				      &value))
	    return 1;
	}
      m = pool_elt_at_index (nm->static_mappings, value.value);

      *mapping_fib_index = nm->outside_fib_index;
      *mapping_addr = m->external_addr;
      port = m->external_port;
    }

  /* Address only mapping doesn't change port */
  if (nat44_ei_is_addr_only_static_mapping (m))
    *mapping_port = match_port;
  else
    *mapping_port = port;

  if (PREDICT_FALSE (is_addr_only != 0))
    *is_addr_only = nat44_ei_is_addr_only_static_mapping (m);

  if (PREDICT_FALSE (is_identity_nat != 0))
    *is_identity_nat = nat44_ei_is_identity_static_mapping (m);

  return 0;
}

static void
nat44_ei_worker_db_free (nat44_ei_main_per_thread_data_t *tnm)
{
  pool_free (tnm->list_pool);
  pool_free (tnm->lru_pool);
  pool_free (tnm->sessions);
  pool_free (tnm->users);

  clib_bihash_free_8_8 (&tnm->user_hash);
}

u8 *
format_nat44_ei_key (u8 *s, va_list *args)
{
  u64 key = va_arg (*args, u64);

  ip4_address_t addr;
  u16 port;
  nat_protocol_t protocol;
  u32 fib_index;

  split_nat_key (key, &addr, &port, &fib_index, &protocol);

  s = format (s, "%U proto %U port %d fib %d", format_ip4_address, &addr,
	      format_nat_protocol, protocol, clib_net_to_host_u16 (port),
	      fib_index);
  return s;
}

u8 *
format_nat44_ei_user_kvp (u8 *s, va_list *args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);
  nat44_ei_user_key_t k;

  k.as_u64 = v->key;

  s = format (s, "%U fib %d user-index %llu", format_ip4_address, &k.addr,
	      k.fib_index, v->value);

  return s;
}

u8 *
format_nat44_ei_session_kvp (u8 *s, va_list *args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);

  s =
    format (s, "%U session-index %llu", format_nat44_ei_key, v->key, v->value);

  return s;
}

u8 *
format_nat44_ei_static_mapping_kvp (u8 *s, va_list *args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);

  s = format (s, "%U static-mapping-index %llu", format_nat44_ei_key, v->key,
	      v->value);

  return s;
}

static void
nat44_ei_worker_db_init (nat44_ei_main_per_thread_data_t *tnm,
			 u32 translations, u32 translation_buckets,
			 u32 user_buckets)
{
  dlist_elt_t *head;

  pool_alloc (tnm->list_pool, translations);
  pool_alloc (tnm->lru_pool, translations);
  pool_alloc (tnm->sessions, translations);

  clib_bihash_init_8_8 (&tnm->user_hash, "users", user_buckets, 0);

  clib_bihash_set_kvp_format_fn_8_8 (&tnm->user_hash,
				     format_nat44_ei_user_kvp);

  pool_get (tnm->lru_pool, head);
  tnm->tcp_trans_lru_head_index = head - tnm->lru_pool;
  clib_dlist_init (tnm->lru_pool, tnm->tcp_trans_lru_head_index);

  pool_get (tnm->lru_pool, head);
  tnm->tcp_estab_lru_head_index = head - tnm->lru_pool;
  clib_dlist_init (tnm->lru_pool, tnm->tcp_estab_lru_head_index);

  pool_get (tnm->lru_pool, head);
  tnm->udp_lru_head_index = head - tnm->lru_pool;
  clib_dlist_init (tnm->lru_pool, tnm->udp_lru_head_index);

  pool_get (tnm->lru_pool, head);
  tnm->icmp_lru_head_index = head - tnm->lru_pool;
  clib_dlist_init (tnm->lru_pool, tnm->icmp_lru_head_index);

  pool_get (tnm->lru_pool, head);
  tnm->unk_proto_lru_head_index = head - tnm->lru_pool;
  clib_dlist_init (tnm->lru_pool, tnm->unk_proto_lru_head_index);
}

static void
nat44_ei_db_free ()
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_main_per_thread_data_t *tnm;

  pool_free (nm->static_mappings);
  clib_bihash_free_8_8 (&nm->static_mapping_by_local);
  clib_bihash_free_8_8 (&nm->static_mapping_by_external);

  if (nm->pat)
    {
      clib_bihash_free_8_8 (&nm->in2out);
      clib_bihash_free_8_8 (&nm->out2in);
      vec_foreach (tnm, nm->per_thread_data)
	{
	  nat44_ei_worker_db_free (tnm);
	}
    }
}

static void
nat44_ei_db_init (u32 translations, u32 translation_buckets, u32 user_buckets)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_main_per_thread_data_t *tnm;

  u32 static_mapping_buckets = 1024;
  u32 static_mapping_memory_size = 64 << 20;

  clib_bihash_init_8_8 (&nm->static_mapping_by_local,
			"static_mapping_by_local", static_mapping_buckets,
			static_mapping_memory_size);
  clib_bihash_init_8_8 (&nm->static_mapping_by_external,
			"static_mapping_by_external", static_mapping_buckets,
			static_mapping_memory_size);
  clib_bihash_set_kvp_format_fn_8_8 (&nm->static_mapping_by_local,
				     format_nat44_ei_static_mapping_kvp);
  clib_bihash_set_kvp_format_fn_8_8 (&nm->static_mapping_by_external,
				     format_nat44_ei_static_mapping_kvp);

  if (nm->pat)
    {
      clib_bihash_init_8_8 (&nm->in2out, "in2out", translation_buckets, 0);
      clib_bihash_init_8_8 (&nm->out2in, "out2in", translation_buckets, 0);
      clib_bihash_set_kvp_format_fn_8_8 (&nm->in2out,
					 format_nat44_ei_session_kvp);
      clib_bihash_set_kvp_format_fn_8_8 (&nm->out2in,
					 format_nat44_ei_session_kvp);
      vec_foreach (tnm, nm->per_thread_data)
	{
	  nat44_ei_worker_db_init (tnm, translations, translation_buckets,
				   user_buckets);
	}
    }
}

void
nat44_ei_sessions_clear ()
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_main_per_thread_data_t *tnm;

  if (nm->pat)
    {
      clib_bihash_free_8_8 (&nm->in2out);
      clib_bihash_free_8_8 (&nm->out2in);
      clib_bihash_init_8_8 (&nm->in2out, "in2out", nm->translation_buckets, 0);
      clib_bihash_init_8_8 (&nm->out2in, "out2in", nm->translation_buckets, 0);
      clib_bihash_set_kvp_format_fn_8_8 (&nm->in2out,
					 format_nat44_ei_session_kvp);
      clib_bihash_set_kvp_format_fn_8_8 (&nm->out2in,
					 format_nat44_ei_session_kvp);
      vec_foreach (tnm, nm->per_thread_data)
	{
	  nat44_ei_worker_db_free (tnm);
	  nat44_ei_worker_db_init (tnm, nm->translations,
				   nm->translation_buckets, nm->user_buckets);
	}
    }

  vlib_zero_simple_counter (&nm->total_users, 0);
  vlib_zero_simple_counter (&nm->total_sessions, 0);
  vlib_zero_simple_counter (&nm->user_limit_reached, 0);
}

static void
nat44_ei_update_outside_fib (ip4_main_t *im, uword opaque, u32 sw_if_index,
			     u32 new_fib_index, u32 old_fib_index)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_outside_fib_t *outside_fib;
  nat44_ei_interface_t *i;
  u8 is_add = 1;
  u8 match = 0;

  if (!nm->enabled || (new_fib_index == old_fib_index) ||
      (!vec_len (nm->outside_fibs)))
    {
      return;
    }

  pool_foreach (i, nm->interfaces)
    {
      if (i->sw_if_index == sw_if_index)
	{
	  if (!(nat44_ei_interface_is_outside (i)))
	    return;
	  match = 1;
	}
    }

  pool_foreach (i, nm->output_feature_interfaces)
    {
      if (i->sw_if_index == sw_if_index)
	{
	  if (!(nat44_ei_interface_is_outside (i)))
	    return;
	  match = 1;
	}
    }

  if (!match)
    return;

  vec_foreach (outside_fib, nm->outside_fibs)
    {
      if (outside_fib->fib_index == old_fib_index)
	{
	  outside_fib->refcount--;
	  if (!outside_fib->refcount)
	    vec_del1 (nm->outside_fibs, outside_fib - nm->outside_fibs);
	  break;
	}
    }

  vec_foreach (outside_fib, nm->outside_fibs)
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
      vec_add2 (nm->outside_fibs, outside_fib, 1);
      outside_fib->refcount = 1;
      outside_fib->fib_index = new_fib_index;
    }
}

int
nat44_ei_add_address (nat44_ei_main_t *nm, ip4_address_t *addr, u32 vrf_id)
{
  nat44_ei_address_t *ap;
  nat44_ei_interface_t *i;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  /* Check if address already exists */
  vec_foreach (ap, nm->addresses)
    {
      if (ap->addr.as_u32 == addr->as_u32)
	{
	  nat44_ei_log_err ("address exist");
	  return VNET_API_ERROR_VALUE_EXIST;
	}
    }

  vec_add2 (nm->addresses, ap, 1);

  ap->addr = *addr;
  if (vrf_id != ~0)
    ap->fib_index = fib_table_find_or_create_and_lock (
      FIB_PROTOCOL_IP4, vrf_id, nm->fib_src_low);
  else
    ap->fib_index = ~0;

#define _(N, i, n, s)                                                         \
  clib_memset (ap->busy_##n##_port_refcounts, 0,                              \
	       sizeof (ap->busy_##n##_port_refcounts));                       \
  ap->busy_##n##_ports = 0;                                                   \
  ap->busy_##n##_ports_per_thread = 0;                                        \
  vec_validate_init_empty (ap->busy_##n##_ports_per_thread,                   \
			   tm->n_vlib_mains - 1, 0);
  foreach_nat_protocol
#undef _

    /* Add external address to FIB */
    pool_foreach (i, nm->interfaces)
  {
    if (nat44_ei_interface_is_inside (i) || nm->out2in_dpo)
      continue;

    nat44_ei_add_del_addr_to_fib (addr, 32, i->sw_if_index, 1);
    break;
  }
  pool_foreach (i, nm->output_feature_interfaces)
    {
      if (nat44_ei_interface_is_inside (i) || nm->out2in_dpo)
	continue;

      nat44_ei_add_del_addr_to_fib (addr, 32, i->sw_if_index, 1);
      break;
    }

  return 0;
}

int
nat44_ei_add_interface_address (nat44_ei_main_t *nm, u32 sw_if_index,
				int is_del)
{
  ip4_main_t *ip4_main = nm->ip4_main;
  ip4_address_t *first_int_addr;
  nat44_ei_static_map_resolve_t *rp;
  u32 *indices_to_delete = 0;
  int i, j;
  u32 *auto_add_sw_if_indices = nm->auto_add_sw_if_indices;

  first_int_addr = ip4_interface_first_address (ip4_main, sw_if_index,
						0 /* just want the address */);

  for (i = 0; i < vec_len (auto_add_sw_if_indices); i++)
    {
      if (auto_add_sw_if_indices[i] == sw_if_index)
	{
	  if (is_del)
	    {
	      /* if have address remove it */
	      if (first_int_addr)
		(void) nat44_ei_del_address (nm, first_int_addr[0], 1);
	      else
		{
		  for (j = 0; j < vec_len (nm->to_resolve); j++)
		    {
		      rp = nm->to_resolve + j;
		      if (rp->sw_if_index == sw_if_index)
			vec_add1 (indices_to_delete, j);
		    }
		  if (vec_len (indices_to_delete))
		    {
		      for (j = vec_len (indices_to_delete) - 1; j >= 0; j--)
			vec_del1 (nm->to_resolve, j);
		      vec_free (indices_to_delete);
		    }
		}
	      vec_del1 (nm->auto_add_sw_if_indices, i);
	    }
	  else
	    return VNET_API_ERROR_VALUE_EXIST;

	  return 0;
	}
    }

  if (is_del)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* add to the auto-address list */
  vec_add1 (nm->auto_add_sw_if_indices, sw_if_index);

  /* If the address is already bound - or static - add it now */
  if (first_int_addr)
    (void) nat44_ei_add_address (nm, first_int_addr, ~0);

  return 0;
}

static int
nat44_ei_is_address_used_in_static_mapping (ip4_address_t addr)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_static_mapping_t *m;
  pool_foreach (m, nm->static_mappings)
    {
      if (nat44_ei_is_addr_only_static_mapping (m) ||
	  nat44_ei_is_identity_static_mapping (m))
	continue;
      if (m->external_addr.as_u32 == addr.as_u32)
	return 1;
    }
  return 0;
}

int
nat44_ei_del_address (nat44_ei_main_t *nm, ip4_address_t addr, u8 delete_sm)
{
  nat44_ei_address_t *a = 0;
  nat44_ei_session_t *ses;
  u32 *ses_to_be_removed = 0, *ses_index;
  nat44_ei_main_per_thread_data_t *tnm;
  nat44_ei_interface_t *interface;
  nat44_ei_static_mapping_t *m;
  int i;

  /* Find SNAT address */
  for (i = 0; i < vec_len (nm->addresses); i++)
    {
      if (nm->addresses[i].addr.as_u32 == addr.as_u32)
	{
	  a = nm->addresses + i;
	  break;
	}
    }
  if (!a)
    {
      nat44_ei_log_err ("no such address");
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (delete_sm)
    {
      pool_foreach (m, nm->static_mappings)
	{
	  if (m->external_addr.as_u32 == addr.as_u32)
	    (void) nat44_ei_add_del_static_mapping (
	      m->local_addr, m->external_addr, m->local_port, m->external_port,
	      m->proto, ~0 /* sw_if_index */, m->vrf_id,
	      nat44_ei_is_addr_only_static_mapping (m),
	      nat44_ei_is_identity_static_mapping (m), m->tag, 0);
	}
    }
  else
    {
      /* Check if address is used in some static mapping */
      if (nat44_ei_is_address_used_in_static_mapping (addr))
	{
	  nat44_ei_log_err ("address used in static mapping");
	  return VNET_API_ERROR_UNSPECIFIED;
	}
    }

  if (a->fib_index != ~0)
    fib_table_unlock (a->fib_index, FIB_PROTOCOL_IP4, nm->fib_src_low);

  /* Delete sessions using address */
  if (a->busy_tcp_ports || a->busy_udp_ports || a->busy_icmp_ports)
    {
      vec_foreach (tnm, nm->per_thread_data)
	{
	  pool_foreach (ses, tnm->sessions)
	    {
	      if (ses->out2in.addr.as_u32 == addr.as_u32)
		{
		  nat44_ei_free_session_data (nm, ses,
					      tnm - nm->per_thread_data, 0);
		  vec_add1 (ses_to_be_removed, ses - tnm->sessions);
		}
	    }
	  vec_foreach (ses_index, ses_to_be_removed)
	    {
	      ses = pool_elt_at_index (tnm->sessions, ses_index[0]);
	      nat44_ei_delete_session (nm, ses, tnm - nm->per_thread_data);
	    }
	  vec_free (ses_to_be_removed);
	}
    }

#define _(N, i, n, s) vec_free (a->busy_##n##_ports_per_thread);
  foreach_nat_protocol
#undef _
    vec_del1 (nm->addresses, i);

  /* Delete external address from FIB */
  pool_foreach (interface, nm->interfaces)
    {
      if (nat44_ei_interface_is_inside (interface) || nm->out2in_dpo)
	continue;
      nat44_ei_add_del_addr_to_fib (&addr, 32, interface->sw_if_index, 0);
      break;
    }

  pool_foreach (interface, nm->output_feature_interfaces)
    {
      if (nat44_ei_interface_is_inside (interface) || nm->out2in_dpo)
	continue;
      nat44_ei_add_del_addr_to_fib (&addr, 32, interface->sw_if_index, 0);
      break;
    }

  return 0;
}

static void
nat44_ei_ip4_add_del_interface_address_cb (ip4_main_t *im, uword opaque,
					   u32 sw_if_index,
					   ip4_address_t *address,
					   u32 address_length,
					   u32 if_address_index, u32 is_delete)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_static_map_resolve_t *rp;
  ip4_address_t l_addr;
  int i, j;
  int rv;
  nat44_ei_address_t *addresses = nm->addresses;

  if (!nm->enabled)
    return;

  for (i = 0; i < vec_len (nm->auto_add_sw_if_indices); i++)
    {
      if (sw_if_index == nm->auto_add_sw_if_indices[i])
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

      (void) nat44_ei_add_address (nm, address, ~0);
      /* Scan static map resolution vector */
      for (j = 0; j < vec_len (nm->to_resolve); j++)
	{
	  rp = nm->to_resolve + j;
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
	      rv = nat44_ei_add_del_static_mapping (
		l_addr, address[0], rp->l_port, rp->e_port, rp->proto,
		~0 /* sw_if_index */, rp->vrf_id, rp->addr_only,
		rp->identity_nat, rp->tag, 1);
	      if (rv)
		nat_elog_notice_X1 (
		  nm, "nat44_ei_add_del_static_mapping returned %d", "i4", rv);
	    }
	}
      return;
    }
  else
    {
      (void) nat44_ei_del_address (nm, address[0], 1);
      return;
    }
}

int
nat44_ei_set_frame_queue_nelts (u32 frame_queue_nelts)
{
  fail_if_enabled ();
  nat44_ei_main_t *nm = &nat44_ei_main;
  nm->frame_queue_nelts = frame_queue_nelts;
  return 0;
}

static void
nat44_ei_ip4_add_del_addr_only_sm_cb (ip4_main_t *im, uword opaque,
				      u32 sw_if_index, ip4_address_t *address,
				      u32 address_length, u32 if_address_index,
				      u32 is_delete)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_static_map_resolve_t *rp;
  nat44_ei_static_mapping_t *m;
  clib_bihash_kv_8_8_t kv, value;
  int i, rv;
  ip4_address_t l_addr;

  if (!nm->enabled)
    return;

  for (i = 0; i < vec_len (nm->to_resolve); i++)
    {
      rp = nm->to_resolve + i;
      if (rp->addr_only == 0)
	continue;
      if (rp->sw_if_index == sw_if_index)
	goto match;
    }

  return;

match:
  init_nat_k (&kv, *address, rp->addr_only ? 0 : rp->e_port,
	      nm->outside_fib_index, rp->addr_only ? 0 : rp->proto);
  if (clib_bihash_search_8_8 (&nm->static_mapping_by_external, &kv, &value))
    m = 0;
  else
    m = pool_elt_at_index (nm->static_mappings, value.value);

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

  rv = nat44_ei_add_del_static_mapping (
    l_addr, address[0], rp->l_port, rp->e_port, rp->proto,
    ~0 /* sw_if_index */, rp->vrf_id, rp->addr_only, rp->identity_nat, rp->tag,
    !is_delete);
  if (rv)
    nat_elog_notice_X1 (nm, "nat44_ei_add_del_static_mapping returned %d",
			"i4", rv);
}

VLIB_NODE_FN (nat44_ei_classify_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  nat44_ei_classify_next_t next_index;
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_static_mapping_t *m;
  u32 next_in2out = 0, next_out2in = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = NAT44_EI_CLASSIFY_NEXT_IN2OUT;
	  ip4_header_t *ip0;
	  nat44_ei_address_t *ap;
	  clib_bihash_kv_8_8_t kv0, value0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);

	  vec_foreach (ap, nm->addresses)
	    {
	      if (ip0->dst_address.as_u32 == ap->addr.as_u32)
		{
		  next0 = NAT44_EI_CLASSIFY_NEXT_OUT2IN;
		  goto enqueue0;
		}
	    }

	  if (PREDICT_FALSE (pool_elts (nm->static_mappings)))
	    {
	      init_nat_k (&kv0, ip0->dst_address, 0, 0, 0);
	      /* try to classify the fragment based on IP header alone */
	      if (!clib_bihash_search_8_8 (&nm->static_mapping_by_external,
					   &kv0, &value0))
		{
		  m = pool_elt_at_index (nm->static_mappings, value0.value);
		  if (m->local_addr.as_u32 != m->external_addr.as_u32)
		    next0 = NAT44_EI_CLASSIFY_NEXT_OUT2IN;
		  goto enqueue0;
		}
	      init_nat_k (&kv0, ip0->dst_address,
			  vnet_buffer (b0)->ip.reass.l4_dst_port, 0,
			  ip_proto_to_nat_proto (ip0->protocol));
	      if (!clib_bihash_search_8_8 (&nm->static_mapping_by_external,
					   &kv0, &value0))
		{
		  m = pool_elt_at_index (nm->static_mappings, value0.value);
		  if (m->local_addr.as_u32 != m->external_addr.as_u32)
		    next0 = NAT44_EI_CLASSIFY_NEXT_OUT2IN;
		}
	    }

	enqueue0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat44_ei_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->cached = 0;
	      t->next_in2out = next0 == NAT44_EI_CLASSIFY_NEXT_IN2OUT ? 1 : 0;
	    }

	  next_in2out += next0 == NAT44_EI_CLASSIFY_NEXT_IN2OUT;
	  next_out2in += next0 == NAT44_EI_CLASSIFY_NEXT_OUT2IN;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (
    vm, node->node_index, NAT44_EI_CLASSIFY_ERROR_NEXT_IN2OUT, next_in2out);
  vlib_node_increment_counter (
    vm, node->node_index, NAT44_EI_CLASSIFY_ERROR_NEXT_OUT2IN, next_out2in);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (nat44_ei_classify_node) = {
  .name = "nat44-ei-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_ei_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat44_ei_classify_error_strings),
  .error_strings = nat44_ei_classify_error_strings,
  .n_next_nodes = NAT44_EI_CLASSIFY_N_NEXT,
  .next_nodes = {
    [NAT44_EI_CLASSIFY_NEXT_IN2OUT] = "nat44-ei-in2out",
    [NAT44_EI_CLASSIFY_NEXT_OUT2IN] = "nat44-ei-out2in",
    [NAT44_EI_CLASSIFY_NEXT_DROP] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
