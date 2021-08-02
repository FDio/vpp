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

#include <vpp/app/version.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip_table.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/plugin/plugin.h>
#include <vppinfra/bihash_16_8.h>

#include <nat/lib/log.h>
#include <nat/lib/nat_inlines.h>
#include <nat/lib/ipfix_logging.h>
#include <vnet/syslog/syslog.h>
#include <nat/lib/nat_syslog_constants.h>
#include <nat/lib/nat_syslog.h>

#include <nat/nat44-ed/nat44_ed.h>
#include <nat/nat44-ed/nat44_ed_affinity.h>
#include <nat/nat44-ed/nat44_ed_inlines.h>

#include <vpp/stats/stat_segment.h>

snat_main_t snat_main;

static_always_inline void nat_validate_interface_counters (snat_main_t *sm,
							   u32 sw_if_index);

#define skip_if_disabled()                                                    \
  do                                                                          \
    {                                                                         \
      snat_main_t *sm = &snat_main;                                           \
      if (PREDICT_FALSE (!sm->enabled))                                       \
	return;                                                               \
    }                                                                         \
  while (0)

#define fail_if_enabled()                                                     \
  do                                                                          \
    {                                                                         \
      snat_main_t *sm = &snat_main;                                           \
      if (PREDICT_FALSE (sm->enabled))                                        \
	{                                                                     \
	  nat_log_err ("plugin enabled");                                     \
	  return 1;                                                           \
	}                                                                     \
    }                                                                         \
  while (0)

#define fail_if_disabled()                                                    \
  do                                                                          \
    {                                                                         \
      snat_main_t *sm = &snat_main;                                           \
      if (PREDICT_FALSE (!sm->enabled))                                       \
	{                                                                     \
	  nat_log_err ("plugin disabled");                                    \
	  return 1;                                                           \
	}                                                                     \
    }                                                                         \
  while (0)

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

/* Hook up output features */
VNET_FEATURE_INIT (ip4_snat_in2out_output, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-in2out-output",
  .runs_after = VNET_FEATURES ("ip4-sv-reassembly-output-feature"),
  .runs_before = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
};
VNET_FEATURE_INIT (ip4_snat_in2out_output_worker_handoff, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-in2out-output-worker-handoff",
  .runs_after = VNET_FEATURES ("ip4-sv-reassembly-output-feature"),
  .runs_before = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
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

VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Network Address Translation (NAT)",
};

static void nat44_ed_db_init (u32 translations, u32 translation_buckets);
static void nat44_ed_worker_db_free (snat_main_per_thread_data_t *tsm);

static int nat44_ed_add_static_mapping_internal (
  ip4_address_t l_addr, ip4_address_t e_addr, u16 l_port, u16 e_port,
  ip_protocol_t proto, u32 vrf_id, u32 sw_if_index, u32 flags,
  ip4_address_t pool_addr, u8 *tag);
static int nat44_ed_del_static_mapping_internal (ip4_address_t l_addr,
						 ip4_address_t e_addr,
						 u16 l_port, u16 e_port,
						 ip_protocol_t proto,
						 u32 vrf_id, u32 flags);

u32 nat_calc_bihash_buckets (u32 n_elts);

u8 *
format_ed_session_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_16_8_t *v = va_arg (*args, clib_bihash_kv_16_8_t *);

  u8 proto;
  u16 r_port, l_port;
  ip4_address_t l_addr, r_addr;
  u32 fib_index;

  split_ed_kv (v, &l_addr, &r_addr, &proto, &fib_index, &l_port, &r_port);
  s = format (s,
	      "local %U:%d remote %U:%d proto %U fib %d thread-index %u "
	      "session-index %u",
	      format_ip4_address, &l_addr, clib_net_to_host_u16 (l_port),
	      format_ip4_address, &r_addr, clib_net_to_host_u16 (r_port),
	      format_ip_protocol, proto, fib_index,
	      ed_value_get_thread_index (v), ed_value_get_session_index (v));

  return s;
}

static_always_inline int
nat44_ed_sm_i2o_add (snat_main_t *sm, snat_static_mapping_t *m,
		     ip4_address_t addr, u16 port, u32 fib_index, u8 proto)
{
  ASSERT (!pool_is_free (sm->static_mappings, m));
  clib_bihash_kv_16_8_t kv;
  nat44_ed_sm_init_i2o_kv (&kv, addr.as_u32, port, fib_index, proto,
			   m - sm->static_mappings);
  return clib_bihash_add_del_16_8 (&sm->flow_hash, &kv, 1 /*is_add*/);
}

static_always_inline int
nat44_ed_sm_i2o_del (snat_main_t *sm, ip4_address_t addr, u16 port,
		     u32 fib_index, u8 proto)
{
  clib_bihash_kv_16_8_t kv;
  nat44_ed_sm_init_i2o_k (&kv, addr.as_u32, port, fib_index, proto);
  return clib_bihash_add_del_16_8 (&sm->flow_hash, &kv, 0 /*is_add*/);
}

static_always_inline int
nat44_ed_sm_o2i_add (snat_main_t *sm, snat_static_mapping_t *m,
		     ip4_address_t addr, u16 port, u32 fib_index, u8 proto)
{
  ASSERT (!pool_is_free (sm->static_mappings, m));
  clib_bihash_kv_16_8_t kv;
  nat44_ed_sm_init_o2i_kv (&kv, addr.as_u32, port, fib_index, proto,
			   m - sm->static_mappings);
  return clib_bihash_add_del_16_8 (&sm->flow_hash, &kv, 1 /*is_add*/);
}

static_always_inline int
nat44_ed_sm_o2i_del (snat_main_t *sm, ip4_address_t addr, u16 port,
		     u32 fib_index, u8 proto)
{
  clib_bihash_kv_16_8_t kv;
  nat44_ed_sm_init_o2i_k (&kv, addr.as_u32, port, fib_index, proto);
  return clib_bihash_add_del_16_8 (&sm->flow_hash, &kv, 0 /*is_add*/);
}

void
nat44_ed_free_session_data (snat_main_t *sm, snat_session_t *s,
			    u32 thread_index, u8 is_ha)
{
  per_vrf_sessions_unregister_session (s, thread_index);

  if (nat_ed_ses_i2o_flow_hash_add_del (sm, thread_index, s, 0))
    nat_elog_warn (sm, "flow hash del failed");

  if (nat_ed_ses_o2i_flow_hash_add_del (sm, thread_index, s, 0))
    nat_elog_warn (sm, "flow hash del failed");

  if (na44_ed_is_fwd_bypass_session (s))
    {
      return;
    }

  if (nat44_ed_is_affinity_session (s))
    nat_affinity_unlock (s->ext_host_addr, s->out2in.addr, s->proto,
			 s->out2in.port);

  if (!is_ha)
    nat_syslog_nat44_sdel (0, s->in2out.fib_index, &s->in2out.addr,
			   s->in2out.port, &s->ext_host_nat_addr,
			   s->ext_host_nat_port, &s->out2in.addr,
			   s->out2in.port, &s->ext_host_addr, s->ext_host_port,
			   s->proto, nat44_ed_is_twice_nat_session (s));

  if (!is_ha)
    {
      /* log NAT event */
      nat_ipfix_logging_nat44_ses_delete (
	thread_index, s->in2out.addr.as_u32, s->out2in.addr.as_u32, s->proto,
	s->in2out.port, s->out2in.port, s->in2out.fib_index);
    }
}

static ip_interface_address_t *
nat44_ed_get_ip_interface_address (u32 sw_if_index, ip4_address_t addr)
{
  snat_main_t *sm = &snat_main;

  ip_lookup_main_t *lm = &sm->ip4_main->lookup_main;
  ip_interface_address_t *ia;
  ip4_address_t *ip4a;

  foreach_ip_interface_address (
    lm, ia, sw_if_index, 1, ({
      ip4a = ip_interface_address_get_address (lm, ia);
      nat_log_debug ("sw_if_idx: %u addr: %U ? %U", sw_if_index,
		     format_ip4_address, ip4a, format_ip4_address, &addr);
      if (ip4a->as_u32 == addr.as_u32)
	{
	  return ia;
	}
    }));
  return NULL;
}

static int
nat44_ed_resolve_nat_addr_len (snat_address_t *ap,
			       snat_interface_t *interfaces)
{
  ip_interface_address_t *ia;
  snat_interface_t *i;
  u32 fib_index;

  pool_foreach (i, interfaces)
    {
      if (!nat44_ed_is_interface_outside (i))
	{
	  continue;
	}

      fib_index = ip4_fib_table_get_index_for_sw_if_index (i->sw_if_index);
      if (fib_index != ap->fib_index)
	{
	  continue;
	}

      if ((ia = nat44_ed_get_ip_interface_address (i->sw_if_index, ap->addr)))
	{
	  ap->addr_len = ia->address_length;
	  ap->sw_if_index = i->sw_if_index;
	  ap->net.as_u32 = (ap->addr.as_u32 >> (32 - ap->addr_len))
			   << (32 - ap->addr_len);

	  nat_log_debug ("pool addr %U binds to -> sw_if_idx: %u net: %U/%u",
			 format_ip4_address, &ap->addr, ap->sw_if_index,
			 format_ip4_address, &ap->net, ap->addr_len);
	  return 0;
	}
    }
  return 1;
}

static void
nat44_ed_update_outside_if_addresses (snat_address_t *ap)
{
  snat_main_t *sm = &snat_main;

  if (!nat44_ed_resolve_nat_addr_len (ap, sm->interfaces))
    {
      return;
    }

  if (!nat44_ed_resolve_nat_addr_len (ap, sm->output_feature_interfaces))
    {
      return;
    }
}

static void
nat44_ed_bind_if_addr_to_nat_addr (u32 sw_if_index)
{
  snat_main_t *sm = &snat_main;
  ip_interface_address_t *ia;
  snat_address_t *ap;

  u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  vec_foreach (ap, sm->addresses)
    {
      if (fib_index != ap->fib_index)
	{
	  continue;
	}

      if ((ia = nat44_ed_get_ip_interface_address (sw_if_index, ap->addr)))
	{
	  ap->addr_len = ia->address_length;
	  ap->sw_if_index = sw_if_index;
	  ap->net.as_u32 = (ap->addr.as_u32 >> (32 - ap->addr_len))
			   << (32 - ap->addr_len);

	  nat_log_debug ("pool addr %U binds to -> sw_if_idx: %u net: %U/%u",
			 format_ip4_address, &ap->addr, ap->sw_if_index,
			 format_ip4_address, &ap->net, ap->addr_len);
	  return;
	}
    }
}

static_always_inline snat_fib_entry_reg_t *
nat44_ed_get_fib_entry_reg (ip4_address_t addr, u32 sw_if_index, int *out_idx)
{
  snat_main_t *sm = &snat_main;
  snat_fib_entry_reg_t *fe;
  int i;

  for (i = 0; i < vec_len (sm->fib_entry_reg); i++)
    {
      fe = sm->fib_entry_reg + i;
      if ((addr.as_u32 == fe->addr.as_u32) && (sw_if_index == fe->sw_if_index))
	{
	  if (out_idx)
	    {
	      *out_idx = i;
	    }
	  return fe;
	}
    }
  return NULL;
}

static void
nat44_ed_add_fib_entry_reg (ip4_address_t addr, u32 sw_if_index)
{
  // Add the external NAT address to the FIB as receive entries. This ensures
  // that VPP will reply to ARP for this address and we don't need to enable
  // proxy ARP on the outside interface.
  snat_main_t *sm = &snat_main;
  snat_fib_entry_reg_t *fe;

  if (!(fe = nat44_ed_get_fib_entry_reg (addr, sw_if_index, 0)))
    {
      fib_prefix_t prefix = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
		  .ip4.as_u32 = addr.as_u32,
		},
      };
      u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);
      fib_table_entry_update_one_path (fib_index, &prefix, sm->fib_src_low,
				       (FIB_ENTRY_FLAG_CONNECTED |
					FIB_ENTRY_FLAG_LOCAL |
					FIB_ENTRY_FLAG_EXCLUSIVE),
				       DPO_PROTO_IP4, NULL, sw_if_index, ~0, 1,
				       NULL, FIB_ROUTE_PATH_FLAG_NONE);

      vec_add2 (sm->fib_entry_reg, fe, 1);
      clib_memset (fe, 0, sizeof (*fe));
      fe->addr.as_u32 = addr.as_u32;
      fe->sw_if_index = sw_if_index;
    }
  fe->count++;
}

static void
nat44_ed_del_fib_entry_reg (ip4_address_t addr, u32 sw_if_index)
{
  snat_main_t *sm = &snat_main;
  snat_fib_entry_reg_t *fe;
  int i;

  if ((fe = nat44_ed_get_fib_entry_reg (addr, sw_if_index, &i)))
    {
      fe->count--;
      if (0 == fe->count)
	{
	  fib_prefix_t prefix = {
            .fp_len = 32,
            .fp_proto = FIB_PROTOCOL_IP4,
            .fp_addr = {
              .ip4.as_u32 = addr.as_u32,
		    },
          };
	  u32 fib_index =
	    ip4_fib_table_get_index_for_sw_if_index (sw_if_index);
	  fib_table_entry_delete (fib_index, &prefix, sm->fib_src_low);
	  vec_del1 (sm->fib_entry_reg, i);
	}
    }
}

static void
nat44_ed_add_del_interface_fib_reg_entries (ip4_address_t addr, u8 is_add)
{
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;

  pool_foreach (i, sm->interfaces)
    {
      if (nat44_ed_is_interface_outside (i))
	{
	  if (is_add)
	    {
	      nat44_ed_add_fib_entry_reg (addr, i->sw_if_index);
	    }
	  else
	    {
	      nat44_ed_del_fib_entry_reg (addr, i->sw_if_index);
	    }
	}
    }
  pool_foreach (i, sm->output_feature_interfaces)
    {
      if (nat44_ed_is_interface_outside (i))
	{
	  if (is_add)
	    {
	      nat44_ed_add_fib_entry_reg (addr, i->sw_if_index);
	    }
	  else
	    {
	      nat44_ed_del_fib_entry_reg (addr, i->sw_if_index);
	    }
	}
    }
}

static_always_inline void
nat44_ed_add_del_nat_addr_fib_reg_entries (u32 sw_if_index, u8 is_add)
{
  snat_main_t *sm = &snat_main;
  snat_address_t *ap;

  vec_foreach (ap, sm->addresses)
    {
      if (is_add)
	{
	  nat44_ed_add_fib_entry_reg (ap->addr, sw_if_index);
	}
      else
	{
	  nat44_ed_del_fib_entry_reg (ap->addr, sw_if_index);
	}
    }
}

static_always_inline void
nat44_ed_add_del_sm_fib_reg_entries (u32 sw_if_index, u8 is_add)
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;

  pool_foreach (m, sm->static_mappings)
    {
      if (is_add)
	{
	  nat44_ed_add_fib_entry_reg (m->external_addr, sw_if_index);
	}
      else
	{
	  nat44_ed_del_fib_entry_reg (m->external_addr, sw_if_index);
	}
    }
}

int
nat44_ed_add_address (ip4_address_t *addr, u32 vrf_id, u8 twice_nat)
{
  snat_main_t *sm = &snat_main;
  snat_address_t *ap, *addresses;

  addresses = twice_nat ? sm->twice_nat_addresses : sm->addresses;

  if (!sm->enabled)
    {
      return VNET_API_ERROR_UNSUPPORTED;
    }

  // check if address already exists
  vec_foreach (ap, addresses)
    {
      if (ap->addr.as_u32 == addr->as_u32)
        {
          nat_log_err ("address exist");
          return VNET_API_ERROR_VALUE_EXIST;
        }
    }

  if (twice_nat)
    {
      vec_add2 (sm->twice_nat_addresses, ap, 1);
    }
  else
    {
      vec_add2 (sm->addresses, ap, 1);
    }

  ap->addr_len = ~0;
  ap->fib_index = ~0;
  ap->addr = *addr;

  if (vrf_id != ~0)
    {
      ap->fib_index = fib_table_find_or_create_and_lock (
	FIB_PROTOCOL_IP4, vrf_id, sm->fib_src_low);
    }

  if (!twice_nat)
    {
      // if we don't have enabled interface we don't add address
      // to fib
      nat44_ed_add_del_interface_fib_reg_entries (*addr, 1);
      nat44_ed_update_outside_if_addresses (ap);
    }
  return 0;
}

int
nat44_ed_del_address (ip4_address_t addr, u8 twice_nat)
{
  snat_main_t *sm = &snat_main;
  snat_address_t *a = 0, *addresses;
  snat_session_t *ses;
  u32 *ses_to_be_removed = 0, *ses_index;
  snat_main_per_thread_data_t *tsm;
  int j;

  addresses = twice_nat ? sm->twice_nat_addresses : sm->addresses;

  for (j = 0; j < vec_len (addresses); j++)
    {
      if (addresses[j].addr.as_u32 == addr.as_u32)
	{
	  a = addresses + j;
	  break;
	}
    }
  if (!a)
    {
      nat_log_err ("no such address");
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  // delete dynamic sessions only
  vec_foreach (tsm, sm->per_thread_data)
    {
      pool_foreach (ses, tsm->sessions)
	{
	  if (ses->flags & SNAT_SESSION_FLAG_STATIC_MAPPING)
	    {
	      continue;
	    }
	  if (ses->out2in.addr.as_u32 == addr.as_u32)
	    {
	      nat44_ed_free_session_data (sm, ses, tsm - sm->per_thread_data,
					  0);
	      vec_add1 (ses_to_be_removed, ses - tsm->sessions);
	    }
	}
      vec_foreach (ses_index, ses_to_be_removed)
	{
	  ses = pool_elt_at_index (tsm->sessions, ses_index[0]);
	  nat_ed_session_delete (sm, ses, tsm - sm->per_thread_data, 1);
	}
      vec_free (ses_to_be_removed);
    }

  if (!twice_nat)
    {
      nat44_ed_add_del_interface_fib_reg_entries (addr, 0);
    }

  if (a->fib_index != ~0)
    {
      fib_table_unlock (a->fib_index, FIB_PROTOCOL_IP4, sm->fib_src_low);
    }

  if (!twice_nat)
    {
      vec_del1 (sm->addresses, j);
    }
  else
    {
      vec_del1 (sm->twice_nat_addresses, j);
    }

  return 0;
}

u32
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
  pool_foreach (s, tsm->sessions) {
    if (s->in2out.fib_index != fib_index ||
        s->in2out.addr.as_u32 != l_addr.as_u32)
      {
        continue;
      }
    if (!addr_only)
      {
	if ((s->out2in.addr.as_u32 != e_addr.as_u32) ||
	    s->out2in.port != e_port || s->in2out.port != l_port ||
	    s->proto != protocol)
	  continue;
      }

    if (nat44_ed_is_lb_session (s))
      continue;
    if (!nat44_ed_is_session_static (s))
      continue;
    nat44_ed_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
    vec_add1 (indexes_to_free, s - tsm->sessions);
    if (!addr_only)
      break;
  }
  u32 *ses_index;
  vec_foreach (ses_index, indexes_to_free)
  {
    s = pool_elt_at_index (tsm->sessions, *ses_index);
    nat_ed_session_delete (sm, s, tsm - sm->per_thread_data, 1);
  }
  vec_free (indexes_to_free);
}

static_always_inline snat_static_mapping_t *
nat44_ed_sm_lookup (snat_main_t *sm, clib_bihash_kv_16_8_t *kv)
{
  clib_bihash_kv_16_8_t v;
  int rc = clib_bihash_search_16_8 (&sm->flow_hash, kv, &v);
  if (!rc)
    {
      ASSERT (0 == ed_value_get_thread_index (&v));
      return pool_elt_at_index (sm->static_mappings,
				ed_value_get_session_index (&v));
    }
  return NULL;
}

snat_static_mapping_t *
nat44_ed_sm_o2i_lookup (snat_main_t *sm, ip4_address_t addr, u16 port,
			u32 fib_index, u8 proto)
{
  clib_bihash_kv_16_8_t kv;
  nat44_ed_sm_init_o2i_k (&kv, addr.as_u32, port, fib_index, proto);
  return nat44_ed_sm_lookup (sm, &kv);
}

snat_static_mapping_t *
nat44_ed_sm_i2o_lookup (snat_main_t *sm, ip4_address_t addr, u16 port,
			u32 fib_index, u8 proto)
{
  clib_bihash_kv_16_8_t kv;
  nat44_ed_sm_init_i2o_k (&kv, addr.as_u32, port, fib_index, proto);
  return nat44_ed_sm_lookup (sm, &kv);
}

static snat_static_mapping_resolve_t *
nat44_ed_get_resolve_record (ip4_address_t l_addr, u16 l_port, u16 e_port,
			     ip_protocol_t proto, u32 vrf_id, u32 sw_if_index,
			     u32 flags, int *out_idx)
{
  snat_static_mapping_resolve_t *rp;
  snat_main_t *sm = &snat_main;
  int i;

  for (i = 0; i < vec_len (sm->sm_to_resolve); i++)
    {
      rp = sm->sm_to_resolve + i;

      if (rp->sw_if_index == sw_if_index && rp->vrf_id == vrf_id)
	{
	  if (is_sm_identity_nat (rp->flags) && is_sm_identity_nat (flags))
	    {
	      if (!(is_sm_addr_only (rp->flags) && is_sm_addr_only (flags)))
		{
		  if (rp->e_port != e_port || rp->proto != proto)
		    {
		      continue;
		    }
		}
	    }
	  else if (rp->l_addr.as_u32 == l_addr.as_u32)
	    {
	      if (!(is_sm_addr_only (rp->flags) && is_sm_addr_only (flags)))
		{
		  if (rp->l_port != l_port || rp->e_port != e_port ||
		      rp->proto != proto)
		    {
		      continue;
		    }
		}
	    }
	  else
	    {
	      continue;
	    }
	  if (out_idx)
	    {
	      *out_idx = i;
	    }
	  return rp;
	}
    }
  return NULL;
}

static int
nat44_ed_del_resolve_record (ip4_address_t l_addr, u16 l_port, u16 e_port,
			     ip_protocol_t proto, u32 vrf_id, u32 sw_if_index,
			     u32 flags)
{
  snat_main_t *sm = &snat_main;
  int i;
  if (nat44_ed_get_resolve_record (l_addr, l_port, e_port, proto, vrf_id,
				   sw_if_index, flags, &i))
    {
      vec_del1 (sm->sm_to_resolve, i);
      return 0;
    }
  return 1;
}

static_always_inline int
nat44_ed_validate_sm_input (u32 flags)
{
  // identity nat can be initiated only from inside interface
  if (is_sm_identity_nat (flags) && is_sm_out2in_only (flags))
    {
      return VNET_API_ERROR_UNSUPPORTED;
    }

  if (is_sm_twice_nat (flags) || is_sm_self_twice_nat (flags))
    {
      if (is_sm_addr_only (flags) || is_sm_identity_nat (flags))
	{
	  return VNET_API_ERROR_UNSUPPORTED;
	}
    }
  return 0;
}

int
nat44_ed_add_static_mapping (ip4_address_t l_addr, ip4_address_t e_addr,
			     u16 l_port, u16 e_port, ip_protocol_t proto,
			     u32 vrf_id, u32 sw_if_index, u32 flags,
			     ip4_address_t pool_addr, u8 *tag)
{
  snat_static_mapping_resolve_t *rp;
  snat_main_t *sm = &snat_main;
  int rv;

  if (!sm->enabled)
    {
      return VNET_API_ERROR_UNSUPPORTED;
    }

  rv = nat44_ed_validate_sm_input (flags);
  if (rv != 0)
    {
      return rv;
    }

  // interface bound mapping
  if (is_sm_switch_address (flags))
    {
      if (nat44_ed_get_resolve_record (l_addr, l_port, e_port, proto, vrf_id,
				       sw_if_index, flags, 0))
	{
	  return VNET_API_ERROR_VALUE_EXIST;
	}

      vec_add2 (sm->sm_to_resolve, rp, 1);
      rp->l_addr.as_u32 = l_addr.as_u32;
      rp->l_port = l_port;
      rp->e_port = e_port;
      rp->sw_if_index = sw_if_index;
      rp->vrf_id = vrf_id;
      rp->proto = proto;
      rp->flags = flags;
      rp->pool_addr = pool_addr;
      rp->tag = vec_dup (tag);
      rp->is_resolved = 0;

      ip4_address_t *first_int_addr =
	ip4_interface_first_address (sm->ip4_main, sw_if_index, 0);
      if (!first_int_addr)
	{
	  return 0;
	}

      e_addr.as_u32 = first_int_addr->as_u32;
      rp->is_resolved = 1;
    }

  rv = nat44_ed_add_static_mapping_internal (l_addr, e_addr, l_port, e_port,
					     proto, vrf_id, sw_if_index, flags,
					     pool_addr, tag);
  if ((0 != rv) && is_sm_switch_address (flags))
    {
      nat44_ed_del_resolve_record (l_addr, l_port, e_port, proto, vrf_id,
				   sw_if_index, flags);
    }

  return rv;
}

int
nat44_ed_del_static_mapping (ip4_address_t l_addr, ip4_address_t e_addr,
			     u16 l_port, u16 e_port, ip_protocol_t proto,
			     u32 vrf_id, u32 sw_if_index, u32 flags)
{
  snat_main_t *sm = &snat_main;
  int rv;

  if (!sm->enabled)
    {
      return VNET_API_ERROR_UNSUPPORTED;
    }

  rv = nat44_ed_validate_sm_input (flags);
  if (rv != 0)
    {
      return rv;
    }

  // interface bound mapping
  if (is_sm_switch_address (flags))
    {
      if (nat44_ed_del_resolve_record (l_addr, l_port, e_port, proto, vrf_id,
				       sw_if_index, flags))
	{
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      ip4_address_t *first_int_addr =
	ip4_interface_first_address (sm->ip4_main, sw_if_index, 0);
      if (!first_int_addr)
	{
	  // dhcp resolution required
	  return 0;
	}

      e_addr.as_u32 = first_int_addr->as_u32;
    }

  return nat44_ed_del_static_mapping_internal (l_addr, e_addr, l_port, e_port,
					       proto, vrf_id, flags);
}

static int
nat44_ed_add_static_mapping_internal (ip4_address_t l_addr,
				      ip4_address_t e_addr, u16 l_port,
				      u16 e_port, ip_protocol_t proto,
				      u32 vrf_id, u32 sw_if_index, u32 flags,
				      ip4_address_t pool_addr, u8 *tag)
{
  snat_main_t *sm = &snat_main;
  nat44_lb_addr_port_t *local;
  snat_static_mapping_t *m;
  u32 fib_index = ~0;

  if (is_sm_addr_only (flags))
    {
      e_port = l_port = proto = 0;
    }

  if (is_sm_identity_nat (flags))
    {
      l_port = e_port;
      l_addr.as_u32 = e_addr.as_u32;
    }

  m = nat44_ed_sm_o2i_lookup (sm, e_addr, e_port, 0, proto);
  if (m)
    {
      // case:
      // adding local identity nat record for different vrf table

      if (!is_sm_identity_nat (m->flags))
	{
	  return VNET_API_ERROR_VALUE_EXIST;
	}

      pool_foreach (local, m->locals)
	{
	  if (local->vrf_id == vrf_id)
	    {
	      return VNET_API_ERROR_VALUE_EXIST;
	    }
	}

      pool_get (m->locals, local);

      local->vrf_id = vrf_id;
      local->fib_index = fib_table_find_or_create_and_lock (
	FIB_PROTOCOL_IP4, vrf_id, sm->fib_src_low);

      nat44_ed_sm_i2o_add (sm, m, m->local_addr, m->local_port,
			   local->fib_index, m->proto);

      return 0;
    }

  if (vrf_id != ~0)
    {
      fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id,
						     sm->fib_src_low);
    }
  else
    {
      // fallback to default vrf
      vrf_id = sm->inside_vrf_id;
      fib_index = sm->inside_fib_index;
      fib_table_lock (fib_index, FIB_PROTOCOL_IP4, sm->fib_src_low);
    }

  // test if local mapping record doesn't exist
  // identity nat supports multiple records in local mapping
  if (!(is_sm_out2in_only (flags) || is_sm_identity_nat (flags)))
    {
      if (nat44_ed_sm_i2o_lookup (sm, l_addr, l_port, fib_index, proto))
	{
	  return VNET_API_ERROR_VALUE_EXIST;
	}
    }

  pool_get (sm->static_mappings, m);
  clib_memset (m, 0, sizeof (*m));

  m->flags = flags;
  m->local_addr = l_addr;
  m->external_addr = e_addr;

  m->pool_addr = pool_addr;
  m->tag = vec_dup (tag);

  if (!is_sm_addr_only (flags))
    {
      m->local_port = l_port;
      m->external_port = e_port;
      m->proto = proto;
    }

  if (is_sm_identity_nat (flags))
    {
      pool_get (m->locals, local);

      local->vrf_id = vrf_id;
      local->fib_index = fib_index;
    }
  else
    {
      m->vrf_id = vrf_id;
      m->fib_index = fib_index;
    }

  if (!is_sm_out2in_only (flags))
    {
      nat44_ed_sm_i2o_add (sm, m, m->local_addr, m->local_port, fib_index,
			   m->proto);
    }

  nat44_ed_sm_o2i_add (sm, m, m->external_addr, m->external_port, 0, m->proto);

  if (sm->num_workers > 1)
    {
      // store worker index for this record
      ip4_header_t ip = {
	.src_address = m->local_addr,
      };
      u32 worker_index;
      worker_index =
	nat44_ed_get_in2out_worker_index (0, &ip, m->fib_index, 0);
      vec_add1 (m->workers, worker_index);
    }

  nat44_ed_add_del_interface_fib_reg_entries (e_addr, 1);

  return 0;
}

static int
nat44_ed_del_static_mapping_internal (ip4_address_t l_addr,
				      ip4_address_t e_addr, u16 l_port,
				      u16 e_port, ip_protocol_t proto,
				      u32 vrf_id, u32 flags)
{
  snat_main_per_thread_data_t *tsm;
  snat_main_t *sm = &snat_main;

  nat44_lb_addr_port_t *local;
  snat_static_mapping_t *m;
  u32 fib_index = ~0;

  if (is_sm_addr_only (flags))
    {
      e_port = l_port = proto = 0;
    }

  if (is_sm_identity_nat (flags))
    {
      l_port = e_port;
      l_addr.as_u32 = e_addr.as_u32;
    }

  // fib index 0
  m = nat44_ed_sm_o2i_lookup (sm, e_addr, e_port, 0, proto);
  if (!m)
    {
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (is_sm_identity_nat (flags))
    {
      u8 found = 0;

      if (vrf_id == ~0)
	{
	  vrf_id = sm->inside_vrf_id;
	}

      pool_foreach (local, m->locals)
	{
	  if (local->vrf_id == vrf_id)
	    {
	      local = pool_elt_at_index (m->locals, local - m->locals);
	      fib_index = local->fib_index;
	      pool_put (m->locals, local);
	      found = 1;
	    }
	}

      if (!found)
	{
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
	}
    }
  else
    {
      fib_index = m->fib_index;
    }

  if (!is_sm_out2in_only (flags))
    {
      nat44_ed_sm_i2o_del (sm, l_addr, l_port, fib_index, proto);
    }

  // delete sessions for static mapping
  if (sm->num_workers > 1)
    {
      tsm = vec_elt_at_index (sm->per_thread_data, m->workers[0]);
    }
  else
    {
      tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);
    }

  nat_ed_static_mapping_del_sessions (sm, tsm, m->local_addr, m->local_port,
				      m->proto, fib_index,
				      is_sm_addr_only (flags), e_addr, e_port);

  fib_table_unlock (fib_index, FIB_PROTOCOL_IP4, sm->fib_src_low);

  if (!pool_elts (m->locals))
    {
      // this is last record remove all required stuff
      // fib_index 0
      nat44_ed_sm_o2i_del (sm, e_addr, e_port, 0, proto);

      vec_free (m->tag);
      vec_free (m->workers);
      pool_put (sm->static_mappings, m);

      nat44_ed_add_del_interface_fib_reg_entries (e_addr, 0);
    }

  return 0;
}

int
nat44_ed_add_lb_static_mapping (ip4_address_t e_addr, u16 e_port,
				ip_protocol_t proto,
				nat44_lb_addr_port_t *locals, u32 flags,
				u8 *tag, u32 affinity)
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  snat_address_t *a = 0;

  nat44_lb_addr_port_t *local;
  uword *bitmap = 0;
  int rc = 0;

  int i;

  if (!sm->enabled)
    {
      return VNET_API_ERROR_UNSUPPORTED;
    }

  m = nat44_ed_sm_o2i_lookup (sm, e_addr, e_port, 0, proto);

  if (m)
    {
      return VNET_API_ERROR_VALUE_EXIST;
    }

  if (vec_len (locals) < 2)
    {
      return VNET_API_ERROR_INVALID_VALUE;
    }

  if (!is_sm_out2in_only (flags))
    {
      /* Find external address in allocated addresses and reserve port for
	 address and port pair mapping when dynamic translations enabled */
      for (i = 0; i < vec_len (sm->addresses); i++)
	{
	  if (sm->addresses[i].addr.as_u32 == e_addr.as_u32)
	    {
	      /* External port must be unused */
	      a = sm->addresses + i;
	      if (nat44_ed_sm_o2i_lookup (sm, a->addr, e_port, 0, proto))
		{
		  return VNET_API_ERROR_VALUE_EXIST;
		}
	      break;
	    }
	}
      // external address must be allocated
      if (!a)
	{
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
	}
    }

  pool_get (sm->static_mappings, m);
  clib_memset (m, 0, sizeof (*m));
  m->tag = vec_dup (tag);
  m->external_addr = e_addr;
  m->external_port = e_port;
  m->affinity = affinity;
  m->proto = proto;

  m->flags = flags;
  m->flags |= NAT_SM_FLAG_LB;

  if (affinity)
    m->affinity_per_service_list_head_index =
      nat_affinity_get_per_service_list_head_index ();
  else
    m->affinity_per_service_list_head_index = ~0;

  if (nat44_ed_sm_o2i_add (sm, m, m->external_addr, m->external_port, 0,
			   m->proto))
    {
      nat_log_err ("sm o2i key add failed");
      return VNET_API_ERROR_UNSPECIFIED;
    }

  for (i = 0; i < vec_len (locals); i++)
    {
      locals[i].fib_index = fib_table_find_or_create_and_lock (
	FIB_PROTOCOL_IP4, locals[i].vrf_id, sm->fib_src_low);
      if (!is_sm_out2in_only (flags))
	{
	  if (nat44_ed_sm_o2i_add (sm, m, e_addr, e_port, 0, proto))
	    {
	      nat_log_err ("sm o2i key add failed");
	      rc = VNET_API_ERROR_UNSPECIFIED;
	      // here we continue with add operation so that it can be safely
	      // reversed in delete path - otherwise we'd have to track what
	      // we've done and deal with partial cleanups and since bihash
	      // adds are (extremely improbable) the only points of failure,
	      // it's easier to just do it this way
	    }
	}
      locals[i].prefix = (i == 0) ?
			   locals[i].probability :
			   (locals[i - 1].prefix + locals[i].probability);
      pool_get (m->locals, local);
      *local = locals[i];
      if (sm->num_workers > 1)
	{
	  ip4_header_t ip = {
	    .src_address = locals[i].addr,
	  };
	  bitmap = clib_bitmap_set (
	    bitmap, nat44_ed_get_in2out_worker_index (0, &ip, m->fib_index, 0),
	    1);
	}
    }

  /* Assign workers */
  if (sm->num_workers > 1)
    {
      clib_bitmap_foreach (i, bitmap)
	{
	  vec_add1 (m->workers, i);
	}
    }

  return rc;
}

int
nat44_ed_del_lb_static_mapping (ip4_address_t e_addr, u16 e_port,
				ip_protocol_t proto, u32 flags)
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;

  nat44_lb_addr_port_t *local;
  snat_main_per_thread_data_t *tsm;
  snat_session_t *s;

  if (!sm->enabled)
    {
      return VNET_API_ERROR_UNSUPPORTED;
    }

  m = nat44_ed_sm_o2i_lookup (sm, e_addr, e_port, 0, proto);
  if (!m)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (!is_sm_lb (m->flags))
    return VNET_API_ERROR_INVALID_VALUE;

  if (nat44_ed_sm_o2i_del (sm, m->external_addr, m->external_port, 0,
			   m->proto))
    {
      nat_log_err ("sm o2i key del failed");
      return VNET_API_ERROR_UNSPECIFIED;
    }

  pool_foreach (local, m->locals)
    {
      fib_table_unlock (local->fib_index, FIB_PROTOCOL_IP4, sm->fib_src_low);
      if (!is_sm_out2in_only (flags))
	{
	  if (nat44_ed_sm_i2o_del (sm, local->addr, local->port,
				   local->fib_index, m->proto))
	    {
	      nat_log_err ("sm i2o key del failed");
	      return VNET_API_ERROR_UNSPECIFIED;
	    }
	}

      if (sm->num_workers > 1)
	{
	  ip4_header_t ip = {
	    .src_address = local->addr,
	  };
	  tsm = vec_elt_at_index (
	    sm->per_thread_data,
	    nat44_ed_get_in2out_worker_index (0, &ip, m->fib_index, 0));
	}
      else
	tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

      /* Delete sessions */
      pool_foreach (s, tsm->sessions)
	{
	  if (!(nat44_ed_is_lb_session (s)))
	    continue;

	  if ((s->in2out.addr.as_u32 != local->addr.as_u32) ||
	      s->in2out.port != local->port)
	    continue;

	  nat44_ed_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
	  nat_ed_session_delete (sm, s, tsm - sm->per_thread_data, 1);
	}
    }

  if (m->affinity)
    {
      nat_affinity_flush_service (m->affinity_per_service_list_head_index);
    }

  pool_free (m->locals);
  vec_free (m->tag);
  vec_free (m->workers);
  pool_put (sm->static_mappings, m);

  return 0;
}

int
nat44_ed_add_del_lb_static_mapping_local (ip4_address_t e_addr, u16 e_port,
					  ip4_address_t l_addr, u16 l_port,
					  ip_protocol_t proto, u32 vrf_id,
					  u8 probability, u8 is_add)
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m = 0;
  nat44_lb_addr_port_t *local, *prev_local, *match_local = 0;
  snat_main_per_thread_data_t *tsm;
  snat_session_t *s;
  u32 *locals = 0;
  uword *bitmap = 0;
  int i;

  if (!sm->enabled)
    {
      return VNET_API_ERROR_UNSUPPORTED;
    }

  m = nat44_ed_sm_o2i_lookup (sm, e_addr, e_port, 0, proto);

  if (!m)
    {
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (!is_sm_lb (m->flags))
    {
      return VNET_API_ERROR_INVALID_VALUE;
    }

  pool_foreach (local, m->locals)
   {
    if ((local->addr.as_u32 == l_addr.as_u32) && (local->port == l_port) &&
        (local->vrf_id == vrf_id))
      {
        match_local = local;
        break;
      }
  }

  if (is_add)
    {
      if (match_local)
	{
	  return VNET_API_ERROR_VALUE_EXIST;
	}

      pool_get (m->locals, local);
      clib_memset (local, 0, sizeof (*local));
      local->addr.as_u32 = l_addr.as_u32;
      local->port = l_port;
      local->probability = probability;
      local->vrf_id = vrf_id;
      local->fib_index =
	fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id,
					   sm->fib_src_low);

      if (!is_sm_out2in_only (m->flags))
	{
	  if (nat44_ed_sm_i2o_add (sm, m, l_addr, l_port, local->fib_index,
				   proto))
	    {
	      nat_log_err ("sm i2o key add failed");
	      pool_put (m->locals, local);
	      return VNET_API_ERROR_UNSPECIFIED;
	    }
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

      if (!is_sm_out2in_only (m->flags))
	{
	  if (nat44_ed_sm_i2o_del (sm, l_addr, l_port, match_local->fib_index,
				   proto))
	    nat_log_err ("sm i2o key del failed");
	}

      if (sm->num_workers > 1)
	{
	  ip4_header_t ip = {
	    .src_address = local->addr,
	  };
	  tsm = vec_elt_at_index (
	    sm->per_thread_data,
	    nat44_ed_get_in2out_worker_index (0, &ip, m->fib_index, 0));
	}
      else
	tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

      /* Delete sessions */
      pool_foreach (s, tsm->sessions) {
	  if (!(nat44_ed_is_lb_session (s)))
	    continue;

	  if ((s->in2out.addr.as_u32 != match_local->addr.as_u32) ||
	      s->in2out.port != match_local->port)
	    continue;

	  nat44_ed_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
	  nat_ed_session_delete (sm, s, tsm - sm->per_thread_data, 1);
      }

      pool_put (m->locals, match_local);
    }

  vec_free (m->workers);

  pool_foreach (local, m->locals)
   {
    vec_add1 (locals, local - m->locals);
    if (sm->num_workers > 1)
      {
        ip4_header_t ip;
	ip.src_address.as_u32 = local->addr.as_u32,
	bitmap = clib_bitmap_set (
	  bitmap,
	  nat44_ed_get_in2out_worker_index (0, &ip, local->fib_index, 0), 1);
      }
  }

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
      clib_bitmap_foreach (i, bitmap)  { vec_add1(m->workers, i); }
    }

  return 0;
}

void
expire_per_vrf_sessions (u32 fib_index)
{
  per_vrf_sessions_t *per_vrf_sessions;
  snat_main_per_thread_data_t *tsm;
  snat_main_t *sm = &snat_main;

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

static_always_inline nat_outside_fib_t *
nat44_ed_get_outside_fib (nat_outside_fib_t *outside_fibs, u32 fib_index)
{
  nat_outside_fib_t *f;
  vec_foreach (f, outside_fibs)
    {
      if (f->fib_index == fib_index)
	{
	  return f;
	}
    }
  return 0;
}

static_always_inline snat_interface_t *
nat44_ed_get_interface (snat_interface_t *interfaces, u32 sw_if_index)
{
  snat_interface_t *i;
  pool_foreach (i, interfaces)
    {
      if (i->sw_if_index == sw_if_index)
	{
	  return i;
	}
    }
  return 0;
}

int
nat44_ed_add_interface (u32 sw_if_index, u8 is_inside)
{
  const char *del_feature_name, *feature_name;
  snat_main_t *sm = &snat_main;

  nat_outside_fib_t *outside_fib;
  snat_interface_t *i;
  u32 fib_index;
  int rv;

  if (!sm->enabled)
    {
      nat_log_err ("nat44 is disabled");
      return VNET_API_ERROR_UNSUPPORTED;
    }

  if (nat44_ed_get_interface (sm->output_feature_interfaces, sw_if_index))
    {
      nat_log_err ("error interface already configured");
      return VNET_API_ERROR_VALUE_EXIST;
    }

  i = nat44_ed_get_interface (sm->interfaces, sw_if_index);
  if (i)
    {
      if ((nat44_ed_is_interface_inside (i) && is_inside) ||
	  (nat44_ed_is_interface_outside (i) && !is_inside))
	{
	  return 0;
	}
      if (sm->num_workers > 1)
	{
	  del_feature_name = !is_inside ? "nat44-in2out-worker-handoff" :
					  "nat44-out2in-worker-handoff";
	  feature_name = "nat44-handoff-classify";
	}
      else
	{
	  del_feature_name = !is_inside ? "nat-pre-in2out" : "nat-pre-out2in";

	  feature_name = "nat44-ed-classify";
	}

      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
      if (rv)
	return rv;
      vnet_feature_enable_disable ("ip4-unicast", del_feature_name,
				   sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("ip4-unicast", feature_name, sw_if_index, 1,
				   0, 0);
    }
  else
    {
      if (sm->num_workers > 1)
	{
	  feature_name = is_inside ? "nat44-in2out-worker-handoff" :
				     "nat44-out2in-worker-handoff";
	}
      else
	{
	  feature_name = is_inside ? "nat-pre-in2out" : "nat-pre-out2in";
	}

      nat_validate_interface_counters (sm, sw_if_index);
      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
      if (rv)
	return rv;
      vnet_feature_enable_disable ("ip4-unicast", feature_name, sw_if_index, 1,
				   0, 0);

      pool_get (sm->interfaces, i);
      i->sw_if_index = sw_if_index;
      i->flags = 0;
    }

  fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);

  update_per_vrf_sessions_vec (fib_index, 0 /*is_del*/);

  if (!is_inside)
    {
      i->flags |= NAT_INTERFACE_FLAG_IS_OUTSIDE;

      outside_fib = nat44_ed_get_outside_fib (sm->outside_fibs, fib_index);
      if (outside_fib)
	{
	  outside_fib->refcount++;
	}
      else
	{
	  vec_add2 (sm->outside_fibs, outside_fib, 1);
	  outside_fib->fib_index = fib_index;
	  outside_fib->refcount = 1;
	}

      nat44_ed_add_del_nat_addr_fib_reg_entries (sw_if_index, 1);
      nat44_ed_add_del_sm_fib_reg_entries (sw_if_index, 1);

      nat44_ed_bind_if_addr_to_nat_addr (sw_if_index);
    }
  else
    {
      i->flags |= NAT_INTERFACE_FLAG_IS_INSIDE;
    }

  return 0;
}

int
nat44_ed_del_interface (u32 sw_if_index, u8 is_inside)
{
  const char *del_feature_name, *feature_name;
  snat_main_t *sm = &snat_main;

  nat_outside_fib_t *outside_fib;
  snat_interface_t *i;
  u32 fib_index;
  int rv;

  if (!sm->enabled)
    {
      nat_log_err ("nat44 is disabled");
      return VNET_API_ERROR_UNSUPPORTED;
    }

  i = nat44_ed_get_interface (sm->interfaces, sw_if_index);
  if (i == 0)
    {
      nat_log_err ("error interface couldn't be found");
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (nat44_ed_is_interface_inside (i) && nat44_ed_is_interface_outside (i))
    {
      if (sm->num_workers > 1)
	{
	  del_feature_name = "nat44-handoff-classify";
	  feature_name = !is_inside ? "nat44-in2out-worker-handoff" :
				      "nat44-out2in-worker-handoff";
	}
      else
	{
	  del_feature_name = "nat44-ed-classify";
	  feature_name = !is_inside ? "nat-pre-in2out" : "nat-pre-out2in";
	}

      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
      if (rv)
	{
	  return rv;
	}
      vnet_feature_enable_disable ("ip4-unicast", del_feature_name,
				   sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("ip4-unicast", feature_name, sw_if_index, 1,
				   0, 0);

      if (is_inside)
	{
	  i->flags &= ~NAT_INTERFACE_FLAG_IS_INSIDE;
	}
      else
	{
	  i->flags &= ~NAT_INTERFACE_FLAG_IS_OUTSIDE;
	}
    }
  else
    {
      if (sm->num_workers > 1)
	{
	  feature_name = is_inside ? "nat44-in2out-worker-handoff" :
				     "nat44-out2in-worker-handoff";
	}
      else
	{
	  feature_name = is_inside ? "nat-pre-in2out" : "nat-pre-out2in";
	}

      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
      if (rv)
	{
	  return rv;
	}
      vnet_feature_enable_disable ("ip4-unicast", feature_name, sw_if_index, 0,
				   0, 0);

      // remove interface
      pool_put (sm->interfaces, i);
    }

  fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);

  update_per_vrf_sessions_vec (fib_index, 1 /*is_del*/);

  if (!is_inside)
    {
      outside_fib = nat44_ed_get_outside_fib (sm->outside_fibs, fib_index);
      if (outside_fib)
	{
	  outside_fib->refcount--;
	  if (!outside_fib->refcount)
	    {
	      vec_del1 (sm->outside_fibs, outside_fib - sm->outside_fibs);
	    }
	}

      nat44_ed_add_del_nat_addr_fib_reg_entries (sw_if_index, 0);
      nat44_ed_add_del_sm_fib_reg_entries (sw_if_index, 0);
    }

  return 0;
}

int
nat44_ed_add_output_interface (u32 sw_if_index)
{
  snat_main_t *sm = &snat_main;

  nat_outside_fib_t *outside_fib;
  snat_interface_t *i;
  u32 fib_index;
  int rv;

  if (!sm->enabled)
    {
      nat_log_err ("nat44 is disabled");
      return VNET_API_ERROR_UNSUPPORTED;
    }

  if (nat44_ed_get_interface (sm->interfaces, sw_if_index))
    {
      nat_log_err ("error interface already configured");
      return VNET_API_ERROR_VALUE_EXIST;
    }

  if (nat44_ed_get_interface (sm->output_feature_interfaces, sw_if_index))
    {
      nat_log_err ("error interface already configured");
      return VNET_API_ERROR_VALUE_EXIST;
    }

  if (sm->num_workers > 1)
    {
      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
      if (rv)
	{
	  return rv;
	}

      rv = ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index, 1);
      if (rv)
	{
	  return rv;
	}

      vnet_feature_enable_disable (
	"ip4-unicast", "nat44-out2in-worker-handoff", sw_if_index, 1, 0, 0);
      vnet_feature_enable_disable ("ip4-output",
				   "nat44-in2out-output-worker-handoff",
				   sw_if_index, 1, 0, 0);
    }
  else
    {
      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
      if (rv)
	{
	  return rv;
	}

      rv = ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index, 1);
      if (rv)
	{
	  return rv;
	}

      vnet_feature_enable_disable ("ip4-unicast", "nat-pre-out2in",
				   sw_if_index, 1, 0, 0);
      vnet_feature_enable_disable ("ip4-output", "nat-pre-in2out-output",
				   sw_if_index, 1, 0, 0);
    }

  nat_validate_interface_counters (sm, sw_if_index);

  pool_get (sm->output_feature_interfaces, i);
  i->sw_if_index = sw_if_index;
  i->flags = 0;
  i->flags |= NAT_INTERFACE_FLAG_IS_INSIDE;
  i->flags |= NAT_INTERFACE_FLAG_IS_OUTSIDE;

  fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);
  update_per_vrf_sessions_vec (fib_index, 0 /*is_del*/);

  outside_fib = nat44_ed_get_outside_fib (sm->outside_fibs, fib_index);
  if (outside_fib)
    {
      outside_fib->refcount++;
    }
  else
    {
      vec_add2 (sm->outside_fibs, outside_fib, 1);
      outside_fib->fib_index = fib_index;
      outside_fib->refcount = 1;
    }

  nat44_ed_add_del_nat_addr_fib_reg_entries (sw_if_index, 1);
  nat44_ed_add_del_sm_fib_reg_entries (sw_if_index, 1);

  nat44_ed_bind_if_addr_to_nat_addr (sw_if_index);

  return 0;
}

int
nat44_ed_del_output_interface (u32 sw_if_index)
{
  snat_main_t *sm = &snat_main;

  nat_outside_fib_t *outside_fib;
  snat_interface_t *i;
  u32 fib_index;
  int rv;

  if (!sm->enabled)
    {
      nat_log_err ("nat44 is disabled");
      return VNET_API_ERROR_UNSUPPORTED;
    }

  i = nat44_ed_get_interface (sm->output_feature_interfaces, sw_if_index);
  if (!i)
    {
      nat_log_err ("error interface couldn't be found");
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (sm->num_workers > 1)
    {
      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
      if (rv)
	{
	  return rv;
	}

      rv = ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index, 0);
      if (rv)
	{
	  return rv;
	}

      vnet_feature_enable_disable (
	"ip4-unicast", "nat44-out2in-worker-handoff", sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("ip4-output",
				   "nat44-in2out-output-worker-handoff",
				   sw_if_index, 0, 0, 0);
    }
  else
    {
      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
      if (rv)
	{
	  return rv;
	}

      rv = ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index, 0);
      if (rv)
	{
	  return rv;
	}

      vnet_feature_enable_disable ("ip4-unicast", "nat-pre-out2in",
				   sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("ip4-output", "nat-pre-in2out-output",
				   sw_if_index, 0, 0, 0);
    }

  // remove interface
  pool_put (sm->output_feature_interfaces, i);

  fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);
  update_per_vrf_sessions_vec (fib_index, 1 /*is_del*/);

  outside_fib = nat44_ed_get_outside_fib (sm->outside_fibs, fib_index);
  if (outside_fib)
    {
      outside_fib->refcount--;
      if (!outside_fib->refcount)
	{
	  vec_del1 (sm->outside_fibs, outside_fib - sm->outside_fibs);
	}
    }

  nat44_ed_add_del_nat_addr_fib_reg_entries (sw_if_index, 0);
  nat44_ed_add_del_sm_fib_reg_entries (sw_if_index, 0);

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
  clib_bitmap_foreach (i, bitmap)
    {
      vec_add1(sm->workers, i);
      sm->per_thread_data[sm->first_worker_index + i].snat_thread_index = j;
      sm->per_thread_data[sm->first_worker_index + i].thread_index = i;
      j++;
    }

  sm->port_per_thread = (0xffff - 1024) / _vec_len (sm->workers);

  return 0;
}

int
nat44_ed_set_frame_queue_nelts (u32 frame_queue_nelts)
{
  fail_if_enabled ();
  snat_main_t *sm = &snat_main;
  sm->frame_queue_nelts = frame_queue_nelts;
  return 0;
}

static void
nat44_ed_update_outside_fib_cb (ip4_main_t *im, uword opaque, u32 sw_if_index,
				u32 new_fib_index, u32 old_fib_index)
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

  pool_foreach (i, sm->interfaces)
    {
      if (i->sw_if_index == sw_if_index)
        {
	  if (!(nat44_ed_is_interface_outside (i)))
	    return;
          match = 1;
        }
    }

  pool_foreach (i, sm->output_feature_interfaces)
    {
      if (i->sw_if_index == sw_if_index)
        {
	  if (!(nat44_ed_is_interface_outside (i)))
	    return;
          match = 1;
        }
    }

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

static void nat44_ed_update_outside_fib_cb (ip4_main_t *im, uword opaque,
					    u32 sw_if_index, u32 new_fib_index,
					    u32 old_fib_index);

static void nat44_ed_add_del_interface_address_cb (
  ip4_main_t *im, uword opaque, u32 sw_if_index, ip4_address_t *address,
  u32 address_length, u32 if_address_index, u32 is_delete);

static void nat44_ed_add_del_static_mapping_cb (
  ip4_main_t *im, uword opaque, u32 sw_if_index, ip4_address_t *address,
  u32 address_length, u32 if_address_index, u32 is_delete);

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
  init_ed_kv (&kv, l_addr.as_u32, l_port, r_addr.as_u32, r_port, fib_index,
	      proto, thread_index, session_index);
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
}

static clib_error_t *
nat_ip_table_add_del (vnet_main_t * vnm, u32 table_id, u32 is_add)
{
  u32 fib_index;
  if (!is_add)
    {
      fib_index = ip4_fib_index_from_table_id (table_id);
      if (fib_index != ~0)
	{
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

  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ed-out2in");
  sm->out2in_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ed-in2out");
  sm->in2out_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "nat44-ed-in2out-output");
  sm->in2out_output_node_index = node->index;
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
nat_validate_interface_counters (snat_main_t *sm, u32 sw_if_index)
{
#define _(x)                                                                  \
  nat_validate_simple_counter (sm->counters.fastpath.in2out.x, sw_if_index);  \
  nat_validate_simple_counter (sm->counters.fastpath.out2in.x, sw_if_index);  \
  nat_validate_simple_counter (sm->counters.slowpath.in2out.x, sw_if_index);  \
  nat_validate_simple_counter (sm->counters.slowpath.out2in.x, sw_if_index);
  foreach_nat_counter;
#undef _
  nat_validate_simple_counter (sm->counters.hairpinning, sw_if_index);
}

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

  sm->log_level = NAT_LOG_ERROR;

  nat44_set_node_indexes (sm, vm);

  sm->log_class = vlib_log_register_class ("nat", 0);
  nat_ipfix_logging_init (vm);

  nat_init_simple_counter (sm->total_sessions, "total-sessions",
			   "/nat44-ed/total-sessions");
  sm->max_cfg_sessions_gauge = stat_segment_new_entry (
    (u8 *) "/nat44-ed/max-cfg-sessions", STAT_DIR_TYPE_SCALAR_INDEX);

#define _(x)                                                                  \
  nat_init_simple_counter (sm->counters.fastpath.in2out.x, #x,                \
			   "/nat44-ed/in2out/fastpath/" #x);                  \
  nat_init_simple_counter (sm->counters.fastpath.out2in.x, #x,                \
			   "/nat44-ed/out2in/fastpath/" #x);                  \
  nat_init_simple_counter (sm->counters.slowpath.in2out.x, #x,                \
			   "/nat44-ed/in2out/slowpath/" #x);                  \
  nat_init_simple_counter (sm->counters.slowpath.out2in.x, #x,                \
			   "/nat44-ed/out2in/slowpath/" #x);
  foreach_nat_counter;
#undef _
  nat_init_simple_counter (sm->counters.hairpinning, "hairpinning",
			   "/nat44-ed/hairpinning");

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
    {
      sm->per_thread_data[0].snat_thread_index = 0;
    }

  /* callbacks to call when interface address changes. */
  cbi.function = nat44_ed_add_del_interface_address_cb;
  vec_add1 (sm->ip4_main->add_del_interface_address_callbacks, cbi);
  cbi.function = nat44_ed_add_del_static_mapping_cb;
  vec_add1 (sm->ip4_main->add_del_interface_address_callbacks, cbi);

  /* callbacks to call when interface to table biding changes */
  cbt.function = nat44_ed_update_outside_fib_cb;
  vec_add1 (sm->ip4_main->table_bind_callbacks, cbt);

  sm->fib_src_low =
    fib_source_allocate ("nat-low", FIB_SOURCE_PRIORITY_LOW,
			 FIB_SOURCE_BH_SIMPLE);
  sm->fib_src_hi =
    fib_source_allocate ("nat-hi", FIB_SOURCE_PRIORITY_HI,
			 FIB_SOURCE_BH_SIMPLE);

  nat_affinity_init (vm);
  test_key_calc_split ();

  return nat44_api_hookup (vm);
}

VLIB_INIT_FUNCTION (nat_init);

int
nat44_plugin_enable (nat44_config_t c)
{
  snat_main_t *sm = &snat_main;

  fail_if_enabled ();

  sm->forwarding_enabled = 0;
  sm->mss_clamping = 0;

  if (!c.sessions)
    c.sessions = 63 * 1024;

  sm->max_translations_per_thread = c.sessions;
  stat_segment_set_state_counter (sm->max_cfg_sessions_gauge,
				  sm->max_translations_per_thread);
  sm->translation_buckets = nat_calc_bihash_buckets (c.sessions);

  vec_add1 (sm->max_translations_per_fib, sm->max_translations_per_thread);

  sm->inside_vrf_id = c.inside_vrf;
  sm->inside_fib_index =
    fib_table_find_or_create_and_lock
    (FIB_PROTOCOL_IP4, c.inside_vrf, sm->fib_src_hi);

  sm->outside_vrf_id = c.outside_vrf;
  sm->outside_fib_index = fib_table_find_or_create_and_lock (
    FIB_PROTOCOL_IP4, c.outside_vrf, sm->fib_src_hi);

  nat44_ed_db_init (sm->max_translations_per_thread, sm->translation_buckets);

  nat_affinity_enable ();

  nat_reset_timeouts (&sm->timeouts);

  vlib_zero_simple_counter (&sm->total_sessions, 0);

  if (!sm->frame_queue_nelts)
    {
      sm->frame_queue_nelts = NAT_FQ_NELTS_DEFAULT;
    }

  if (sm->num_workers > 1)
    {
      if (sm->fq_in2out_index == ~0)
	{
	  sm->fq_in2out_index = vlib_frame_queue_main_init (
	    sm->in2out_node_index, sm->frame_queue_nelts);
	}
      if (sm->fq_out2in_index == ~0)
	{
	  sm->fq_out2in_index = vlib_frame_queue_main_init (
	    sm->out2in_node_index, sm->frame_queue_nelts);
	}
      if (sm->fq_in2out_output_index == ~0)
	{
	  sm->fq_in2out_output_index = vlib_frame_queue_main_init (
	    sm->in2out_output_node_index, sm->frame_queue_nelts);
	}
    }

  sm->enabled = 1;
  sm->rconfig = c;

  return 0;
}

int
nat44_ed_del_addresses ()
{
  snat_main_t *sm = &snat_main;
  snat_address_t *a, *vec;
  int error = 0;

  vec = vec_dup (sm->addresses);
  vec_foreach (a, vec)
    {
      error = nat44_ed_del_address (a->addr, 0);
      if (error)
	{
	  nat_log_err ("error occurred while removing adderess");
	}
    }
  vec_free (vec);
  vec_free (sm->addresses);
  sm->addresses = 0;

  vec = vec_dup (sm->twice_nat_addresses);
  vec_foreach (a, vec)
    {
      error = nat44_ed_del_address (a->addr, 1);
      if (error)
	{
	  nat_log_err ("error occurred while removing adderess");
	}
    }
  vec_free (vec);
  vec_free (sm->twice_nat_addresses);
  sm->twice_nat_addresses = 0;

  vec_free (sm->addr_to_resolve);
  sm->addr_to_resolve = 0;

  return error;
}

int
nat44_ed_del_interfaces ()
{
  snat_main_t *sm = &snat_main;
  snat_interface_t *i, *pool;
  int error = 0;

  pool = pool_dup (sm->interfaces);
  pool_foreach (i, pool)
    {
      if (nat44_ed_is_interface_inside (i))
	{
	  error = nat44_ed_del_interface (i->sw_if_index, 1);
	}
      if (nat44_ed_is_interface_outside (i))
	{
	  error = nat44_ed_del_interface (i->sw_if_index, 0);
	}

      if (error)
	{
	  nat_log_err ("error occurred while removing interface");
	}
    }
  pool_free (pool);
  pool_free (sm->interfaces);
  sm->interfaces = 0;
  return error;
}

int
nat44_ed_del_output_interfaces ()
{
  snat_main_t *sm = &snat_main;
  snat_interface_t *i, *pool;
  int error = 0;

  pool = pool_dup (sm->output_feature_interfaces);
  pool_foreach (i, pool)
    {
      error = nat44_ed_del_output_interface (i->sw_if_index);
      if (error)
	{
	  nat_log_err ("error occurred while removing output interface");
	}
    }
  pool_free (pool);
  pool_free (sm->output_feature_interfaces);
  sm->output_feature_interfaces = 0;
  return error;
}

int
nat44_ed_del_static_mappings ()
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m, *pool;
  int error = 0;

  pool = pool_dup (sm->static_mappings);
  pool_foreach (m, pool)
    {
      error = nat44_ed_del_static_mapping_internal (
	m->local_addr, m->external_addr, m->local_port, m->external_port,
	m->proto, m->vrf_id, m->flags);
      if (error)
	{
	  nat_log_err ("error occurred while removing mapping");
	}
    }
  pool_free (pool);
  pool_free (sm->static_mappings);
  sm->static_mappings = 0;

  vec_free (sm->sm_to_resolve);
  sm->sm_to_resolve = 0;

  return error;
}

int
nat44_plugin_disable ()
{
  snat_main_per_thread_data_t *tsm;
  snat_main_t *sm = &snat_main;
  int rc, error = 0;

  fail_if_disabled ();

  rc = nat44_ed_del_static_mappings ();
  if (rc)
    error = 1;

  rc = nat44_ed_del_addresses ();
  if (rc)
    error = 1;

  rc = nat44_ed_del_interfaces ();
  if (rc)
    error = 1;

  rc = nat44_ed_del_output_interfaces ();
  if (rc)
    error = 1;

  vec_free (sm->max_translations_per_fib);
  sm->max_translations_per_fib = 0;

  clib_bihash_free_16_8 (&sm->flow_hash);

  vec_foreach (tsm, sm->per_thread_data)
    {
      nat44_ed_worker_db_free (tsm);
    }

  clib_memset (&sm->rconfig, 0, sizeof (sm->rconfig));

  sm->forwarding_enabled = 0;
  sm->enabled = 0;

  return error;
}

void
nat44_ed_forwarding_enable_disable (u8 is_enable)
{
  snat_main_per_thread_data_t *tsm;
  snat_main_t *sm = &snat_main;
  snat_session_t *s;

  u32 *ses_to_be_removed = 0, *ses_index;

  sm->forwarding_enabled = is_enable != 0;

  if (!sm->enabled || is_enable)
    {
      return;
    }

  vec_foreach (tsm, sm->per_thread_data)
    {
      pool_foreach (s, tsm->sessions)
	{
	  if (na44_ed_is_fwd_bypass_session (s))
	    {
	      vec_add1 (ses_to_be_removed, s - tsm->sessions);
	    }
	}
      vec_foreach (ses_index, ses_to_be_removed)
	{
	  s = pool_elt_at_index (tsm->sessions, ses_index[0]);
	  nat44_ed_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
	  nat_ed_session_delete (sm, s, tsm - sm->per_thread_data, 1);
	}

      vec_free (ses_to_be_removed);
    }
}

static_always_inline snat_static_mapping_t *
nat44_ed_sm_match (snat_main_t *sm, ip4_address_t match_addr, u16 match_port,
		   u32 match_fib_index, ip_protocol_t match_protocol,
		   int by_external, int addr_only)
{
  snat_static_mapping_t *m;
  if (!by_external)
    {
      if (!addr_only)
	{
	  m = nat44_ed_sm_i2o_lookup (sm, match_addr, match_port,
				      match_fib_index, match_protocol);
	  if (m)
	    return m;
	}

      /* Try address only mapping */
      m = nat44_ed_sm_i2o_lookup (sm, match_addr, 0, match_fib_index, 0);
      if (m)
	return m;

      if (sm->inside_fib_index != match_fib_index)
	{
	  if (!addr_only)
	    {
	      m =
		nat44_ed_sm_i2o_lookup (sm, match_addr, match_port,
					sm->inside_fib_index, match_protocol);
	      if (m)
		return m;
	    }

	  /* Try address only mapping */
	  m = nat44_ed_sm_i2o_lookup (sm, match_addr, 0, sm->inside_fib_index,
				      0);
	  if (m)
	    return m;
	}
      if (sm->outside_fib_index != match_fib_index)
	{
	  if (!addr_only)
	    {
	      m =
		nat44_ed_sm_i2o_lookup (sm, match_addr, match_port,
					sm->outside_fib_index, match_protocol);
	      if (m)
		return m;
	    }

	  /* Try address only mapping */
	  m = nat44_ed_sm_i2o_lookup (sm, match_addr, 0, sm->outside_fib_index,
				      0);
	  if (m)
	    return m;
	}
    }
  else
    {
      if (!addr_only)
	{
	  m = nat44_ed_sm_o2i_lookup (sm, match_addr, match_port, 0,
				      match_protocol);
	  if (m)
	    return m;
	}

      /* Try address only mapping */
      m = nat44_ed_sm_o2i_lookup (sm, match_addr, 0, 0, 0);
      if (m)
	return m;
    }
  return 0;
}

int
snat_static_mapping_match (vlib_main_t *vm, snat_main_t *sm,
			   ip4_address_t match_addr, u16 match_port,
			   u32 match_fib_index, ip_protocol_t match_protocol,
			   ip4_address_t *mapping_addr, u16 *mapping_port,
			   u32 *mapping_fib_index, int by_external,
			   int is_l4_layer_truncated, u8 *is_addr_only,
			   twice_nat_type_t *twice_nat, lb_nat_type_t *lb,
			   ip4_address_t *ext_host_addr, u8 *is_identity_nat,
			   snat_static_mapping_t **out)
{
  snat_static_mapping_t *m;
  u32 rand, lo = 0, hi, mid, *tmp = 0, i;
  nat44_lb_addr_port_t *local;
  u8 backend_index;

  m = nat44_ed_sm_match (sm, match_addr, match_port, match_fib_index,
			 match_protocol, by_external, is_l4_layer_truncated);
  if (!m)
    {
      return 1;
    }

  if (by_external)
    {
      if (is_sm_lb (m->flags))
	{
	  if (PREDICT_FALSE (lb != 0))
	    *lb = m->affinity ? AFFINITY_LB_NAT : LB_NAT;
	  if (m->affinity && !nat_affinity_find_and_lock (
			       vm, ext_host_addr[0], match_addr,
			       match_protocol, match_port, &backend_index))
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
              pool_foreach_index (i, m->locals)
               {
                local = pool_elt_at_index (m->locals, i);

                ip4_header_t ip = {
		  .src_address = local->addr,
	        };

		if (nat44_ed_get_in2out_worker_index (0, &ip, m->fib_index,
						      0) == thread_index)
		  {
		    vec_add1 (tmp, i);
		  }
	       }
	      ASSERT (vec_len (tmp) != 0);
	    }
	  else
	    {
              pool_foreach_index (i, m->locals)
               {
                vec_add1 (tmp, i);
              }
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
		nat_elog_info (sm, "create affinity record failed");
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
	  *mapping_port =
	    is_sm_addr_only (m->flags) ? match_port : m->local_port;
	}
    }
  else
    {
      *mapping_addr = m->external_addr;
      /* Address only mapping doesn't change port */
      *mapping_port =
	is_sm_addr_only (m->flags) ? match_port : m->external_port;
      *mapping_fib_index = sm->outside_fib_index;
    }

end:
  if (PREDICT_FALSE (is_addr_only != 0))
    *is_addr_only = is_sm_addr_only (m->flags);

  if (PREDICT_FALSE (twice_nat != 0))
    {
      *twice_nat = TWICE_NAT_DISABLED;

      if (is_sm_twice_nat (m->flags))
	{
	  *twice_nat = TWICE_NAT;
	}
      else if (is_sm_self_twice_nat (m->flags))
	{
	  *twice_nat = TWICE_NAT_SELF;
	}
    }

  if (PREDICT_FALSE (is_identity_nat != 0))
    *is_identity_nat = is_sm_identity_nat (m->flags);

  if (out != 0)
    *out = m;

  return 0;
}

u32
nat44_ed_get_in2out_worker_index (vlib_buffer_t *b, ip4_header_t *ip,
				  u32 rx_fib_index, u8 is_output)
{
  snat_main_t *sm = &snat_main;
  u32 next_worker_index = sm->first_worker_index;
  u32 hash;

  clib_bihash_kv_16_8_t kv16, value16;

  u32 fib_index = rx_fib_index;
  if (b)
    {
      if (PREDICT_FALSE (is_output))
	{
	  fib_index = sm->outside_fib_index;
	  nat_outside_fib_t *outside_fib;
	  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
	  fib_prefix_t pfx = {
		  .fp_proto = FIB_PROTOCOL_IP4,
		  .fp_len = 32,
		  .fp_addr = {
			  .ip4.as_u32 = ip->dst_address.as_u32,
		  } ,
	  };

	  switch (vec_len (sm->outside_fibs))
	    {
	    case 0:
	      fib_index = sm->outside_fib_index;
	      break;
	    case 1:
	      fib_index = sm->outside_fibs[0].fib_index;
	      break;
	    default:
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
	      break;
	    }
	}

      if (PREDICT_FALSE (ip->protocol == IP_PROTOCOL_ICMP))
	{
	  ip4_address_t lookup_saddr, lookup_daddr;
	  u16 lookup_sport, lookup_dport;
	  u8 lookup_protocol;

	  if (!nat_get_icmp_session_lookup_values (
		b, ip, &lookup_saddr, &lookup_sport, &lookup_daddr,
		&lookup_dport, &lookup_protocol))
	    {
	      init_ed_k (&kv16, lookup_saddr.as_u32, lookup_sport,
			 lookup_daddr.as_u32, lookup_dport, rx_fib_index,
			 lookup_protocol);
	      if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv16, &value16))
		{
		  next_worker_index = ed_value_get_thread_index (&value16);
		  vnet_buffer2 (b)->nat.cached_session_index =
		    ed_value_get_session_index (&value16);
		  goto out;
		}
	    }
	}

      init_ed_k (&kv16, ip->src_address.as_u32,
		 vnet_buffer (b)->ip.reass.l4_src_port, ip->dst_address.as_u32,
		 vnet_buffer (b)->ip.reass.l4_dst_port, fib_index,
		 ip->protocol);

      if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv16, &value16))
	{
	  next_worker_index = ed_value_get_thread_index (&value16);
	  vnet_buffer2 (b)->nat.cached_session_index =
	    ed_value_get_session_index (&value16);
	  goto out;
	}

      // dst NAT
      init_ed_k (&kv16, ip->dst_address.as_u32,
		 vnet_buffer (b)->ip.reass.l4_dst_port, ip->src_address.as_u32,
		 vnet_buffer (b)->ip.reass.l4_src_port, rx_fib_index,
		 ip->protocol);
      if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv16, &value16))
	{
	  next_worker_index = ed_value_get_thread_index (&value16);
	  vnet_buffer2 (b)->nat.cached_dst_nat_session_index =
	    ed_value_get_session_index (&value16);
	  goto out;
	}
    }

  hash = ip->src_address.as_u32 + (ip->src_address.as_u32 >> 8) +
    (ip->src_address.as_u32 >> 16) + (ip->src_address.as_u32 >> 24);

  if (PREDICT_TRUE (is_pow2 (_vec_len (sm->workers))))
    next_worker_index += sm->workers[hash & (_vec_len (sm->workers) - 1)];
  else
    next_worker_index += sm->workers[hash % _vec_len (sm->workers)];

out:
  if (PREDICT_TRUE (!is_output))
    {
      nat_elog_debug_handoff (sm, "HANDOFF IN2OUT", next_worker_index,
			      rx_fib_index,
			      clib_net_to_host_u32 (ip->src_address.as_u32),
			      clib_net_to_host_u32 (ip->dst_address.as_u32));
    }
  else
    {
      nat_elog_debug_handoff (sm, "HANDOFF IN2OUT-OUTPUT-FEATURE",
			      next_worker_index, rx_fib_index,
			      clib_net_to_host_u32 (ip->src_address.as_u32),
			      clib_net_to_host_u32 (ip->dst_address.as_u32));
    }

  return next_worker_index;
}

u32
nat44_ed_get_out2in_worker_index (vlib_buffer_t *b, ip4_header_t *ip,
				  u32 rx_fib_index, u8 is_output)
{
  snat_main_t *sm = &snat_main;
  clib_bihash_kv_16_8_t kv16, value16;

  u8 proto, next_worker_index = 0;
  u16 port;
  snat_static_mapping_t *m;
  u32 hash;

  proto = ip->protocol;

  if (PREDICT_FALSE (IP_PROTOCOL_ICMP == proto))
    {
      ip4_address_t lookup_saddr, lookup_daddr;
      u16 lookup_sport, lookup_dport;
      u8 lookup_protocol;
      if (!nat_get_icmp_session_lookup_values (
	    b, ip, &lookup_saddr, &lookup_sport, &lookup_daddr, &lookup_dport,
	    &lookup_protocol))
	{
	  init_ed_k (&kv16, lookup_saddr.as_u32, lookup_sport,
		     lookup_daddr.as_u32, lookup_dport, rx_fib_index,
		     lookup_protocol);
	  if (PREDICT_TRUE (
		!clib_bihash_search_16_8 (&sm->flow_hash, &kv16, &value16)))
	    {
	      next_worker_index = ed_value_get_thread_index (&value16);
	      nat_elog_debug_handoff (
		sm, "HANDOFF OUT2IN (session)", next_worker_index,
		rx_fib_index, clib_net_to_host_u32 (ip->src_address.as_u32),
		clib_net_to_host_u32 (ip->dst_address.as_u32));
	      return next_worker_index;
	    }
	}
    }

  init_ed_k (&kv16, ip->src_address.as_u32,
	     vnet_buffer (b)->ip.reass.l4_src_port, ip->dst_address.as_u32,
	     vnet_buffer (b)->ip.reass.l4_dst_port, rx_fib_index,
	     ip->protocol);

  if (PREDICT_TRUE (
	!clib_bihash_search_16_8 (&sm->flow_hash, &kv16, &value16)))
    {
      vnet_buffer2 (b)->nat.cached_session_index =
	ed_value_get_session_index (&value16);
      next_worker_index = ed_value_get_thread_index (&value16);
      nat_elog_debug_handoff (sm, "HANDOFF OUT2IN (session)",
			      next_worker_index, rx_fib_index,
			      clib_net_to_host_u32 (ip->src_address.as_u32),
			      clib_net_to_host_u32 (ip->dst_address.as_u32));
      return next_worker_index;
    }

  /* first try static mappings without port */
  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
    {
      m = nat44_ed_sm_o2i_lookup (sm, ip->dst_address, 0, 0, proto);
      if (m)
	{
	  {
	    next_worker_index = m->workers[0];
	    goto done;
	  }
	}
    }

  /* unknown protocol */
  if (PREDICT_FALSE (nat44_ed_is_unk_proto (proto)))
    {
      /* use current thread */
      next_worker_index = vlib_get_thread_index ();
      goto done;
    }

  port = vnet_buffer (b)->ip.reass.l4_dst_port;

  if (PREDICT_FALSE (ip->protocol == IP_PROTOCOL_ICMP))
    {
      udp_header_t *udp = ip4_next_header (ip);
      icmp46_header_t *icmp = (icmp46_header_t *) udp;
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      if (!icmp_type_is_error_message
	  (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags))
	port = vnet_buffer (b)->ip.reass.l4_src_port;
      else
	{
	  /* if error message, then it's not fragmented and we can access it */
	  ip4_header_t *inner_ip = (ip4_header_t *) (echo + 1);
	  proto = inner_ip->protocol;
	  void *l4_header = ip4_next_header (inner_ip);
	  switch (proto)
	    {
	    case IP_PROTOCOL_ICMP:
	      icmp = (icmp46_header_t *) l4_header;
	      echo = (icmp_echo_header_t *) (icmp + 1);
	      port = echo->identifier;
	      break;
	    case IP_PROTOCOL_UDP:
	      /* breakthrough */
	    case IP_PROTOCOL_TCP:
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
      m = nat44_ed_sm_o2i_lookup (sm, ip->dst_address, port, 0, proto);
      if (m)
	{
	  if (!is_sm_lb (m->flags))
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
  nat_elog_debug_handoff (sm, "HANDOFF OUT2IN", next_worker_index,
			  rx_fib_index,
			  clib_net_to_host_u32 (ip->src_address.as_u32),
			  clib_net_to_host_u32 (ip->dst_address.as_u32));
  return next_worker_index;
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

  stat_segment_set_state_counter (sm->max_cfg_sessions_gauge,
				  sm->max_translations_per_thread);

  sm->translation_buckets =
    nat_calc_bihash_buckets (sm->max_translations_per_thread);

  nat44_ed_sessions_clear ();
  return 0;
}

static void
nat44_ed_worker_db_init (snat_main_per_thread_data_t *tsm, u32 translations,
			 u32 translation_buckets)
{
  dlist_elt_t *head;

  pool_alloc (tsm->sessions, translations);
  pool_alloc (tsm->lru_pool, translations);

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
}

static void
reinit_ed_flow_hash ()
{
  snat_main_t *sm = &snat_main;
  // we expect 2 flows per session, so multiply translation_buckets by 2
  clib_bihash_init_16_8 (
    &sm->flow_hash, "ed-flow-hash",
    clib_max (1, sm->num_workers) * 2 * sm->translation_buckets, 0);
  clib_bihash_set_kvp_format_fn_16_8 (&sm->flow_hash, format_ed_session_kvp);
}

static void
nat44_ed_db_init (u32 translations, u32 translation_buckets)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;

  reinit_ed_flow_hash ();

  vec_foreach (tsm, sm->per_thread_data)
    {
      nat44_ed_worker_db_init (tsm, sm->max_translations_per_thread,
			       sm->translation_buckets);
    }
}

static void
nat44_ed_worker_db_free (snat_main_per_thread_data_t *tsm)
{
  pool_free (tsm->lru_pool);
  pool_free (tsm->sessions);
  vec_free (tsm->per_vrf_sessions_vec);
}

void
nat44_ed_sessions_clear ()
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;

  reinit_ed_flow_hash ();

  vec_foreach (tsm, sm->per_thread_data)
    {
      nat44_ed_worker_db_free (tsm);
      nat44_ed_worker_db_init (tsm, sm->max_translations_per_thread,
			       sm->translation_buckets);
    }
  vlib_zero_simple_counter (&sm->total_sessions, 0);
}

static void
nat44_ed_add_del_static_mapping_cb (ip4_main_t *im, uword opaque,
				    u32 sw_if_index, ip4_address_t *address,
				    u32 address_length, u32 if_address_index,
				    u32 is_delete)
{
  snat_static_mapping_resolve_t *rp;
  snat_main_t *sm = &snat_main;
  int rv = 0;

  if (!sm->enabled)
    {
      return;
    }

  vec_foreach (rp, sm->sm_to_resolve)
    {
      if (sw_if_index == rp->sw_if_index)
	{
	  if (is_delete)
	    {
	      if (rp->is_resolved)
		{
		  rv = nat44_ed_del_static_mapping_internal (
		    rp->l_addr, address[0], rp->l_port, rp->e_port, rp->proto,
		    rp->vrf_id, rp->flags);
		  if (rv)
		    {
		      nat_log_err ("ed del static mapping failed");
		    }
		  else
		    {
		      rp->is_resolved = 0;
		    }
		}
	    }
	  else
	    {
	      if (!rp->is_resolved)
		{
		  rv = nat44_ed_add_static_mapping_internal (
		    rp->l_addr, address[0], rp->l_port, rp->e_port, rp->proto,
		    rp->vrf_id, ~0, rp->flags, rp->pool_addr, rp->tag);
		  if (rv)
		    {
		      nat_log_err ("ed add static mapping failed");
		    }
		  else
		    {
		      rp->is_resolved = 1;
		    }
		}
	    }
	}
    }
}

static int
nat44_ed_get_addr_resolve_record (u32 sw_if_index, u8 twice_nat, int *out)
{
  snat_main_t *sm = &snat_main;
  snat_address_resolve_t *rp;
  int i;

  for (i = 0; i < vec_len (sm->addr_to_resolve); i++)
    {
      rp = sm->addr_to_resolve + i;

      if ((rp->sw_if_index == sw_if_index) && (rp->is_twice_nat == twice_nat))
	{
	  if (out)
	    {
	      *out = i;
	    }
	  return 0;
	}
    }
  return 1;
}
static int
nat44_ed_del_addr_resolve_record (u32 sw_if_index, u8 twice_nat)
{
  snat_main_t *sm = &snat_main;
  int i;
  if (!nat44_ed_get_addr_resolve_record (sw_if_index, twice_nat, &i))
    {
      vec_del1 (sm->addr_to_resolve, i);
      return 0;
    }
  return 1;
}

static void
nat44_ed_add_del_interface_address_cb (ip4_main_t *im, uword opaque,
				       u32 sw_if_index, ip4_address_t *address,
				       u32 address_length,
				       u32 if_address_index, u32 is_delete)
{
  snat_main_t *sm = &snat_main;
  snat_address_resolve_t *arp;
  snat_address_t *ap;
  u8 twice_nat = 0;
  int i, rv;

  if (!sm->enabled)
    {
      return;
    }

  if (nat44_ed_get_addr_resolve_record (sw_if_index, twice_nat, &i))
    {
      twice_nat = 1;
      if (nat44_ed_get_addr_resolve_record (sw_if_index, twice_nat, &i))
	{
	  u32 fib_index =
	    ip4_fib_table_get_index_for_sw_if_index (sw_if_index);
	  vec_foreach (ap, sm->addresses)
	    {
	      if ((fib_index == ap->fib_index) &&
		  (address->as_u32 == ap->addr.as_u32))
		{
		  if (!is_delete)
		    {
		      ap->addr_len = address_length;
		      ap->sw_if_index = sw_if_index;
		      ap->net.as_u32 = (ap->addr.as_u32 >> (32 - ap->addr_len))
				       << (32 - ap->addr_len);

		      nat_log_debug (
			"pool addr %U binds to -> sw_if_idx: %u net: %U/%u",
			format_ip4_address, &ap->addr, ap->sw_if_index,
			format_ip4_address, &ap->net, ap->addr_len);
		    }
		  else
		    {
		      ap->addr_len = ~0;
		    }
		  break;
		}
	    }
	  return;
	}
    }

  arp = sm->addr_to_resolve + i;

  if (!is_delete)
    {
      if (arp->is_resolved)
	{
	  return;
	}

      rv = nat44_ed_add_address (address, ~0, arp->is_twice_nat);
      if (0 == rv)
	{
	  arp->is_resolved = 1;
	}
    }
  else
    {
      if (!arp->is_resolved)
	{
	  return;
	}

      rv = nat44_ed_del_address (address[0], arp->is_twice_nat);
      if (0 == rv)
	{
	  arp->is_resolved = 0;
	}
    }
}

int
nat44_ed_add_interface_address (u32 sw_if_index, u8 twice_nat)
{
  snat_main_t *sm = &snat_main;
  ip4_main_t *ip4_main = sm->ip4_main;
  ip4_address_t *first_int_addr;
  snat_address_resolve_t *ap;
  int rv;

  if (!sm->enabled)
    {
      return VNET_API_ERROR_UNSUPPORTED;
    }

  if (!nat44_ed_get_addr_resolve_record (sw_if_index, twice_nat, 0))
    {
      return VNET_API_ERROR_VALUE_EXIST;
    }

  vec_add2 (sm->addr_to_resolve, ap, 1);
  ap->sw_if_index = sw_if_index;
  ap->is_twice_nat = twice_nat;
  ap->is_resolved = 0;

  first_int_addr = ip4_interface_first_address (ip4_main, sw_if_index, 0);
  if (first_int_addr)
    {
      rv = nat44_ed_add_address (first_int_addr, ~0, twice_nat);
      if (0 != rv)
	{
	  nat44_ed_del_addr_resolve_record (sw_if_index, twice_nat);
	  return rv;
	}
      ap->is_resolved = 1;
    }

  return 0;
}

int
nat44_ed_del_interface_address (u32 sw_if_index, u8 twice_nat)
{
  snat_main_t *sm = &snat_main;
  ip4_main_t *ip4_main = sm->ip4_main;
  ip4_address_t *first_int_addr;

  if (!sm->enabled)
    {
      return VNET_API_ERROR_UNSUPPORTED;
    }

  if (nat44_ed_del_addr_resolve_record (sw_if_index, twice_nat))
    {
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  first_int_addr = ip4_interface_first_address (ip4_main, sw_if_index, 0);
  if (first_int_addr)
    {
      return nat44_ed_del_address (first_int_addr[0], twice_nat);
    }

  return 0;
}

int
nat44_ed_del_session (snat_main_t *sm, ip4_address_t *addr, u16 port,
		      ip4_address_t *eh_addr, u16 eh_port, u8 proto,
		      u32 vrf_id, int is_in)
{
  ip4_header_t ip;
  clib_bihash_kv_16_8_t kv, value;
  u32 fib_index;
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm;

  if (!sm->enabled)
    {
      return VNET_API_ERROR_UNSUPPORTED;
    }

  fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);
  ip.dst_address.as_u32 = ip.src_address.as_u32 = addr->as_u32;
  if (sm->num_workers > 1)
    tsm = vec_elt_at_index (
      sm->per_thread_data,
      nat44_ed_get_in2out_worker_index (0, &ip, fib_index, 0));
  else
    tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

  init_ed_k (&kv, addr->as_u32, port, eh_addr->as_u32, eh_port, fib_index,
	     proto);
  if (clib_bihash_search_16_8 (&sm->flow_hash, &kv, &value))
    {
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (pool_is_free_index (tsm->sessions, ed_value_get_session_index (&value)))
    return VNET_API_ERROR_UNSPECIFIED;
  s = pool_elt_at_index (tsm->sessions, ed_value_get_session_index (&value));
  nat44_ed_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
  nat_ed_session_delete (sm, s, tsm - sm->per_thread_data, 1);
  return 0;
}

VLIB_NODE_FN (nat_default_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  return 0;
}

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
    [NAT_NEXT_IN2OUT_CLASSIFY] = "nat44-in2out-worker-handoff",
    [NAT_NEXT_OUT2IN_CLASSIFY] = "nat44-out2in-worker-handoff",
  },
};

void
nat_6t_l3_l4_csum_calc (nat_6t_flow_t *f)
{
  f->l3_csum_delta = 0;
  f->l4_csum_delta = 0;
  if (f->ops & NAT_FLOW_OP_SADDR_REWRITE &&
      f->rewrite.saddr.as_u32 != f->match.saddr.as_u32)
    {
      f->l3_csum_delta =
	ip_csum_add_even (f->l3_csum_delta, f->rewrite.saddr.as_u32);
      f->l3_csum_delta =
	ip_csum_sub_even (f->l3_csum_delta, f->match.saddr.as_u32);
    }
  else
    {
      f->rewrite.saddr.as_u32 = f->match.saddr.as_u32;
    }
  if (f->ops & NAT_FLOW_OP_DADDR_REWRITE &&
      f->rewrite.daddr.as_u32 != f->match.daddr.as_u32)
    {
      f->l3_csum_delta =
	ip_csum_add_even (f->l3_csum_delta, f->rewrite.daddr.as_u32);
      f->l3_csum_delta =
	ip_csum_sub_even (f->l3_csum_delta, f->match.daddr.as_u32);
    }
  else
    {
      f->rewrite.daddr.as_u32 = f->match.daddr.as_u32;
    }
  if (f->ops & NAT_FLOW_OP_SPORT_REWRITE && f->rewrite.sport != f->match.sport)
    {
      f->l4_csum_delta = ip_csum_add_even (f->l4_csum_delta, f->rewrite.sport);
      f->l4_csum_delta = ip_csum_sub_even (f->l4_csum_delta, f->match.sport);
    }
  else
    {
      f->rewrite.sport = f->match.sport;
    }
  if (f->ops & NAT_FLOW_OP_DPORT_REWRITE && f->rewrite.dport != f->match.dport)
    {
      f->l4_csum_delta = ip_csum_add_even (f->l4_csum_delta, f->rewrite.dport);
      f->l4_csum_delta = ip_csum_sub_even (f->l4_csum_delta, f->match.dport);
    }
  else
    {
      f->rewrite.dport = f->match.dport;
    }
  if (f->ops & NAT_FLOW_OP_ICMP_ID_REWRITE &&
      f->rewrite.icmp_id != f->match.sport)
    {
      f->l4_csum_delta =
	ip_csum_add_even (f->l4_csum_delta, f->rewrite.icmp_id);
      f->l4_csum_delta = ip_csum_sub_even (f->l4_csum_delta, f->match.sport);
    }
  else
    {
      f->rewrite.icmp_id = f->match.sport;
    }
  if (f->ops & NAT_FLOW_OP_TXFIB_REWRITE)
    {
    }
  else
    {
      f->rewrite.fib_index = f->match.fib_index;
    }
}

static_always_inline int
nat_6t_flow_icmp_translate (vlib_main_t *vm, snat_main_t *sm, vlib_buffer_t *b,
			    ip4_header_t *ip, nat_6t_flow_t *f);

static_always_inline void
nat_6t_flow_ip4_translate (snat_main_t *sm, vlib_buffer_t *b, ip4_header_t *ip,
			   nat_6t_flow_t *f, ip_protocol_t proto,
			   int is_icmp_inner_ip4, int skip_saddr_rewrite)
{
  udp_header_t *udp = ip4_next_header (ip);
  tcp_header_t *tcp = (tcp_header_t *) udp;

  if ((IP_PROTOCOL_TCP == proto || IP_PROTOCOL_UDP == proto) &&
      !vnet_buffer (b)->ip.reass.is_non_first_fragment)
    {
      if (!is_icmp_inner_ip4)
	{ // regular case
	  ip->src_address = f->rewrite.saddr;
	  ip->dst_address = f->rewrite.daddr;
	  udp->src_port = f->rewrite.sport;
	  udp->dst_port = f->rewrite.dport;
	}
      else
	{ // icmp inner ip4 - reversed saddr/daddr
	  ip->src_address = f->rewrite.daddr;
	  ip->dst_address = f->rewrite.saddr;
	  udp->src_port = f->rewrite.dport;
	  udp->dst_port = f->rewrite.sport;
	}

      if (IP_PROTOCOL_TCP == proto)
	{
	  ip_csum_t tcp_sum = tcp->checksum;
	  tcp_sum = ip_csum_sub_even (tcp_sum, f->l3_csum_delta);
	  tcp_sum = ip_csum_sub_even (tcp_sum, f->l4_csum_delta);
	  mss_clamping (sm->mss_clamping, tcp, &tcp_sum);
	  tcp->checksum = ip_csum_fold (tcp_sum);
	}
      else if (IP_PROTOCOL_UDP == proto && udp->checksum)
	{
	  ip_csum_t udp_sum = udp->checksum;
	  udp_sum = ip_csum_sub_even (udp_sum, f->l3_csum_delta);
	  udp_sum = ip_csum_sub_even (udp_sum, f->l4_csum_delta);
	  udp->checksum = ip_csum_fold (udp_sum);
	}
    }
  else
    {
      if (!is_icmp_inner_ip4)
	{ // regular case
	  if (!skip_saddr_rewrite)
	    {
	      ip->src_address = f->rewrite.saddr;
	    }
	  ip->dst_address = f->rewrite.daddr;
	}
      else
	{ // icmp inner ip4 - reversed saddr/daddr
	  ip->src_address = f->rewrite.daddr;
	  ip->dst_address = f->rewrite.saddr;
	}
    }

  if (skip_saddr_rewrite)
    {
      ip->checksum = ip4_header_checksum (ip);
    }
  else
    {
      ip_csum_t ip_sum = ip->checksum;
      ip_sum = ip_csum_sub_even (ip_sum, f->l3_csum_delta);
      ip->checksum = ip_csum_fold (ip_sum);
    }
  if (0xffff == ip->checksum)
    ip->checksum = 0;
  ASSERT (ip4_header_checksum_is_valid (ip));
}

static_always_inline int
it_fits (vlib_main_t *vm, vlib_buffer_t *b, void *object, size_t size)
{
  int result = ((u8 *) object + size <=
		(u8 *) vlib_buffer_get_current (b) + b->current_length) &&
	       vlib_object_within_buffer_data (vm, b, object, size);
  return result;
}

static_always_inline int
nat_6t_flow_icmp_translate (vlib_main_t *vm, snat_main_t *sm, vlib_buffer_t *b,
			    ip4_header_t *ip, nat_6t_flow_t *f)
{
  if (IP_PROTOCOL_ICMP != ip->protocol)
    return NAT_ED_TRNSL_ERR_TRANSLATION_FAILED;

  icmp46_header_t *icmp = ip4_next_header (ip);
  icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);

  if (!vnet_buffer (b)->ip.reass.l4_layer_truncated &&
      !vnet_buffer (b)->ip.reass.is_non_first_fragment)
    {
      if (!icmp_type_is_error_message (icmp->type))
	{
	  if ((f->ops & NAT_FLOW_OP_ICMP_ID_REWRITE) &&
	      (f->rewrite.icmp_id != echo->identifier))
	    {
	      ip_csum_t sum = icmp->checksum;
	      sum = ip_csum_update (sum, echo->identifier, f->rewrite.icmp_id,
				    icmp_echo_header_t,
				    identifier /* changed member */);
	      echo->identifier = f->rewrite.icmp_id;
	      icmp->checksum = ip_csum_fold (sum);
	    }
	}
      else
	{
	  ip_csum_t sum = ip_incremental_checksum (
	    0, icmp,
	    clib_net_to_host_u16 (ip->length) - ip4_header_bytes (ip));
	  sum = (u16) ~ip_csum_fold (sum);
	  if (sum != 0)
	    {
	      return NAT_ED_TRNSL_ERR_INVALID_CSUM;
	    }

	  // errors are not fragmented
	  ip4_header_t *inner_ip = (ip4_header_t *) (echo + 1);

	  if (!ip4_header_checksum_is_valid (inner_ip))
	    {
	      return NAT_ED_TRNSL_ERR_INNER_IP_CORRUPT;
	    }

	  ip_protocol_t inner_proto = inner_ip->protocol;

	  ip_csum_t old_icmp_sum = icmp->checksum;
	  ip_csum_t old_inner_ip_sum = inner_ip->checksum;
	  ip_csum_t old_udp_sum;
	  ip_csum_t old_tcp_sum;
	  ip_csum_t new_icmp_sum;
	  udp_header_t *udp;
	  tcp_header_t *tcp;

	  switch (inner_proto)
	    {
	    case IP_PROTOCOL_UDP:
	      udp = (udp_header_t *) (inner_ip + 1);
	      if (!it_fits (vm, b, udp, sizeof (*udp)))
		{
		  return NAT_ED_TRNSL_ERR_PACKET_TRUNCATED;
		}
	      old_udp_sum = udp->checksum;
	      nat_6t_flow_ip4_translate (sm, b, inner_ip, f, inner_proto,
					 1 /* is_icmp_inner_ip4 */,
					 0 /* skip_saddr_rewrite */);
	      new_icmp_sum = ip_csum_sub_even (old_icmp_sum, f->l3_csum_delta);
	      new_icmp_sum = ip_csum_sub_even (new_icmp_sum, f->l4_csum_delta);
	      new_icmp_sum =
		ip_csum_update (new_icmp_sum, old_inner_ip_sum,
				inner_ip->checksum, ip4_header_t, checksum);
	      new_icmp_sum =
		ip_csum_update (new_icmp_sum, old_udp_sum, udp->checksum,
				udp_header_t, checksum);
	      new_icmp_sum = ip_csum_fold (new_icmp_sum);
	      icmp->checksum = new_icmp_sum;
	      break;
	    case IP_PROTOCOL_TCP:
	      tcp = (tcp_header_t *) (inner_ip + 1);
	      if (!it_fits (vm, b, tcp, sizeof (*tcp)))
		{
		  return NAT_ED_TRNSL_ERR_PACKET_TRUNCATED;
		}
	      old_tcp_sum = tcp->checksum;
	      nat_6t_flow_ip4_translate (sm, b, inner_ip, f, inner_proto,
					 1 /* is_icmp_inner_ip4 */,
					 0 /* skip_saddr_rewrite */);
	      new_icmp_sum = ip_csum_sub_even (old_icmp_sum, f->l3_csum_delta);
	      new_icmp_sum = ip_csum_sub_even (new_icmp_sum, f->l4_csum_delta);
	      new_icmp_sum =
		ip_csum_update (new_icmp_sum, old_inner_ip_sum,
				inner_ip->checksum, ip4_header_t, checksum);
	      new_icmp_sum =
		ip_csum_update (new_icmp_sum, old_tcp_sum, tcp->checksum,
				tcp_header_t, checksum);
	      new_icmp_sum = ip_csum_fold (new_icmp_sum);
	      icmp->checksum = new_icmp_sum;
	      break;
	    case IP_PROTOCOL_ICMP:
	      if (f->ops & NAT_FLOW_OP_ICMP_ID_REWRITE)
		{
		  icmp46_header_t *inner_icmp = ip4_next_header (inner_ip);
		  if (!it_fits (vm, b, inner_icmp, sizeof (*inner_icmp)))
		    {
		      return NAT_ED_TRNSL_ERR_PACKET_TRUNCATED;
		    }
		  icmp_echo_header_t *inner_echo =
		    (icmp_echo_header_t *) (inner_icmp + 1);
		  if (f->rewrite.icmp_id != inner_echo->identifier)
		    {
		      ip_csum_t sum = icmp->checksum;
		      sum = ip_csum_update (
			sum, inner_echo->identifier, f->rewrite.icmp_id,
			icmp_echo_header_t, identifier /* changed member */);
		      icmp->checksum = ip_csum_fold (sum);
		      ip_csum_t inner_sum = inner_icmp->checksum;
		      inner_sum = ip_csum_update (
			sum, inner_echo->identifier, f->rewrite.icmp_id,
			icmp_echo_header_t, identifier /* changed member */);
		      inner_icmp->checksum = ip_csum_fold (inner_sum);
		      inner_echo->identifier = f->rewrite.icmp_id;
		    }
		}
	      break;
	    default:
	      clib_warning ("unexpected NAT protocol value `%d'", inner_proto);
	      return NAT_ED_TRNSL_ERR_TRANSLATION_FAILED;
	    }
	}
    }

  return NAT_ED_TRNSL_ERR_SUCCESS;
}

static_always_inline nat_translation_error_e
nat_6t_flow_buf_translate (vlib_main_t *vm, snat_main_t *sm, vlib_buffer_t *b,
			   ip4_header_t *ip, nat_6t_flow_t *f,
			   ip_protocol_t proto, int is_output_feature,
			   int is_i2o)
{
  if (!is_output_feature && f->ops & NAT_FLOW_OP_TXFIB_REWRITE)
    {
      vnet_buffer (b)->sw_if_index[VLIB_TX] = f->rewrite.fib_index;
    }

  if (IP_PROTOCOL_ICMP == proto)
    {
      if (ip->src_address.as_u32 != f->rewrite.saddr.as_u32)
	{
	  // packet is returned from a router, not from destination
	  // skip source address rewrite if in o2i path
	  nat_6t_flow_ip4_translate (sm, b, ip, f, proto,
				     0 /* is_icmp_inner_ip4 */,
				     !is_i2o /* skip_saddr_rewrite */);
	}
      else
	{
	  nat_6t_flow_ip4_translate (sm, b, ip, f, proto,
				     0 /* is_icmp_inner_ip4 */,
				     0 /* skip_saddr_rewrite */);
	}
      return nat_6t_flow_icmp_translate (vm, sm, b, ip, f);
    }

  nat_6t_flow_ip4_translate (sm, b, ip, f, proto, 0 /* is_icmp_inner_ip4 */,
			     0 /* skip_saddr_rewrite */);

  return NAT_ED_TRNSL_ERR_SUCCESS;
}

nat_translation_error_e
nat_6t_flow_buf_translate_i2o (vlib_main_t *vm, snat_main_t *sm,
			       vlib_buffer_t *b, ip4_header_t *ip,
			       nat_6t_flow_t *f, ip_protocol_t proto,
			       int is_output_feature)
{
  return nat_6t_flow_buf_translate (vm, sm, b, ip, f, proto, is_output_feature,
				    1 /* is_i2o */);
}

nat_translation_error_e
nat_6t_flow_buf_translate_o2i (vlib_main_t *vm, snat_main_t *sm,
			       vlib_buffer_t *b, ip4_header_t *ip,
			       nat_6t_flow_t *f, ip_protocol_t proto,
			       int is_output_feature)
{
  return nat_6t_flow_buf_translate (vm, sm, b, ip, f, proto, is_output_feature,
				    0 /* is_i2o */);
}

u8 *
format_nat_6t (u8 *s, va_list *args)
{
  nat_6t_t *t = va_arg (*args, nat_6t_t *);

  s = format (s, "saddr %U sport %u daddr %U dport %u proto %U fib_idx %u",
	      format_ip4_address, t->saddr.as_u8,
	      clib_net_to_host_u16 (t->sport), format_ip4_address,
	      t->daddr.as_u8, clib_net_to_host_u16 (t->dport),
	      format_ip_protocol, t->proto, t->fib_index);
  return s;
}

u8 *
format_nat_ed_translation_error (u8 *s, va_list *args)
{
  nat_translation_error_e e = va_arg (*args, nat_translation_error_e);

  switch (e)
    {
    case NAT_ED_TRNSL_ERR_SUCCESS:
      s = format (s, "success");
      break;
    case NAT_ED_TRNSL_ERR_TRANSLATION_FAILED:
      s = format (s, "translation-failed");
      break;
    case NAT_ED_TRNSL_ERR_FLOW_MISMATCH:
      s = format (s, "flow-mismatch");
      break;
    case NAT_ED_TRNSL_ERR_PACKET_TRUNCATED:
      s = format (s, "packet-truncated");
      break;
    case NAT_ED_TRNSL_ERR_INNER_IP_CORRUPT:
      s = format (s, "inner-ip-corrupted");
      break;
    case NAT_ED_TRNSL_ERR_INVALID_CSUM:
      s = format (s, "invalid-checksum");
      break;
    }
  return s;
}

u8 *
format_nat_6t_flow (u8 *s, va_list *args)
{
  nat_6t_flow_t *f = va_arg (*args, nat_6t_flow_t *);

  s = format (s, "match: %U ", format_nat_6t, &f->match);
  int r = 0;
  if (f->ops & NAT_FLOW_OP_SADDR_REWRITE)
    {
      s = format (s, "rewrite: saddr %U ", format_ip4_address,
		  f->rewrite.saddr.as_u8);
      r = 1;
    }
  if (f->ops & NAT_FLOW_OP_SPORT_REWRITE)
    {
      if (!r)
	{
	  s = format (s, "rewrite: ");
	  r = 1;
	}
      s = format (s, "sport %u ", clib_net_to_host_u16 (f->rewrite.sport));
    }
  if (f->ops & NAT_FLOW_OP_DADDR_REWRITE)
    {
      if (!r)
	{
	  s = format (s, "rewrite: ");
	  r = 1;
	}
      s = format (s, "daddr %U ", format_ip4_address, f->rewrite.daddr.as_u8);
    }
  if (f->ops & NAT_FLOW_OP_DPORT_REWRITE)
    {
      if (!r)
	{
	  s = format (s, "rewrite: ");
	  r = 1;
	}
      s = format (s, "dport %u ", clib_net_to_host_u16 (f->rewrite.dport));
    }
  if (f->ops & NAT_FLOW_OP_ICMP_ID_REWRITE)
    {
      if (!r)
	{
	  s = format (s, "rewrite: ");
	  r = 1;
	}
      s = format (s, "icmp-id %u ", clib_net_to_host_u16 (f->rewrite.icmp_id));
    }
  if (f->ops & NAT_FLOW_OP_TXFIB_REWRITE)
    {
      if (!r)
	{
	  s = format (s, "rewrite: ");
	  r = 1;
	}
      s = format (s, "txfib %u ", f->rewrite.fib_index);
    }
  return s;
}

static inline void
nat_syslog_nat44_sess (u32 ssubix, u32 sfibix, ip4_address_t *isaddr,
		       u16 isport, ip4_address_t *xsaddr, u16 xsport,
		       ip4_address_t *idaddr, u16 idport,
		       ip4_address_t *xdaddr, u16 xdport, u8 proto, u8 is_add,
		       u8 is_twicenat)
{
  syslog_msg_t syslog_msg;
  fib_table_t *fib;

  if (!syslog_is_enabled ())
    return;

  if (syslog_severity_filter_block (SADD_SDEL_SEVERITY))
    return;

  fib = fib_table_get (sfibix, FIB_PROTOCOL_IP4);

  syslog_msg_init (&syslog_msg, NAT_FACILITY, SADD_SDEL_SEVERITY, NAT_APPNAME,
		   is_add ? SADD_MSGID : SDEL_MSGID);

  syslog_msg_sd_init (&syslog_msg, NSESS_SDID);
  syslog_msg_add_sd_param (&syslog_msg, SSUBIX_SDPARAM_NAME, "%d", ssubix);
  syslog_msg_add_sd_param (&syslog_msg, SVLAN_SDPARAM_NAME, "%d",
			   fib->ft_table_id);
  syslog_msg_add_sd_param (&syslog_msg, IATYP_SDPARAM_NAME, IATYP_IPV4);
  syslog_msg_add_sd_param (&syslog_msg, ISADDR_SDPARAM_NAME, "%U",
			   format_ip4_address, isaddr);
  syslog_msg_add_sd_param (&syslog_msg, ISPORT_SDPARAM_NAME, "%d",
			   clib_net_to_host_u16 (isport));
  syslog_msg_add_sd_param (&syslog_msg, XATYP_SDPARAM_NAME, IATYP_IPV4);
  syslog_msg_add_sd_param (&syslog_msg, XSADDR_SDPARAM_NAME, "%U",
			   format_ip4_address, xsaddr);
  syslog_msg_add_sd_param (&syslog_msg, XSPORT_SDPARAM_NAME, "%d",
			   clib_net_to_host_u16 (xsport));
  syslog_msg_add_sd_param (&syslog_msg, PROTO_SDPARAM_NAME, "%d", proto);
  syslog_msg_add_sd_param (&syslog_msg, XDADDR_SDPARAM_NAME, "%U",
			   format_ip4_address, xdaddr);
  syslog_msg_add_sd_param (&syslog_msg, XDPORT_SDPARAM_NAME, "%d",
			   clib_net_to_host_u16 (xdport));
  if (is_twicenat)
    {
      syslog_msg_add_sd_param (&syslog_msg, IDADDR_SDPARAM_NAME, "%U",
			       format_ip4_address, idaddr);
      syslog_msg_add_sd_param (&syslog_msg, IDPORT_SDPARAM_NAME, "%d",
			       clib_net_to_host_u16 (idport));
    }

  syslog_msg_send (&syslog_msg);
}

void
nat_syslog_nat44_sadd (u32 ssubix, u32 sfibix, ip4_address_t *isaddr,
		       u16 isport, ip4_address_t *idaddr, u16 idport,
		       ip4_address_t *xsaddr, u16 xsport,
		       ip4_address_t *xdaddr, u16 xdport, u8 proto,
		       u8 is_twicenat)
{
  nat_syslog_nat44_sess (ssubix, sfibix, isaddr, isport, xsaddr, xsport,
			 idaddr, idport, xdaddr, xdport, proto, 1,
			 is_twicenat);
}

void
nat_syslog_nat44_sdel (u32 ssubix, u32 sfibix, ip4_address_t *isaddr,
		       u16 isport, ip4_address_t *idaddr, u16 idport,
		       ip4_address_t *xsaddr, u16 xsport,
		       ip4_address_t *xdaddr, u16 xdport, u8 proto,
		       u8 is_twicenat)
{
  nat_syslog_nat44_sess (ssubix, sfibix, isaddr, isport, xsaddr, xsport,
			 idaddr, idport, xdaddr, xdport, proto, 0,
			 is_twicenat);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
