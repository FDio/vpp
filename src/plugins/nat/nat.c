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
#include <nat/nat_ipfix_logging.h>
#include <nat/nat_det.h>
#include <nat/nat64.h>
#include <nat/dslite.h>
#include <nat/nat_reass.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>

#include <vpp/app/version.h>

snat_main_t snat_main;


/* Hook up input features */
VNET_FEATURE_INIT (ip4_snat_in2out, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-in2out",
  .runs_before = VNET_FEATURES ("nat44-out2in"),
};
VNET_FEATURE_INIT (ip4_snat_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-out2in",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
VNET_FEATURE_INIT (ip4_nat_classify, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-classify",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
VNET_FEATURE_INIT (ip4_snat_det_in2out, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-det-in2out",
  .runs_before = VNET_FEATURES ("nat44-det-out2in"),
};
VNET_FEATURE_INIT (ip4_snat_det_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-det-out2in",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
VNET_FEATURE_INIT (ip4_nat_det_classify, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-det-classify",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
VNET_FEATURE_INIT (ip4_snat_in2out_worker_handoff, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-in2out-worker-handoff",
  .runs_before = VNET_FEATURES ("nat44-out2in-worker-handoff"),
};
VNET_FEATURE_INIT (ip4_snat_out2in_worker_handoff, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-out2in-worker-handoff",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
VNET_FEATURE_INIT (ip4_nat_handoff_classify, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-handoff-classify",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
VNET_FEATURE_INIT (ip4_snat_in2out_fast, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-in2out-fast",
  .runs_before = VNET_FEATURES ("nat44-out2in-fast"),
};
VNET_FEATURE_INIT (ip4_snat_out2in_fast, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-out2in-fast",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
VNET_FEATURE_INIT (ip4_snat_hairpin_dst, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat44-hairpin-dst",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

/* Hook up output features */
VNET_FEATURE_INIT (ip4_snat_in2out_output, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-in2out-output",
  .runs_before = VNET_FEATURES ("interface-output"),
};
VNET_FEATURE_INIT (ip4_snat_in2out_output_worker_handoff, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-in2out-output-worker-handoff",
  .runs_before = VNET_FEATURES ("interface-output"),
};
VNET_FEATURE_INIT (ip4_snat_hairpin_src, static) = {
  .arc_name = "ip4-output",
  .node_name = "nat44-hairpin-src",
  .runs_before = VNET_FEATURES ("interface-output"),
};

/* Hook up ip4-local features */
VNET_FEATURE_INIT (ip4_nat_hairpinning, static) =
{
  .arc_name = "ip4-local",
  .node_name = "nat44-hairpinning",
  .runs_before = VNET_FEATURES("ip4-local-end-of-arc"),
};


/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Network Address Translation",
};
/* *INDENT-ON* */

vlib_node_registration_t nat44_classify_node;
vlib_node_registration_t nat44_det_classify_node;
vlib_node_registration_t nat44_handoff_classify_node;

typedef enum {
  NAT44_CLASSIFY_NEXT_IN2OUT,
  NAT44_CLASSIFY_NEXT_OUT2IN,
  NAT44_CLASSIFY_N_NEXT,
} nat44_classify_next_t;

static inline uword
nat44_classify_node_fn_inline (vlib_main_t * vm,
                               vlib_node_runtime_t * node,
                               vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  nat44_classify_next_t next_index;
  snat_main_t *sm = &snat_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t *b0;
          u32 next0 = NAT44_CLASSIFY_NEXT_IN2OUT;
          ip4_header_t *ip0;
          snat_address_t *ap;
          snat_session_key_t m_key0;
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

          vec_foreach (ap, sm->addresses)
            {
              if (ip0->dst_address.as_u32 == ap->addr.as_u32)
                {
                  next0 = NAT44_CLASSIFY_NEXT_OUT2IN;
                  break;
                }
            }

          if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
            {
              m_key0.addr = ip0->dst_address;
              m_key0.port = 0;
              m_key0.protocol = 0;
              m_key0.fib_index = sm->outside_fib_index;
              kv0.key = m_key0.as_u64;
              if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv0, &value0))
                {
                  next0 = NAT44_CLASSIFY_NEXT_OUT2IN;
                }
            }
          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
nat44_classify_node_fn (vlib_main_t * vm,
                        vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
  return nat44_classify_node_fn_inline (vm, node, frame);
};

VLIB_REGISTER_NODE (nat44_classify_node) = {
  .function = nat44_classify_node_fn,
  .name = "nat44-classify",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = NAT44_CLASSIFY_N_NEXT,
  .next_nodes = {
    [NAT44_CLASSIFY_NEXT_IN2OUT] = "nat44-in2out",
    [NAT44_CLASSIFY_NEXT_OUT2IN] = "nat44-out2in",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (nat44_classify_node,
                              nat44_classify_node_fn);

static uword
nat44_det_classify_node_fn (vlib_main_t * vm,
                            vlib_node_runtime_t * node,
                            vlib_frame_t * frame)
{
  return nat44_classify_node_fn_inline (vm, node, frame);
};

VLIB_REGISTER_NODE (nat44_det_classify_node) = {
  .function = nat44_det_classify_node_fn,
  .name = "nat44-det-classify",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = NAT44_CLASSIFY_N_NEXT,
  .next_nodes = {
    [NAT44_CLASSIFY_NEXT_IN2OUT] = "nat44-det-in2out",
    [NAT44_CLASSIFY_NEXT_OUT2IN] = "nat44-det-out2in",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (nat44_det_classify_node,
                              nat44_det_classify_node_fn);

static uword
nat44_handoff_classify_node_fn (vlib_main_t * vm,
                                vlib_node_runtime_t * node,
                                vlib_frame_t * frame)
{
  return nat44_classify_node_fn_inline (vm, node, frame);
};

VLIB_REGISTER_NODE (nat44_handoff_classify_node) = {
  .function = nat44_handoff_classify_node_fn,
  .name = "nat44-handoff-classify",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = NAT44_CLASSIFY_N_NEXT,
  .next_nodes = {
    [NAT44_CLASSIFY_NEXT_IN2OUT] = "nat44-in2out-worker-handoff",
    [NAT44_CLASSIFY_NEXT_OUT2IN] = "nat44-out2in-worker-handoff",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (nat44_handoff_classify_node,
                              nat44_handoff_classify_node_fn);

/**
 * @brief Add/del NAT address to FIB.
 *
 * Add the external NAT address to the FIB as receive entries. This ensures
 * that VPP will reply to ARP for this address and we don't need to enable
 * proxy ARP on the outside interface.
 *
 * @param addr IPv4 address.
 * @param plen address prefix length
 * @param sw_if_index Interface.
 * @param is_add If 0 delete, otherwise add.
 */
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
  u32 fib_index = ip4_fib_table_get_index_for_sw_if_index(sw_if_index);

  if (is_add)
    fib_table_entry_update_one_path(fib_index,
                                    &prefix,
                                    FIB_SOURCE_PLUGIN_HI,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_LOCAL |
                                     FIB_ENTRY_FLAG_EXCLUSIVE),
                                    DPO_PROTO_IP4,
                                    NULL,
                                    sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
  else
    fib_table_entry_delete(fib_index,
                           &prefix,
                           FIB_SOURCE_PLUGIN_HI);
}

void snat_add_address (snat_main_t *sm, ip4_address_t *addr, u32 vrf_id)
{
  snat_address_t * ap;
  snat_interface_t *i;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  if (vrf_id != ~0)
    sm->vrf_mode = 1;

  /* Check if address already exists */
  vec_foreach (ap, sm->addresses)
    {
      if (ap->addr.as_u32 == addr->as_u32)
        return;
    }

  vec_add2 (sm->addresses, ap, 1);
  ap->addr = *addr;
  if (vrf_id != ~0)
    ap->fib_index =
      fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id,
                                         FIB_SOURCE_PLUGIN_HI);
  else
    ap->fib_index = ~0;
#define _(N, i, n, s) \
  clib_bitmap_alloc (ap->busy_##n##_port_bitmap, 65535); \
  ap->busy_##n##_ports = 0; \
  vec_validate_init_empty (ap->busy_##n##_ports_per_thread, tm->n_vlib_mains - 1, 0);
  foreach_snat_protocol
#undef _

  /* Add external address to FIB */
  pool_foreach (i, sm->interfaces,
  ({
    if (nat_interface_is_inside(i))
      continue;

    snat_add_del_addr_to_fib(addr, 32, i->sw_if_index, 1);
    break;
  }));
  pool_foreach (i, sm->output_feature_interfaces,
  ({
    if (nat_interface_is_inside(i))
      continue;

    snat_add_del_addr_to_fib(addr, 32, i->sw_if_index, 1);
    break;
  }));
}

static int is_snat_address_used_in_static_mapping (snat_main_t *sm,
                                                   ip4_address_t addr)
{
  snat_static_mapping_t *m;
  pool_foreach (m, sm->static_mappings,
  ({
      if (m->external_addr.as_u32 == addr.as_u32)
        return 1;
  }));

  return 0;
}

void increment_v4_address (ip4_address_t * a)
{
  u32 v;

  v = clib_net_to_host_u32(a->as_u32) + 1;
  a->as_u32 = clib_host_to_net_u32(v);
}

static void
snat_add_static_mapping_when_resolved (snat_main_t * sm,
                                       ip4_address_t l_addr,
                                       u16 l_port,
                                       u32 sw_if_index,
                                       u16 e_port,
                                       u32 vrf_id,
                                       snat_protocol_t proto,
                                       int addr_only,
                                       int is_add)
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
}

/**
 * @brief Add static mapping.
 *
 * Create static mapping between local addr+port and external addr+port.
 *
 * @param l_addr Local IPv4 address.
 * @param e_addr External IPv4 address.
 * @param l_port Local port number.
 * @param e_port External port number.
 * @param vrf_id VRF ID.
 * @param addr_only If 0 address port and pair mapping, otherwise address only.
 * @param sw_if_index External port instead of specific IP address.
 * @param is_add If 0 delete static mapping, otherwise add.
 *
 * @returns
 */
int snat_add_static_mapping(ip4_address_t l_addr, ip4_address_t e_addr,
                            u16 l_port, u16 e_port, u32 vrf_id, int addr_only,
                            u32 sw_if_index, snat_protocol_t proto, int is_add)
{
  snat_main_t * sm = &snat_main;
  snat_static_mapping_t *m;
  snat_session_key_t m_key;
  clib_bihash_kv_8_8_t kv, value;
  snat_address_t *a = 0;
  u32 fib_index = ~0;
  uword * p;
  snat_interface_t *interface;
  int i;

  /* If the external address is a specific interface address */
  if (sw_if_index != ~0)
    {
      ip4_address_t * first_int_addr;

      /* Might be already set... */
      first_int_addr = ip4_interface_first_address
        (sm->ip4_main, sw_if_index, 0 /* just want the address*/);

      /* DHCP resolution required? */
      if (first_int_addr == 0)
        {
          snat_add_static_mapping_when_resolved
            (sm, l_addr, l_port, sw_if_index, e_port, vrf_id, proto,
             addr_only,  is_add);
          return 0;
        }
        else
          e_addr.as_u32 = first_int_addr->as_u32;
    }

  m_key.addr = e_addr;
  m_key.port = addr_only ? 0 : e_port;
  m_key.protocol = addr_only ? 0 : proto;
  m_key.fib_index = sm->outside_fib_index;
  kv.key = m_key.as_u64;
  if (clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
    m = 0;
  else
    m = pool_elt_at_index (sm->static_mappings, value.value);

  if (is_add)
    {
      if (m)
        return VNET_API_ERROR_VALUE_EXIST;

      /* Convert VRF id to FIB index */
      if (vrf_id != ~0)
        {
          p = hash_get (sm->ip4_main->fib_index_by_table_id, vrf_id);
          if (!p)
            return VNET_API_ERROR_NO_SUCH_FIB;
          fib_index = p[0];
        }
      /* If not specified use inside VRF id from SNAT plugin startup config */
      else
        {
          fib_index = sm->inside_fib_index;
          vrf_id = sm->inside_vrf_id;
        }

      /* Find external address in allocated addresses and reserve port for
         address and port pair mapping when dynamic translations enabled */
      if (!addr_only && !(sm->static_mapping_only))
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
                          a->busy_##n##_ports_per_thread[(e_port - 1024) / sm->port_per_thread]++; \
                        } \
                      break;
                      foreach_snat_protocol
#undef _
                    default:
                      clib_warning("unknown_protocol");
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
      m->local_addr = l_addr;
      m->external_addr = e_addr;
      m->addr_only = addr_only;
      m->vrf_id = vrf_id;
      m->fib_index = fib_index;
      if (!addr_only)
        {
          m->local_port = l_port;
          m->external_port = e_port;
          m->proto = proto;
        }

      m_key.addr = m->local_addr;
      m_key.port = m->local_port;
      m_key.protocol = m->proto;
      m_key.fib_index = m->fib_index;
      kv.key = m_key.as_u64;
      kv.value = m - sm->static_mappings;
      clib_bihash_add_del_8_8(&sm->static_mapping_by_local, &kv, 1);

      m_key.addr = m->external_addr;
      m_key.port = m->external_port;
      m_key.fib_index = sm->outside_fib_index;
      kv.key = m_key.as_u64;
      kv.value = m - sm->static_mappings;
      clib_bihash_add_del_8_8(&sm->static_mapping_by_external, &kv, 1);

      if (sm->workers)
        {
          ip4_header_t ip = {
            .src_address = m->local_addr,
          };
          m->worker_index = sm->worker_in2out_cb (&ip, m->fib_index);
        }
    }
  else
    {
      if (!m)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      /* Free external address port */
      if (!addr_only && !(sm->static_mapping_only))
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
                          a->busy_##n##_ports_per_thread[(e_port - 1024) / sm->port_per_thread]--; \
                        } \
                      break;
                      foreach_snat_protocol
#undef _
                    default:
                      clib_warning("unknown_protocol");
                      return VNET_API_ERROR_INVALID_VALUE_2;
                    }
                  break;
                }
            }
        }

      m_key.addr = m->local_addr;
      m_key.port = m->local_port;
      m_key.protocol = m->proto;
      m_key.fib_index = m->fib_index;
      kv.key = m_key.as_u64;
      clib_bihash_add_del_8_8(&sm->static_mapping_by_local, &kv, 0);

      m_key.addr = m->external_addr;
      m_key.port = m->external_port;
      m_key.fib_index = sm->outside_fib_index;
      kv.key = m_key.as_u64;
      clib_bihash_add_del_8_8(&sm->static_mapping_by_external, &kv, 0);

      /* Delete session(s) for static mapping if exist */
      if (!(sm->static_mapping_only) ||
          (sm->static_mapping_only && sm->static_mapping_connection_tracking))
        {
          snat_user_key_t u_key;
          snat_user_t *u;
          dlist_elt_t * head, * elt;
          u32 elt_index, head_index, del_elt_index;
          u32 ses_index;
          u64 user_index;
          snat_session_t * s;
          snat_main_per_thread_data_t *tsm;

          u_key.addr = m->local_addr;
          u_key.fib_index = m->fib_index;
          kv.key = u_key.as_u64;
          if (sm->num_workers > 1)
            tsm = vec_elt_at_index (sm->per_thread_data, m->worker_index);
          else
            tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);
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
                      s =  pool_elt_at_index (tsm->sessions, ses_index);
                      del_elt_index = elt_index;
                      elt_index = elt->next;
                      elt = pool_elt_at_index (tsm->list_pool, elt_index);
                      ses_index = elt->value;

                      if (!addr_only)
                        {
                          if ((s->out2in.addr.as_u32 != e_addr.as_u32) &&
                              (clib_net_to_host_u16 (s->out2in.port) != e_port))
                            continue;
                        }

                      if (snat_is_unk_proto_session (s))
                        {
                          clib_bihash_kv_16_8_t up_kv;
                          nat_ed_ses_key_t up_key;
                          up_key.l_addr = s->in2out.addr;
                          up_key.r_addr = s->ext_host_addr;
                          up_key.fib_index = s->in2out.fib_index;
                          up_key.proto = s->in2out.port;
                          up_key.rsvd = 0;
                          up_key.l_port = 0;
                          up_kv.key[0] = up_key.as_u64[0];
                          up_kv.key[1] = up_key.as_u64[1];
                          if (clib_bihash_add_del_16_8 (&sm->in2out_ed,
                                                        &up_kv, 0))
                            clib_warning ("in2out key del failed");

                          up_key.l_addr = s->out2in.addr;
                          up_key.fib_index = s->out2in.fib_index;
                          up_kv.key[0] = up_key.as_u64[0];
                          up_kv.key[1] = up_key.as_u64[1];
                          if (clib_bihash_add_del_16_8 (&sm->out2in_ed,
                                                        &up_kv, 0))
                            clib_warning ("out2in key del failed");

                          goto delete;
                        }
                      /* log NAT event */
                      snat_ipfix_logging_nat44_ses_delete(s->in2out.addr.as_u32,
                                                          s->out2in.addr.as_u32,
                                                          s->in2out.protocol,
                                                          s->in2out.port,
                                                          s->out2in.port,
                                                          s->in2out.fib_index);

                      value.key = s->in2out.as_u64;
                      if (clib_bihash_add_del_8_8 (&tsm->in2out, &value, 0))
                        clib_warning ("in2out key del failed");
                      value.key = s->out2in.as_u64;
                      if (clib_bihash_add_del_8_8 (&tsm->out2in, &value, 0))
                        clib_warning ("out2in key del failed");
delete:
                      pool_put (tsm->sessions, s);

                      clib_dlist_remove (tsm->list_pool, del_elt_index);
                      pool_put_index (tsm->list_pool, del_elt_index);
                      u->nstaticsessions--;

                      if (!addr_only)
                        break;
                    }
                  if (addr_only)
                    {
                      pool_put (tsm->users, u);
                      clib_bihash_add_del_8_8 (&tsm->user_hash, &kv, 0);
                    }
                }
            }
        }

      /* Delete static mapping from pool */
      pool_put (sm->static_mappings, m);
    }

  if (!addr_only)
    return 0;

  /* Add/delete external address to FIB */
  pool_foreach (interface, sm->interfaces,
  ({
    if (nat_interface_is_inside(interface))
      continue;

    snat_add_del_addr_to_fib(&e_addr, 32, interface->sw_if_index, is_add);
    break;
  }));
  pool_foreach (interface, sm->output_feature_interfaces,
  ({
    if (nat_interface_is_inside(interface))
      continue;

    snat_add_del_addr_to_fib(&e_addr, 32, interface->sw_if_index, is_add);
    break;
  }));

  return 0;
}

int nat44_add_del_lb_static_mapping (ip4_address_t e_addr, u16 e_port,
                                     snat_protocol_t proto, u32 vrf_id,
                                     nat44_lb_addr_port_t *locals, u8 is_add)
{
  snat_main_t * sm = &snat_main;
  snat_static_mapping_t *m;
  snat_session_key_t m_key;
  clib_bihash_kv_8_8_t kv, value;
  u32 fib_index;
  snat_address_t *a = 0;
  int i;
  nat44_lb_addr_port_t *local;
  u32 worker_index = 0;
  snat_main_per_thread_data_t *tsm;

  m_key.addr = e_addr;
  m_key.port = e_port;
  m_key.protocol = proto;
  m_key.fib_index = sm->outside_fib_index;
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

      fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
                                                     vrf_id,
                                                     FIB_SOURCE_PLUGIN_HI);

      /* Find external address in allocated addresses and reserve port for
         address and port pair mapping when dynamic translations enabled */
      if (!sm->static_mapping_only)
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
                          a->busy_##n##_ports_per_thread[(e_port - 1024) / sm->port_per_thread]++; \
                        } \
                      break;
                      foreach_snat_protocol
#undef _
                    default:
                      clib_warning("unknown_protocol");
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
      m->external_addr = e_addr;
      m->addr_only = 0;
      m->vrf_id = vrf_id;
      m->fib_index = fib_index;
      m->external_port = e_port;
      m->proto = proto;

      m_key.addr = m->external_addr;
      m_key.port = m->external_port;
      m_key.protocol = m->proto;
      m_key.fib_index = sm->outside_fib_index;
      kv.key = m_key.as_u64;
      kv.value = m - sm->static_mappings;
      if (clib_bihash_add_del_8_8(&sm->static_mapping_by_external, &kv, 1))
        {
          clib_warning ("static_mapping_by_external key add failed");
          return VNET_API_ERROR_UNSPECIFIED;
        }

      /* Assign worker */
      if (sm->workers)
        {
          worker_index = sm->first_worker_index +
            sm->workers[sm->next_worker++ % vec_len (sm->workers)];
          tsm = vec_elt_at_index (sm->per_thread_data, worker_index);
          m->worker_index = worker_index;
        }
      else
        tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

      m_key.port = clib_host_to_net_u16 (m->external_port);
      kv.key = m_key.as_u64;
      kv.value = ~0ULL;
      if (clib_bihash_add_del_8_8(&tsm->out2in, &kv, 1))
        {
          clib_warning ("static_mapping_by_local key add failed");
          return VNET_API_ERROR_UNSPECIFIED;
        }

      m_key.fib_index = m->fib_index;
      for (i = 0; i < vec_len (locals); i++)
        {
          m_key.addr = locals[i].addr;
          m_key.port = locals[i].port;
          kv.key = m_key.as_u64;
          kv.value = m - sm->static_mappings;
          clib_bihash_add_del_8_8(&sm->static_mapping_by_local, &kv, 1);
          locals[i].prefix = (i == 0) ? locals[i].probability :\
            (locals[i - 1].prefix + locals[i].probability);
          vec_add1 (m->locals, locals[i]);

          m_key.port = clib_host_to_net_u16 (locals[i].port);
          kv.key = m_key.as_u64;
          kv.value = ~0ULL;
          if (clib_bihash_add_del_8_8(&tsm->in2out, &kv, 1))
            {
              clib_warning ("in2out key add failed");
              return VNET_API_ERROR_UNSPECIFIED;
            }
        }
    }
  else
    {
      if (!m)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

      fib_table_unlock (m->fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_PLUGIN_HI);

      /* Free external address port */
      if (!sm->static_mapping_only)
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
                          a->busy_##n##_ports_per_thread[(e_port - 1024) / sm->port_per_thread]--; \
                        } \
                      break;
                      foreach_snat_protocol
#undef _
                    default:
                      clib_warning("unknown_protocol");
                      return VNET_API_ERROR_INVALID_VALUE_2;
                    }
                  break;
                }
            }
        }

      tsm = vec_elt_at_index (sm->per_thread_data, m->worker_index);
      m_key.addr = m->external_addr;
      m_key.port = m->external_port;
      m_key.protocol = m->proto;
      m_key.fib_index = sm->outside_fib_index;
      kv.key = m_key.as_u64;
      if (clib_bihash_add_del_8_8(&sm->static_mapping_by_external, &kv, 0))
        {
          clib_warning ("static_mapping_by_external key del failed");
          return VNET_API_ERROR_UNSPECIFIED;
        }

      m_key.port = clib_host_to_net_u16 (m->external_port);
      kv.key = m_key.as_u64;
      if (clib_bihash_add_del_8_8(&tsm->out2in, &kv, 0))
        {
          clib_warning ("outi2in key del failed");
          return VNET_API_ERROR_UNSPECIFIED;
        }

      vec_foreach (local, m->locals)
        {
          m_key.addr = local->addr;
          m_key.port = local->port;
          m_key.fib_index = m->fib_index;
          kv.key = m_key.as_u64;
          if (clib_bihash_add_del_8_8(&sm->static_mapping_by_local, &kv, 0))
            {
              clib_warning ("static_mapping_by_local key del failed");
              return VNET_API_ERROR_UNSPECIFIED;
            }

          m_key.port = clib_host_to_net_u16 (local->port);
          kv.key = m_key.as_u64;
          if (clib_bihash_add_del_8_8(&tsm->in2out, &kv, 0))
            {
              clib_warning ("in2out key del failed");
              return VNET_API_ERROR_UNSPECIFIED;
            }
        }
      vec_free(m->locals);

      pool_put (sm->static_mappings, m);
    }

  return 0;
}

int snat_del_address (snat_main_t *sm, ip4_address_t addr, u8 delete_sm)
{
  snat_address_t *a = 0;
  snat_session_t *ses;
  u32 *ses_to_be_removed = 0, *ses_index;
  clib_bihash_kv_8_8_t kv, value;
  snat_user_key_t user_key;
  snat_user_t *u;
  snat_main_per_thread_data_t *tsm;
  snat_static_mapping_t *m;
  snat_interface_t *interface;
  int i;

  /* Find SNAT address */
  for (i=0; i < vec_len (sm->addresses); i++)
    {
      if (sm->addresses[i].addr.as_u32 == addr.as_u32)
        {
          a = sm->addresses + i;
          break;
        }
    }
  if (!a)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (delete_sm)
    {
      pool_foreach (m, sm->static_mappings,
      ({
          if (m->external_addr.as_u32 == addr.as_u32)
            (void) snat_add_static_mapping (m->local_addr, m->external_addr,
                                            m->local_port, m->external_port,
                                            m->vrf_id, m->addr_only, ~0,
                                            m->proto, 0);
      }));
    }
  else
    {
      /* Check if address is used in some static mapping */
      if (is_snat_address_used_in_static_mapping(sm, addr))
        {
          clib_warning ("address used in static mapping");
          return VNET_API_ERROR_UNSPECIFIED;
        }
    }

  if (a->fib_index != ~0)
    fib_table_unlock(a->fib_index, FIB_PROTOCOL_IP4,
                     FIB_SOURCE_PLUGIN_HI);

  /* Delete sessions using address */
  if (a->busy_tcp_ports || a->busy_udp_ports || a->busy_icmp_ports)
    {
      vec_foreach (tsm, sm->per_thread_data)
        {
          pool_foreach (ses, tsm->sessions, ({
            if (ses->out2in.addr.as_u32 == addr.as_u32)
              {
                if (snat_is_unk_proto_session (ses))
                  {
                    clib_bihash_kv_16_8_t up_kv;
                    nat_ed_ses_key_t up_key;
                    up_key.l_addr = ses->in2out.addr;
                    up_key.r_addr = ses->ext_host_addr;
                    up_key.fib_index = ses->in2out.fib_index;
                    up_key.proto = ses->in2out.port;
                    up_key.rsvd = 0;
                    up_key.l_port = 0;
                    up_kv.key[0] = up_key.as_u64[0];
                    up_kv.key[1] = up_key.as_u64[1];
                    if (clib_bihash_add_del_16_8 (&sm->in2out_ed,
                                                  &up_kv, 0))
                      clib_warning ("in2out key del failed");

                    up_key.l_addr = ses->out2in.addr;
                    up_key.fib_index = ses->out2in.fib_index;
                    up_kv.key[0] = up_key.as_u64[0];
                    up_kv.key[1] = up_key.as_u64[1];
                    if (clib_bihash_add_del_16_8 (&sm->out2in_ed,
                                                  &up_kv, 0))
                      clib_warning ("out2in key del failed");
                  }
                else
                  {
                    /* log NAT event */
                    snat_ipfix_logging_nat44_ses_delete(ses->in2out.addr.as_u32,
                                                        ses->out2in.addr.as_u32,
                                                        ses->in2out.protocol,
                                                        ses->in2out.port,
                                                        ses->out2in.port,
                                                        ses->in2out.fib_index);
                    kv.key = ses->in2out.as_u64;
                    clib_bihash_add_del_8_8 (&tsm->in2out, &kv, 0);
                    kv.key = ses->out2in.as_u64;
                    clib_bihash_add_del_8_8 (&tsm->out2in, &kv, 0);
                  }
                vec_add1 (ses_to_be_removed, ses - tsm->sessions);
                clib_dlist_remove (tsm->list_pool, ses->per_user_index);
                user_key.addr = ses->in2out.addr;
                user_key.fib_index = ses->in2out.fib_index;
                kv.key = user_key.as_u64;
                if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
                  {
                    u = pool_elt_at_index (tsm->users, value.value);
                    u->nsessions--;
                  }
              }
          }));

          vec_foreach (ses_index, ses_to_be_removed)
            pool_put_index (tsm->sessions, ses_index[0]);

          vec_free (ses_to_be_removed);
       }
    }

  vec_del1 (sm->addresses, i);

  /* Delete external address from FIB */
  pool_foreach (interface, sm->interfaces,
  ({
    if (nat_interface_is_inside(interface))
      continue;

    snat_add_del_addr_to_fib(&addr, 32, interface->sw_if_index, 0);
    break;
  }));
  pool_foreach (interface, sm->output_feature_interfaces,
  ({
    if (nat_interface_is_inside(interface))
      continue;

    snat_add_del_addr_to_fib(&addr, 32, interface->sw_if_index, 0);
    break;
  }));

  return 0;
}

int snat_interface_add_del (u32 sw_if_index, u8 is_inside, int is_del)
{
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;
  const char * feature_name, *del_feature_name;
  snat_address_t * ap;
  snat_static_mapping_t * m;
  snat_det_map_t * dm;

  if (sm->static_mapping_only && !(sm->static_mapping_connection_tracking))
    feature_name = is_inside ?  "nat44-in2out-fast" : "nat44-out2in-fast";
  else
    {
      if (sm->num_workers > 1 && !sm->deterministic)
        feature_name = is_inside ?  "nat44-in2out-worker-handoff" : "nat44-out2in-worker-handoff";
      else if (sm->deterministic)
        feature_name = is_inside ?  "nat44-det-in2out" : "nat44-det-out2in";
      else
        feature_name = is_inside ?  "nat44-in2out" : "nat44-out2in";
    }

  if (sm->fq_in2out_index == ~0 && !sm->deterministic && sm->num_workers > 1)
    sm->fq_in2out_index = vlib_frame_queue_main_init (sm->in2out_node_index, 0);

  if (sm->fq_out2in_index == ~0 && !sm->deterministic && sm->num_workers > 1)
    sm->fq_out2in_index = vlib_frame_queue_main_init (sm->out2in_node_index, 0);

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
                  del_feature_name = "nat44-handoff-classify";
                else if (sm->deterministic)
                  del_feature_name = "nat44-det-classify";
                else
                  del_feature_name = "nat44-classify";

                vnet_feature_enable_disable ("ip4-unicast", del_feature_name,
                                             sw_if_index, 0, 0, 0);
                vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                             sw_if_index, 1, 0, 0);
              }
            else
              {
                vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                             sw_if_index, 0, 0, 0);
                pool_put (sm->interfaces, i);
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
            else
              {
                del_feature_name = !is_inside ?  "nat44-in2out" : "nat44-out2in";
                feature_name = "nat44-classify";
              }

            vnet_feature_enable_disable ("ip4-unicast", del_feature_name,
                                         sw_if_index, 0, 0, 0);
            vnet_feature_enable_disable ("ip4-unicast", feature_name,
                                         sw_if_index, 1, 0, 0);
            goto set_flags;
          }

        goto fib;
      }
  }));

  if (is_del)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pool_get (sm->interfaces, i);
  i->sw_if_index = sw_if_index;
  i->flags = 0;
  vnet_feature_enable_disable ("ip4-unicast", feature_name, sw_if_index, 1, 0, 0);

set_flags:
  if (is_inside)
    i->flags |= NAT_INTERFACE_FLAG_IS_INSIDE;
  else
    i->flags |= NAT_INTERFACE_FLAG_IS_OUTSIDE;

  /* Add/delete external addresses to FIB */
fib:
  if (is_inside)
    {
      vnet_feature_enable_disable ("ip4-local", "nat44-hairpinning",
                                   sw_if_index, !is_del, 0, 0);
      return 0;
    }

  vec_foreach (ap, sm->addresses)
    snat_add_del_addr_to_fib(&ap->addr, 32, sw_if_index, !is_del);

  pool_foreach (m, sm->static_mappings,
  ({
    if (!(m->addr_only))
      continue;

    snat_add_del_addr_to_fib(&m->external_addr, 32, sw_if_index, !is_del);
  }));

  pool_foreach (dm, sm->det_maps,
  ({
    snat_add_del_addr_to_fib(&dm->out_addr, dm->out_plen, sw_if_index, !is_del);
  }));

  return 0;
}

int snat_interface_add_del_output_feature (u32 sw_if_index,
                                           u8 is_inside,
                                           int is_del)
{
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;
  snat_address_t * ap;
  snat_static_mapping_t * m;

  if (sm->deterministic ||
      (sm->static_mapping_only && !(sm->static_mapping_connection_tracking)))
    return VNET_API_ERROR_UNSUPPORTED;

  if (is_inside)
    {
      vnet_feature_enable_disable ("ip4-unicast", "nat44-hairpin-dst",
                                   sw_if_index, !is_del, 0, 0);
      vnet_feature_enable_disable ("ip4-output", "nat44-hairpin-src",
                                   sw_if_index, !is_del, 0, 0);
      goto fq;
    }

  if (sm->num_workers > 1)
    {
      vnet_feature_enable_disable ("ip4-unicast", "nat44-out2in-worker-handoff",
                                   sw_if_index, !is_del, 0, 0);
      vnet_feature_enable_disable ("ip4-output",
                                   "nat44-in2out-output-worker-handoff",
                                   sw_if_index, !is_del, 0, 0);
    }
  else
    {
      vnet_feature_enable_disable ("ip4-unicast", "nat44-out2in", sw_if_index,
                                   !is_del, 0, 0);
      vnet_feature_enable_disable ("ip4-output", "nat44-in2out-output",
                                   sw_if_index, !is_del, 0, 0);
    }

fq:
  if (sm->fq_in2out_output_index == ~0 && sm->num_workers > 1)
    sm->fq_in2out_output_index =
      vlib_frame_queue_main_init (sm->in2out_output_node_index, 0);

  if (sm->fq_out2in_index == ~0 && sm->num_workers > 1)
    sm->fq_out2in_index = vlib_frame_queue_main_init (sm->out2in_node_index, 0);

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

  vec_foreach (ap, sm->addresses)
    snat_add_del_addr_to_fib(&ap->addr, 32, sw_if_index, !is_del);

  pool_foreach (m, sm->static_mappings,
  ({
    if (!(m->addr_only))
      continue;

    snat_add_del_addr_to_fib(&m->external_addr, 32, sw_if_index, !is_del);
  }));

  return 0;
}

int snat_set_workers (uword * bitmap)
{
  snat_main_t *sm = &snat_main;
  int i, j = 0;

  if (sm->num_workers < 2)
    return VNET_API_ERROR_FEATURE_DISABLED;

  if (clib_bitmap_last_set (bitmap) >= sm->num_workers)
    return VNET_API_ERROR_INVALID_WORKER;

  vec_free (sm->workers);
  clib_bitmap_foreach (i, bitmap,
    ({
      vec_add1(sm->workers, i);
      sm->per_thread_data[i].snat_thread_index = j;
      j++;
    }));

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
                                       u32 if_address_index,
                                       u32 is_delete);

static clib_error_t * snat_init (vlib_main_t * vm)
{
  snat_main_t * sm = &snat_main;
  clib_error_t * error = 0;
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  uword *p;
  vlib_thread_registration_t *tr;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  uword *bitmap = 0;
  u32 i;
  ip4_add_del_interface_address_callback_t cb4;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main();
  sm->ip4_main = im;
  sm->ip4_lookup_main = lm;
  sm->api_main = &api_main;
  sm->first_worker_index = 0;
  sm->next_worker = 0;
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
      for (i=0; i < sm->num_workers; i++)
        bitmap = clib_bitmap_set (bitmap, i, 1);
      snat_set_workers(bitmap);
      clib_bitmap_free (bitmap);
    }
  else
    {
      sm->per_thread_data[0].snat_thread_index = 0;
    }

  error = snat_api_init(vm, sm);
  if (error)
    return error;

  /* Set up the interface address add/del callback */
  cb4.function = snat_ip4_add_del_interface_address_cb;
  cb4.function_opaque = 0;

  vec_add1 (im->add_del_interface_address_callbacks, cb4);

  /* Init IPFIX logging */
  snat_ipfix_logging_init(vm);

  /* Init NAT64 */
  error = nat64_init(vm);
  if (error)
    return error;

  dslite_init(vm);

  /* Init virtual fragmenentation reassembly */
  return nat_reass_init(vm);
}

VLIB_INIT_FUNCTION (snat_init);

void snat_free_outside_address_and_port (snat_address_t * addresses,
                                         u32 thread_index,
                                         snat_session_key_t * k,
                                         u32 address_index)
{
  snat_address_t *a;
  u16 port_host_byte_order = clib_net_to_host_u16 (k->port);

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
      clib_warning("unknown_protocol");
      return;
    }
}

/**
 * @brief Match NAT44 static mapping.
 *
 * @param sm          NAT main.
 * @param match       Address and port to match.
 * @param mapping     External or local address and port of the matched mapping.
 * @param by_external If 0 match by local address otherwise match by external
 *                    address.
 * @param is_addr_only If matched mapping is address only
 *
 * @returns 0 if match found otherwise 1.
 */
int snat_static_mapping_match (snat_main_t * sm,
                               snat_session_key_t match,
                               snat_session_key_t * mapping,
                               u8 by_external,
                               u8 *is_addr_only)
{
  clib_bihash_kv_8_8_t kv, value;
  snat_static_mapping_t *m;
  snat_session_key_t m_key;
  clib_bihash_8_8_t *mapping_hash = &sm->static_mapping_by_local;
  u32 rand, lo = 0, hi, mid;

  if (by_external)
    mapping_hash = &sm->static_mapping_by_external;

  m_key.addr = match.addr;
  m_key.port = clib_net_to_host_u16 (match.port);
  m_key.protocol = match.protocol;
  m_key.fib_index = match.fib_index;

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
      if (vec_len (m->locals))
        {
          hi = vec_len (m->locals) - 1;
          rand = 1 + (random_u32 (&sm->random_seed) % m->locals[hi].prefix);
          while (lo < hi)
            {
              mid = ((hi - lo) >> 1) + lo;
              (rand > m->locals[mid].prefix) ? (lo = mid + 1) : (hi = mid);
            }
          if (!(m->locals[lo].prefix >= rand))
            return 1;
          mapping->addr = m->locals[lo].addr;
          mapping->port = clib_host_to_net_u16 (m->locals[lo].port);
        }
      else
        {
          mapping->addr = m->local_addr;
          /* Address only mapping doesn't change port */
          mapping->port = m->addr_only ? match.port
            : clib_host_to_net_u16 (m->local_port);
        }
      mapping->fib_index = m->fib_index;
      mapping->protocol = m->proto;
    }
  else
    {
      mapping->addr = m->external_addr;
      /* Address only mapping doesn't change port */
      mapping->port = m->addr_only ? match.port
        : clib_host_to_net_u16 (m->external_port);
      mapping->fib_index = sm->outside_fib_index;
    }

  if (PREDICT_FALSE(is_addr_only != 0))
    *is_addr_only = m->addr_only;

  return 0;
}

static_always_inline u16
snat_random_port (u16 min, u16 max)
{
  snat_main_t *sm = &snat_main;
  return min + random_u32 (&sm->random_seed) /
    (random_u32_max() / (max - min + 1) + 1);
}

int snat_alloc_outside_address_and_port (snat_address_t * addresses,
                                         u32 fib_index,
                                         u32 thread_index,
                                         snat_session_key_t * k,
                                         u32 * address_indexp,
                                         u8 vrf_mode,
                                         u16 port_per_thread,
                                         u32 snat_thread_index)
{
  int i;
  snat_address_t *a;
  u32 portnum;

  for (i = 0; i < vec_len (addresses); i++)
    {
      a = addresses + i;
      if (vrf_mode && a->fib_index != ~0 && a->fib_index != fib_index)
        continue;
      switch (k->protocol)
        {
#define _(N, j, n, s) \
        case SNAT_PROTOCOL_##N: \
          if (a->busy_##n##_ports_per_thread[thread_index] < port_per_thread) \
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
                  *address_indexp = i; \
                  return 0; \
                } \
            } \
          break;
          foreach_snat_protocol
#undef _
        default:
          clib_warning("unknown protocol");
          return 1;
        }

    }
  /* Totally out of translations to use... */
  snat_ipfix_logging_addresses_exhausted(0);
  return 1;
}


static clib_error_t *
add_address_command_fn (vlib_main_t * vm,
                        unformat_input_t * input,
                        vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snat_main_t * sm = &snat_main;
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
      if (unformat (line_input, "%U - %U",
                    unformat_ip4_address, &start_addr,
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

  if (sm->static_mapping_only)
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
    clib_warning ("%U - %U, %d addresses...",
                  format_ip4_address, &start_addr,
                  format_ip4_address, &end_addr,
                  count);

  this_addr = start_addr;

  for (i = 0; i < count; i++)
    {
      if (is_add)
        snat_add_address (sm, &this_addr, vrf_id);
      else
        rv = snat_del_address (sm, this_addr, 0);

      switch (rv)
        {
        case VNET_API_ERROR_NO_SUCH_ENTRY:
          error = clib_error_return (0, "S-NAT address not exist.");
          goto done;
        case VNET_API_ERROR_UNSPECIFIED:
          error = clib_error_return (0, "S-NAT address used in static mapping.");
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

VLIB_CLI_COMMAND (add_address_command, static) = {
  .path = "nat44 add address",
  .short_help = "nat44 add address <ip4-range-start> [- <ip4-range-end>] "
                "[tenant-vrf <vrf-id>] [del]",
  .function = add_address_command_fn,
};

static clib_error_t *
snat_feature_command_fn (vlib_main_t * vm,
                          unformat_input_t * input,
                          vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 sw_if_index;
  u32 * inside_sw_if_indices = 0;
  u32 * outside_sw_if_indices = 0;
  u8 is_output_feature = 0;
  int is_del = 0;
  int i;

  sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

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
      for (i = 0; i < vec_len(inside_sw_if_indices); i++)
        {
          sw_if_index = inside_sw_if_indices[i];
          if (is_output_feature)
            {
              if (snat_interface_add_del_output_feature (sw_if_index, 1, is_del))
                {
                  error = clib_error_return (0, "%s %U failed",
                                             is_del ? "del" : "add",
                                             format_vnet_sw_interface_name, vnm,
                                             vnet_get_sw_interface (vnm,
                                                                    sw_if_index));
                  goto done;
                }
            }
          else
            {
              if (snat_interface_add_del (sw_if_index, 1, is_del))
                {
                  error = clib_error_return (0, "%s %U failed",
                                             is_del ? "del" : "add",
                                             format_vnet_sw_interface_name, vnm,
                                             vnet_get_sw_interface (vnm,
                                                                    sw_if_index));
                  goto done;
                }
            }
        }
    }

  if (vec_len (outside_sw_if_indices))
    {
      for (i = 0; i < vec_len(outside_sw_if_indices); i++)
        {
          sw_if_index = outside_sw_if_indices[i];
          if (is_output_feature)
            {
              if (snat_interface_add_del_output_feature (sw_if_index, 0, is_del))
                {
                  error = clib_error_return (0, "%s %U failed",
                                             is_del ? "del" : "add",
                                             format_vnet_sw_interface_name, vnm,
                                             vnet_get_sw_interface (vnm,
                                                                    sw_if_index));
                  goto done;
                }
            }
          else
            {
              if (snat_interface_add_del (sw_if_index, 0, is_del))
                {
                  error = clib_error_return (0, "%s %U failed",
                                             is_del ? "del" : "add",
                                             format_vnet_sw_interface_name, vnm,
                                             vnet_get_sw_interface (vnm,
                                                                    sw_if_index));
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

VLIB_CLI_COMMAND (set_interface_snat_command, static) = {
  .path = "set interface nat44",
  .function = snat_feature_command_fn,
  .short_help = "set interface nat44 in <intfc> out <intfc> [output-feature] "
                "[del]",
};

uword
unformat_snat_protocol (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(N, i, n, s) else if (unformat (input, s)) *r = SNAT_PROTOCOL_##N;
  foreach_snat_protocol
#undef _
  else
    return 0;
  return 1;
}

u8 *
format_snat_protocol (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(N, j, n, str) case SNAT_PROTOCOL_##N: t = (u8 *) str; break;
      foreach_snat_protocol
#undef _
    default:
      s = format (s, "unknown");
      return s;
    }
  s = format (s, "%s", t);
  return s;
}

static clib_error_t *
add_static_mapping_command_fn (vlib_main_t * vm,
                               unformat_input_t * input,
                               vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t * error = 0;
  ip4_address_t l_addr, e_addr;
  u32 l_port = 0, e_port = 0, vrf_id = ~0;
  int is_add = 1;
  int addr_only = 1;
  u32 sw_if_index = ~0;
  vnet_main_t * vnm = vnet_get_main();
  int rv;
  snat_protocol_t proto;
  u8 proto_set = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U %u", unformat_ip4_address, &l_addr,
                    &l_port))
        addr_only = 0;
      else if (unformat (line_input, "local %U", unformat_ip4_address, &l_addr))
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

      else if (unformat (line_input, "external %U",
                         unformat_vnet_sw_interface, vnm, &sw_if_index))
        ;
      else if (unformat (line_input, "vrf %u", &vrf_id))
        ;
      else if (unformat (line_input, "%U", unformat_snat_protocol, &proto))
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

  if (!addr_only && !proto_set)
    {
      error = clib_error_return (0, "missing protocol");
      goto done;
    }

  rv = snat_add_static_mapping(l_addr, e_addr, (u16) l_port, (u16) e_port,
                               vrf_id, addr_only, sw_if_index, proto, is_add);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "External port already in use.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      if (is_add)
        error = clib_error_return (0, "External addres must be allocated.");
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

/*?
 * @cliexpar
 * @cliexstart{snat add static mapping}
 * Static mapping allows hosts on the external network to initiate connection
 * to to the local network host.
 * To create static mapping between local host address 10.0.0.3 port 6303 and
 * external address 4.4.4.4 port 3606 for TCP protocol use:
 *  vpp# nat44 add static mapping tcp local 10.0.0.3 6303 external 4.4.4.4 3606
 * If not runnig "static mapping only" NAT plugin mode use before:
 *  vpp# nat44 add address 4.4.4.4
 * To create static mapping between local and external address use:
 *  vpp# nat44 add static mapping local 10.0.0.3 external 4.4.4.4
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_static_mapping_command, static) = {
  .path = "nat44 add static mapping",
  .function = add_static_mapping_command_fn,
  .short_help =
    "nat44 add static mapping tcp|udp|icmp local <addr> [<port>] external <addr> [<port>] [vrf <table-id>] [del]",
};

static clib_error_t *
add_lb_static_mapping_command_fn (vlib_main_t * vm,
                                  unformat_input_t * input,
                                  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t * error = 0;
  ip4_address_t l_addr, e_addr;
  u32 l_port = 0, e_port = 0, vrf_id = 0, probability = 0;
  int is_add = 1;
  int rv;
  snat_protocol_t proto;
  u8 proto_set = 0;
  nat44_lb_addr_port_t *locals = 0, local;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U:%u probability %u",
                    unformat_ip4_address, &l_addr, &l_port, &probability))
        {
          memset (&local, 0, sizeof (local));
          local.addr = l_addr;
          local.port = (u16) l_port;
          local.probability = (u8) probability;
          vec_add1 (locals, local);
        }
      else if (unformat (line_input, "external %U:%u", unformat_ip4_address,
                         &e_addr, &e_port))
        ;
      else if (unformat (line_input, "vrf %u", &vrf_id))
        ;
      else if (unformat (line_input, "protocol %U", unformat_snat_protocol,
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

  rv = nat44_add_del_lb_static_mapping (e_addr, (u16) e_port, proto, vrf_id,
                                        locals, is_add);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "External port already in use.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      if (is_add)
        error = clib_error_return (0, "External addres must be allocated.");
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

VLIB_CLI_COMMAND (add_lb_static_mapping_command, static) = {
  .path = "nat44 add load-balancing static mapping",
  .function = add_lb_static_mapping_command_fn,
  .short_help =
    "nat44 add load-balancing static mapping protocol tcp|udp external <addr>:<port> local <addr>:<port> probability <n> [vrf <table-id>] [del]",
};

static clib_error_t *
set_workers_command_fn (vlib_main_t * vm,
                        unformat_input_t * input,
                        vlib_cli_command_t * cmd)
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

  rv = snat_set_workers(bitmap);

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
  .short_help =
    "set nat workers <workers-list>",
};

static clib_error_t *
snat_ipfix_logging_enable_disable_command_fn (vlib_main_t * vm,
                                              unformat_input_t * input,
                                              vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 domain_id = 0;
  u32 src_port = 0;
  u8 enable = 1;
  int rv = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

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

  rv = snat_ipfix_logging_enable_disable (enable, domain_id, (u16) src_port);

  if (rv)
    {
      error = clib_error_return (0, "ipfix logging enable failed");
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

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
  .short_help = "nat ipfix logging [domain <domain-id>] [src-port <port>] [disable]",
};

static u32
snat_get_worker_in2out_cb (ip4_header_t * ip0, u32 rx_fib_index0)
{
  snat_main_t *sm = &snat_main;
  u32 next_worker_index = 0;
  u32 hash;

  next_worker_index = sm->first_worker_index;
  hash = ip0->src_address.as_u32 + (ip0->src_address.as_u32 >> 8) +
         (ip0->src_address.as_u32 >> 16) + (ip0->src_address.as_u32 >>24);

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
  nat_ed_ses_key_t key;
  clib_bihash_kv_16_8_t s_kv, s_value;
  snat_main_per_thread_data_t *tsm;
  snat_session_t *s;
  int i;
  u32 proto;

  /* first try static mappings without port */
  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
    {
      m_key.addr = ip0->dst_address;
      m_key.port = 0;
      m_key.protocol = 0;
      m_key.fib_index = rx_fib_index0;
      kv.key = m_key.as_u64;
      if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
        {
          m = pool_elt_at_index (sm->static_mappings, value.value);
          return m->worker_index;
        }
    }

  proto = ip_proto_to_snat_proto (ip0->protocol);
  udp = ip4_next_header (ip0);
  port = udp->dst_port;

  /* unknown protocol */
  if (PREDICT_FALSE (proto == ~0))
    {
      key.l_addr = ip0->dst_address;
      key.r_addr = ip0->src_address;
      key.fib_index = rx_fib_index0;
      key.proto = ip0->protocol;
      key.rsvd = 0;
      key.l_port = 0;
      s_kv.key[0] = key.as_u64[0];
      s_kv.key[1] = key.as_u64[1];

      if (!clib_bihash_search_16_8 (&sm->out2in_ed, &s_kv, &s_value))
        {
          for (i = 0; i < _vec_len (sm->per_thread_data); i++)
            {
              tsm = vec_elt_at_index (sm->per_thread_data, i);
              if (!pool_is_free_index(tsm->sessions, s_value.value))
                {
                  s = pool_elt_at_index (tsm->sessions, s_value.value);
                  if (s->out2in.addr.as_u32 == ip0->dst_address.as_u32 &&
                      s->out2in.port == ip0->protocol &&
                      snat_is_unk_proto_session (s))
                    return i;
                }
            }
         }

      /* if no session use current thread */
      return vlib_get_thread_index ();
    }

  if (PREDICT_FALSE (ip0->protocol == IP_PROTOCOL_ICMP))
    {
      icmp46_header_t * icmp = (icmp46_header_t *) udp;
      icmp_echo_header_t *echo = (icmp_echo_header_t *)(icmp + 1);
      if (!icmp_is_error_message (icmp))
        port = echo->identifier;
      else
        {
          ip4_header_t *inner_ip = (ip4_header_t *)(echo + 1);
          proto = ip_proto_to_snat_proto (inner_ip->protocol);
          void *l4_header = ip4_next_header (inner_ip);
          switch (proto)
            {
            case SNAT_PROTOCOL_ICMP:
              icmp = (icmp46_header_t*)l4_header;
              echo = (icmp_echo_header_t *)(icmp + 1);
              port = echo->identifier;
              break;
            case SNAT_PROTOCOL_UDP:
            case SNAT_PROTOCOL_TCP:
              port = ((tcp_udp_header_t*)l4_header)->src_port;
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
      if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
        {
          m = pool_elt_at_index (sm->static_mappings, value.value);
          return m->worker_index;
        }
    }

  /* worker by outside port */
  return (u32) ((clib_net_to_host_u16 (port) - 1024) / sm->port_per_thread);
}

static clib_error_t *
snat_config (vlib_main_t * vm, unformat_input_t * input)
{
  snat_main_t * sm = &snat_main;
  u32 translation_buckets = 1024;
  u32 translation_memory_size = 128<<20;
  u32 user_buckets = 128;
  u32 user_memory_size = 64<<20;
  u32 max_translations_per_user = 100;
  u32 outside_vrf_id = 0;
  u32 inside_vrf_id = 0;
  u32 static_mapping_buckets = 1024;
  u32 static_mapping_memory_size = 64<<20;
  u8 static_mapping_only = 0;
  u8 static_mapping_connection_tracking = 0;
  snat_main_per_thread_data_t *tsm;

  sm->deterministic = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "translation hash buckets %d", &translation_buckets))
        ;
      else if (unformat (input, "translation hash memory %d",
                         &translation_memory_size));
      else if (unformat (input, "user hash buckets %d", &user_buckets))
        ;
      else if (unformat (input, "user hash memory %d",
                         &user_memory_size))
        ;
      else if (unformat (input, "max translations per user %d",
                         &max_translations_per_user))
        ;
      else if (unformat (input, "outside VRF id %d",
                         &outside_vrf_id))
        ;
      else if (unformat (input, "inside VRF id %d",
                         &inside_vrf_id))
        ;
      else if (unformat (input, "static mapping only"))
        {
          static_mapping_only = 1;
          if (unformat (input, "connection tracking"))
            static_mapping_connection_tracking = 1;
        }
      else if (unformat (input, "deterministic"))
        sm->deterministic = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

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
  sm->inside_vrf_id = inside_vrf_id;
  sm->inside_fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
                                                            inside_vrf_id,
                                                            FIB_SOURCE_PLUGIN_HI);
  sm->static_mapping_only = static_mapping_only;
  sm->static_mapping_connection_tracking = static_mapping_connection_tracking;

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
      sm->worker_in2out_cb = snat_get_worker_in2out_cb;
      sm->worker_out2in_cb = snat_get_worker_out2in_cb;
      sm->in2out_node_index = snat_in2out_node.index;
      sm->in2out_output_node_index = snat_in2out_output_node.index;
      sm->out2in_node_index = snat_out2in_node.index;
      if (!static_mapping_only ||
          (static_mapping_only && static_mapping_connection_tracking))
        {
          sm->icmp_match_in2out_cb = icmp_match_in2out_slow;
          sm->icmp_match_out2in_cb = icmp_match_out2in_slow;

          vec_foreach (tsm, sm->per_thread_data)
            {
              clib_bihash_init_8_8 (&tsm->in2out, "in2out", translation_buckets,
                                    translation_memory_size);

              clib_bihash_init_8_8 (&tsm->out2in, "out2in", translation_buckets,
                                    translation_memory_size);

              clib_bihash_init_8_8 (&tsm->user_hash, "users", user_buckets,
                                    user_memory_size);
            }

          clib_bihash_init_16_8 (&sm->in2out_ed, "in2out-ed",
                                 translation_buckets, translation_memory_size);

          clib_bihash_init_16_8 (&sm->out2in_ed, "out2in-ed",
                                 translation_buckets, translation_memory_size);
        }
      else
        {
          sm->icmp_match_in2out_cb = icmp_match_in2out_fast;
          sm->icmp_match_out2in_cb = icmp_match_out2in_fast;
        }
      clib_bihash_init_8_8 (&sm->static_mapping_by_local,
                            "static_mapping_by_local", static_mapping_buckets,
                            static_mapping_memory_size);

      clib_bihash_init_8_8 (&sm->static_mapping_by_external,
                            "static_mapping_by_external", static_mapping_buckets,
                            static_mapping_memory_size);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (snat_config, "nat");

u8 * format_snat_session_state (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v, N, str) case SNAT_SESSION_##N: t = (u8 *) str; break;
    foreach_snat_session_state
#undef _
    default:
      t = format (t, "unknown");
    }
  s = format (s, "%s", t);
  return s;
}

u8 * format_snat_key (u8 * s, va_list * args)
{
  snat_session_key_t * key = va_arg (*args, snat_session_key_t *);

  s = format (s, "%U proto %U port %d fib %d",
              format_ip4_address, &key->addr,
              format_snat_protocol, key->protocol,
              clib_net_to_host_u16 (key->port), key->fib_index);
  return s;
}

u8 * format_snat_session (u8 * s, va_list * args)
{
  snat_main_t * sm __attribute__((unused)) = va_arg (*args, snat_main_t *);
  snat_session_t * sess = va_arg (*args, snat_session_t *);

  if (snat_is_unk_proto_session (sess))
    {
      s = format (s, "  i2o %U proto %u fib %u\n",
                  format_ip4_address, &sess->in2out.addr, sess->in2out.port,
                  sess->in2out.fib_index);
      s = format (s, "    o2i %U proto %u fib %u\n",
                  format_ip4_address, &sess->out2in.addr, sess->out2in.port,
                  sess->out2in.fib_index);
    }
  else
    {
      s = format (s, "  i2o %U\n", format_snat_key, &sess->in2out);
      s = format (s, "    o2i %U\n", format_snat_key, &sess->out2in);
    }
  if (sess->ext_host_addr.as_u32)
      s = format (s, "       external host %U\n",
                  format_ip4_address, &sess->ext_host_addr);
  s = format (s, "       last heard %.2f\n", sess->last_heard);
  s = format (s, "       total pkts %d, total bytes %lld\n",
              sess->total_pkts, sess->total_bytes);
  if (snat_is_session_static (sess))
    s = format (s, "       static translation\n");
  else
    s = format (s, "       dynamic translation\n");
  if (sess->flags & SNAT_SESSION_FLAG_LOAD_BALANCING)
    s = format (s, "       load-balancing\n");

  return s;
}

u8 * format_snat_user (u8 * s, va_list * args)
{
  snat_main_per_thread_data_t * sm = va_arg (*args, snat_main_per_thread_data_t *);
  snat_user_t * u = va_arg (*args, snat_user_t *);
  int verbose = va_arg (*args, int);
  dlist_elt_t * head, * elt;
  u32 elt_index, head_index;
  u32 session_index;
  snat_session_t * sess;

  s = format (s, "%U: %d dynamic translations, %d static translations\n",
              format_ip4_address, &u->addr, u->nsessions, u->nstaticsessions);

  if (verbose == 0)
    return s;

  if (u->nsessions || u->nstaticsessions)
    {
      head_index = u->sessions_per_user_list_head_index;
      head = pool_elt_at_index (sm->list_pool, head_index);

      elt_index = head->next;
      elt = pool_elt_at_index (sm->list_pool, elt_index);
      session_index = elt->value;

      while (session_index != ~0)
        {
          sess = pool_elt_at_index (sm->sessions, session_index);

          s = format (s, "  %U\n", format_snat_session, sm, sess);

          elt_index = elt->next;
          elt = pool_elt_at_index (sm->list_pool, elt_index);
          session_index = elt->value;
        }
    }

  return s;
}

u8 * format_snat_static_mapping (u8 * s, va_list * args)
{
  snat_static_mapping_t *m = va_arg (*args, snat_static_mapping_t *);
  nat44_lb_addr_port_t *local;

  if (m->addr_only)
      s = format (s, "local %U external %U vrf %d",
                  format_ip4_address, &m->local_addr,
                  format_ip4_address, &m->external_addr,
                  m->vrf_id);
  else
   {
      if (vec_len (m->locals))
        {
          s = format (s, "%U vrf %d external %U:%d",
                      format_snat_protocol, m->proto,
                      m->vrf_id,
                      format_ip4_address, &m->external_addr, m->external_port);
          vec_foreach (local, m->locals)
            s = format (s, "\n  local %U:%d probability %d\%",
                        format_ip4_address, &local->addr, local->port,
                        local->probability);
        }
      else
        s = format (s, "%U local %U:%d external %U:%d vrf %d",
                    format_snat_protocol, m->proto,
                    format_ip4_address, &m->local_addr, m->local_port,
                    format_ip4_address, &m->external_addr, m->external_port,
                    m->vrf_id);
   }
  return s;
}

u8 * format_snat_static_map_to_resolve (u8 * s, va_list * args)
{
  snat_static_map_resolve_t *m = va_arg (*args, snat_static_map_resolve_t *);
  vnet_main_t *vnm = vnet_get_main();

  if (m->addr_only)
      s = format (s, "local %U external %U vrf %d",
                  format_ip4_address, &m->l_addr,
                  format_vnet_sw_interface_name, vnm,
                  vnet_get_sw_interface (vnm, m->sw_if_index),
                  m->vrf_id);
  else
      s = format (s, "%U local %U:%d external %U:%d vrf %d",
                  format_snat_protocol, m->proto,
                  format_ip4_address, &m->l_addr, m->l_port,
                  format_vnet_sw_interface_name, vnm,
                  vnet_get_sw_interface (vnm, m->sw_if_index), m->e_port,
                  m->vrf_id);

  return s;
}

u8 * format_det_map_ses (u8 * s, va_list * args)
{
  snat_det_map_t * det_map = va_arg (*args, snat_det_map_t *);
  ip4_address_t in_addr, out_addr;
  u32 in_offset, out_offset;
  snat_det_session_t * ses = va_arg (*args, snat_det_session_t *);
  u32 * i = va_arg (*args, u32 *);

  u32 user_index = *i / SNAT_DET_SES_PER_USER;
  in_addr.as_u32 = clib_host_to_net_u32 (
    clib_net_to_host_u32(det_map->in_addr.as_u32) + user_index);
  in_offset = clib_net_to_host_u32(in_addr.as_u32) -
    clib_net_to_host_u32(det_map->in_addr.as_u32);
  out_offset = in_offset / det_map->sharing_ratio;
  out_addr.as_u32 = clib_host_to_net_u32(
    clib_net_to_host_u32(det_map->out_addr.as_u32) + out_offset);
  s = format (s, "in %U:%d out %U:%d external host %U:%d state: %U expire: %d\n",
              format_ip4_address, &in_addr,
              clib_net_to_host_u16 (ses->in_port),
              format_ip4_address, &out_addr,
              clib_net_to_host_u16 (ses->out.out_port),
              format_ip4_address, &ses->out.ext_host_addr,
              clib_net_to_host_u16 (ses->out.ext_host_port),
              format_snat_session_state, ses->state,
              ses->expire);

  return s;
}

static clib_error_t *
show_snat_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  int verbose = 0;
  snat_main_t * sm = &snat_main;
  snat_user_t * u;
  snat_static_mapping_t *m;
  snat_interface_t *i;
  snat_address_t * ap;
  vnet_main_t *vnm = vnet_get_main();
  snat_main_per_thread_data_t *tsm;
  u32 users_num = 0, sessions_num = 0, *worker, *sw_if_index;
  uword j = 0;
  snat_static_map_resolve_t *rp;
  snat_det_map_t * dm;
  snat_det_session_t * ses;

  if (unformat (input, "detail"))
    verbose = 1;
  else if (unformat (input, "verbose"))
    verbose = 2;

  if (sm->static_mapping_only)
    {
      if (sm->static_mapping_connection_tracking)
        vlib_cli_output (vm, "NAT plugin mode: static mapping only connection "
                         "tracking");
      else
        vlib_cli_output (vm, "NAT plugin mode: static mapping only");
    }
  else if (sm->deterministic)
    {
      vlib_cli_output (vm, "NAT plugin mode: deterministic mapping");
    }
  else
    {
      vlib_cli_output (vm, "NAT plugin mode: dynamic translations enabled");
    }

  if (verbose > 0)
    {
      pool_foreach (i, sm->interfaces,
      ({
        vlib_cli_output (vm, "%U %s", format_vnet_sw_interface_name, vnm,
                         vnet_get_sw_interface (vnm, i->sw_if_index),
                         (nat_interface_is_inside(i) &&
                          nat_interface_is_outside(i)) ? "in out" :
                         (nat_interface_is_inside(i) ? "in" : "out"));
      }));

      pool_foreach (i, sm->output_feature_interfaces,
      ({
        vlib_cli_output (vm, "%U output-feature %s",
                         format_vnet_sw_interface_name, vnm,
                         vnet_get_sw_interface (vnm, i->sw_if_index),
                         (nat_interface_is_inside(i) &&
                          nat_interface_is_outside(i)) ? "in out" :
                         (nat_interface_is_inside(i) ? "in" : "out"));
      }));

      if (vec_len (sm->auto_add_sw_if_indices))
        {
          vlib_cli_output (vm, "NAT44 pool addresses interfaces:");
          vec_foreach (sw_if_index, sm->auto_add_sw_if_indices)
            {
              vlib_cli_output (vm, "%U", format_vnet_sw_interface_name, vnm,
                               vnet_get_sw_interface (vnm, *sw_if_index));
            }
        }

      vec_foreach (ap, sm->addresses)
        {
          vlib_cli_output (vm, "%U", format_ip4_address, &ap->addr);
          if (ap->fib_index != ~0)
              vlib_cli_output (vm, "  tenant VRF: %u",
                               ip4_fib_get(ap->fib_index)->table_id);
          else
            vlib_cli_output (vm, "  tenant VRF independent");
#define _(N, i, n, s) \
          vlib_cli_output (vm, "  %d busy %s ports", ap->busy_##n##_ports, s);
          foreach_snat_protocol
#undef _
        }
    }

  if (sm->num_workers > 1)
    {
      vlib_cli_output (vm, "%d workers", vec_len (sm->workers));
      if (verbose > 0)
        {
          vec_foreach (worker, sm->workers)
            {
              vlib_worker_thread_t *w =
                vlib_worker_threads + *worker + sm->first_worker_index;
              vlib_cli_output (vm, "  %s", w->name);
            }
        }
    }

  if (sm->deterministic)
    {
      vlib_cli_output (vm, "udp timeout: %dsec", sm->udp_timeout);
      vlib_cli_output (vm, "tcp-established timeout: %dsec",
                       sm->tcp_established_timeout);
      vlib_cli_output (vm, "tcp-transitory timeout: %dsec",
                       sm->tcp_transitory_timeout);
      vlib_cli_output (vm, "icmp timeout: %dsec", sm->icmp_timeout);
      vlib_cli_output (vm, "%d deterministic mappings",
                       pool_elts (sm->det_maps));
      if (verbose > 0)
        {
          pool_foreach (dm, sm->det_maps,
          ({
            vlib_cli_output (vm, "in %U/%d out %U/%d\n",
                             format_ip4_address, &dm->in_addr, dm->in_plen,
                             format_ip4_address, &dm->out_addr, dm->out_plen);
            vlib_cli_output (vm, " outside address sharing ratio: %d\n",
                             dm->sharing_ratio);
            vlib_cli_output (vm, " number of ports per inside host: %d\n",
                             dm->ports_per_host);
            vlib_cli_output (vm, " sessions number: %d\n", dm->ses_num);
            if (verbose > 1)
              {
                vec_foreach_index (j, dm->sessions)
                  {
                    ses = vec_elt_at_index (dm->sessions, j);
                    if (ses->in_port)
                      vlib_cli_output (vm, "  %U", format_det_map_ses, dm, ses,
                                       &j);
                  }
              }
          }));
        }
    }
  else
    {
      if (sm->static_mapping_only && !(sm->static_mapping_connection_tracking))
        {
          vlib_cli_output (vm, "%d static mappings",
                           pool_elts (sm->static_mappings));

          if (verbose > 0)
            {
              pool_foreach (m, sm->static_mappings,
              ({
                vlib_cli_output (vm, "%U", format_snat_static_mapping, m);
              }));
            }
        }
      else
        {
          vec_foreach (tsm, sm->per_thread_data)
            {
              users_num += pool_elts (tsm->users);
              sessions_num += pool_elts (tsm->sessions);
            }

          vlib_cli_output (vm, "%d users, %d outside addresses, %d active sessions,"
                           " %d static mappings",
                           users_num,
                           vec_len (sm->addresses),
                           sessions_num,
                           pool_elts (sm->static_mappings));

          if (verbose > 0)
            {
              vlib_cli_output (vm, "%U", format_bihash_16_8, &sm->in2out_ed,
                               verbose - 1);
              vlib_cli_output (vm, "%U", format_bihash_16_8, &sm->out2in_ed,
                               verbose - 1);
              vec_foreach_index (j, sm->per_thread_data)
                {
                  tsm = vec_elt_at_index (sm->per_thread_data, j);

                  if (pool_elts (tsm->users) == 0)
                    continue;

                  vlib_worker_thread_t *w = vlib_worker_threads + j;
                  vlib_cli_output (vm, "Thread %d (%s at lcore %u):", j, w->name,
                                   w->lcore_id);
                  vlib_cli_output (vm, "  %U", format_bihash_8_8, &tsm->in2out,
                                   verbose - 1);
                  vlib_cli_output (vm, "  %U", format_bihash_8_8, &tsm->out2in,
                                   verbose - 1);
                  vlib_cli_output (vm, "  %d list pool elements",
                                   pool_elts (tsm->list_pool));

                  pool_foreach (u, tsm->users,
                  ({
                    vlib_cli_output (vm, "  %U", format_snat_user, tsm, u,
                                     verbose - 1);
                  }));
                }

              if (pool_elts (sm->static_mappings))
                {
                  vlib_cli_output (vm, "static mappings:");
                  pool_foreach (m, sm->static_mappings,
                  ({
                    vlib_cli_output (vm, "%U", format_snat_static_mapping, m);
                  }));
                  for (j = 0; j < vec_len (sm->to_resolve); j++)
                    {
                      rp = sm->to_resolve + j;
                      vlib_cli_output (vm, "%U",
                                       format_snat_static_map_to_resolve, rp);
                    }
                }
            }
        }
    }

  return 0;
}

VLIB_CLI_COMMAND (show_snat_command, static) = {
    .path = "show nat44",
    .short_help = "show nat44",
    .function = show_snat_command_fn,
};


static void
snat_ip4_add_del_interface_address_cb (ip4_main_t * im,
                                       uword opaque,
                                       u32 sw_if_index,
                                       ip4_address_t * address,
                                       u32 address_length,
                                       u32 if_address_index,
                                       u32 is_delete)
{
  snat_main_t *sm = &snat_main;
  snat_static_map_resolve_t *rp;
  u32 *indices_to_delete = 0;
  int i, j;
  int rv;

  for (i = 0; i < vec_len(sm->auto_add_sw_if_indices); i++)
    {
      if (sw_if_index == sm->auto_add_sw_if_indices[i])
        {
          if (!is_delete)
            {
              /* Don't trip over lease renewal, static config */
              for (j = 0; j < vec_len(sm->addresses); j++)
                if (sm->addresses[j].addr.as_u32 == address->as_u32)
                  return;

              snat_add_address (sm, address, ~0);
              /* Scan static map resolution vector */
              for (j = 0; j < vec_len (sm->to_resolve); j++)
                {
                  rp = sm->to_resolve + j;
                  /* On this interface? */
                  if (rp->sw_if_index == sw_if_index)
                    {
                      /* Add the static mapping */
                      rv = snat_add_static_mapping (rp->l_addr,
                                                    address[0],
                                                    rp->l_port,
                                                    rp->e_port,
                                                    rp->vrf_id,
                                                    rp->addr_only,
                                                    ~0 /* sw_if_index */,
                                                    rp->proto,
                                                    rp->is_add);
                      if (rv)
                        clib_warning ("snat_add_static_mapping returned %d", 
                                      rv);
                      vec_add1 (indices_to_delete, j);
                    }
                }
              /* If we resolved any of the outstanding static mappings */
              if (vec_len(indices_to_delete))
                {
                  /* Delete them */
                  for (j = vec_len(indices_to_delete)-1; j >= 0; j--)
                    vec_delete(sm->to_resolve, 1, j);
                  vec_free(indices_to_delete);
                }
              return;
            }
          else
            {
              (void) snat_del_address(sm, address[0], 1);
              return;
            }
        }
    }
}


int snat_add_interface_address (snat_main_t *sm, u32 sw_if_index, int is_del)
{
  ip4_main_t * ip4_main = sm->ip4_main;
  ip4_address_t * first_int_addr;
  snat_static_map_resolve_t *rp;
  u32 *indices_to_delete = 0;
  int i, j;

  first_int_addr = ip4_interface_first_address (ip4_main, sw_if_index,
                                                0 /* just want the address*/);

  for (i = 0; i < vec_len(sm->auto_add_sw_if_indices); i++)
    {
      if (sm->auto_add_sw_if_indices[i] == sw_if_index)
        {
          if (is_del)
            {
              /* if have address remove it */
              if (first_int_addr)
                  (void) snat_del_address (sm, first_int_addr[0], 1);
              else
                {
                  for (j = 0; j < vec_len (sm->to_resolve); j++)
                    {
                      rp = sm->to_resolve + j;
                      if (rp->sw_if_index == sw_if_index)
                        vec_add1 (indices_to_delete, j);
                    }
                  if (vec_len(indices_to_delete))
                    {
                      for (j = vec_len(indices_to_delete)-1; j >= 0; j--)
                        vec_del1(sm->to_resolve, j);
                      vec_free(indices_to_delete);
                    }
                }
              vec_del1(sm->auto_add_sw_if_indices, i);
            }
          else
            return VNET_API_ERROR_VALUE_EXIST;

          return 0;
        }
    }

  if (is_del)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* add to the auto-address list */
  vec_add1(sm->auto_add_sw_if_indices, sw_if_index);

  /* If the address is already bound - or static - add it now */
  if (first_int_addr)
      snat_add_address (sm, first_int_addr, ~0);

  return 0;
}

static clib_error_t *
snat_add_interface_address_command_fn (vlib_main_t * vm,
                                       unformat_input_t * input,
                                       vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
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
                    sm->vnet_main, &sw_if_index))
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

  rv = snat_add_interface_address (sm, sw_if_index, is_del);

  switch (rv)
    {
    case 0:
      break;

    default:
      error = clib_error_return (0, "snat_add_interface_address returned %d",
                                 rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (snat_add_interface_address_command, static) = {
    .path = "nat44 add interface address",
    .short_help = "nat44 add interface address <interface> [del]",
    .function = snat_add_interface_address_command_fn,
};

int
nat44_del_session (snat_main_t *sm, ip4_address_t *addr, u16 port,
                   snat_protocol_t proto, u32 vrf_id, int is_in)
{
  snat_main_per_thread_data_t *tsm;
  clib_bihash_kv_8_8_t kv, value;
  ip4_header_t ip;
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);
  snat_session_key_t key;
  snat_session_t *s;
  clib_bihash_8_8_t *t;
  snat_user_key_t u_key;
  snat_user_t *u;

  ip.dst_address.as_u32 = ip.src_address.as_u32 = addr->as_u32;
  if (sm->num_workers)
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
      s = pool_elt_at_index (tsm->sessions, value.value);
      kv.key = s->in2out.as_u64;
      clib_bihash_add_del_8_8 (&tsm->in2out, &kv, 0);
      kv.key = s->out2in.as_u64;
      clib_bihash_add_del_8_8 (&tsm->out2in, &kv, 0);
      u_key.addr = s->in2out.addr;
      u_key.fib_index = s->in2out.fib_index;
      kv.key = u_key.as_u64;
      if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
        {
          u = pool_elt_at_index (tsm->users, value.value);
          u->nsessions--;
        }
      clib_dlist_remove (tsm->list_pool, s->per_user_index);
      pool_put (tsm->sessions, s);
      return 0;
    }

  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

static clib_error_t *
nat44_del_session_command_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  int is_in = 0;
  clib_error_t *error = 0;
  ip4_address_t addr;
  u32 port = 0, vrf_id = sm->outside_vrf_id;
  snat_protocol_t proto;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%u %U", unformat_ip4_address, &addr, &port,
          unformat_snat_protocol, &proto))
        ;
      else if (unformat (line_input, "in"))
        {
          is_in = 1;
          vrf_id = sm->inside_vrf_id;
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

  rv = nat44_del_session(sm, &addr, port, proto, vrf_id, is_in);

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

VLIB_CLI_COMMAND (nat44_del_session_command, static) = {
    .path = "nat44 del session",
    .short_help = "nat44 del session in|out <addr>:<port> tcp|udp|icmp [vrf <id>]",
    .function = nat44_del_session_command_fn,
};

static clib_error_t *
snat_det_map_command_fn (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, out_addr;
  u32 in_plen, out_plen;
  int is_add = 1, rv;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "in %U/%u", unformat_ip4_address, &in_addr, &in_plen))
        ;
      else if (unformat (line_input, "out %U/%u", unformat_ip4_address, &out_addr, &out_plen))
        ;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  unformat_free (line_input);

  rv = snat_det_add_map(sm, &in_addr, (u8) in_plen, &out_addr, (u8)out_plen,
                        is_add);

  if (rv)
    {
      error = clib_error_return (0, "snat_det_add_map return %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * @cliexpar
 * @cliexstart{snat deterministic add}
 * Create bijective mapping of inside address to outside address and port range
 * pairs, with the purpose of enabling deterministic NAT to reduce logging in
 * CGN deployments.
 * To create deterministic mapping between inside network 10.0.0.0/18 and
 * outside network 1.1.1.0/30 use:
 * # vpp# nat44 deterministic add in 10.0.0.0/18 out 1.1.1.0/30
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_det_map_command, static) = {
    .path = "nat44 deterministic add",
    .short_help = "nat44 deterministic add in <addr>/<plen> out <addr>/<plen> [del]",
    .function = snat_det_map_command_fn,
};

static clib_error_t *
snat_det_forward_command_fn (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, out_addr;
  u16 lo_port;
  snat_det_map_t * dm;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip4_address, &in_addr))
        ;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  unformat_free (line_input);

  dm = snat_det_map_by_user(sm, &in_addr);
  if (!dm)
    vlib_cli_output (vm, "no match");
  else
    {
      snat_det_forward (dm, &in_addr, &out_addr, &lo_port);
      vlib_cli_output (vm, "%U:<%d-%d>", format_ip4_address, &out_addr,
                       lo_port, lo_port + dm->ports_per_host - 1);
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * @cliexpar
 * @cliexstart{snat deterministic forward}
 * Return outside address and port range from inside address for deterministic
 * NAT.
 * To obtain outside address and port of inside host use:
 *  vpp# nat44 deterministic forward 10.0.0.2
 *  1.1.1.0:<1054-1068>
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_det_forward_command, static) = {
    .path = "nat44 deterministic forward",
    .short_help = "nat44 deterministic forward <addr>",
    .function = snat_det_forward_command_fn,
};

static clib_error_t *
snat_det_reverse_command_fn (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, out_addr;
  u32 out_port;
  snat_det_map_t * dm;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%d", unformat_ip4_address, &out_addr, &out_port))
        ;
      else
        {
          error =  clib_error_return (0, "unknown input '%U'",
                                      format_unformat_error, line_input);
        }
    }

  unformat_free (line_input);

  if (out_port < 1024 || out_port > 65535)
    {
      error = clib_error_return (0, "wrong port, must be <1024-65535>");
      goto done;
    }

  dm = snat_det_map_by_out(sm, &out_addr);
  if (!dm)
    vlib_cli_output (vm, "no match");
  else
    {
      snat_det_reverse (dm, &out_addr, (u16) out_port, &in_addr);
      vlib_cli_output (vm, "%U", format_ip4_address, &in_addr);
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * @cliexpar
 * @cliexstart{snat deterministic reverse}
 * Return inside address from outside address and port for deterministic NAT.
 * To obtain inside host address from outside address and port use:
 *  #vpp nat44 deterministic reverse 1.1.1.1:1276
 *  10.0.16.16
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_det_reverse_command, static) = {
    .path = "nat44 deterministic reverse",
    .short_help = "nat44 deterministic reverse <addr>:<port>",
    .function = snat_det_reverse_command_fn,
};

static clib_error_t *
set_timeout_command_fn (vlib_main_t * vm,
                        unformat_input_t * input,
                        vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "udp %u", &sm->udp_timeout))
        ;
      else if (unformat (line_input, "tcp-established %u",
               &sm->tcp_established_timeout))
        ;
      else if (unformat (line_input, "tcp-transitory %u",
               &sm->tcp_transitory_timeout))
        ;
      else if (unformat (line_input, "icmp %u", &sm->icmp_timeout))
        ;
      else if (unformat (line_input, "reset"))
        {
          sm->udp_timeout = SNAT_UDP_TIMEOUT;
          sm->tcp_established_timeout = SNAT_TCP_ESTABLISHED_TIMEOUT;
          sm->tcp_transitory_timeout = SNAT_TCP_TRANSITORY_TIMEOUT;
          sm->icmp_timeout = SNAT_ICMP_TIMEOUT;
        }
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  unformat_free (line_input);

done:
  unformat_free (line_input);

  return error;
}

/*?
 * @cliexpar
 * @cliexstart{set snat deterministic timeout}
 * Set values of timeouts for deterministic NAT (in seconds), use:
 *  vpp# set nat44 deterministic timeout udp 120 tcp-established 7500
 *  tcp-transitory 250 icmp 90
 * To reset default values use:
 *  vpp# set nat44 deterministic timeout reset
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_timeout_command, static) = {
  .path = "set nat44 deterministic timeout",
  .function = set_timeout_command_fn,
  .short_help =
    "set nat44 deterministic timeout [udp <sec> | tcp-established <sec> "
    "tcp-transitory <sec> | icmp <sec> | reset]",
};

static clib_error_t *
snat_det_close_session_out_fn (vlib_main_t *vm,
                               unformat_input_t * input,
                               vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t out_addr, ext_addr, in_addr;
  u32 out_port, ext_port;
  snat_det_map_t * dm;
  snat_det_session_t * ses;
  snat_det_out_key_t key;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%d %U:%d",
                    unformat_ip4_address, &out_addr, &out_port,
                    unformat_ip4_address, &ext_addr, &ext_port))
        ;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  unformat_free (line_input);

  dm = snat_det_map_by_out(sm, &out_addr);
  if (!dm)
    vlib_cli_output (vm, "no match");
  else
    {
      snat_det_reverse(dm, &ext_addr, (u16)out_port, &in_addr);
      key.ext_host_addr = out_addr;
      key.ext_host_port = ntohs((u16)ext_port);
      key.out_port = ntohs((u16)out_port);
      ses = snat_det_get_ses_by_out(dm, &out_addr, key.as_u64);
      if (!ses)
        vlib_cli_output (vm, "no match");
      else
       snat_det_ses_close(dm, ses);
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * @cliexpar
 * @cliexstart{snat deterministic close session out}
 * Close session using outside ip address and port
 * and external ip address and port, use:
 *  vpp# nat44 deterministic close session out 1.1.1.1:1276 2.2.2.2:2387
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_det_close_sesion_out_command, static) = {
  .path = "nat44 deterministic close session out",
  .short_help = "nat44 deterministic close session out "
                "<out_addr>:<out_port> <ext_addr>:<ext_port>",
  .function = snat_det_close_session_out_fn,
};

static clib_error_t *
snat_det_close_session_in_fn (vlib_main_t *vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, ext_addr;
  u32 in_port, ext_port;
  snat_det_map_t * dm;
  snat_det_session_t * ses;
  snat_det_out_key_t key;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%d %U:%d",
                    unformat_ip4_address, &in_addr, &in_port,
                    unformat_ip4_address, &ext_addr, &ext_port))
        ;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  unformat_free (line_input);

  dm = snat_det_map_by_user (sm, &in_addr);
  if (!dm)
    vlib_cli_output (vm, "no match");
  else
    {
      key.ext_host_addr = ext_addr;
      key.ext_host_port = ntohs ((u16)ext_port);
      ses = snat_det_find_ses_by_in (dm, &in_addr, ntohs((u16)in_port), key);
      if (!ses)
        vlib_cli_output (vm, "no match");
      else
        snat_det_ses_close(dm, ses);
    }

done:
  unformat_free(line_input);

  return error;
}

/*?
 * @cliexpar
 * @cliexstart{snat deterministic close_session_in}
 * Close session using inside ip address and port
 * and external ip address and port, use:
 *  vpp# nat44 deterministic close session in 3.3.3.3:3487 2.2.2.2:2387
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_det_close_session_in_command, static) = {
  .path = "nat44 deterministic close session in",
  .short_help = "nat44 deterministic close session in "
                "<in_addr>:<in_port> <ext_addr>:<ext_port>",
  .function = snat_det_close_session_in_fn,
};
