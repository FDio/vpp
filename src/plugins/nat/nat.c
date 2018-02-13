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

void
nat_free_session_data (snat_main_t * sm, snat_session_t * s, u32 thread_index)
{
  snat_session_key_t key;
  clib_bihash_kv_8_8_t kv;
  nat_ed_ses_key_t ed_key;
  clib_bihash_kv_16_8_t ed_kv;
  int i;
  snat_address_t *a;
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_index);

  /* Endpoint dependent session lookup tables */
  if (is_ed_session (s))
    {
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
      if (clib_bihash_add_del_16_8 (&sm->out2in_ed, &ed_kv, 0))
        clib_warning ("out2in_ed key del failed");

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
      if (clib_bihash_add_del_16_8 (&sm->in2out_ed, &ed_kv, 0))
        clib_warning ("in2out_ed key del failed");
    }

  if (snat_is_unk_proto_session (s))
    return;

  /* log NAT event */
  snat_ipfix_logging_nat44_ses_delete(s->in2out.addr.as_u32,
                                      s->out2in.addr.as_u32,
                                      s->in2out.protocol,
                                      s->in2out.port,
                                      s->out2in.port,
                                      s->in2out.fib_index);

  /* Twice NAT address and port for external host */
  if (is_twice_nat_session (s))
    {
      for (i = 0; i < vec_len (sm->twice_nat_addresses); i++)
        {
          key.protocol = s->in2out.protocol;
          key.port = s->ext_host_nat_port;
          a = sm->twice_nat_addresses + i;
          if (a->addr.as_u32 == s->ext_host_nat_addr.as_u32)
            {
              snat_free_outside_address_and_port (sm->twice_nat_addresses,
                                                  thread_index, &key, i);
              break;
            }
        }
    }

  if (is_ed_session (s))
    return;

  /* Session lookup tables */
  kv.key = s->in2out.as_u64;
  if (clib_bihash_add_del_8_8 (&tsm->in2out, &kv, 0))
    clib_warning ("in2out key del failed");
  kv.key = s->out2in.as_u64;
  if (clib_bihash_add_del_8_8 (&tsm->out2in, &kv, 0))
    clib_warning ("out2in key del failed");

  if (snat_is_session_static (s))
    return;

  if (s->outside_address_index != ~0)
    snat_free_outside_address_and_port (sm->addresses, thread_index,
                                        &s->out2in, s->outside_address_index);
}

snat_user_t *
nat_user_get_or_create (snat_main_t *sm, ip4_address_t *addr, u32 fib_index,
                        u32 thread_index)
{
  snat_user_t *u = 0;
  snat_user_key_t user_key;
  clib_bihash_kv_8_8_t kv, value;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  dlist_elt_t * per_user_list_head_elt;

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
        clib_warning ("user_hash keay add failed");
    }
  else
    {
      u = pool_elt_at_index (tsm->users, value.value);
    }

  return u;
}

snat_session_t *
nat_session_alloc_or_recycle (snat_main_t *sm, snat_user_t *u, u32 thread_index)
{
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  u32 oldest_per_user_translation_list_index, session_index;
  dlist_elt_t * oldest_per_user_translation_list_elt;
  dlist_elt_t * per_user_translation_list_elt;

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
      s->outside_address_index = ~0;
      s->flags = 0;
      s->total_bytes = 0;
      s->total_pkts = 0;
    }
  else
    {
      pool_get (tsm->sessions, s);
      memset (s, 0, sizeof (*s));
      s->outside_address_index = ~0;

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
                  goto enqueue0;
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
                  goto enqueue0;
                }
              udp_header_t * udp0 = ip4_next_header (ip0);
              m_key0.port = clib_net_to_host_u16 (udp0->dst_port);
              m_key0.protocol = ip_proto_to_snat_proto (ip0->protocol);
              kv0.key = m_key0.as_u64;
              if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv0, &value0))
                next0 = NAT44_CLASSIFY_NEXT_OUT2IN;
            }

        enqueue0:
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

void snat_add_address (snat_main_t *sm, ip4_address_t *addr, u32 vrf_id,
                       u8 twice_nat)
{
  snat_address_t * ap;
  snat_interface_t *i;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  /* Check if address already exists */
  vec_foreach (ap, twice_nat ? sm->twice_nat_addresses : sm->addresses)
    {
      if (ap->addr.as_u32 == addr->as_u32)
        return;
    }

  if (twice_nat)
    vec_add2 (sm->twice_nat_addresses, ap, 1);
  else
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

  if (twice_nat)
    return;

  /* Add external address to FIB */
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
                                       int is_add,
                                       u8 * tag)
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
  rp->tag = vec_dup (tag);
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
 * @param twice_nat If 1 translate external host address and port.
 * @param out2in_only If 1 rule match only out2in direction
 * @param tag - opaque string tag
 *
 * @returns
 */
int snat_add_static_mapping(ip4_address_t l_addr, ip4_address_t e_addr,
                            u16 l_port, u16 e_port, u32 vrf_id, int addr_only,
                            u32 sw_if_index, snat_protocol_t proto, int is_add,
                            u8 twice_nat, u8 out2in_only, u8 * tag)
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
  snat_main_per_thread_data_t *tsm;
  snat_user_key_t u_key;
  snat_user_t *u;
  dlist_elt_t * head, * elt;
  u32 elt_index, head_index;
  u32 ses_index;
  u64 user_index;
  snat_session_t * s;

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
             addr_only,  is_add, tag);
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

      if (twice_nat && addr_only)
        return VNET_API_ERROR_UNSUPPORTED;

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
          if (!a && (l_addr.as_u32 != e_addr.as_u32))
            return VNET_API_ERROR_NO_SUCH_ENTRY;
        }

      pool_get (sm->static_mappings, m);
      memset (m, 0, sizeof (*m));
      m->tag = vec_dup (tag);
      m->local_addr = l_addr;
      m->external_addr = e_addr;
      m->addr_only = addr_only;
      m->vrf_id = vrf_id;
      m->fib_index = fib_index;
      m->twice_nat = twice_nat;
      m->out2in_only = out2in_only;
      if (!addr_only)
        {
          m->local_port = l_port;
          m->external_port = e_port;
          m->proto = proto;
        }

      if (sm->workers)
        {
          ip4_header_t ip = {
            .src_address = m->local_addr,
          };
          m->worker_index = sm->worker_in2out_cb (&ip, m->fib_index);
          tsm = vec_elt_at_index (sm->per_thread_data, m->worker_index);
        }
      else
        tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

      m_key.addr = m->local_addr;
      m_key.port = m->local_port;
      m_key.protocol = m->proto;
      m_key.fib_index = m->fib_index;
      kv.key = m_key.as_u64;
      kv.value = m - sm->static_mappings;
      if (!out2in_only)
        clib_bihash_add_del_8_8(&sm->static_mapping_by_local, &kv, 1);
      if (twice_nat || out2in_only)
        {
          m_key.port = clib_host_to_net_u16 (l_port);
          kv.key = m_key.as_u64;
          kv.value = ~0ULL;
          if (clib_bihash_add_del_8_8(&tsm->in2out, &kv, 1))
            clib_warning ("in2out key add failed");
        }

      m_key.addr = m->external_addr;
      m_key.port = m->external_port;
      m_key.fib_index = sm->outside_fib_index;
      kv.key = m_key.as_u64;
      kv.value = m - sm->static_mappings;
      clib_bihash_add_del_8_8(&sm->static_mapping_by_external, &kv, 1);
      if (twice_nat || out2in_only)
        {
          m_key.port = clib_host_to_net_u16 (e_port);
          kv.key = m_key.as_u64;
          kv.value = ~0ULL;
          if (clib_bihash_add_del_8_8(&tsm->out2in, &kv, 1))
            clib_warning ("out2in key add failed");
        }

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
                      s =  pool_elt_at_index (tsm->sessions, ses_index);
                      elt = pool_elt_at_index (tsm->list_pool, elt->next);
                      ses_index = elt->value;

                      if (snat_is_session_static (s))
                        continue;

                      if (!addr_only)
                        {
                          if ((s->out2in.addr.as_u32 != e_addr.as_u32) &&
                              (clib_net_to_host_u16 (s->out2in.port) != e_port))
                            continue;
                        }

                      nat_free_session_data (sm, s, tsm - sm->per_thread_data);
                      clib_dlist_remove (tsm->list_pool, s->per_user_index);
                      pool_put_index (tsm->list_pool, s->per_user_index);
                      pool_put (tsm->sessions, s);
                      u->nsessions--;

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
        return VNET_API_ERROR_NO_SUCH_ENTRY;

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

      if (sm->num_workers > 1)
        tsm = vec_elt_at_index (sm->per_thread_data, m->worker_index);
      else
        tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

      m_key.addr = m->local_addr;
      m_key.port = m->local_port;
      m_key.protocol = m->proto;
      m_key.fib_index = m->fib_index;
      kv.key = m_key.as_u64;
      if (!out2in_only)
        clib_bihash_add_del_8_8(&sm->static_mapping_by_local, &kv, 0);
      if (twice_nat || out2in_only)
        {
          m_key.port = clib_host_to_net_u16 (m->local_port);
          kv.key = m_key.as_u64;
          kv.value = ~0ULL;
          if (clib_bihash_add_del_8_8(&tsm->in2out, &kv, 0))
            clib_warning ("in2out key del failed");
        }

      m_key.addr = m->external_addr;
      m_key.port = m->external_port;
      m_key.fib_index = sm->outside_fib_index;
      kv.key = m_key.as_u64;
      clib_bihash_add_del_8_8(&sm->static_mapping_by_external, &kv, 0);
      if (twice_nat || out2in_only)
        {
          m_key.port = clib_host_to_net_u16 (m->external_port);
          kv.key = m_key.as_u64;
          kv.value = ~0ULL;
          if (clib_bihash_add_del_8_8(&tsm->out2in, &kv, 0))
            clib_warning ("in2out key del failed");
        }

      /* Delete session(s) for static mapping if exist */
      if (!(sm->static_mapping_only) ||
          (sm->static_mapping_only && sm->static_mapping_connection_tracking))
        {
          u_key.addr = m->local_addr;
          u_key.fib_index = m->fib_index;
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
                      s =  pool_elt_at_index (tsm->sessions, ses_index);
                      elt = pool_elt_at_index (tsm->list_pool, elt->next);
                      ses_index = elt->value;

                      if (!addr_only)
                        {
                          if ((s->out2in.addr.as_u32 != e_addr.as_u32) &&
                              (clib_net_to_host_u16 (s->out2in.port) != e_port))
                            continue;
                        }

                      nat_free_session_data (sm, s, tsm - sm->per_thread_data);
                      clib_dlist_remove (tsm->list_pool, s->per_user_index);
                      pool_put_index (tsm->list_pool, s->per_user_index);
                      pool_put (tsm->sessions, s);
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

      vec_free (m->tag);
      /* Delete static mapping from pool */
      pool_put (sm->static_mappings, m);
    }

  if (!addr_only || (l_addr.as_u32 == e_addr.as_u32))
    return 0;

  /* Add/delete external address to FIB */
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

  return 0;
}

int nat44_add_del_lb_static_mapping (ip4_address_t e_addr, u16 e_port,
                                     snat_protocol_t proto, u32 vrf_id,
                                     nat44_lb_addr_port_t *locals, u8 is_add,
                                     u8 twice_nat, u8 out2in_only, u8 *tag)
{
  snat_main_t * sm = &snat_main;
  snat_static_mapping_t *m;
  snat_session_key_t m_key;
  clib_bihash_kv_8_8_t kv, value;
  u32 fib_index;
  snat_address_t *a = 0;
  int i;
  nat44_lb_addr_port_t *local;
  u32 worker_index = 0, elt_index, head_index, ses_index;
  snat_main_per_thread_data_t *tsm;
  snat_user_key_t u_key;
  snat_user_t *u;
  snat_session_t * s;
  dlist_elt_t * head, * elt;

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
      m->tag = vec_dup (tag);
      m->external_addr = e_addr;
      m->addr_only = 0;
      m->vrf_id = vrf_id;
      m->fib_index = fib_index;
      m->external_port = e_port;
      m->proto = proto;
      m->twice_nat = twice_nat;
      m->out2in_only = out2in_only;

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
          clib_warning ("out2in key add failed");
          return VNET_API_ERROR_UNSPECIFIED;
        }

      m_key.fib_index = m->fib_index;
      for (i = 0; i < vec_len (locals); i++)
        {
          m_key.addr = locals[i].addr;
          if (!out2in_only)
            {
              m_key.port = locals[i].port;
              kv.key = m_key.as_u64;
              kv.value = m - sm->static_mappings;
              clib_bihash_add_del_8_8(&sm->static_mapping_by_local, &kv, 1);
            }
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
          if (!out2in_only)
            {
              m_key.port = local->port;
              m_key.fib_index = m->fib_index;
              kv.key = m_key.as_u64;
              if (clib_bihash_add_del_8_8(&sm->static_mapping_by_local, &kv, 0))
                {
                  clib_warning ("static_mapping_by_local key del failed");
                  return VNET_API_ERROR_UNSPECIFIED;
                }
            }

          m_key.port = clib_host_to_net_u16 (local->port);
          kv.key = m_key.as_u64;
          if (clib_bihash_add_del_8_8(&tsm->in2out, &kv, 0))
            {
              clib_warning ("in2out key del failed");
              return VNET_API_ERROR_UNSPECIFIED;
            }
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

                      if ((s->in2out.addr.as_u32 != local->addr.as_u32) &&
                          (clib_net_to_host_u16 (s->in2out.port) != local->port))
                        continue;

                      nat_free_session_data (sm, s, tsm - sm->per_thread_data);
                      clib_dlist_remove (tsm->list_pool, s->per_user_index);
                      pool_put_index (tsm->list_pool, s->per_user_index);
                      pool_put (tsm->sessions, s);
                      u->nstaticsessions--;
                    }
                }
            }
        }
      vec_free(m->locals);
      vec_free(m->tag);

      pool_put (sm->static_mappings, m);
    }

  return 0;
}

int
snat_del_address (snat_main_t *sm, ip4_address_t addr, u8 delete_sm,
                  u8 twice_nat)
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
  snat_address_t *addresses = twice_nat ? sm->twice_nat_addresses : sm->addresses;

  /* Find SNAT address */
  for (i=0; i < vec_len (addresses); i++)
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
      pool_foreach (m, sm->static_mappings,
      ({
          if (m->external_addr.as_u32 == addr.as_u32)
            (void) snat_add_static_mapping (m->local_addr, m->external_addr,
                                            m->local_port, m->external_port,
                                            m->vrf_id, m->addr_only, ~0,
                                            m->proto, 0, m->twice_nat,
                                            m->out2in_only, m->tag);
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
                ses->outside_address_index = ~0;
                nat_free_session_data (sm, ses, tsm - sm->per_thread_data);
                clib_dlist_remove (tsm->list_pool, ses->per_user_index);
                pool_put_index (tsm->list_pool, ses->per_user_index);
                vec_add1 (ses_to_be_removed, ses - tsm->sessions);
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

  if (twice_nat)
    {
      vec_del1 (sm->twice_nat_addresses, i);
      return 0;
    }
  else
    vec_del1 (sm->addresses, i);

  /* Delete external address from FIB */
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

  if (sm->out2in_dpo && !is_inside)
    return VNET_API_ERROR_UNSUPPORTED;

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
                else
                  {
                    del_feature_name = "nat44-classify";
                    feature_name = !is_inside ?  "nat44-in2out" : "nat44-out2in";
                  }

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
  if (is_inside && !sm->out2in_dpo)
    {
      vnet_feature_enable_disable ("ip4-local", "nat44-hairpinning",
                                   sw_if_index, !is_del, 0, 0);
      return 0;
    }

  vec_foreach (ap, sm->addresses)
    snat_add_del_addr_to_fib(&ap->addr, 32, sw_if_index, !is_del);

  pool_foreach (m, sm->static_mappings,
  ({
    if (!(m->addr_only) || (m->local_addr.as_u32 == m->external_addr.as_u32))
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
      sm->per_thread_data[sm->first_worker_index + i].snat_thread_index = j;
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

static int
nat_alloc_addr_and_port_default (snat_address_t * addresses,
                                 u32 fib_index,
                                 u32 thread_index,
                                 snat_session_key_t * k,
                                 u32 * address_indexp,
                                 u16 port_per_thread,
                                 u32 snat_thread_index);

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
  sm->alloc_addr_and_port = nat_alloc_addr_and_port_default;
  sm->forwarding_enabled = 0;

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

  nat_dpo_module_init ();

  /* Init IPFIX logging */
  snat_ipfix_logging_init(vm);

  /* Init NAT64 */
  error = nat64_init(vm);
  if (error)
    return error;

  dslite_init(vm);

  nat66_init();

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
 * @param twice_nat If matched mapping is twice NAT.
 *
 * @returns 0 if match found otherwise 1.
 */
int snat_static_mapping_match (snat_main_t * sm,
                               snat_session_key_t match,
                               snat_session_key_t * mapping,
                               u8 by_external,
                               u8 *is_addr_only,
                               u8 *twice_nat)
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

  if (PREDICT_FALSE(twice_nat != 0))
    *twice_nat = m->twice_nat;

  return 0;
}

static_always_inline u16
snat_random_port (u16 min, u16 max)
{
  snat_main_t *sm = &snat_main;
  return min + random_u32 (&sm->random_seed) /
    (random_u32_max() / (max - min + 1) + 1);
}

int
snat_alloc_outside_address_and_port (snat_address_t * addresses,
                                     u32 fib_index,
                                     u32 thread_index,
                                     snat_session_key_t * k,
                                     u32 * address_indexp,
                                     u16 port_per_thread,
                                     u32 snat_thread_index)
{
  snat_main_t *sm = &snat_main;

  return sm->alloc_addr_and_port(addresses, fib_index, thread_index, k,
                                 address_indexp, port_per_thread,
                                 snat_thread_index);
}

static int
nat_alloc_addr_and_port_default (snat_address_t * addresses,
                                 u32 fib_index,
                                 u32 thread_index,
                                 snat_session_key_t * k,
                                 u32 * address_indexp,
                                 u16 port_per_thread,
                                 u32 snat_thread_index)
{
  int i, gi = 0;
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
                      *address_indexp = i; \
                      return 0; \
                    } \
                } \
              else if (a->fib_index == ~0) \
                { \
                  ga = a; \
                  gi = i; \
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
              *address_indexp = gi; \
              return 0; \
            }
	  break;
	  foreach_snat_protocol
#undef _
	default:
	  clib_warning ("unknown protocol");
	  return 1;
	}
    }

  /* Totally out of translations to use... */
  snat_ipfix_logging_addresses_exhausted(0);
  return 1;
}

static int
nat_alloc_addr_and_port_mape (snat_address_t * addresses,
                              u32 fib_index,
                              u32 thread_index,
                              snat_session_key_t * k,
                              u32 * address_indexp,
                              u16 port_per_thread,
                              u32 snat_thread_index)
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

exhausted:
  /* Totally out of translations to use... */
  snat_ipfix_logging_addresses_exhausted(0);
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
  u32 next_worker_index = 0;

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
      key.l_addr = ip0->dst_address;
      key.r_addr = ip0->src_address;
      key.fib_index = rx_fib_index0;
      key.proto = ip0->protocol;
      key.r_port = 0;
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
  next_worker_index = sm->first_worker_index;
  next_worker_index +=
    sm->workers[(clib_net_to_host_u16 (port) - 1024) / sm->port_per_thread];
  return next_worker_index;
}

static clib_error_t *
snat_config (vlib_main_t * vm, unformat_input_t * input)
{
  snat_main_t * sm = &snat_main;
  u32 translation_buckets = 128;
  u32 translation_memory_size = 1<<15;
  u32 user_buckets = 128;
  u32 user_memory_size = 1<<15;
  u32 max_translations_per_user = 100;
  u32 outside_vrf_id = 0;
  u32 inside_vrf_id = 0;
  u32 static_mapping_buckets = 1024;
  u32 static_mapping_memory_size = 1<<15;
  u32 nat64_bib_buckets = 128;
  u32 nat64_bib_memory_size = 1 << 15;
  u32 nat64_st_buckets = 128;
  u32 nat64_st_memory_size = 1 << 15;
  u8 static_mapping_only = 0;
  u8 static_mapping_connection_tracking = 0;
  snat_main_per_thread_data_t *tsm;
  dslite_main_t * dm = &dslite_main;

  sm->deterministic = 0;
  sm->out2in_dpo = 0;

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
      else if (unformat (input, "nat64 bib hash buckets %d",
                         &nat64_bib_buckets))
        ;
      else if (unformat (input, "nat64 bib hash memory %d",
                         &nat64_bib_memory_size))
        ;
      else if (unformat (input, "nat64 st hash buckets %d", &nat64_st_buckets))
        ;
      else if (unformat (input, "nat64 st hash memory %d",
                         &nat64_st_memory_size))
        ;
      else if (unformat (input, "out2in dpo"))
        sm->out2in_dpo = 1;
      else if (unformat (input, "dslite ce"))
        dslite_set_ce(dm, 1);
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

  nat64_set_hash(nat64_bib_buckets, nat64_bib_memory_size, nat64_st_buckets,
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
                  format_ip4_address, &sess->in2out.addr,
                  clib_net_to_host_u16 (sess->in2out.port),
                  sess->in2out.fib_index);
      s = format (s, "    o2i %U proto %u fib %u\n",
                  format_ip4_address, &sess->out2in.addr,
                  clib_net_to_host_u16 (sess->out2in.port),
                  sess->out2in.fib_index);
    }
  else
    {
      s = format (s, "  i2o %U\n", format_snat_key, &sess->in2out);
      s = format (s, "    o2i %U\n", format_snat_key, &sess->out2in);
    }
  if (is_twice_nat_session (sess))
    {
      s = format (s, "       external host o2i %U:%d i2o %U:%d\n",
                  format_ip4_address, &sess->ext_host_addr,
                  clib_net_to_host_u16 (sess->ext_host_port),
                  format_ip4_address, &sess->ext_host_nat_addr,
                  clib_net_to_host_u16 (sess->ext_host_nat_port));
    }
  else
    {
      if (sess->ext_host_addr.as_u32)
          s = format (s, "       external host %U\n",
                      format_ip4_address, &sess->ext_host_addr);
    }
  s = format (s, "       last heard %.2f\n", sess->last_heard);
  s = format (s, "       total pkts %d, total bytes %lld\n",
              sess->total_pkts, sess->total_bytes);
  if (snat_is_session_static (sess))
    s = format (s, "       static translation\n");
  else
    s = format (s, "       dynamic translation\n");
  if (sess->flags & SNAT_SESSION_FLAG_LOAD_BALANCING)
    s = format (s, "       load-balancing\n");
  if (is_twice_nat_session (sess))
    s = format (s, "       twice-nat\n");

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
      s = format (s, "local %U external %U vrf %d %s",
                  format_ip4_address, &m->local_addr,
                  format_ip4_address, &m->external_addr,
                  m->vrf_id, m->twice_nat ? "twice-nat" : "");
  else
   {
      if (vec_len (m->locals))
        {
          s = format (s, "%U vrf %d external %U:%d %s %s",
                      format_snat_protocol, m->proto,
                      m->vrf_id,
                      format_ip4_address, &m->external_addr, m->external_port,
                      m->twice_nat ? "twice-nat" : "",
                      m->out2in_only ? "out2in-only" : "");
          vec_foreach (local, m->locals)
            s = format (s, "\n  local %U:%d probability %d\%",
                        format_ip4_address, &local->addr, local->port,
                        local->probability);
        }
      else
        s = format (s, "%U local %U:%d external %U:%d vrf %d %s %s",
                    format_snat_protocol, m->proto,
                    format_ip4_address, &m->local_addr, m->local_port,
                    format_ip4_address, &m->external_addr, m->external_port,
                    m->vrf_id, m->twice_nat ? "twice-nat" : "",
                    m->out2in_only ? "out2in-only" : "");
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
                  format_vnet_sw_if_index_name, vnm, m->sw_if_index,
                  m->vrf_id);
  else
      s = format (s, "%U local %U:%d external %U:%d vrf %d",
                  format_snat_protocol, m->proto,
                  format_ip4_address, &m->l_addr, m->l_port,
                  format_vnet_sw_if_index_name, vnm, m->sw_if_index,
                  m->e_port, m->vrf_id);

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
  ip4_address_t l_addr;
  int i, j;
  int rv;
  u8 twice_nat = 0;
  snat_address_t *addresses = sm->addresses;

  for (i = 0; i < vec_len(sm->auto_add_sw_if_indices); i++)
    {
      if (sw_if_index == sm->auto_add_sw_if_indices[i])
          goto match;
    }

  for (i = 0; i < vec_len(sm->auto_add_sw_if_indices_twice_nat); i++)
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
      for (j = 0; j < vec_len(addresses); j++)
        if (addresses[j].addr.as_u32 == address->as_u32)
          return;

      snat_add_address (sm, address, ~0, twice_nat);
      /* Scan static map resolution vector */
      for (j = 0; j < vec_len (sm->to_resolve); j++)
        {
          rp = sm->to_resolve + j;
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
                                            ~0 /* sw_if_index */,
                                            rp->proto,
                                            rp->is_add,
                                            0, 0, rp->tag);
              if (rv)
                clib_warning ("snat_add_static_mapping returned %d",
                              rv);
              vec_free (rp->tag);
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
      (void) snat_del_address(sm, address[0], 1, twice_nat);
      return;
    }
}


int snat_add_interface_address (snat_main_t *sm, u32 sw_if_index, int is_del,
                                u8 twice_nat)
{
  ip4_main_t * ip4_main = sm->ip4_main;
  ip4_address_t * first_int_addr;
  snat_static_map_resolve_t *rp;
  u32 *indices_to_delete = 0;
  int i, j;
  u32 *auto_add_sw_if_indices =
    twice_nat ? sm->auto_add_sw_if_indices_twice_nat : sm->auto_add_sw_if_indices;

  first_int_addr = ip4_interface_first_address (ip4_main, sw_if_index,
                                                0 /* just want the address*/);

  for (i = 0; i < vec_len(auto_add_sw_if_indices); i++)
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
                  if (vec_len(indices_to_delete))
                    {
                      for (j = vec_len(indices_to_delete)-1; j >= 0; j--)
                        vec_del1(sm->to_resolve, j);
                      vec_free(indices_to_delete);
                    }
                }
              if (twice_nat)
                vec_del1(sm->auto_add_sw_if_indices_twice_nat, i);
              else
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
  if (twice_nat)
    vec_add1(sm->auto_add_sw_if_indices_twice_nat, sw_if_index);
  else
    vec_add1(sm->auto_add_sw_if_indices, sw_if_index);

  /* If the address is already bound - or static - add it now */
  if (first_int_addr)
      snat_add_address (sm, first_int_addr, ~0, twice_nat);

  return 0;
}

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

void
nat_set_alloc_addr_and_port_mape (u16 psid, u16 psid_offset, u16 psid_length)
{
  snat_main_t *sm = &snat_main;

  sm->alloc_addr_and_port = nat_alloc_addr_and_port_mape;
  sm->psid = psid;
  sm->psid_offset = psid_offset;
  sm->psid_length = psid_length;
}

void
nat_set_alloc_addr_and_port_default (void)
{
  snat_main_t *sm = &snat_main;

  sm->alloc_addr_and_port = nat_alloc_addr_and_port_default;
}

