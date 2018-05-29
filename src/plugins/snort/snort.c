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

#include <vnet/ip/ip.h>
#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>
#include <memif/memif.h>
#include <memif/private.h>
#include <snort/snort.h>
#include <vnet/ip/ip4.h>

static snort_main_t snort_main;

snort_main_t *
snort_get_main (void)
{
  return &snort_main;
}

u32
snort_interface_index (snort_interface_t *sif)
{
  return (sif - snort_main.interfaces);
}

snort_interface_t *
snort_interface_get (u32 sif_index)
{
  return pool_elt_at_index (snort_main.interfaces, sif_index);
}

snort_interface_t *
snort_interface_lookup (u32 sw_if_index)
{
  snort_main_t *sm = &snort_main;
  if (sw_if_index >= vec_len (sm->snort_iface_by_sw_if_index))
    return 0;

  u32 sif_index = sm->snort_iface_by_sw_if_index[sw_if_index];
  return pool_elt_at_index (sm->interfaces, sif_index);
}

snort_interface_t *
snort_interface_alloc (void)
{
  snort_interface_t *sif;
  pool_get (snort_main.interfaces, sif);
  memset (sif, 0, sizeof (*sif));
  return sif;
}

void
snort_interface_free (snort_interface_t *sif)
{
  if (CLIB_DEBUG)
    memset (sif, 0xfb, sizeof (*sif));
  pool_put (snort_main.interfaces, sif);
}

clib_error_t *
snort_interface_add_del (snort_interface_add_del_args_t *a)
{
  snort_main_t *sm = &snort_main;
  snort_interface_t *sif;

  sif = snort_interface_lookup (a->sw_if_index);
  if (a->is_add)
    {
      if (sif)
	{
	  clib_warning ("Snort already enabled on interface: %u",
		        a->sw_if_index);
	  return 0;
	}
      sif = snort_interface_alloc ();
      sif->sw_if_index = a->sw_if_index;
      vec_validate (sm->snort_iface_by_sw_if_index, a->sw_if_index);
      sm->snort_iface_by_sw_if_index[a->sw_if_index] = snort_interface_index (
	  sif);
      vnet_feature_enable_disable ("ip4-unicast", "snort-input", a->sw_if_index,
	                           1, 0, 0);
    }
  else
    {
      if (!sif)
	return clib_error_return_code(0, -1, 0,
	                              "Snort not enabled on interface: %u",
	                              a->sw_if_index);
      vnet_feature_enable_disable ("ip4-unicast", "snort-input", a->sw_if_index, 0, 0,
	                           0);
      sm->snort_iface_by_sw_if_index[a->sw_if_index] = ~0;
      snort_interface_free (sif);
    }
  return 0;
}

snort_flow_t *
snort_interface_get_flow (snort_interface_t *sif, u32 sf_index)
{
  return pool_elt_at_index(sif->flows, sf_index);
}

VNET_FEATURE_INIT (snort_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "snort-input",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-dhcp-client-detect",
                               "nat44-out2in",
                               "nat44-in2out"),
};

#define foreach_snort_error                       	\
  _(NONE, "No error")

typedef enum {
#define _(sym,str) SNORT_ERROR_##sym,
  foreach_snort_error
#undef _
  SNORT_N_ERROR,
} snort_error_t;

static char * snort_error_strings[] = {
#define _(sym,string) string,
  foreach_snort_error
#undef _
};

#define foreach_snort_next				\
  _(DROP, "error-drop")					\
  _(INSPECT, "interface-output")			\

typedef enum _snort_next
{
#define _(s,n) SNORT_NEXT_##s,
  foreach_snort_next
#undef _
  SNORT_N_NEXT,
} snort_next_t;

u8 *
format_snort_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  /* TODO */
  return s;
}

static void
snort_make_kv4 (clib_bihash_kv_16_8_t *kv, ip4_address_t *src,
                ip4_address_t *dst, u16 src_port, u16 dst_port, u8 proto)
{
  v4_flow_key_t *key;
  key = (v4_flow_key_t *) &kv->key;
  key->src.as_u32 = src->as_u32;
  key->dst.as_u32 = dst->as_u32;
  key->proto = proto;
  key->src_port = src_port;
  key->dst_port = dst_port;
  kv->value = ~0ULL;
}

static void
snort_make_kv6 (clib_bihash_kv_48_8_t *kv, ip6_address_t *src,
                ip6_address_t *dst, u16 src_port, u16 dst_port, u8 proto)
{
  v6_flow_key_t *key;
  key = (v6_flow_key_t *) &kv->key;
  key->src.as_u64[0] = src->as_u64[0];
  key->src.as_u64[1] = src->as_u64[1];
  key->dst.as_u64[0] = dst->as_u64[0];
  key->dst.as_u64[1] = dst->as_u64[1];
  key->proto = proto;
  key->src_port = src_port;
  key->dst_port = dst_port;
  kv->value = ~0ULL;
}

static inline snort_flow_t *
snort_interface_flow_lookup_w_ih (snort_main_t *sm, snort_interface_t *sif,
                                  void *ih, u8 is_ip4)
{
  u16 src_port = 0, dst_port = 0;
  udp_header_t *uh;
  if (is_ip4)
    {
      ip4_header_t *ih4 = (ip4_header_t *)ih;
      clib_bihash_kv_16_8_t kv;

      if (ih4->protocol == IP_PROTOCOL_TCP
	  || ih4->protocol == IP_PROTOCOL_UDP)
	{
	  uh = ip4_next_header (ih4);
	  src_port = uh->src_port;
	  dst_port = uh->dst_port;
	}
      snort_make_kv4 (&kv, &ih4->src_address, &ih4->dst_address,
	              src_port, dst_port, ih4->protocol);
      if (clib_bihash_search_inline_16_8 (&sm->v4_flow_hash, &kv) == 0)
        return snort_interface_get_flow (sif, kv.value);
    }
  else
    {
      ip6_header_t *ih6 = (ip6_header_t *)ih;
      clib_bihash_kv_48_8_t kv;
      if (ih6->protocol == IP_PROTOCOL_TCP
	  || ih6->protocol == IP_PROTOCOL_UDP)
	{
	  uh = ip6_next_header (ih6);
	  src_port = uh->src_port;
	  dst_port = uh->dst_port;
	}
      snort_make_kv6 (&kv, &ih6->src_address, &ih6->dst_address,
	              uh->src_port, uh->dst_port, ih6->protocol);
      if (clib_bihash_search_inline_48_8 (&sm->v6_flow_hash, &kv) == 0)
        return snort_interface_get_flow (sif, kv.value);
    }
  return 0;
}

snort_flow_t *
snort_interface_flow_alloc (snort_interface_t *sif)
{
  snort_flow_t *sf;
  pool_get (sif->flows, sf);
  memset (sf, 0, sizeof (*sf));
  sf->action = SNORT_ACTION_INSPECT;
  return sf;
}

void
snort_interface_flow_free (snort_interface_t *sif, snort_flow_t *sf)
{
  pool_put (sif->flows, sf);
  if (CLIB_DEBUG)
    memset (sf, 0xf2, sizeof (*sf));
}

u32
snort_interface_flow_index (snort_interface_t *sif, snort_flow_t *sf)
{
  return (sf - sif->flows);
}

clib_error_t *
snort_interface_flow_add_del (snort_interface_flow_add_del_args_t *a)
{
  snort_main_t *sm = &snort_main;
  snort_interface_t *sif;
  snort_flow_id_t *fi = &a->flow_id;
  snort_flow_t *sf;
  int rv = 0;

  if (!(sif = snort_interface_lookup (a->sw_if_index)))
    return clib_error_return_code(0, -1, 0, "unkown snort interface %u",
	                          a->sw_if_index);

  if (fi->is_ip4)
    {
      clib_bihash_kv_16_8_t kv;
      snort_make_kv4 (&kv, &fi->v4.src, &fi->v4.dst,
                      fi->v4.src_port, fi->v4.dst_port, fi->v4.proto);
      if (clib_bihash_search_inline_16_8 (&sm->v4_flow_hash, &kv) == 0)
	{
	  sf = snort_interface_get_flow (sif, (u32) kv.value);
	  sf->action = a->action;
	}
      else
	{
	  sf = snort_interface_flow_alloc (sif);
	  sf->action = a->action;
	  kv.value = snort_interface_flow_index (sif, sf);
	  rv = clib_bihash_add_del_16_8 (&sm->v4_flow_hash, &kv, a->is_add);
	}
    }
  else
    {
      clib_bihash_kv_48_8_t kv;
      snort_make_kv6 (&kv, &fi->v6.src, &fi->v6.dst,
                      fi->v6.src_port, fi->v6.dst_port, fi->v6.proto);
      if (clib_bihash_search_inline_48_8 (&sm->v6_flow_hash, &kv) == 0)
	{
	  sf = snort_interface_get_flow (sif, (u32) kv.value);
	  sf->action = a->action;
	}
      else
	{
	  sf = snort_interface_flow_alloc (sif);
	  sf->action = a->action;
	  kv.value = snort_interface_flow_index (sif, sf);
	  rv = clib_bihash_add_del_48_8 (&sm->v6_flow_hash, &kv, a->is_add);
	}
    }

  if (rv)
    {
      snort_interface_flow_free (sif, sf);
      return clib_error_return_code(0, -1, 0, "failed to add flow: %u", rv);
    }
  sf->id = a->flow_id;
  return 0;
}

static uword
snort_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, * from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  snort_main_t *sm = &snort_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 4)
    {
      u32 next0, next1, sw_if_index0, sw_if_index1;
      snort_interface_t *sif0, *sif1;
      snort_flow_t *flow0, *flow1;
      void *data0, *data1;
      
      {
	vlib_prefetch_buffer_header (b[2], LOAD);
	vlib_prefetch_buffer_header (b[3], LOAD);

	CLIB_PREFETCH (b[2]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	CLIB_PREFETCH (b[3]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      }
      
      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      sw_if_index1 = vnet_buffer (b[1])->sw_if_index[VLIB_RX];

      sif0 = snort_interface_lookup (sw_if_index0);
      sif1 = snort_interface_lookup (sw_if_index1);

      flow0 = snort_interface_flow_lookup_w_ih (sm, sif0,
	                                        vlib_buffer_get_current (b[0]),
	                                        1);
      flow1 = snort_interface_flow_lookup_w_ih (sm, sif1,
	                                        vlib_buffer_get_current (b[1]),
	                                        1);

      if (flow0)
	{
	  if (flow0->action == SNORT_ACTION_FWD)
	    vnet_feature_next (sw_if_index0, &next0, b[0]);
	  else
	    next0 = SNORT_NEXT_DROP;
	}
      else
	{
	  next0 = SNORT_NEXT_INSPECT;
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = sm->sw_if_index;
	  b[0]->current_data -= sizeof (u32);
	  b[0]->current_length += sizeof (u32);
	  data0 = vlib_buffer_get_current(b[0]);
	  *(u32 *) data0 = sw_if_index0;
	}
      if (flow1)
	{
	  if (flow1->action == SNORT_ACTION_FWD)
	    vnet_feature_next (sw_if_index1, &next1, b[1]);
	  else
	    next1 = SNORT_NEXT_DROP;
	}
      else
	{
	  next1 = SNORT_NEXT_INSPECT;
	  vnet_buffer (b[1])->sw_if_index[VLIB_TX] = sm->sw_if_index;
	  b[1]->current_data -= sizeof (u32);
	  b[1]->current_length += sizeof (u32);
	  data1 = vlib_buffer_get_current(b[1]);
	  *(u32 *) data1 = sw_if_index1;
	}

      next[0] = next0;
      next[1] = next1;

      b += 2;
      next += 2;
      n_left_from -= 2;
    }
  while (n_left_from)
    {
      u32 next0, sw_if_index0;
      snort_interface_t *sif0;
      snort_flow_t *flow0;
      void *data0;

      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      sif0 = snort_interface_lookup (sw_if_index0);
      flow0 = snort_interface_flow_lookup_w_ih (sm, sif0,
	                                        vlib_buffer_get_current (b[0]),
	                                        1);
      if (flow0)
	{
	  if (flow0->action == SNORT_ACTION_FWD)
	    vnet_feature_next (sw_if_index0, &next0, b[0]);
	  else
	    next0 = SNORT_NEXT_DROP;
	}
      else
	{
	  next0 = SNORT_NEXT_INSPECT;
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = sm->sw_if_index;
	  b[0]->current_data -= sizeof (u32);
	  b[0]->current_length += sizeof (u32);
	  data0 = vlib_buffer_get_current(b[0]);
	  *(u32 *) data0 = sw_if_index0;
	}

      next[0] = next0;
      b += 1;
      next += 1;
      n_left_from -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

vlib_node_registration_t snort_input_node;

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (snort_input_node) = {
  .function = snort_input_fn,
  .name = "snort-input",
  .vector_size = sizeof (u32),
  .format_trace = format_snort_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(snort_error_strings),
  .error_strings = snort_error_strings,
  .n_next_nodes = SNORT_N_NEXT,
  .next_nodes = {
#define _(s,n) [SNORT_NEXT_##s] = n,
      foreach_snort_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (snort_input_node, snort_input_fn);

#define MEMIF_IFACE_RX_QUEUES 1
#define MEMIF_IFACE_TX_QUEUES 1
#define MEMIF_IFACE_BUFFER_SIZE 2048
#define MEMIF_IFACE_RING_SIZE 1024

clib_error_t *
snort_enable_disable (snort_enable_disable_args_t *a)
{
  snort_main_t *sm = snort_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;

  if (a->is_en)
    {
      sm->sw_if_index = a->sw_if_index;
      vnet_sw_interface_set_flags (vnm, sm->sw_if_index,
                                   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
      ip4_address_t intf_addr = {.as_u8 = {192, 168, 1, 1}};
      ip4_add_del_interface_address (vlib_get_main (), a->sw_if_index,
				     &intf_addr, 24, 0);
    }
  else
    {
      if (!sm->is_enabled)
	return clib_error_return_code (0, -1, 0, "failed to disable: %d", -1);

      vnet_sw_interface_set_flags (vnm, sm->sw_if_index, 0);
      sm->sw_if_index = ~0;
      /* TBD disable all features */
    }
  sm->is_enabled = a->is_en;

  return error;
}

static clib_error_t *
snort_init (vlib_main_t * vm)
{
  snort_main_t *sm = &snort_main;
  clib_error_t *error;

  if ((error = vlib_call_plugin_init_function (vm, "memif_plugin.so",
                                               memif_init)))
    return error;

  snort_plugin_api_hookup (vm);

  clib_bihash_init_16_8 (&sm->v4_flow_hash, "v4 flow table", 20000, 64 << 20);
  clib_bihash_init_48_8 (&sm->v6_flow_hash, "v6 flow table", 20000, 64 << 20);

  return 0;
}

VLIB_INIT_FUNCTION (snort_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Snort Adapter Plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
