/*
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

#include <ila/ila.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/lookup.h>
#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_table.h>
#include <vpp/app/version.h>

static ila_main_t ila_main;

#define ILA_TABLE_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define ILA_TABLE_DEFAULT_HASH_MEMORY_SIZE (32<<20)

#define foreach_ila_error \
 _(NONE, "valid ILA packets")

typedef enum {
#define _(sym,str) ILA_ERROR_##sym,
  foreach_ila_error
#undef _
    ILA_N_ERROR,
} ila_error_t;

static char *ila_error_strings[] = {
#define _(sym,string) string,
  foreach_ila_error
#undef _
};

typedef enum {
  ILA_ILA2SIR_NEXT_DROP,
  ILA_ILA2SIR_N_NEXT,
} ila_ila2sir_next_t;

typedef struct {
  u32 ila_index;
  ip6_address_t initial_dst;
  u32 adj_index;
} ila_ila2sir_trace_t;

static ila_entry_t ila_sir2ila_default_entry = {
  .csum_mode = ILA_CSUM_MODE_NO_ACTION,
  .type = ILA_TYPE_IID,
  .dir = ILA_DIR_ILA2SIR, //Will pass the packet with no
};

/**
 * @brief Dynamically registered DPO Type for ILA
 */
static dpo_type_t ila_dpo_type;

/**
 * @brief Dynamically registered FIB node type for ILA
 */
static fib_node_type_t ila_fib_node_type;

/**
 * FIB source for adding entries
 */
static fib_source_t ila_fib_src;

u8 *
format_half_ip6_address (u8 * s, va_list * va)
{
  u64 v = clib_net_to_host_u64 (va_arg (*va, u64));

  return format (s, "%04x:%04x:%04x:%04x",
		 v >> 48, (v >> 32) & 0xffff, (v >> 16) & 0xffff, v & 0xffff);

}

u8 *
format_ila_direction (u8 * s, va_list * args)
{
  ila_direction_t t = va_arg (*args, ila_direction_t);
#define _(i,n,st) \
  if (t == ILA_DIR_##i) \
    return format(s, st);
  ila_foreach_direction
#undef _
    return format (s, "invalid_ila_direction");
}

static u8 *
format_csum_mode (u8 * s, va_list * va)
{
  ila_csum_mode_t csum_mode = va_arg (*va, ila_csum_mode_t);
  char *txt;

  switch (csum_mode)
    {
#define _(i,n,st) \
  case ILA_CSUM_MODE_##i: \
    txt = st; \
    break;
      ila_csum_foreach_type
#undef _
    default:
      txt = "invalid_ila_csum_mode";
      break;
    }
  return format (s, txt);
}

u8 *
format_ila_type (u8 * s, va_list * args)
{
  ila_type_t t = va_arg (*args, ila_type_t);
#define _(i,n,st) \
  if (t == ILA_TYPE_##i) \
    return format(s, st);
  ila_foreach_type
#undef _
    return format (s, "invalid_ila_type");
}

static u8 *
format_ila_entry (u8 * s, va_list * va)
{
  vnet_main_t *vnm = va_arg (*va, vnet_main_t *);
  ila_entry_t *e = va_arg (*va, ila_entry_t *);

  if (!e)
    {
      return format (s, "%-15s%=40s%=40s%+16s%+18s%+11s", "Type", "SIR Address",
		     "ILA Address", "Checksum Mode", "Direction", "Next DPO");
    }
  else if (vnm)
    {
      if (ip6_address_is_zero(&e->next_hop))
	{
	  return format (s, "%-15U%=40U%=40U%18U%11U%s",
			 format_ila_type, e->type,
			 format_ip6_address, &e->sir_address,
			 format_ip6_address, &e->ila_address,
			 format_csum_mode, e->csum_mode,
			 format_ila_direction, e->dir,
			 "n/a");
	}
      else
	{
	  return format (s, "%-15U%=40U%=40U%18U%11U%U",
			 format_ila_type, e->type,
			 format_ip6_address, &e->sir_address,
			 format_ip6_address, &e->ila_address,
			 format_csum_mode, e->csum_mode,
			 format_ila_direction, e->dir,
			 format_dpo_id, &e->ila_dpo, 0);
	}
    }

  return NULL;
}

u8 *
format_ila_ila2sir_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ila_ila2sir_trace_t *t = va_arg (*args, ila_ila2sir_trace_t *);
  return format (s,
		 "ILA -> SIR adj index: %d entry index: %d initial_dst: %U",
		 t->adj_index, t->ila_index, format_ip6_address,
		 &t->initial_dst);
}

static uword
unformat_ila_direction (unformat_input_t * input, va_list * args)
{
  ila_direction_t *result = va_arg (*args, ila_direction_t *);
#define _(i,n,s) \
  if (unformat(input, s)) \
      { \
        *result = ILA_DIR_##i; \
        return 1;\
      }

  ila_foreach_direction
#undef _
    return 0;
}

static uword
unformat_ila_type (unformat_input_t * input, va_list * args)
{
  ila_type_t *result = va_arg (*args, ila_type_t *);
#define _(i,n,s) \
  if (unformat(input, s)) \
      { \
        *result = ILA_TYPE_##i; \
        return 1;\
      }

  ila_foreach_type
#undef _
    return 0;
}

static uword
unformat_ila_csum_mode (unformat_input_t * input, va_list * args)
{
  ila_csum_mode_t *result = va_arg (*args, ila_csum_mode_t *);
  if (unformat (input, "none") || unformat (input, "no-action"))
    {
      *result = ILA_CSUM_MODE_NO_ACTION;
      return 1;
    }
  if (unformat (input, "neutral-map"))
    {
      *result = ILA_CSUM_MODE_NEUTRAL_MAP;
      return 1;
    }
  if (unformat (input, "adjust-transport"))
    {
      *result = ILA_CSUM_MODE_ADJUST_TRANSPORT;
      return 1;
    }
  return 0;
}

static uword
unformat_half_ip6_address (unformat_input_t * input, va_list * args)
{
  u64 *result = va_arg (*args, u64 *);
  u32 a[4];

  if (!unformat (input, "%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3]))
    return 0;

  if (a[0] > 0xFFFF || a[1] > 0xFFFF || a[2] > 0xFFFF || a[3] > 0xFFFF)
    return 0;

  *result = clib_host_to_net_u64 ((((u64) a[0]) << 48) |
				  (((u64) a[1]) << 32) |
				  (((u64) a[2]) << 16) | (((u64) a[3])));

  return 1;
}

static vlib_node_registration_t ila_ila2sir_node;

static uword
ila_ila2sir (vlib_main_t * vm,
	     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  ila_main_t *ilm = &ila_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 pi0, pi1;
	  vlib_buffer_t *p0, *p1;
	  ila_entry_t *ie0, *ie1;
	  ip6_header_t *ip60, *ip61;
	  ip6_address_t *sir_address0, *sir_address1;

	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	    CLIB_PREFETCH (p2->data, sizeof (ip6_header_t), LOAD);
	    CLIB_PREFETCH (p3->data, sizeof (ip6_header_t), LOAD);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);
	  ip60 = vlib_buffer_get_current (p0);
	  ip61 = vlib_buffer_get_current (p1);
	  sir_address0 = &ip60->dst_address;
	  sir_address1 = &ip61->dst_address;
	  ie0 = pool_elt_at_index (ilm->entries,
				   vnet_buffer (p0)->ip.adj_index);
	  ie1 = pool_elt_at_index (ilm->entries,
				   vnet_buffer (p1)->ip.adj_index);

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ila_ila2sir_trace_t *tr =
		vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->ila_index = ie0 - ilm->entries;
	      tr->initial_dst = ip60->dst_address;
	      tr->adj_index = vnet_buffer (p0)->ip.adj_index;
	    }

	  if (PREDICT_FALSE (p1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ila_ila2sir_trace_t *tr =
		vlib_add_trace (vm, node, p1, sizeof (*tr));
	      tr->ila_index = ie1 - ilm->entries;
	      tr->initial_dst = ip61->dst_address;
	      tr->adj_index = vnet_buffer (p1)->ip.adj_index;
	    }

	  sir_address0 = (ie0->dir != ILA_DIR_SIR2ILA) ? &ie0->sir_address : sir_address0;
	  sir_address1 = (ie1->dir != ILA_DIR_SIR2ILA) ? &ie1->sir_address : sir_address1;
	  ip60->dst_address.as_u64[0] = sir_address0->as_u64[0];
	  ip60->dst_address.as_u64[1] = sir_address0->as_u64[1];
	  ip61->dst_address.as_u64[0] = sir_address1->as_u64[0];
	  ip61->dst_address.as_u64[1] = sir_address1->as_u64[1];

	  vnet_buffer (p0)->ip.adj_index = ie0->ila_dpo.dpoi_index;
	  vnet_buffer (p1)->ip.adj_index = ie1->ila_dpo.dpoi_index;

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, pi1,
					   ie0->ila_dpo.dpoi_next_node,
					   ie1->ila_dpo.dpoi_next_node);
	}

      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  ila_entry_t *ie0;
	  ip6_header_t *ip60;
	  ip6_address_t *sir_address0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current (p0);
	  sir_address0 = &ip60->dst_address;
	  ie0 = pool_elt_at_index (ilm->entries,
				   vnet_buffer (p0)->ip.adj_index);

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ila_ila2sir_trace_t *tr =
		vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->ila_index = ie0 ? (ie0 - ilm->entries) : ~0;
	      tr->initial_dst = ip60->dst_address;
	      tr->adj_index = vnet_buffer (p0)->ip.adj_index;
	    }

	  sir_address0 = (ie0->dir != ILA_DIR_SIR2ILA) ? &ie0->sir_address : sir_address0;
	  ip60->dst_address.as_u64[0] = sir_address0->as_u64[0];
	  ip60->dst_address.as_u64[1] = sir_address0->as_u64[1];
	  vnet_buffer (p0)->ip.adj_index = ie0->ila_dpo.dpoi_index;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0,
					   ie0->ila_dpo.dpoi_next_node);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/** *INDENT-OFF* */
VLIB_REGISTER_NODE (ila_ila2sir_node, static) =
{
  .function = ila_ila2sir,
  .name = "ila-to-sir",
  .vector_size = sizeof (u32),
  .format_trace = format_ila_ila2sir_trace,
  .n_errors = ILA_N_ERROR,
  .error_strings = ila_error_strings,
  .n_next_nodes = ILA_ILA2SIR_N_NEXT,
  .next_nodes =
  {
      [ILA_ILA2SIR_NEXT_DROP] = "error-drop"
  },
};
/** *INDENT-ON* */

typedef enum
{
  ILA_SIR2ILA_NEXT_DROP,
  ILA_SIR2ILA_N_NEXT,
} ila_sir2ila_next_t;

typedef struct
{
  u32 ila_index;
  ip6_address_t initial_dst;
} ila_sir2ila_trace_t;

u8 *
format_ila_sir2ila_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ila_sir2ila_trace_t *t = va_arg (*args, ila_sir2ila_trace_t *);

  return format (s, "SIR -> ILA entry index: %d initial_dst: %U",
		 t->ila_index, format_ip6_address, &t->initial_dst);
}

static vlib_node_registration_t ila_sir2ila_node;

static uword
ila_sir2ila (vlib_main_t * vm,
	     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  ila_main_t *ilm = &ila_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 pi0, pi1;
	  vlib_buffer_t *p0, *p1;
	  ip6_header_t *ip60, *ip61;
	  u32 next0 = ILA_SIR2ILA_NEXT_DROP;
	  u32 next1 = ILA_SIR2ILA_NEXT_DROP;
	  BVT (clib_bihash_kv) kv0, value0;
	  BVT (clib_bihash_kv) kv1, value1;
	  ila_entry_t *ie0 = &ila_sir2ila_default_entry;
	  ila_entry_t *ie1 = &ila_sir2ila_default_entry;
	  ip6_address_t *ila_address0, *ila_address1;

	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	    CLIB_PREFETCH (p2->data, sizeof (ip6_header_t), LOAD);
	    CLIB_PREFETCH (p3->data, sizeof (ip6_header_t), LOAD);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);
	  ip60 = vlib_buffer_get_current (p0);
	  ip61 = vlib_buffer_get_current (p1);
	  ila_address0 = &ip60->dst_address;
	  ila_address1 = &ip61->dst_address;
	  kv0.key[0] = ip60->dst_address.as_u64[0];
	  kv0.key[1] = ip60->dst_address.as_u64[1];
	  kv0.key[2] = 0;
	  kv1.key[0] = ip61->dst_address.as_u64[0];
	  kv1.key[1] = ip61->dst_address.as_u64[1];
	  kv1.key[2] = 0;

	  if (PREDICT_TRUE((BV (clib_bihash_search)
	      (&ilm->id_to_entry_table, &kv0, &value0)) == 0)) {
	      ie0 = &ilm->entries[value0.value];
	      ila_address0 = (ie0->dir != ILA_DIR_ILA2SIR) ? &ie0->ila_address : ila_address0;
	  }

	  if ((BV (clib_bihash_search)
	       (&ilm->id_to_entry_table, &kv1, &value1)) == 0) {
	    ie1 = &ilm->entries[value1.value];
	    ila_address1 = (ie1->dir != ILA_DIR_ILA2SIR) ? &ie1->ila_address : ila_address1;
	  }

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ila_sir2ila_trace_t *tr =
		vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->ila_index =
		(ie0 != &ila_sir2ila_default_entry) ? (ie0 - ilm->entries) : ~0;
	      tr->initial_dst = ip60->dst_address;
	    }

	  if (PREDICT_FALSE (p1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ila_sir2ila_trace_t *tr =
		vlib_add_trace (vm, node, p1, sizeof (*tr));
	      tr->ila_index =
		(ie1 != &ila_sir2ila_default_entry) ? (ie1 - ilm->entries) : ~0;
	      tr->initial_dst = ip61->dst_address;
	    }

	  ip60->dst_address.as_u64[0] = ila_address0->as_u64[0];
	  ip60->dst_address.as_u64[1] = ila_address0->as_u64[1];
	  ip61->dst_address.as_u64[0] = ila_address1->as_u64[0];
	  ip61->dst_address.as_u64[1] = ila_address1->as_u64[1];

	  vnet_feature_next (&next0, p0);
	  vnet_feature_next (&next1, p1);

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, pi1, next0,
					   next1);
	}

      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  ip6_header_t *ip60;
	  u32 next0 = ILA_SIR2ILA_NEXT_DROP;
	  BVT (clib_bihash_kv) kv0, value0;
	  ila_entry_t *ie0 = &ila_sir2ila_default_entry;
	  ip6_address_t *ila_address0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current (p0);
	  ila_address0 = &ip60->dst_address;

	  kv0.key[0] = ip60->dst_address.as_u64[0];
	  kv0.key[1] = ip60->dst_address.as_u64[1];
	  kv0.key[2] = 0;

	  if (PREDICT_TRUE((BV (clib_bihash_search)
	       (&ilm->id_to_entry_table, &kv0, &value0)) == 0)) {
	    ie0 = &ilm->entries[value0.value];
	    ila_address0 = (ie0->dir != ILA_DIR_ILA2SIR) ? &ie0->ila_address : ila_address0;
	  }

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ila_sir2ila_trace_t *tr =
		vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->ila_index =
		(ie0 != &ila_sir2ila_default_entry) ? (ie0 - ilm->entries) : ~0;
	      tr->initial_dst = ip60->dst_address;
	    }

	  //This operation should do everything for any type (except vnid4 obviously)
	  ip60->dst_address.as_u64[0] = ila_address0->as_u64[0];
	  ip60->dst_address.as_u64[1] = ila_address0->as_u64[1];

	  vnet_feature_next (&next0, p0);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/** *INDENT-OFF* */
VLIB_REGISTER_NODE (ila_sir2ila_node, static) =
{
  .function = ila_sir2ila,.name = "sir-to-ila",
  .vector_size = sizeof (u32),
  .format_trace = format_ila_sir2ila_trace,
  .n_errors = ILA_N_ERROR,
  .error_strings = ila_error_strings,
  .n_next_nodes = ILA_SIR2ILA_N_NEXT,
  .next_nodes =
  {
      [ILA_SIR2ILA_NEXT_DROP] = "error-drop"
  },
};
/** *INDENT-ON* */

/** *INDENT-OFF* */
VNET_FEATURE_INIT (ila_sir2ila, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "sir-to-ila",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
/** *INDENT-ON* */

static void
ila_entry_stack (ila_entry_t *ie)
{
    /*
     * restack on the next-hop's FIB entry
     */
    dpo_stack(ila_dpo_type,
	      DPO_PROTO_IP6,
	      &ie->ila_dpo,
	      fib_entry_contribute_ip_forwarding(
		  ie->next_hop_fib_entry_index));
}

int
ila_add_del_entry (ila_add_del_entry_args_t * args)
{
  ila_main_t *ilm = &ila_main;
  BVT (clib_bihash_kv) kv, value;

  //Sanity check
  if (args->type == ILA_TYPE_IID || args->type == ILA_TYPE_LUID)
    {
      if ((args->sir_address.as_u8[8] >> 5) != args->type)
	{
	  clib_warning ("Incorrect SIR address (ILA type mismatch %d %d)",
			args->sir_address.as_u8[8] >> 1, args->type);
	  return -1;
	}
      if (args->sir_address.as_u8[8] & 0x10)
	{
	  clib_warning ("Checksum bit should not be set in SIR address");
	  return -1;
	}
    }
  else if (args->type == ILA_TYPE_VNIDM)
    {
      if (args->sir_address.as_u8[0] != 0xff ||
	  (args->sir_address.as_u8[1] & 0xf0) != 0xf0)
	{
	  clib_warning ("SIR multicast address must start with fff");
	  return -1;
	}
      if (args->sir_address.as_u16[1] || args->sir_address.as_u16[2] ||
	  args->sir_address.as_u16[3] || args->sir_address.as_u16[4] ||
	  args->sir_address.as_u16[5] || (args->sir_address.as_u8[12] & 0xf0))
	{
	  clib_warning ("SIR multicast address must start with fff");
	  return -1;
	}
    }

  if (!args->is_del)
    {
      ila_entry_t *e;
      pool_get (ilm->entries, e);
      e->type = args->type;
      e->sir_address = args->sir_address;
      e->next_hop = args->next_hop_address;
      e->csum_mode = args->csum_mode;
      e->dir = args->dir;

      //Construct ILA address
      switch (e->type)
	{
	case ILA_TYPE_IID:
	  e->ila_address = e->sir_address;
	  break;
	case ILA_TYPE_LUID:
	  e->ila_address.as_u64[0] = args->locator;
	  e->ila_address.as_u64[1] = args->sir_address.as_u64[1];
	  break;
	case ILA_TYPE_VNID6:
	  e->ila_address.as_u64[0] = args->locator;
	  e->ila_address.as_u8[8] = (ILA_TYPE_VNID6 << 1);
	  e->ila_address.as_u32[2] |= args->vnid;
	  e->ila_address.as_u32[3] = args->sir_address.as_u32[3];
	  break;
	case ILA_TYPE_VNIDM:
	  e->ila_address.as_u64[0] = args->locator;
	  e->ila_address.as_u8[8] = (ILA_TYPE_VNIDM << 1);
	  e->ila_address.as_u32[2] |= args->vnid;
	  e->ila_address.as_u32[3] = args->sir_address.as_u32[3];
	  e->ila_address.as_u8[12] |= args->sir_address.as_u8[2] << 4;
	  break;
	case ILA_TYPE_VNID4:
	  clib_warning ("ILA type '%U' is not supported", format_ila_type,
			e->type);
	  return -1;
	}

      //Modify ILA checksum if necessary
      if (e->csum_mode == ILA_CSUM_MODE_NEUTRAL_MAP)
	{
	  ip_csum_t csum = e->ila_address.as_u16[7];
	  int i;
	  for (i = 0; i < 4; i++)
	    {
	      csum = ip_csum_sub_even (csum, e->sir_address.as_u32[i]);
	      csum = ip_csum_add_even (csum, e->ila_address.as_u32[i]);
	    }
	  csum = ip_csum_add_even (csum, clib_host_to_net_u16 (0x1000));
	  e->ila_address.as_u16[7] = ip_csum_fold (csum);
	  e->ila_address.as_u8[8] |= 0x10;
	}

      //Create entry with the sir address
      kv.key[0] = e->sir_address.as_u64[0];
      kv.key[1] = e->sir_address.as_u64[1];
      kv.key[2] = 0;
      kv.value = e - ilm->entries;
      BV (clib_bihash_add_del) (&ilm->id_to_entry_table, &kv,
				1 /* is_add */ );

      if (!ip6_address_is_zero(&e->next_hop))
	{
	  /*
	   * become a child of the FIB netry for the next-hop
	   * so we are informed when its forwarding changes
	   */
	  fib_prefix_t next_hop = {
	      .fp_addr = {
		  .ip6 = e->next_hop,
	      },
	      .fp_len = 128,
	      .fp_proto = FIB_PROTOCOL_IP6,
	  };

	  e->next_hop_fib_entry_index = 
	      fib_table_entry_special_add(0,
					  &next_hop,
					  FIB_SOURCE_RR,
					  FIB_ENTRY_FLAG_NONE);
	  e->next_hop_child_index =
	      fib_entry_child_add(e->next_hop_fib_entry_index,
				  ila_fib_node_type,
				  e - ilm->entries);

	  /*
	   * Create a route that results in the ILA entry
	   */
	  dpo_id_t dpo = DPO_INVALID;
	  fib_prefix_t pfx = {
	      .fp_addr = {
		  .ip6 = e->ila_address,
	      },
	      .fp_len = 128,
	      .fp_proto = FIB_PROTOCOL_IP6,
	  };

	  dpo_set(&dpo, ila_dpo_type, DPO_PROTO_IP6, e - ilm->entries);

	  fib_table_entry_special_dpo_add(0,
					  &pfx,
					  ila_fib_src,
					  FIB_ENTRY_FLAG_EXCLUSIVE,
					  &dpo);
	  dpo_reset(&dpo);

	  /*
	   * finally stack the ILA entry so it will forward to the next-hop
	   */
	  ila_entry_stack (e);
	}
    }
  else
    {
      ila_entry_t *e;
      kv.key[0] = args->sir_address.as_u64[0];
      kv.key[1] = args->sir_address.as_u64[1];
      kv.key[2] = 0;

      if ((BV (clib_bihash_search) (&ilm->id_to_entry_table, &kv, &value) <
	   0))
	{
	  return -1;
	}

      e = &ilm->entries[value.value];

      if (!ip6_address_is_zero(&e->next_hop))
	{
	  fib_prefix_t pfx = {
	      .fp_addr = {
		  .ip6 = e->ila_address,
	      },
	      .fp_len = 128,
	      .fp_proto = FIB_PROTOCOL_IP6,
	  };

	  fib_table_entry_special_remove(0, &pfx, ila_fib_src);
	  /*
	   * remove this ILA entry as child of the FIB netry for the next-hop
	   */
	  fib_entry_child_remove(e->next_hop_fib_entry_index,
				 e->next_hop_child_index);
	  fib_table_entry_delete_index(e->next_hop_fib_entry_index,
				       FIB_SOURCE_RR);
	  e->next_hop_fib_entry_index = FIB_NODE_INDEX_INVALID;
	}
      dpo_reset (&e->ila_dpo);

      BV (clib_bihash_add_del) (&ilm->id_to_entry_table, &kv,
				0 /* is_add */ );
      pool_put (ilm->entries, e);
    }
  return 0;
}

int
ila_interface (u32 sw_if_index, u8 disable)
{
  vnet_feature_enable_disable ("ip4-unicast", "sir-to-ila", sw_if_index,
			       !disable, 0, 0);
  return 0;
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Identifier Locator Addressing (ILA) for IPv6",
};
/* *INDENT-ON* */

u8 *format_ila_dpo (u8 * s, va_list * va)
{
  index_t index = va_arg (*va, index_t);
  CLIB_UNUSED(u32 indent) = va_arg (*va, u32);
  ila_main_t *ilm = &ila_main;
  ila_entry_t *ie = pool_elt_at_index (ilm->entries, index);
  return format(s, "ILA: idx:%d sir:%U",
		index,
		format_ip6_address, &ie->sir_address);
}

/**
 * @brief no-op lock function.
 * The lifetime of the ILA entry is managed by the control plane
 */
static void
ila_dpo_lock (dpo_id_t *dpo)
{
}

/**
 * @brief no-op unlock function.
 * The lifetime of the ILA entry is managed by the control plane
 */
static void
ila_dpo_unlock (dpo_id_t *dpo)
{
}

const static dpo_vft_t ila_vft = {
    .dv_lock = ila_dpo_lock,
    .dv_unlock = ila_dpo_unlock,
    .dv_format = format_ila_dpo,
};
const static char* const ila_ip6_nodes[] =
{
    "ila-to-sir",
    NULL,
};
const static char* const * const ila_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP6]  = ila_ip6_nodes,
};

static fib_node_t *
ila_fib_node_get_node (fib_node_index_t index)
{
  ila_main_t *ilm = &ila_main;
  ila_entry_t *ie = pool_elt_at_index (ilm->entries, index);

  return (&ie->ila_fib_node);
}

/**
 * @brief no-op unlock function.
 * The lifetime of the ILA entry is managed by the control plane
 */
static void
ila_fib_node_last_lock_gone (fib_node_t *node)
{
}

static ila_entry_t *
ila_entry_from_fib_node (fib_node_t *node)
{
    return ((ila_entry_t*)(((char*)node) -
			   STRUCT_OFFSET_OF(ila_entry_t, ila_fib_node)));
}

/**
 * @brief
 * Callback function invoked when the forwarding changes for the ILA next-hop
 */
static fib_node_back_walk_rc_t
ila_fib_node_back_walk_notify (fib_node_t *node,
			       fib_node_back_walk_ctx_t *ctx)
{
    ila_entry_stack(ila_entry_from_fib_node(node));

    return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * ILA's FIB graph node virtual function table
 */
static const fib_node_vft_t ila_fib_node_vft = {
    .fnv_get = ila_fib_node_get_node,
    .fnv_last_lock = ila_fib_node_last_lock_gone,
    .fnv_back_walk = ila_fib_node_back_walk_notify,
};

clib_error_t *
ila_init (vlib_main_t * vm)
{
  ila_main_t *ilm = &ila_main;
  ilm->entries = NULL;

  ilm->lookup_table_nbuckets = ILA_TABLE_DEFAULT_HASH_NUM_BUCKETS;
  ilm->lookup_table_nbuckets = 1 << max_log2 (ilm->lookup_table_nbuckets);
  ilm->lookup_table_size = ILA_TABLE_DEFAULT_HASH_MEMORY_SIZE;

  BV (clib_bihash_init) (&ilm->id_to_entry_table,
			 "ila id to entry index table",
			 ilm->lookup_table_nbuckets, ilm->lookup_table_size);

  ila_dpo_type = dpo_register_new_type(&ila_vft, ila_nodes);
  ila_fib_node_type = fib_node_register_new_type(&ila_fib_node_vft);
  ila_fib_src = fib_source_allocate("ila",
                                    FIB_SOURCE_PRIORITY_HI,
                                    FIB_SOURCE_BH_SIMPLE);
  return NULL;
}

VLIB_INIT_FUNCTION (ila_init);

static clib_error_t *
ila_entry_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ila_add_del_entry_args_t args = { 0 };
  u8 next_hop_set = 0;
  int ret;
  clib_error_t *error = 0;

  args.type = ILA_TYPE_IID;
  args.csum_mode = ILA_CSUM_MODE_NO_ACTION;
  args.local_adj_index = ~0;
  args.dir = ILA_DIR_BIDIR;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "type %U", unformat_ila_type, &args.type))
	;
      else if (unformat
	       (line_input, "sir-address %U", unformat_ip6_address,
		&args.sir_address))
	;
      else if (unformat
	       (line_input, "locator %U", unformat_half_ip6_address,
		&args.locator))
	;
      else if (unformat
	       (line_input, "csum-mode %U", unformat_ila_csum_mode,
		&args.csum_mode))
	;
      else if (unformat (line_input, "vnid %x", &args.vnid))
	;
      else if (unformat
	       (line_input, "next-hop %U", unformat_ip6_address,
		&args.next_hop_address))
	;
      else if (unformat
	      (line_input, "direction %U", unformat_ila_direction, &args.dir))
        next_hop_set = 1;
      else if (unformat (line_input, "del"))
	args.is_del = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!next_hop_set)
    {
      error = clib_error_return (0, "Specified a next hop");
      goto done;
    }

  if ((ret = ila_add_del_entry (&args)))
    {
      error = clib_error_return (0, "ila_add_del_entry returned error %d", ret);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (ila_entry_command, static) =
{
  .path = "ila entry",
  .short_help = "ila entry [type <type>] [sir-address <address>] [locator <locator>] [vnid <hex-vnid>]"
    " [adj-index <adj-index>] [next-hop <next-hop>] [direction (bidir|sir2ila|ila2sir)]"
    " [csum-mode (no-action|neutral-map|transport-adjust)] [del]",
  .function = ila_entry_command_fn,
};

static clib_error_t *
ila_interface_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u8 disable = 0;

  if (!unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      return clib_error_return (0, "Invalid interface name");
    }

  if (unformat (input, "disable"))
    {
      disable = 1;
    }

  int ret;
  if ((ret = ila_interface (sw_if_index, disable)))
    return clib_error_return (0, "ila_interface returned error %d", ret);

  return NULL;
}

VLIB_CLI_COMMAND (ila_interface_command, static) =
{
  .path = "ila interface",
  .short_help = "ila interface <interface-name> [disable]",
  .function = ila_interface_command_fn,
};

static clib_error_t *
ila_show_entries_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ila_main_t *ilm = &ila_main;
  ila_entry_t *e;

  vlib_cli_output (vm, "  %U\n", format_ila_entry, vnm, NULL);
  pool_foreach (e, ilm->entries,
    ({
      vlib_cli_output (vm, "  %U\n", format_ila_entry, vnm, e);
    }));

  return NULL;
}

VLIB_CLI_COMMAND (ila_show_entries_command, static) =
{
  .path = "show ila entries",
  .short_help = "show ila entries",
  .function = ila_show_entries_command_fn,
};
