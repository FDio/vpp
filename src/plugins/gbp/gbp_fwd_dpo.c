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

#include <plugins/gbp/gbp.h>
#include <plugins/gbp/gbp_fwd_dpo.h>

#include <vnet/ethernet/ethernet.h>


#ifndef CLIB_MARCH_VARIANT
/**
 * The 'DB' of GBP FWD DPOs.
 * There is one per-proto
 */
static index_t gbp_fwd_dpo_db[DPO_PROTO_NUM] = { INDEX_INVALID };

/**
 * DPO type registered for these GBP FWD
 */
static dpo_type_t gbp_fwd_dpo_type;

/**
 * @brief pool of all interface DPOs
 */
gbp_fwd_dpo_t *gbp_fwd_dpo_pool;

static gbp_fwd_dpo_t *
gbp_fwd_dpo_alloc (void)
{
  gbp_fwd_dpo_t *gfd;

  pool_get (gbp_fwd_dpo_pool, gfd);

  return (gfd);
}

static inline gbp_fwd_dpo_t *
gbp_fwd_dpo_get_from_dpo (const dpo_id_t * dpo)
{
  ASSERT (gbp_fwd_dpo_type == dpo->dpoi_type);

  return (gbp_fwd_dpo_get (dpo->dpoi_index));
}

static inline index_t
gbp_fwd_dpo_get_index (gbp_fwd_dpo_t * gfd)
{
  return (gfd - gbp_fwd_dpo_pool);
}

static void
gbp_fwd_dpo_lock (dpo_id_t * dpo)
{
  gbp_fwd_dpo_t *gfd;

  gfd = gbp_fwd_dpo_get_from_dpo (dpo);
  gfd->gfd_locks++;
}

static void
gbp_fwd_dpo_unlock (dpo_id_t * dpo)
{
  gbp_fwd_dpo_t *gfd;

  gfd = gbp_fwd_dpo_get_from_dpo (dpo);
  gfd->gfd_locks--;

  if (0 == gfd->gfd_locks)
    {
      gbp_fwd_dpo_db[gfd->gfd_proto] = INDEX_INVALID;
      pool_put (gbp_fwd_dpo_pool, gfd);
    }
}

void
gbp_fwd_dpo_add_or_lock (dpo_proto_t dproto, dpo_id_t * dpo)
{
  gbp_fwd_dpo_t *gfd;

  if (INDEX_INVALID == gbp_fwd_dpo_db[dproto])
    {
      gfd = gbp_fwd_dpo_alloc ();

      gfd->gfd_proto = dproto;

      gbp_fwd_dpo_db[dproto] = gbp_fwd_dpo_get_index (gfd);
    }
  else
    {
      gfd = gbp_fwd_dpo_get (gbp_fwd_dpo_db[dproto]);
    }

  dpo_set (dpo, gbp_fwd_dpo_type, dproto, gbp_fwd_dpo_get_index (gfd));
}

u8 *
format_gbp_fwd_dpo (u8 * s, va_list * ap)
{
  index_t index = va_arg (*ap, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*ap, u32);
  gbp_fwd_dpo_t *gfd = gbp_fwd_dpo_get (index);

  return (format (s, "gbp-fwd-dpo: %U", format_dpo_proto, gfd->gfd_proto));
}

const static dpo_vft_t gbp_fwd_dpo_vft = {
  .dv_lock = gbp_fwd_dpo_lock,
  .dv_unlock = gbp_fwd_dpo_unlock,
  .dv_format = format_gbp_fwd_dpo,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a glean
 *        object.
 *
 * this means that these graph nodes are ones from which a glean is the
 * parent object in the DPO-graph.
 */
const static char *const gbp_fwd_dpo_ip4_nodes[] = {
  "ip4-gbp-fwd-dpo",
  NULL,
};

const static char *const gbp_fwd_dpo_ip6_nodes[] = {
  "ip6-gbp-fwd-dpo",
  NULL,
};

const static char *const *const gbp_fwd_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = gbp_fwd_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = gbp_fwd_dpo_ip6_nodes,
};

dpo_type_t
gbp_fwd_dpo_get_type (void)
{
  return (gbp_fwd_dpo_type);
}

static clib_error_t *
gbp_fwd_dpo_module_init (vlib_main_t * vm)
{
  dpo_proto_t dproto;

  FOR_EACH_DPO_PROTO (dproto)
  {
    gbp_fwd_dpo_db[dproto] = INDEX_INVALID;
  }

  gbp_fwd_dpo_type = dpo_register_new_type (&gbp_fwd_dpo_vft,
					    gbp_fwd_dpo_nodes);

  return (NULL);
}

VLIB_INIT_FUNCTION (gbp_fwd_dpo_module_init);
#endif /* CLIB_MARCH_VARIANT */

typedef struct gbp_fwd_dpo_trace_t_
{
  u32 sclass;
  u32 dpo_index;
} gbp_fwd_dpo_trace_t;

typedef enum
{
  GBP_FWD_DROP,
  GBP_FWD_FWD,
  GBP_FWD_N_NEXT,
} gbp_fwd_next_t;

always_inline uword
gbp_fwd_dpo_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame, fib_protocol_t fproto)
{
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  const dpo_id_t *next_dpo0;
	  vlib_buffer_t *b0;
	  sclass_t sclass0;
	  u32 bi0, next0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sclass0 = vnet_buffer2 (b0)->gbp.sclass;
	  next_dpo0 = gbp_epg_dpo_lookup (sclass0, fproto);

	  if (PREDICT_TRUE (NULL != next_dpo0))
	    {
	      vnet_buffer (b0)->ip.adj_index = next_dpo0->dpoi_index;
	      next0 = GBP_FWD_FWD;
	    }
	  else
	    {
	      next0 = GBP_FWD_DROP;
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gbp_fwd_dpo_trace_t *tr;

	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->sclass = sclass0;
	      tr->dpo_index = (NULL != next_dpo0 ?
			       next_dpo0->dpoi_index : ~0);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

static u8 *
format_gbp_fwd_dpo_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_fwd_dpo_trace_t *t = va_arg (*args, gbp_fwd_dpo_trace_t *);

  s = format (s, " sclass:%d dpo:%d", t->sclass, t->dpo_index);

  return s;
}

VLIB_NODE_FN (ip4_gbp_fwd_dpo_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * from_frame)
{
  return (gbp_fwd_dpo_inline (vm, node, from_frame, FIB_PROTOCOL_IP4));
}

VLIB_NODE_FN (ip6_gbp_fwd_dpo_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * from_frame)
{
  return (gbp_fwd_dpo_inline (vm, node, from_frame, FIB_PROTOCOL_IP6));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_gbp_fwd_dpo_node) = {
    .name = "ip4-gbp-fwd-dpo",
    .vector_size = sizeof (u32),
    .format_trace = format_gbp_fwd_dpo_trace,
    .n_next_nodes = GBP_FWD_N_NEXT,
    .next_nodes =
    {
        [GBP_FWD_DROP] = "ip4-drop",
        [GBP_FWD_FWD] = "ip4-dvr-dpo",
    }
};
VLIB_REGISTER_NODE (ip6_gbp_fwd_dpo_node) = {
    .name = "ip6-gbp-fwd-dpo",
    .vector_size = sizeof (u32),
    .format_trace = format_gbp_fwd_dpo_trace,
    .n_next_nodes = GBP_FWD_N_NEXT,
    .next_nodes =
    {
        [GBP_FWD_DROP] = "ip6-drop",
        [GBP_FWD_FWD] = "ip6-dvr-dpo",
    }
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
