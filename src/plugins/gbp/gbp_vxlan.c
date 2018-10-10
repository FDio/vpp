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

#include <plugins/gbp/gbp_vxlan.h>
#include <plugins/gbp/gbp_itf.h>
#include <plugins/gbp/gbp_learn.h>
#include <plugins/gbp/gbp_bridge_domain.h>
#include <plugins/gbp/gbp_route_domain.h>

#include <vnet/vxlan-gbp/vxlan_gbp.h>
#include <vlibmemory/api.h>
#include <vnet/fib/fib_table.h>

/**
 * A reference to a VXLAN-GBP tunnel created as a child/dependent tunnel
 * of the tempplate GBP-VXLAN tunnel
 */
typedef struct vxlan_tunnel_ref_t_
{
  u32 vxr_sw_if_index;
  index_t vxr_itf;
  u32 vxr_locks;
  index_t vxr_parent;
  gbp_vxlan_tunnel_layer_t vxr_layer;
} vxlan_tunnel_ref_t;

/**
 * DB of added tunnels
 */
uword *gv_db;

/**
 * Logger
 */
vlib_log_class_t gt_logger;

/**
 * Pool of template tunnels
 */
gbp_vxlan_tunnel_t *gbp_vxlan_tunnel_pool;

/**
 * Pool of child tunnels
 */
vxlan_tunnel_ref_t *vxlan_tunnel_ref_pool;

/**
 * DB of template interfaces by SW interface index
 */
index_t *gbp_vxlan_tunnel_db;

/**
 * DB of child interfaces by SW interface index
 */
index_t *vxlan_tunnel_ref_db;


static char *gbp_vxlan_tunnel_layer_strings[] = {
#define _(n,s) [GBP_VXLAN_TUN_##n] = s,
  forecah_gbp_vxlan_tunnel_layer
#undef _
};

#define GBP_VXLAN_TUN_DBG(...)                          \
    vlib_log_notice (gt_logger, __VA_ARGS__);



always_inline gbp_vxlan_tunnel_t *
gbp_vxlan_tunnel_get (index_t gti)
{
  return (pool_elt_at_index (gbp_vxlan_tunnel_pool, gti));
}

static vxlan_tunnel_ref_t *
vxlan_tunnel_ref_get (index_t vxri)
{
  return (pool_elt_at_index (vxlan_tunnel_ref_pool, vxri));
}

static u8 *
format_vxlan_tunnel_ref (u8 * s, va_list * args)
{
  index_t vxri = va_arg (*args, u32);
  vxlan_tunnel_ref_t *vxr;

  vxr = vxlan_tunnel_ref_get (vxri);

  s = format (s, "[%U locks:%d]", format_vnet_sw_if_index_name,
	      vnet_get_main (), vxr->vxr_sw_if_index, vxr->vxr_locks);

  return (s);
}

static u32
gdb_vxlan_dep_add (gbp_vxlan_tunnel_t * gt,
		   u32 vni,
		   const ip46_address_t * src, const ip46_address_t * dst)
{
  vnet_vxlan_gbp_tunnel_add_del_args_t args = {
    .is_add = 1,
    .is_ip6 = !ip46_address_is_ip4 (src),
    .vni = vni,
    .src = *src,
    .dst = *dst,
    .instance = ~0,
    .mode = (GBP_VXLAN_TUN_L2 == gt->gt_layer ?
	     VXLAN_GBP_TUNNEL_MODE_L2 : VXLAN_GBP_TUNNEL_MODE_L3),
  };
  vxlan_tunnel_ref_t *vxr;
  u32 sw_if_index;
  index_t vxri;
  int rv;

  sw_if_index = ~0;
  rv = vnet_vxlan_gbp_tunnel_add_del (&args, &sw_if_index);

  if (VNET_API_ERROR_TUNNEL_EXIST == rv)
    {
      vxri = vxlan_tunnel_ref_db[sw_if_index];

      vxr = vxlan_tunnel_ref_get (vxri);
      vxr->vxr_locks++;
    }
  else if (0 == rv)
    {
      ASSERT (~0 != sw_if_index);
      GBP_VXLAN_TUN_DBG ("add-dep:%U %U %U %d", format_vnet_sw_if_index_name,
			 vnet_get_main (), sw_if_index,
			 format_ip46_address, src, IP46_TYPE_ANY,
			 format_ip46_address, dst, IP46_TYPE_ANY, vni);

      pool_get_zero (vxlan_tunnel_ref_pool, vxr);

      vxri = (vxr - vxlan_tunnel_ref_pool);
      vxr->vxr_parent = gt - gbp_vxlan_tunnel_pool;
      vxr->vxr_sw_if_index = sw_if_index;
      vxr->vxr_locks = 1;
      vxr->vxr_layer = gt->gt_layer;

      /*
       * store the child both on the parent's list and the global DB
       */
      vec_add1 (gt->gt_tuns, vxri);

      vec_validate_init_empty (vxlan_tunnel_ref_db,
			       vxr->vxr_sw_if_index, INDEX_INVALID);
      vxlan_tunnel_ref_db[vxr->vxr_sw_if_index] = vxri;

      if (GBP_VXLAN_TUN_L2 == vxr->vxr_layer)
	{
	  vxr->vxr_itf = gbp_itf_add_and_lock (vxr->vxr_sw_if_index,
					       gt->gt_bd_index);

	  gbp_itf_set_l2_output_feature (vxr->vxr_itf, vxr->vxr_sw_if_index,
					 L2OUTPUT_FEAT_GBP_POLICY_MAC);
	  gbp_itf_set_l2_input_feature (vxr->vxr_itf, vxr->vxr_sw_if_index,
					L2INPUT_FEAT_GBP_LEARN);
	}
      else
	{
	  const gbp_route_domain_t *grd;
	  fib_protocol_t fproto;

	  grd = gbp_route_domain_get (gt->gt_grd);

	  FOR_EACH_FIB_IP_PROTOCOL (fproto)
	    ip_table_bind (fproto, vxr->vxr_sw_if_index,
			   grd->grd_table_id[fproto], 1);

	  gbp_learn_enable (vxr->vxr_sw_if_index, GBP_LEARN_MODE_L3);
	}
    }

  return (sw_if_index);
}

u32
vxlan_gbp_tunnel_get_parent (u32 sw_if_index)
{
  ASSERT ((sw_if_index < vec_len (vxlan_tunnel_ref_db)) &&
	  (INDEX_INVALID != vxlan_tunnel_ref_db[sw_if_index]));

  gbp_vxlan_tunnel_t *gt;
  vxlan_tunnel_ref_t *vxr;

  vxr = vxlan_tunnel_ref_get (vxlan_tunnel_ref_db[sw_if_index]);
  gt = gbp_vxlan_tunnel_get (vxr->vxr_parent);

  return (gt->gt_sw_if_index);
}

gbp_vxlan_tunnel_type_t
gbp_vxlan_tunnel_get_type (u32 sw_if_index)
{
  if (sw_if_index < vec_len (vxlan_tunnel_ref_db) &&
      INDEX_INVALID != vxlan_tunnel_ref_db[sw_if_index])
    {
      return (VXLAN_GBP_TUNNEL);
    }
  else if (sw_if_index < vec_len (gbp_vxlan_tunnel_db) &&
	   INDEX_INVALID != gbp_vxlan_tunnel_db[sw_if_index])
    {
      return (GBP_VXLAN_TEMPLATE_TUNNEL);
    }

  ASSERT (0);
  return (GBP_VXLAN_TEMPLATE_TUNNEL);
}

u32
gbp_vxlan_tunnel_clone_and_lock (u32 sw_if_index,
				 const ip46_address_t * src,
				 const ip46_address_t * dst)
{
  gbp_vxlan_tunnel_t *gt;
  index_t gti;

  gti = gbp_vxlan_tunnel_db[sw_if_index];

  if (INDEX_INVALID == gti)
    return (~0);

  gt = pool_elt_at_index (gbp_vxlan_tunnel_pool, gti);

  return (gdb_vxlan_dep_add (gt, gt->gt_vni, src, dst));
}

static void
gdb_vxlan_dep_del (index_t vxri)
{
  vxlan_tunnel_ref_t *vxr;
  gbp_vxlan_tunnel_t *gt;
  u32 pos;

  vxr = vxlan_tunnel_ref_get (vxri);
  gt = gbp_vxlan_tunnel_get (vxr->vxr_parent);

  GBP_VXLAN_TUN_DBG ("del-dep:%U", format_vxlan_tunnel_ref, vxri);

  vxlan_tunnel_ref_db[vxr->vxr_sw_if_index] = INDEX_INVALID;
  pos = vec_search (gt->gt_tuns, vxri);

  ASSERT (~0 != pos);
  vec_del1 (gt->gt_tuns, pos);

  if (GBP_VXLAN_TUN_L2 == vxr->vxr_layer)
    {
      gbp_itf_set_l2_output_feature (vxr->vxr_itf, vxr->vxr_sw_if_index,
				     L2OUTPUT_FEAT_NONE);
      gbp_itf_set_l2_input_feature (vxr->vxr_itf, vxr->vxr_sw_if_index,
				    L2INPUT_FEAT_NONE);
      gbp_itf_unlock (vxr->vxr_itf);
    }
  else
    {
      fib_protocol_t fproto;

      FOR_EACH_FIB_IP_PROTOCOL (fproto)
	ip_table_bind (fproto, vxr->vxr_sw_if_index, 0, 0);
    }

  vnet_vxlan_gbp_tunnel_del (vxr->vxr_sw_if_index);

  pool_put (vxlan_tunnel_ref_pool, vxr);
}

void
vxlan_gbp_tunnel_unlock (u32 sw_if_index)
{
  vxlan_tunnel_ref_t *vxr;
  index_t vxri;

  vxri = vxlan_tunnel_ref_db[sw_if_index];

  ASSERT (vxri != INDEX_INVALID);

  vxr = vxlan_tunnel_ref_get (vxri);
  vxr->vxr_locks--;

  if (0 == vxr->vxr_locks)
    {
      gdb_vxlan_dep_del (vxri);
    }
}

void
vxlan_gbp_tunnel_lock (u32 sw_if_index)
{
  vxlan_tunnel_ref_t *vxr;
  index_t vxri;

  vxri = vxlan_tunnel_ref_db[sw_if_index];

  ASSERT (vxri != INDEX_INVALID);

  vxr = vxlan_tunnel_ref_get (vxri);
  vxr->vxr_locks++;
}

#define foreach_gbp_vxlan_input_next         \
  _(DROP, "error-drop")                      \
  _(L2_INPUT, "l2-input")                    \
  _(IP4_INPUT, "ip4-input")                  \
  _(IP6_INPUT, "ip6-input")

typedef enum
{
#define _(s,n) GBP_VXLAN_INPUT_NEXT_##s,
  foreach_gbp_vxlan_input_next
#undef _
    GBP_VXLAN_INPUT_N_NEXT,
} gbp_vxlan_input_next_t;

#define foreach_gbp_vxlan_error              \
  _(DECAPPED, "decapped")                    \
  _(LEARNED, "learned")

typedef enum
{
#define _(s,n) GBP_VXLAN_ERROR_##s,
  foreach_gbp_vxlan_error
#undef _
    GBP_VXLAN_N_ERROR,
} gbp_vxlan_input_error_t;

static char *gbp_vxlan_error_strings[] = {
#define _(n,s) s
  foreach_gbp_vxlan_error
#undef _
};

typedef struct gbp_vxlan_trace_t_
{
  u8 dropped;
  u32 vni;
  u32 sw_if_index;
  u16 sclass;
  u8 flags;
} gbp_vxlan_trace_t;


static uword
gbp_vxlan_decap (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * from_frame, u8 is_ip4)
{
  u32 n_left_to_next, n_left_from, next_index, *to_next, *from;

  next_index = 0;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  while (n_left_from > 0)
    {

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vxlan_gbp_header_t *vxlan_gbp0;
	  gbp_vxlan_input_next_t next0;
	  gbp_vxlan_tunnel_t *gt0;
	  vlib_buffer_t *b0;
	  u32 bi0, vni0;
	  uword *p;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = GBP_VXLAN_INPUT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  vxlan_gbp0 =
	    vlib_buffer_get_current (b0) - sizeof (vxlan_gbp_header_t);

	  vni0 = vxlan_gbp_get_vni (vxlan_gbp0);
	  p = hash_get (gv_db, vni0);

	  if (PREDICT_FALSE (NULL == p))
	    {
	      gt0 = NULL;
	      next0 = GBP_VXLAN_INPUT_NEXT_DROP;
	    }
	  else
	    {
	      gt0 = gbp_vxlan_tunnel_get (p[0]);

	      vnet_buffer (b0)->sw_if_index[VLIB_RX] = gt0->gt_sw_if_index;

	      if (GBP_VXLAN_TUN_L2 == gt0->gt_layer)
		/*
		 * An L2 layer tunnel goes into the BD
		 */
		next0 = GBP_VXLAN_INPUT_NEXT_L2_INPUT;
	      else
		{
		  /*
		   * An L3 layer tunnel needs to strip the L2 header
		   * an inject into the RD
		   */
		  ethernet_header_t *e0;
		  u16 type0;

		  e0 = vlib_buffer_get_current (b0);
		  type0 = clib_net_to_host_u16 (e0->type);
		  switch (type0)
		    {
		    case ETHERNET_TYPE_IP4:
		      next0 = GBP_VXLAN_INPUT_NEXT_IP4_INPUT;
		      break;
		    case ETHERNET_TYPE_IP6:
		      next0 = GBP_VXLAN_INPUT_NEXT_IP6_INPUT;
		      break;
		    default:
		      goto trace;
		    }
		  vlib_buffer_advance (b0, sizeof (*e0));
		}
	    }

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gbp_vxlan_trace_t *tr;

	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->dropped = (next0 == GBP_VXLAN_INPUT_NEXT_DROP);
	      tr->vni = vni0;
	      tr->sw_if_index = (gt0 ? gt0->gt_sw_if_index : ~0);
	      tr->flags = vxlan_gbp_get_gpflags (vxlan_gbp0);
	      tr->sclass = vxlan_gbp_get_sclass (vxlan_gbp0);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static u8 *
format_gbp_vxlan_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_vxlan_trace_t *t = va_arg (*args, gbp_vxlan_trace_t *);

  s = format (s, "vni:%d dropped:%d rx:%d sclass:%d flags:%U",
	      t->vni, t->dropped, t->sw_if_index,
	      t->sclass, format_vxlan_gbp_header_gpflags, t->flags);

  return (s);
}

static uword
gbp_vxlan4_decap (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return gbp_vxlan_decap (vm, node, from_frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_vxlan4_input_node) =
{
  .function = gbp_vxlan4_decap,
  .name = "gbp-vxlan4",
  .vector_size = sizeof (u32),
  .n_errors = GBP_VXLAN_N_ERROR,
  .error_strings = gbp_vxlan_error_strings,
  .n_next_nodes = GBP_VXLAN_INPUT_N_NEXT,
  .format_trace = format_gbp_vxlan_rx_trace,
  .next_nodes = {
#define _(s,n) [GBP_VXLAN_INPUT_NEXT_##s] = n,
    foreach_gbp_vxlan_input_next
#undef _
  },
};
VLIB_NODE_FUNCTION_MULTIARCH (gbp_vxlan4_input_node, gbp_vxlan4_decap)

/* *INDENT-ON* */

void
gbp_vxlan_walk (gbp_vxlan_cb_t cb, void *ctx)
{
  gbp_vxlan_tunnel_t *gt;

  /* *INDENT-OFF* */
  pool_foreach (gt, gbp_vxlan_tunnel_pool,
    ({
      if (WALK_CONTINUE != cb(gt, ctx))
        break;
    }));
  /* *INDENT-ON* */
}

static walk_rc_t
gbp_vxlan_tunnel_show_one (gbp_vxlan_tunnel_t * gt, void *ctx)
{
  vlib_cli_output (ctx, "%U", format_gbp_vxlan_tunnel,
		   gt - gbp_vxlan_tunnel_pool);

  return (WALK_CONTINUE);
}

static u8 *
format_gbp_vxlan_tunnel_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);

  return format (s, "gbp-vxlan-%d", dev_instance);
}

u8 *
format_gbp_vxlan_tunnel_layer (u8 * s, va_list * args)
{
  gbp_vxlan_tunnel_layer_t gl = va_arg (*args, gbp_vxlan_tunnel_layer_t);
  s = format (s, "%s", gbp_vxlan_tunnel_layer_strings[gl]);

  return (s);
}

u8 *
format_gbp_vxlan_tunnel (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);
  gbp_vxlan_tunnel_t *gt = gbp_vxlan_tunnel_get (dev_instance);
  index_t *vxri;

  s = format (s, "GBP VXLAN tunnel: hw:%d sw:%d vni:%d %U",
	      gt->gt_hw_if_index, gt->gt_sw_if_index, gt->gt_vni,
	      format_gbp_vxlan_tunnel_layer, gt->gt_layer);
  if (GBP_VXLAN_TUN_L2 == gt->gt_layer)
    s = format (s, " BD:%d bd-index:%d", gt->gt_bd_rd_id, gt->gt_bd_index);
  else
    s = format (s, " RD:%d fib-index:[%d,%d]",
		gt->gt_bd_rd_id,
		gt->gt_fib_index[FIB_PROTOCOL_IP4],
		gt->gt_fib_index[FIB_PROTOCOL_IP6]);

  s = format (s, " children:[");
  vec_foreach (vxri, gt->gt_tuns)
  {
    s = format (s, "%U, ", format_vxlan_tunnel_ref, *vxri);
  }
  s = format (s, "]");

  return s;
}

typedef struct gbp_vxlan_tx_trace_t_
{
  u32 vni;
} gbp_vxlan_tx_trace_t;

u8 *
format_gbp_vxlan_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_vxlan_tx_trace_t *t = va_arg (*args, gbp_vxlan_tx_trace_t *);

  s = format (s, "GBP-VXLAN: vni:%d", t->vni);

  return (s);
}

clib_error_t *
gbp_vxlan_interface_admin_up_down (vnet_main_t * vnm,
				   u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi;
  u32 ti;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  if (NULL == gbp_vxlan_tunnel_db ||
      hi->sw_if_index >= vec_len (gbp_vxlan_tunnel_db))
    return (NULL);

  ti = gbp_vxlan_tunnel_db[hi->sw_if_index];

  if (~0 == ti)
    /* not one of ours */
    return (NULL);

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags (vnm, hw_if_index,
				 VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, hw_if_index, 0);

  return (NULL);
}

static uword
gbp_vxlan_interface_tx (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (gbp_vxlan_device_class) = {
  .name = "GBP VXLAN tunnel-template",
  .format_device_name = format_gbp_vxlan_tunnel_name,
  .format_device = format_gbp_vxlan_tunnel,
  .format_tx_trace = format_gbp_vxlan_tx_trace,
  .admin_up_down_function = gbp_vxlan_interface_admin_up_down,
  .tx_function = gbp_vxlan_interface_tx,
};

VNET_HW_INTERFACE_CLASS (gbp_vxlan_hw_interface_class) = {
  .name = "GBP-VXLAN",
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

int
gbp_vxlan_tunnel_add (u32 vni, gbp_vxlan_tunnel_layer_t layer,
		      u32 bd_rd_id, u32 * sw_if_indexp)
{
  gbp_vxlan_tunnel_t *gt;
  index_t gti;
  uword *p;
  int rv;

  rv = 0;
  p = hash_get (gv_db, vni);

  GBP_VXLAN_TUN_DBG ("add: %d %d %d", vni, layer, bd_rd_id);

  if (NULL == p)
    {
      vnet_sw_interface_t *si;
      vnet_hw_interface_t *hi;
      index_t gbi, grdi;
      vnet_main_t *vnm;

      gbi = grdi = INDEX_INVALID;

      if (layer == GBP_VXLAN_TUN_L2)
	{
	  gbi = gbp_bridge_domain_find_and_lock (bd_rd_id);

	  if (INDEX_INVALID == gbi)
	    {
	      return (VNET_API_ERROR_BD_NOT_MODIFIABLE);
	    }
	}
      else
	{
	  grdi = gbp_route_domain_find_and_lock (bd_rd_id);

	  if (INDEX_INVALID == grdi)
	    {
	      return (VNET_API_ERROR_NO_SUCH_FIB);
	    }
	}

      vnm = vnet_get_main ();
      pool_get (gbp_vxlan_tunnel_pool, gt);
      gti = gt - gbp_vxlan_tunnel_pool;

      gt->gt_vni = vni;
      gt->gt_layer = layer;
      gt->gt_bd_rd_id = bd_rd_id;
      gt->gt_hw_if_index = vnet_register_interface (vnm,
						    gbp_vxlan_device_class.index,
						    gti,
						    gbp_vxlan_hw_interface_class.index,
						    gti);

      hi = vnet_get_hw_interface (vnm, gt->gt_hw_if_index);

      gt->gt_sw_if_index = hi->sw_if_index;

      /* don't flood packets in a BD to these interfaces */
      si = vnet_get_sw_interface (vnm, gt->gt_sw_if_index);
      si->flood_class = VNET_FLOOD_CLASS_NO_FLOOD;

      if (layer == GBP_VXLAN_TUN_L2)
	{
	  gbp_bridge_domain_t *gb;

	  gb = gbp_bridge_domain_get (gbi);

	  gt->gt_gbd = gbi;
	  gt->gt_bd_index = gb->gb_bd_id;
	  gb->gb_vni_sw_if_index = gt->gt_sw_if_index;
	  /* set it up as a GBP interface */
	  gt->gt_itf = gbp_itf_add_and_lock (gt->gt_sw_if_index,
					     gt->gt_bd_index);
	  gbp_learn_enable (gt->gt_sw_if_index, GBP_LEARN_MODE_L2);
	}
      else
	{
	  gbp_route_domain_t *grd;
	  fib_protocol_t fproto;

	  grd = gbp_route_domain_get (grdi);

	  gt->gt_grd = grdi;
	  grd->grd_vni_sw_if_index = gt->gt_sw_if_index;

	  gbp_learn_enable (gt->gt_sw_if_index, GBP_LEARN_MODE_L3);

	  ip4_sw_interface_enable_disable (gt->gt_sw_if_index, 1);
	  ip6_sw_interface_enable_disable (gt->gt_sw_if_index, 1);

	  FOR_EACH_FIB_IP_PROTOCOL (fproto)
	  {
	    gt->gt_fib_index[fproto] = grd->grd_fib_index[fproto];

	    ip_table_bind (fproto, gt->gt_sw_if_index,
			   grd->grd_table_id[fproto], 1);
	  }
	}

      /*
       * save the tunnel by VNI and by sw_if_index
       */
      hash_set (gv_db, vni, gti);

      vec_validate (gbp_vxlan_tunnel_db, gt->gt_sw_if_index);
      gbp_vxlan_tunnel_db[gt->gt_sw_if_index] = gti;

      if (sw_if_indexp)
	*sw_if_indexp = gt->gt_sw_if_index;

      vxlan_gbp_register_udp_ports ();
    }
  else
    {
      gti = p[0];
      rv = VNET_API_ERROR_IF_ALREADY_EXISTS;
    }

  GBP_VXLAN_TUN_DBG ("add: %U", format_gbp_vxlan_tunnel, gti);

  return (rv);
}

int
gbp_vxlan_tunnel_del (u32 vni)
{
  gbp_vxlan_tunnel_t *gt;
  uword *p;

  p = hash_get (gv_db, vni);

  if (NULL != p)
    {
      vnet_main_t *vnm;

      vnm = vnet_get_main ();
      gt = gbp_vxlan_tunnel_get (p[0]);

      vxlan_gbp_unregister_udp_ports ();

      GBP_VXLAN_TUN_DBG ("del: %U", format_gbp_vxlan_tunnel,
			 gt - gbp_vxlan_tunnel_pool);

      gbp_endpoint_flush (gt->gt_sw_if_index);
      ASSERT (0 == vec_len (gt->gt_tuns));
      vec_free (gt->gt_tuns);

      if (GBP_VXLAN_TUN_L2 == gt->gt_layer)
	{
	  gbp_learn_disable (gt->gt_sw_if_index, GBP_LEARN_MODE_L2);
	  gbp_itf_unlock (gt->gt_itf);
	  gbp_bridge_domain_unlock (gt->gt_gbd);
	}
      else
	{
	  fib_protocol_t fproto;

	  FOR_EACH_FIB_IP_PROTOCOL (fproto)
	    ip_table_bind (fproto, gt->gt_sw_if_index, 0, 0);

	  ip4_sw_interface_enable_disable (gt->gt_sw_if_index, 0);
	  ip6_sw_interface_enable_disable (gt->gt_sw_if_index, 0);

	  gbp_learn_disable (gt->gt_sw_if_index, GBP_LEARN_MODE_L3);
	  gbp_route_domain_unlock (gt->gt_grd);
	}

      vnet_sw_interface_set_flags (vnm, gt->gt_sw_if_index, 0);
      vnet_delete_hw_interface (vnm, gt->gt_hw_if_index);

      hash_unset (gv_db, vni);
      gbp_vxlan_tunnel_db[gt->gt_sw_if_index] = INDEX_INVALID;

      pool_put (gbp_vxlan_tunnel_pool, gt);
    }
  else
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  return (0);
}

static clib_error_t *
gbp_vxlan_show (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  gbp_vxlan_walk (gbp_vxlan_tunnel_show_one, vm);

  return (NULL);
}

/*?
 * Show Group Based Policy VXLAN tunnels
 *
 * @cliexpar
 * @cliexstart{show gbp vxlan}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_vxlan_show_node, static) = {
  .path = "show gbp vxlan",
  .short_help = "show gbp vxlan\n",
  .function = gbp_vxlan_show,
};
/* *INDENT-ON* */

static clib_error_t *
gbp_vxlan_init (vlib_main_t * vm)
{
  u32 slot4;

  /*
   * insert ourselves into the VXLAN-GBP arc to collect the no-tunnel
   * packets.
   */
  slot4 = vlib_node_add_next_with_slot (vm,
					vxlan4_gbp_input_node.index,
					gbp_vxlan4_input_node.index,
					VXLAN_GBP_INPUT_NEXT_NO_TUNNEL);
  ASSERT (slot4 == VXLAN_GBP_INPUT_NEXT_NO_TUNNEL);

  /* slot6 = vlib_node_add_next_with_slot (vm, */
  /*                                    vxlan6_gbp_input_node.index, */
  /*                                    gbp_vxlan6_input_node.index, */
  /*                                    VXLAN_GBP_INPUT_NEXT_NO_TUNNEL); */
  /* ASSERT (slot6 == VXLAN_GBP_INPUT_NEXT_NO_TUNNEL); */

  gt_logger = vlib_log_register_class ("gbp", "tun");

  return (NULL);
}

VLIB_INIT_FUNCTION (gbp_vxlan_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
