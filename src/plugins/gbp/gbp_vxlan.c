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
#include <plugins/gbp/gbp_learn.h>
#include <plugins/gbp/gbp_bridge_domain.h>
#include <plugins/gbp/gbp_route_domain.h>

#include <vnet/vxlan-gbp/vxlan_gbp.h>
#include <vlibmemory/api.h>
#include <vnet/fib/fib_table.h>
#include <vlib/punt.h>

/**
 * A reference to a VXLAN-GBP tunnel created as a child/dependent tunnel
 * of the tempplate GBP-VXLAN tunnel
 */
typedef struct vxlan_tunnel_ref_t_
{
  gbp_itf_hdl_t vxr_itf;
  u32 vxr_sw_if_index;
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
static vlib_log_class_t gt_logger;

/**
 * Pool of template tunnels
 */
static gbp_vxlan_tunnel_t *gbp_vxlan_tunnel_pool;

/**
 * Pool of child tunnels
 */
static vxlan_tunnel_ref_t *vxlan_tunnel_ref_pool;

/**
 * DB of template interfaces by SW interface index
 */
static index_t *gbp_vxlan_tunnel_db;

/**
 * DB of child interfaces by SW interface index
 */
static index_t *vxlan_tunnel_ref_db;

/**
 * handle registered with the ;unt infra
 */
static vlib_punt_hdl_t punt_hdl;

static char *gbp_vxlan_tunnel_layer_strings[] = {
#define _(n,s) [GBP_VXLAN_TUN_##n] = s,
  forecah_gbp_vxlan_tunnel_layer
#undef _
};

#define GBP_VXLAN_TUN_DBG(...)                          \
    vlib_log_debug (gt_logger, __VA_ARGS__);


gbp_vxlan_tunnel_t *
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

  s = format (s, "[%U]", format_gbp_itf_hdl, vxr->vxr_itf);

  return (s);
}

static void
gdb_vxlan_dep_del (u32 sw_if_index)
{
  vxlan_tunnel_ref_t *vxr;
  gbp_vxlan_tunnel_t *gt;
  index_t vxri;
  u32 pos;

  vxr = vxlan_tunnel_ref_get (vxlan_tunnel_ref_db[sw_if_index]);
  vxri = vxr - vxlan_tunnel_ref_pool;
  gt = gbp_vxlan_tunnel_get (vxr->vxr_parent);

  GBP_VXLAN_TUN_DBG ("del-dep:%U", format_vxlan_tunnel_ref, vxri);

  vxlan_tunnel_ref_db[vxr->vxr_sw_if_index] = INDEX_INVALID;
  pos = vec_search (gt->gt_tuns, vxri);

  ASSERT (~0 != pos);
  vec_del1 (gt->gt_tuns, pos);

  vnet_vxlan_gbp_tunnel_del (vxr->vxr_sw_if_index);

  pool_put (vxlan_tunnel_ref_pool, vxr);
}

static gbp_itf_hdl_t
gdb_vxlan_dep_add (gbp_vxlan_tunnel_t * gt,
		   const ip46_address_t * src, const ip46_address_t * dst)
{
  vnet_vxlan_gbp_tunnel_add_del_args_t args = {
    .is_add = 1,
    .is_ip6 = !ip46_address_is_ip4 (src),
    .vni = gt->gt_vni,
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
      gbp_itf_lock (vxr->vxr_itf);
    }
  else if (0 == rv)
    {
      ASSERT (~0 != sw_if_index);
      GBP_VXLAN_TUN_DBG ("add-dep:%U %U %U %d", format_vnet_sw_if_index_name,
			 vnet_get_main (), sw_if_index,
			 format_ip46_address, src, IP46_TYPE_ANY,
			 format_ip46_address, dst, IP46_TYPE_ANY, gt->gt_vni);

      pool_get_zero (vxlan_tunnel_ref_pool, vxr);

      vxri = (vxr - vxlan_tunnel_ref_pool);
      vxr->vxr_parent = gt - gbp_vxlan_tunnel_pool;
      vxr->vxr_sw_if_index = sw_if_index;
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
	  l2output_feat_masks_t ofeat;
	  l2input_feat_masks_t ifeat;
	  gbp_bridge_domain_t *gbd;

	  gbd = gbp_bridge_domain_get (gt->gt_gbd);
	  vxr->vxr_itf = gbp_itf_l2_add_and_lock_w_free
	    (vxr->vxr_sw_if_index, gt->gt_gbd, gdb_vxlan_dep_del);

	  ofeat = L2OUTPUT_FEAT_GBP_POLICY_MAC;
	  ifeat = L2INPUT_FEAT_NONE;

	  if (!(gbd->gb_flags & GBP_BD_FLAG_DO_NOT_LEARN))
	    ifeat |= L2INPUT_FEAT_GBP_LEARN;

	  gbp_itf_l2_set_output_feature (vxr->vxr_itf, ofeat);
	  gbp_itf_l2_set_input_feature (vxr->vxr_itf, ifeat);
	}
      else
	{
	  vxr->vxr_itf = gbp_itf_l3_add_and_lock_w_free
	    (vxr->vxr_sw_if_index, gt->gt_grd, gdb_vxlan_dep_del);

	  gbp_itf_l3_set_input_feature (vxr->vxr_itf, GBP_ITF_L3_FEAT_LEARN);
	}
    }
  else
    {
      return (GBP_ITF_HDL_INVALID);
    }

  return (vxr->vxr_itf);
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

gbp_itf_hdl_t
vxlan_gbp_tunnel_lock_itf (u32 sw_if_index)
{
  ASSERT ((sw_if_index < vec_len (vxlan_tunnel_ref_db)) &&
	  (INDEX_INVALID != vxlan_tunnel_ref_db[sw_if_index]));

  vxlan_tunnel_ref_t *vxr;

  vxr = vxlan_tunnel_ref_get (vxlan_tunnel_ref_db[sw_if_index]);

  gbp_itf_lock (vxr->vxr_itf);

  return (vxr->vxr_itf);
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

gbp_itf_hdl_t
gbp_vxlan_tunnel_clone_and_lock (u32 sw_if_index,
				 const ip46_address_t * src,
				 const ip46_address_t * dst)
{
  gbp_vxlan_tunnel_t *gt;
  index_t gti;

  gti = gbp_vxlan_tunnel_db[sw_if_index];

  if (INDEX_INVALID == gti)
    return (GBP_ITF_HDL_INVALID);

  gt = pool_elt_at_index (gbp_vxlan_tunnel_pool, gti);

  return (gdb_vxlan_dep_add (gt, src, dst));
}

void
vxlan_gbp_tunnel_unlock (u32 sw_if_index)
{
  /* vxlan_tunnel_ref_t *vxr; */
  /* index_t vxri; */

  /* vxri = vxlan_tunnel_ref_db[sw_if_index]; */

  /* ASSERT (vxri != INDEX_INVALID); */

  /* vxr = vxlan_tunnel_ref_get (vxri); */

  /* gdb_vxlan_dep_del (vxri); */
}

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

  s = format (s, " [%d] gbp-vxlan-tunnel: hw:%d sw:%d vni:%d %U",
	      dev_instance, gt->gt_hw_if_index,
	      gt->gt_sw_if_index, gt->gt_vni,
	      format_gbp_vxlan_tunnel_layer, gt->gt_layer);
  if (GBP_VXLAN_TUN_L2 == gt->gt_layer)
    s = format (s, " BD:%d gbd-index:%d", gt->gt_bd_rd_id, gt->gt_gbd);
  else
    s = format (s, " RD:%d grd-index:%d", gt->gt_bd_rd_id, gt->gt_grd);

  s = format (s, "   dependents:");
  vec_foreach (vxri, gt->gt_tuns)
  {
    s = format (s, "\n    %U, ", format_vxlan_tunnel_ref, *vxri);
  }

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
		      u32 bd_rd_id,
		      const ip4_address_t * src, u32 * sw_if_indexp)
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
      gt->gt_src.ip4.as_u32 = src->as_u32;
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
	  gb->gb_vni = gti;
	  /* set it up as a GBP interface */
	  gt->gt_itf = gbp_itf_l2_add_and_lock (gt->gt_sw_if_index,
						gt->gt_gbd);
	  gbp_itf_l2_set_input_feature (gt->gt_itf, L2INPUT_FEAT_GBP_LEARN);
	}
      else
	{
	  gt->gt_grd = grdi;
	  gt->gt_itf = gbp_itf_l3_add_and_lock (gt->gt_sw_if_index,
						gt->gt_grd);
	  gbp_itf_l3_set_input_feature (gt->gt_itf, GBP_ITF_L3_FEAT_LEARN);
	}

      /*
       * save the tunnel by VNI and by sw_if_index
       */
      hash_set (gv_db, vni, gti);

      vec_validate_init_empty (gbp_vxlan_tunnel_db,
			       gt->gt_sw_if_index, INDEX_INVALID);
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

      gbp_endpoint_flush (GBP_ENDPOINT_SRC_DP, gt->gt_sw_if_index);
      ASSERT (0 == vec_len (gt->gt_tuns));
      vec_free (gt->gt_tuns);

      gbp_itf_unlock (&gt->gt_itf);

      if (GBP_VXLAN_TUN_L2 == gt->gt_layer)
	{
	  gbp_bridge_domain_unlock (gt->gt_gbd);
	}
      else
	{
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

  vlib_cli_output (vm, "GBP-VXLAN Interfaces:");

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
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;

  gt_logger = vlib_log_register_class ("gbp", "tun");

  punt_hdl = vlib_punt_client_register ("gbp-vxlan");

  vlib_punt_register (punt_hdl,
		      vxm->punt_no_such_tunnel[FIB_PROTOCOL_IP4],
		      "gbp-vxlan4");

  return (0);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (gbp_vxlan_init) =
{
  .runs_after = VLIB_INITS("punt_init", "vxlan_gbp_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
