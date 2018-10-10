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
 * DB of added tunnels
 */
uword *gv_db;

vlib_log_class_t gt_logger;

/**
 * Thorttle for limiting the learn punts
 */
throttle_t gv_throttle;

/**
 * Pool of template tunnels
 */
gbp_vxlan_tunnel_t *gbp_vxlan_tunnel_pool;

/**
 * DB of template interfaces by SW interface index
 */
index_t *gbp_vxlan_tunnel_db;

static char *gbp_vxlan_tunnel_layer_strings[] = {
#define _(n,s) [GBP_VXLAN_TUN_##n] = s,
  forecah_gbp_vxlan_tunnel_layer
#undef _
};

#define GBP_VXLAN_TUN_DBG(...)                          \
    vlib_log_notice (gt_logger, __VA_ARGS__);

/**
 * Representation of a dependent tunnel
 */
typedef struct gbp_vxlan_dep_t_
{
  u32 gd_sw_if_index;
  index_t gd_itf;
} gbp_vxlan_dep_t;

const static gbp_vxlan_dep_t GD_INVALID = {
  .gd_sw_if_index = ~0,
  .gd_itf = INDEX_INVALID,
};

typedef struct gbp_vxlan_learn_t_
{
  ip46_address_t src;
  ip46_address_t dst;
  u32 vni;
  index_t gti;
  gbp_vxlan_tunnel_layer_t layer;
} gbp_vxlan_learn_t;

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
  u8 throttled;
  u8 dropped;
  u32 vni;
  u32 sw_if_index;
} gbp_vxlan_trace_t;

static void
gdb_vxlan_dep_add (gbp_vxlan_tunnel_t * gt, const gbp_vxlan_learn_t * gl)
{
  vnet_vxlan_gbp_tunnel_add_del_args_t args = {
    .is_add = 1,
    .is_ip6 = !ip46_address_is_ip4 (&gl->src),
    .vni = gl->vni,
    .src = gl->src,
    .dst = gl->dst,
    .instance = ~0,
    .mode = (GBP_VXLAN_TUN_L2 == gl->layer ?
	     VXLAN_GBP_TUNNEL_MODE_L2 : VXLAN_GBP_TUNNEL_MODE_L3),
  };
  u32 sw_if_index;
  int rv;

  rv = vnet_vxlan_gbp_tunnel_add_del (&args, &sw_if_index);

  if (0 == rv)
    {
      if (~0 != sw_if_index)
	{
	  vnet_sw_interface_t *sw;
	  gbp_vxlan_dep_t *gd;
	  vnet_main_t *vnm;

	  GBP_VXLAN_TUN_DBG ("add-dep:%U", format_vnet_sw_if_index_name,
			     vnet_get_main (), sw_if_index);

	  vec_validate_init_empty (gt->gt_tuns, sw_if_index, GD_INVALID);

	  gd = &gt->gt_tuns[sw_if_index];

	  gd->gd_sw_if_index = sw_if_index;

	  /*
	   * set the interface's MAC to the special value so all adjacencies
	   * though this interface use it as the source
	   */
	  vnm = vnet_get_main ();
	  sw = vnet_get_sw_interface (vnm, gd->gd_sw_if_index);
	  vnet_hw_interface_change_mac_address (vnm, sw->hw_if_index,
						gbp_route_domain_get_local_mac
						()->bytes);


	  if (GBP_VXLAN_TUN_L2 == gt->gt_layer)
	    {
	      gd->gd_itf =
		gbp_itf_add_and_lock (gd->gd_sw_if_index, gt->gt_bd_index);

	      gbp_itf_set_l2_output_feature (gd->gd_itf, gd->gd_sw_if_index,
					     L2OUTPUT_FEAT_GBP_POLICY_MAC);
	      gbp_itf_set_l2_input_feature (gd->gd_itf, gd->gd_sw_if_index,
					    L2INPUT_FEAT_GBP_LEARN);
	    }
	  else
	    {
	      const gbp_route_domain_t *grd;
	      fib_protocol_t fproto;

	      grd = gbp_route_domain_get (gt->gt_grd);

	      FOR_EACH_FIB_IP_PROTOCOL (fproto)
		ip_table_bind (fproto, gd->gd_sw_if_index,
			       grd->grd_table_id[fproto], 1);

	      gbp_learn_enable (gd->gd_sw_if_index, GBP_LEARN_MODE_L3);
	    }
	  return;
	}
    }

  GBP_VXLAN_TUN_DBG ("add-dep:FAILED");
}

static void
gdb_vxlan_dep_del (gbp_vxlan_tunnel_t * gt, gbp_vxlan_dep_t * gd)
{
  GBP_VXLAN_TUN_DBG ("del-dep:%U", format_vnet_sw_if_index_name,
		     vnet_get_main (), gd->gd_sw_if_index);

  if (GBP_VXLAN_TUN_L2 == gt->gt_layer)
    {
      gbp_itf_set_l2_output_feature (gd->gd_itf, gd->gd_sw_if_index,
				     L2OUTPUT_FEAT_NONE);
      gbp_itf_set_l2_input_feature (gd->gd_itf, gd->gd_sw_if_index,
				    L2INPUT_FEAT_NONE);
      gbp_itf_unlock (gd->gd_itf);
    }
  else
    {
      fib_protocol_t fproto;

      FOR_EACH_FIB_IP_PROTOCOL (fproto)
	ip_table_bind (fproto, gd->gd_sw_if_index, 0, 0);
    }

  vnet_vxlan_gbp_tunnel_del (gd->gd_sw_if_index);
}

static void
gbp_vxlan_learn (const gbp_vxlan_learn_t * gl)
{
  GBP_VXLAN_TUN_DBG ("learn: {%U,%U,%d} from:%d",
		     format_ip46_address, &gl->src, IP46_TYPE_ANY,
		     format_ip46_address, &gl->dst, IP46_TYPE_ANY,
		     gl->vni, gl->gti);

  /*
   * create a new dependent tunnel
   */
  gdb_vxlan_dep_add (gbp_vxlan_tunnel_get (gl->gti), gl);
}

always_inline void
gbp_vxlan_learn_ip4 (const ip4_address_t * src,
		     const ip4_address_t * dst,
		     u32 vni, index_t gti, gbp_vxlan_tunnel_layer_t layer)
{
  gbp_vxlan_learn_t gl = {
    .src.ip4 = *src,
    .dst.ip4 = *dst,
    .vni = vni,
    .gti = gti,
    .layer = layer,
  };

  vl_api_rpc_call_main_thread (gbp_vxlan_learn, (u8 *) & gl, sizeof (gl));
}

static uword
gbp_vxlan_decap (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * from_frame, u8 is_ip4)
{
  u32 n_left_to_next, n_left_from, next_index, seed, thread_index, *to_next,
    *from;
  f64 time_now;

  time_now = vlib_time_now (vm);
  thread_index = vm->thread_index;
  seed = throttle_seed (&gv_throttle, thread_index, time_now);
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
	  u32 bi0, t0, vni0;
	  uword *p;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = GBP_VXLAN_INPUT_NEXT_DROP;

	  t0 = 0;
	  b0 = vlib_get_buffer (vm, bi0);
	  vxlan_gbp0 =
	    vlib_buffer_get_current (b0) - sizeof (vxlan_gbp_header_t);

	  vni0 = vxlan_gbp_get_vni (vxlan_gbp0);
	  p = hash_get (gv_db, vni0);

	  /*
	   * For packets that arrve on this base interface, do not learn
	   * endpoints. this is so that they are not learned via this interface
	   * since this interface cannot send traffic. unleraned or unknown
	   * endpoints are sent via the spine proxy. which is fine
	   */
	  vnet_buffer2 (b0)->gbp.flags |= VXLAN_GBP_GPFLAGS_D;

	  if (PREDICT_FALSE (NULL == p))
	    {
	      gt0 = NULL;
	      next0 = GBP_VXLAN_INPUT_NEXT_DROP;
	    }
	  else
	    {
	      gt0 = gbp_vxlan_tunnel_get (p[0]);

	      if (is_ip4)
		{
		  ip4_header_t *ip4_0;
		  ip4_0 =
		    (ip4_header_t *) (((u8 *) vxlan_gbp0) -
				      sizeof (udp_header_t) -
				      sizeof (ip4_header_t));

		  t0 = throttle_check (&gv_throttle, thread_index,
				       ip4_0->src_address.as_u32, seed);
		  if (!t0)
		    {
		      gbp_vxlan_learn_ip4 (&ip4_0->dst_address,
					   &ip4_0->src_address,
					   vni0, p[0], gt0->gt_layer);
		    }
		}
	      else
		{
		  /* NO IPv6 underlay at this time */
		  /* ip6_header_t *ip6_0; */

		  /* ip6_0 = */
		  /*   (ip6_header_t *) (((u8 *) vxlan_gbp0) - */
		  /*                  sizeof (udp_header_t) - */
		  /*                  sizeof (ip6_header_t)); */

		  /* t0 = throttle_check (&gv_throttle, thread_index, */
		  /*                   ip6_address_hash_to_u32 */
		  /*                   (&ip6_0->src_address), seed); */
		  /* if (!t0) */
		  /*   { */
		  /*     gbp_learn_ip6_dp (&ip0->src_address, */
		  /*                       fib_index0, */
		  /*                       sw_if_index0, epg0); */
		  /*   } */

		  /* vlib_buffer_advance (b0, sizeof (*vxlan_gbp0)); */
		}

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
	      gbp_vxlan_trace_t *tr
		= vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->throttled = t0;
	      tr->dropped = (next0 == GBP_VXLAN_INPUT_NEXT_DROP);
	      tr->vni = vni0;
	      tr->sw_if_index = (gt0 ? gt0->gt_sw_if_index : ~0);
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

  s = format (s, "vni:%d throttled:%d dropped:%d rx:%d",
	      t->vni, t->throttled, t->dropped, t->sw_if_index);

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
  gbp_vxlan_dep_t *gd;

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

  vec_foreach (gd, gt->gt_tuns)
  {
    if (~0 != gd->gd_sw_if_index)
      s = format (s, " %U", format_vnet_sw_if_index_name,
		  vnet_get_main (), gd->gd_sw_if_index);
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

/* void */
/* gbp_vxlan_scan (vlib_main_t * vm) */
/* { */
/*   f64 last_start, start_time, delta_t; */
/*   u32 vni, n_elts; */
/*   index_t gti; */
/*   i32 ii; */

/*   delta_t = 0; */
/*   last_start = start_time = vlib_time_now (vm); */

/*   /\* *INDENT-OFF* *\/ */
/*   hash_foreach (vni, gti, gv_db, */
/*   ({ */
/*     gbp_vxlan_tunnel_t *gt; */
/*     gbp_vxlan_dep_t *gd; */

/*     /\* allow no more than 20us without a pause *\/ */
/*     delta_t = vlib_time_now (vm) - last_start; */
/*     if (delta_t > 20e-6) */
/*       { */
/* 	/\* suspend for 100 us *\/ */
/*         n_elts = hash_elts (gv_db); */
/*         vlib_process_suspend (vm, 100e-6); */
/*         last_start = vlib_time_now (vm); */

/*         /\* did the hash table change whilst we were sleeping *\/ */
/*         if (n_elts != hash_elts (gv_db)) */
/*           break; */
/*       } */

/*     /\* */
/*      * check all the dependent tunnels on this tunnel. */
/*      * go backwards so the vec_del is safe */
/*      *\/ */
/*     gt = gbp_vxlan_tunnel_get (gti); */
/*     vec_foreach_index_backwards(ii, gt->gt_tuns) */
/*       { */
/*         gd = &gt->gt_tuns[ii]; */

/*         if (~0 == gd->gd_sw_if_index) */
/*           continue; */

/*         if (1 == gbp_itf_n_locks(gd->gd_itf)) */
/*           { */
/*             vlib_worker_thread_barrier_sync (vm); */
/*             gbp_itf_unlock(gd->gd_itf); */

/*             gdb_vxlan_dep_del(gd->gd_sw_if_index); */

/*             vec_del1 (gt->gt_tuns, ii); */
/*             vlib_worker_thread_barrier_release (vm); */
/*           } */
/*       } */
/*   })); */
/*   /\* *INDENT-ON* *\/ */
/* } */

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
      vnet_main_t *vnm;
      index_t gbi, grdi;

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
      gbp_vxlan_dep_t *gd;
      vnet_main_t *vnm;

      vnm = vnet_get_main ();
      gt = gbp_vxlan_tunnel_get (p[0]);

      GBP_VXLAN_TUN_DBG ("del: %U", format_gbp_vxlan_tunnel,
			 gt - gbp_vxlan_tunnel_pool);

      /* flush all the dependent/derived tunnels */
      vec_foreach (gd, gt->gt_tuns)
      {
	if (~0 != gd->gd_sw_if_index)
	  gdb_vxlan_dep_del (gt, gd);
      }
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
  vlib_thread_main_t *tm = &vlib_thread_main;
  u32 slot4;

  throttle_init (&gv_throttle, tm->n_vlib_mains, 1e-2);

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
