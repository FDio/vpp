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

#include <plugins/gbp/gbp_itf.h>
#include <plugins/gbp/gbp_bridge_domain.h>
#include <plugins/gbp/gbp_route_domain.h>

#define foreach_gbp_itf_mode  \
  _(L2, "l2")                 \
  _(L3, "L3")

typedef enum gbp_ift_mode_t_
{
#define _(s,v)  GBP_ITF_MODE_##s,
  foreach_gbp_itf_mode
#undef _
} gbp_itf_mode_t;

/**
 * Attributes and configurations attached to interfaces by GBP
 */
typedef struct gbp_itf_t_
{
  /**
   * Number of references to this interface
   */
  u32 gi_locks;

  /**
   * The interface this wrapper is managing
   */
  u32 gi_sw_if_index;

  /**
   * The mode of the interface
   */
  gbp_itf_mode_t gi_mode;

  /**
   * Users of this interface - this is encoded in the user's handle
   */
  u32 *gi_users;

  /**
   * L2/L3 Features configured by each user
   */
  u32 *gi_input_fbs;
  u32 gi_input_fb;
  u32 *gi_output_fbs;
  u32 gi_output_fb;

  /**
   * function to call when the interface is deleted.
   */
  gbp_itf_free_fn_t gi_free_fn;

  union
  {
    /**
     * GBP BD or RD index
     */
    u32 gi_gbi;
    index_t gi_gri;
  };
} gbp_itf_t;

static gbp_itf_t *gbp_itf_pool;
static uword *gbp_itf_db;

static const char *gbp_itf_feat_bit_pos_to_arc[] = {
#define _(s,v,a) [GBP_ITF_L3_FEAT_POS_##s] = a,
  foreach_gdb_l3_feature
#undef _
};

static const char *gbp_itf_feat_bit_pos_to_feat[] = {
#define _(s,v,a) [GBP_ITF_L3_FEAT_POS_##s] = v,
  foreach_gdb_l3_feature
#undef _
};

u8 *
format_gbp_itf_l3_feat (u8 * s, va_list * args)
{
  gbp_itf_l3_feat_t flags = va_arg (*args, gbp_itf_l3_feat_t);

#define _(a, b, c)                              \
  if (flags & GBP_ITF_L3_FEAT_##a)              \
    s = format (s, "%s ", b);
  foreach_gdb_l3_feature
#undef _
    return (s);
}

void
gbp_itf_hdl_reset (gbp_itf_hdl_t * gh)
{
  *gh = GBP_ITF_HDL_INVALID;
}

bool
gbp_itf_hdl_is_valid (gbp_itf_hdl_t gh)
{
  return (gh.gh_which != GBP_ITF_HDL_INVALID.gh_which);
}

static gbp_itf_t *
gbp_itf_get (index_t gii)
{
  if (pool_is_free_index (gbp_itf_pool, gii))
    return (NULL);

  return (pool_elt_at_index (gbp_itf_pool, gii));
}

static gbp_itf_t *
gbp_itf_find (u32 sw_if_index)
{
  uword *p;

  p = hash_get (gbp_itf_db, sw_if_index);

  if (NULL != p)
    return (gbp_itf_get (p[0]));

  return (NULL);
}

static gbp_itf_t *
gbp_itf_find_hdl (gbp_itf_hdl_t gh)
{
  return (gbp_itf_find (gh.gh_which));
}

u32
gbp_itf_get_sw_if_index (gbp_itf_hdl_t hdl)
{
  return (hdl.gh_which);
}

static gbp_itf_hdl_t
gbp_itf_mk_hdl (gbp_itf_t * gi)
{
  gbp_itf_hdl_t gh;
  u32 *useri;

  pool_get (gi->gi_users, useri);
  *useri = 0;

  gh.gh_who = useri - gi->gi_users;
  gh.gh_which = gi->gi_sw_if_index;

  return (gh);
}

static gbp_itf_hdl_t
gbp_itf_l2_add_and_lock_i (u32 sw_if_index, index_t gbi, gbp_itf_free_fn_t ff)
{
  gbp_itf_t *gi;

  gi = gbp_itf_find (sw_if_index);

  if (NULL == gi)
    {
      pool_get_zero (gbp_itf_pool, gi);

      gi->gi_sw_if_index = sw_if_index;
      gi->gi_gbi = gbi;
      gi->gi_mode = GBP_ITF_MODE_L2;
      gi->gi_free_fn = ff;

      gbp_bridge_domain_itf_add (gi->gi_gbi, gi->gi_sw_if_index,
				 L2_BD_PORT_TYPE_NORMAL);

      hash_set (gbp_itf_db, gi->gi_sw_if_index, gi - gbp_itf_pool);
    }

  gi->gi_locks++;

  return (gbp_itf_mk_hdl (gi));
}

gbp_itf_hdl_t
gbp_itf_l2_add_and_lock (u32 sw_if_index, index_t gbi)
{
  return (gbp_itf_l2_add_and_lock_i (sw_if_index, gbi, NULL));
}

gbp_itf_hdl_t
gbp_itf_l2_add_and_lock_w_free (u32 sw_if_index,
				index_t gbi, gbp_itf_free_fn_t ff)
{
  return (gbp_itf_l2_add_and_lock_i (sw_if_index, gbi, ff));
}

gbp_itf_hdl_t
gbp_itf_l3_add_and_lock_i (u32 sw_if_index, index_t gri, gbp_itf_free_fn_t ff)
{
  gbp_itf_t *gi;

  gi = gbp_itf_find (sw_if_index);

  if (NULL == gi)
    {
      const gbp_route_domain_t *grd;
      fib_protocol_t fproto;

      pool_get_zero (gbp_itf_pool, gi);

      gi->gi_sw_if_index = sw_if_index;
      gi->gi_mode = GBP_ITF_MODE_L3;
      gi->gi_gri = gri;
      gi->gi_free_fn = ff;

      grd = gbp_route_domain_get (gi->gi_gri);

      ip4_sw_interface_enable_disable (gi->gi_sw_if_index, 1);
      ip6_sw_interface_enable_disable (gi->gi_sw_if_index, 1);

      FOR_EACH_FIB_IP_PROTOCOL (fproto)
	ip_table_bind (fproto, gi->gi_sw_if_index,
		       grd->grd_table_id[fproto], 1);

      hash_set (gbp_itf_db, gi->gi_sw_if_index, gi - gbp_itf_pool);
    }

  gi->gi_locks++;

  return (gbp_itf_mk_hdl (gi));
}

gbp_itf_hdl_t
gbp_itf_l3_add_and_lock (u32 sw_if_index, index_t gri)
{
  return (gbp_itf_l3_add_and_lock_i (sw_if_index, gri, NULL));
}

gbp_itf_hdl_t
gbp_itf_l3_add_and_lock_w_free (u32 sw_if_index,
				index_t gri, gbp_itf_free_fn_t ff)
{
  return (gbp_itf_l3_add_and_lock_i (sw_if_index, gri, ff));
}

void
gbp_itf_lock (gbp_itf_hdl_t gh)
{
  gbp_itf_t *gi;

  if (!gbp_itf_hdl_is_valid (gh))
    return;

  gi = gbp_itf_find_hdl (gh);

  gi->gi_locks++;
}

gbp_itf_hdl_t
gbp_itf_clone_and_lock (gbp_itf_hdl_t gh)
{
  gbp_itf_t *gi;

  if (!gbp_itf_hdl_is_valid (gh))
    return (GBP_ITF_HDL_INVALID);

  gi = gbp_itf_find_hdl (gh);

  gi->gi_locks++;

  return (gbp_itf_mk_hdl (gi));
}

void
gbp_itf_unlock (gbp_itf_hdl_t * gh)
{
  gbp_itf_t *gi;

  if (!gbp_itf_hdl_is_valid (*gh))
    return;

  gi = gbp_itf_find_hdl (*gh);
  ASSERT (gi->gi_locks > 0);
  gi->gi_locks--;

  if (0 == gi->gi_locks)
    {
      if (GBP_ITF_MODE_L2 == gi->gi_mode)
	{
	  gbp_itf_l2_set_input_feature (*gh, L2INPUT_FEAT_NONE);
	  gbp_itf_l2_set_output_feature (*gh, L2OUTPUT_FEAT_NONE);
	  gbp_bridge_domain_itf_del (gi->gi_gbi,
				     gi->gi_sw_if_index,
				     L2_BD_PORT_TYPE_NORMAL);
	}
      else
	{
	  fib_protocol_t fproto;

	  gbp_itf_l3_set_input_feature (*gh, GBP_ITF_L3_FEAT_NONE);
	  FOR_EACH_FIB_IP_PROTOCOL (fproto)
	    ip_table_bind (fproto, gi->gi_sw_if_index, 0, 0);

	  ip4_sw_interface_enable_disable (gi->gi_sw_if_index, 0);
	  ip6_sw_interface_enable_disable (gi->gi_sw_if_index, 0);
	}

      hash_unset (gbp_itf_db, gi->gi_sw_if_index);

      if (gi->gi_free_fn)
	gi->gi_free_fn (gi->gi_sw_if_index);

      pool_free (gi->gi_users);
      vec_free (gi->gi_input_fbs);
      vec_free (gi->gi_output_fbs);

      memset (gi, 0, sizeof (*gi));
    }

  gbp_itf_hdl_reset (gh);
}

void
gbp_itf_l3_set_input_feature (gbp_itf_hdl_t gh, gbp_itf_l3_feat_t feats)
{
  u32 diff_fb, new_fb, *fb, feat;
  gbp_itf_t *gi;

  gi = gbp_itf_find_hdl (gh);

  if (NULL == gi || GBP_ITF_MODE_L3 != gi->gi_mode)
    return;

  vec_validate (gi->gi_input_fbs, gh.gh_who);
  gi->gi_input_fbs[gh.gh_who] = feats;

  new_fb = 0;
  vec_foreach (fb, gi->gi_input_fbs)
  {
    new_fb |= *fb;
  }

  /* add new features */
  diff_fb = (gi->gi_input_fb ^ new_fb) & new_fb;

  /* *INDENT-OFF* */
  foreach_set_bit (feat, diff_fb,
  ({
    vnet_feature_enable_disable (gbp_itf_feat_bit_pos_to_arc[feat],
                                 gbp_itf_feat_bit_pos_to_feat[feat],
                                 gi->gi_sw_if_index, 1, 0, 0);
  }));
  /* *INDENT-ON* */

  /* remove unneeded features */
  diff_fb = (gi->gi_input_fb ^ new_fb) & gi->gi_input_fb;

  /* *INDENT-OFF* */
  foreach_set_bit (feat, diff_fb,
  ({
    vnet_feature_enable_disable (gbp_itf_feat_bit_pos_to_arc[feat],
                                 gbp_itf_feat_bit_pos_to_feat[feat],
                                 gi->gi_sw_if_index, 0, 0, 0);
  }));
  /* *INDENT-ON* */

  gi->gi_input_fb = new_fb;
}

void
gbp_itf_l2_set_input_feature (gbp_itf_hdl_t gh, l2input_feat_masks_t feats)
{
  u32 diff_fb, new_fb, *fb, feat;
  gbp_itf_t *gi;

  gi = gbp_itf_find_hdl (gh);

  if (NULL == gi || GBP_ITF_MODE_L2 != gi->gi_mode)
    {
      ASSERT (0);
      return;
    }

  vec_validate (gi->gi_input_fbs, gh.gh_who);
  gi->gi_input_fbs[gh.gh_who] = feats;

  new_fb = 0;
  vec_foreach (fb, gi->gi_input_fbs)
  {
    new_fb |= *fb;
  }

  /* add new features */
  diff_fb = (gi->gi_input_fb ^ new_fb) & new_fb;

  /* *INDENT-OFF* */
  foreach_set_bit (feat, diff_fb,
  ({
    l2input_intf_bitmap_enable (gi->gi_sw_if_index, (1 << feat), 1);
  }));
  /* *INDENT-ON* */

  /* remove unneeded features */
  diff_fb = (gi->gi_input_fb ^ new_fb) & gi->gi_input_fb;

  /* *INDENT-OFF* */
  foreach_set_bit (feat, diff_fb,
  ({
    l2input_intf_bitmap_enable (gi->gi_sw_if_index, (1 << feat), 0);
  }));
  /* *INDENT-ON* */

  gi->gi_input_fb = new_fb;
}

void
gbp_itf_l2_set_output_feature (gbp_itf_hdl_t gh, l2output_feat_masks_t feats)
{
  u32 diff_fb, new_fb, *fb, feat;
  gbp_itf_t *gi;

  gi = gbp_itf_find_hdl (gh);

  if (NULL == gi || GBP_ITF_MODE_L2 != gi->gi_mode)
    {
      ASSERT (0);
      return;
    }

  vec_validate (gi->gi_output_fbs, gh.gh_who);
  gi->gi_output_fbs[gh.gh_who] = feats;

  new_fb = 0;
  vec_foreach (fb, gi->gi_output_fbs)
  {
    new_fb |= *fb;
  }

  /* add new features */
  diff_fb = (gi->gi_output_fb ^ new_fb) & new_fb;

  /* *INDENT-OFF* */
  foreach_set_bit (feat, diff_fb,
  ({
    l2output_intf_bitmap_enable (gi->gi_sw_if_index, (1 << feat), 1);
  }));
  /* *INDENT-ON* */

  /* remove unneeded features */
  diff_fb = (gi->gi_output_fb ^ new_fb) & gi->gi_output_fb;

  /* *INDENT-OFF* */
  foreach_set_bit (feat, diff_fb,
  ({
    l2output_intf_bitmap_enable (gi->gi_sw_if_index, (1 << feat), 0);
  }));
  /* *INDENT-ON* */

  gi->gi_output_fb = new_fb;
}

static u8 *
format_gbp_itf_mode (u8 * s, va_list * args)
{
  gbp_itf_mode_t mode = va_arg (*args, gbp_itf_mode_t);

  switch (mode)
    {
#define _(a,v)                                  \
    case GBP_ITF_MODE_##a:                      \
      return format(s, "%s", v);
      foreach_gbp_itf_mode
#undef _
    }
  return (s);
}

static u8 *
format_gbp_itf (u8 * s, va_list * args)
{
  index_t gii = va_arg (*args, index_t);
  gbp_itf_t *gi;

  if (INDEX_INVALID == gii)
    return (format (s, "unset"));

  gi = gbp_itf_get (gii);

  s = format (s, "%U locks:%d mode:%U ",
	      format_vnet_sw_if_index_name, vnet_get_main (),
	      gi->gi_sw_if_index, gi->gi_locks,
	      format_gbp_itf_mode, gi->gi_mode);

  if (GBP_ITF_MODE_L2 == gi->gi_mode)
    s = format (s, "gbp-bd:%d input-feats:[%U] output-feats:[%U]",
		gi->gi_gbi,
		format_l2_input_features, gi->gi_input_fb, 0,
		format_l2_output_features, gi->gi_output_fb, 0);
  else
    s = format (s, "gbp-rd:%d input-feats:[%U] output-feats:[%U]",
		gi->gi_gbi,
		format_gbp_itf_l3_feat, gi->gi_input_fb,
		format_gbp_itf_l3_feat, gi->gi_output_fb);

  return (s);
}

u8 *
format_gbp_itf_hdl (u8 * s, va_list * args)
{
  gbp_itf_hdl_t gh = va_arg (*args, gbp_itf_hdl_t);
  gbp_itf_t *gi;

  gi = gbp_itf_find_hdl (gh);

  if (NULL == gi)
    return format (s, "INVALID");

  return (format (s, "%U", format_gbp_itf, gi - gbp_itf_pool));
}

static clib_error_t *
gbp_itf_show (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 gii;

  vlib_cli_output (vm, "Interfaces:");

  /* *INDENT-OFF* */
  pool_foreach_index (gii, gbp_itf_pool,
  ({
    vlib_cli_output (vm, "  [%d] %U", gii, format_gbp_itf, gii);
  }));
  /* *INDENT-ON* */

  return (NULL);
}

/*?
 * Show Group Based Interfaces
 *
 * @cliexpar
 * @cliexstart{show gbp contract}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_contract_show_node, static) = {
  .path = "show gbp interface",
  .short_help = "show gbp interface\n",
  .function = gbp_itf_show,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
