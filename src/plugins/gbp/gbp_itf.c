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

#include <vnet/l2/l2_in_out_feat_arc.h>
#include <plugins/gbp/gbp_itf.h>

/**
 * Attributes and configurations attached to interfaces by GBP
 */
typedef struct gbp_itf_t_
{
  /**
   * Number of references to this interface
   */
  u32 gi_locks;

  u32 gi_sw_if_index;
  u32 gi_bd_index;

  /**
   * L2/L3 Features configured by each user
   */
  u32 *gi_l2_input_fbs;
  u32 gi_l2_input_fb;
  u32 *gi_l2_output_fbs;
  u32 gi_l2_output_fb;
} gbp_itf_t;

static gbp_itf_t *gbp_itfs;

static gbp_itf_t *
gbp_itf_get (index_t gii)
{
  vec_validate (gbp_itfs, gii);

  return (&gbp_itfs[gii]);
}

static index_t
gbp_itf_get_itf (u32 sw_if_index)
{
  return (sw_if_index);
}

index_t
gbp_itf_add_and_lock (u32 sw_if_index, u32 bd_index)
{
  gbp_itf_t *gi;

  gi = gbp_itf_get (gbp_itf_get_itf (sw_if_index));

  if (0 == gi->gi_locks)
    {
      gi->gi_sw_if_index = sw_if_index;
      gi->gi_bd_index = bd_index;

      if (~0 != gi->gi_bd_index)
	set_int_l2_mode (vlib_get_main (), vnet_get_main (),
			 MODE_L2_BRIDGE, sw_if_index, bd_index,
			 L2_BD_PORT_TYPE_NORMAL, 0, 0);

    }

  gi->gi_locks++;

  return (sw_if_index);
}

void
gbp_itf_unlock (index_t gii)
{
  gbp_itf_t *gi;

  gi = gbp_itf_get (gii);
  ASSERT (gi->gi_locks > 0);
  gi->gi_locks--;

  if (0 == gi->gi_locks)
    {
      if (~0 != gi->gi_bd_index)
	set_int_l2_mode (vlib_get_main (), vnet_get_main (), MODE_L3,
			 gi->gi_sw_if_index, 0, L2_BD_PORT_TYPE_NORMAL, 0, 0);
      vec_free (gi->gi_l2_input_fbs);
      vec_free (gi->gi_l2_output_fbs);

      memset (gi, 0, sizeof (*gi));
    }
}

/*
 * enable/disable a feature in l2-input arcs by vlib interface index
 */
int
gbp_itf_l2_feature_enable_disable_if_index (index_t if_index,
					    const char *node_name,
					    int enable_disable)
{
  int err;

  /*
   * unfortunately, l2-input use 3 different arcs for nonip, ip4 and ip6 packets
   * we need to duplicate our nodes on each feature arc
   */

  err = vnet_l2_feature_enable_disable ("l2-input-nonip", node_name, if_index,
					enable_disable, 0, 0);
  if (err)
    goto err_nonip;

  err = vnet_l2_feature_enable_disable ("l2-input-ip4", node_name, if_index,
					enable_disable, 0, 0);
  if (err)
    goto err_ip4;

  err = vnet_l2_feature_enable_disable ("l2-input-ip6", node_name, if_index,
					enable_disable, 0, 0);
  if (err)
    goto err_ip6;

  return 0;

  /* rollback changes in case of errors */
err_ip6:
  err = vnet_l2_feature_enable_disable ("l2-input-ip4", node_name, if_index,
					!enable_disable, 0, 0);
err_ip4:
  err = vnet_l2_feature_enable_disable ("l2-input-nonip", node_name, if_index,
					!enable_disable, 0, 0);
err_nonip:
  return err;
}

/*
 * enable/disable a feature in l2-input arcs by gbp_if_t index
 */
int
gbp_itf_l2_feature_enable_disable (index_t gii, const char *node_name,
				   int enable_disable)
{
  gbp_itf_t *gi = gbp_itf_get (gii);

  if (gi->gi_bd_index == ~0)
    return 0;

  return gbp_itf_l2_feature_enable_disable_if_index (gi->gi_sw_if_index,
						     node_name,
						     enable_disable);
}

void
gbp_itf_set_l2_input_feature (index_t gii,
			      index_t useri, l2input_feat_masks_t feats)
{
  u32 diff_fb, new_fb, *fb, feat;
  gbp_itf_t *gi;

  gi = gbp_itf_get (gii);

  if (gi->gi_bd_index == ~0)
    return;

  vec_validate (gi->gi_l2_input_fbs, useri);
  gi->gi_l2_input_fbs[useri] = feats;

  new_fb = 0;
  vec_foreach (fb, gi->gi_l2_input_fbs)
  {
    new_fb |= *fb;
  }

  /* add new features */
  diff_fb = (gi->gi_l2_input_fb ^ new_fb) & new_fb;

  /* *INDENT-OFF* */
  foreach_set_bit (feat, diff_fb,
  ({
    l2input_intf_bitmap_enable (gi->gi_sw_if_index, (1 << feat), 1);
  }));
  /* *INDENT-ON* */

  /* remove unneeded features */
  diff_fb = (gi->gi_l2_input_fb ^ new_fb) & gi->gi_l2_input_fb;

  /* *INDENT-OFF* */
  foreach_set_bit (feat, diff_fb,
  ({
    l2input_intf_bitmap_enable (gi->gi_sw_if_index, (1 << feat), 0);
  }));
  /* *INDENT-ON* */

  gi->gi_l2_input_fb = new_fb;
}

void
gbp_itf_set_l2_output_feature (index_t gii,
			       index_t useri, l2output_feat_masks_t feats)
{
  u32 diff_fb, new_fb, *fb, feat;
  gbp_itf_t *gi;

  gi = gbp_itf_get (gii);

  if (gi->gi_bd_index == ~0)
    return;

  vec_validate (gi->gi_l2_output_fbs, useri);
  gi->gi_l2_output_fbs[useri] = feats;

  new_fb = 0;
  vec_foreach (fb, gi->gi_l2_output_fbs)
  {
    new_fb |= *fb;
  }

  /* add new features */
  diff_fb = (gi->gi_l2_output_fb ^ new_fb) & new_fb;

  /* *INDENT-OFF* */
  foreach_set_bit (feat, diff_fb,
  ({
    l2output_intf_bitmap_enable (gi->gi_sw_if_index, (1 << feat), 1);
  }));
  /* *INDENT-ON* */

  /* remove unneeded features */
  diff_fb = (gi->gi_l2_output_fb ^ new_fb) & gi->gi_l2_output_fb;

  /* *INDENT-OFF* */
  foreach_set_bit (feat, diff_fb,
  ({
    l2output_intf_bitmap_enable (gi->gi_sw_if_index, (1 << feat), 0);
  }));
  /* *INDENT-ON* */

  gi->gi_l2_output_fb = new_fb;
}

u8 *
format_gbp_itf (u8 * s, va_list * args)
{
  index_t gii = va_arg (*args, index_t);
  gbp_itf_t *gi;

  gi = gbp_itf_get (gii);

  s = format (s, "%U locks:%d input-feats:%U output-feats:%U",
	      format_vnet_sw_if_index_name, vnet_get_main (),
	      gi->gi_sw_if_index, gi->gi_locks,
	      format_l2_input_features, gi->gi_l2_input_fb, 0,
	      format_l2_output_features, gi->gi_l2_output_fb, 0);

  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
