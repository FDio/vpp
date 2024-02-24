/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>
#include <vnet/vnet.h>
#include <vnet/devices/devices.h> /* vnet_get_aggregate_rx_packets */
#include <vnet/interface.h>

vlib_stats_string_vector_t if_names = 0;
vlib_stats_string_vector_t if_tags = 0;
u32 if_speed = 0;
static u32 **dir_entry_indices = 0;

static struct
{
  char *prefix, *name;
  u32 index;
} if_counters[] = {
#define _(e, n, p) { .prefix = #p, .name = #n },
  foreach_simple_interface_counter_name foreach_combined_interface_counter_name
    _ (x, speed, if)
#undef _
};

static clib_error_t *
statseg_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  u8 *name = 0;

  if (if_names == 0)
    {
      if_names = vlib_stats_add_string_vector ("/if/names");
      if_tags = vlib_stats_add_string_vector ("/if/tags");
      if_speed = vlib_stats_add_counter_vector ("/if/speed");

      for (int i = 0; i < ARRAY_LEN (if_counters); i++)
	if_counters[i].index = vlib_stats_find_entry_index (
	  "/%s/%s", if_counters[i].prefix, if_counters[i].name);
    }

  vec_validate (dir_entry_indices, sw_if_index);

  vlib_stats_segment_lock ();

  if (is_add)
    {
      vnet_sw_interface_t *si, *si_sup;
      vnet_hw_interface_t *hi_sup;

      si = vnet_get_sw_interface (vnm, sw_if_index);
      si_sup = vnet_get_sup_sw_interface (vnm, si->sw_if_index);
      ASSERT (si_sup->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
      hi_sup = vnet_get_hw_interface (vnm, si_sup->hw_if_index);

      name = format (0, "%v", hi_sup->name);
      if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	name = format (name, ".%d", si->sub.id);

      vlib_stats_set_string_vector (&if_names, sw_if_index, "%v", name);
      vlib_stats_set_string_vector (&if_tags, sw_if_index, "");
      vlib_stats_set_counter_vector (if_speed, 0, sw_if_index,
				     hi_sup->link_speed);

      for (u32 index, i = 0; i < ARRAY_LEN (if_counters); i++)
	{
	  index = vlib_stats_add_symlink (
	    if_counters[i].index, sw_if_index, "/interfaces/%U/%s",
	    format_vlib_stats_symlink, name, if_counters[i].name);
	  ASSERT (index != ~0);
	  vec_add1 (dir_entry_indices[sw_if_index], index);
	}
    }
  else
    {
      name = format (0, "%s", "deleted");
      vlib_stats_set_string_vector (&if_names, sw_if_index, "%v", name);
      vlib_stats_set_string_vector (&if_tags, sw_if_index, "");
      vlib_stats_set_counter_vector (if_speed, 0, sw_if_index, 0);

      for (u32 i = 0; i < vec_len (dir_entry_indices[sw_if_index]); i++)
	vlib_stats_remove_entry (dir_entry_indices[sw_if_index][i]);
      vec_free (dir_entry_indices[sw_if_index]);
    }

  vec_free (name);

  vlib_stats_segment_unlock ();

  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (statseg_sw_interface_add_del);

void
stat_segment_update_hw_interface_name (vnet_main_t *vnm, u32 hw_if_index)
{
  vnet_hw_interface_t *hi_sup;
  vnet_sw_interface_t *si;
  u32 *sw_if_indices = NULL;
  u32 id, sw_if_index;
  u8 *name = 0;

  if (if_names == 0)
    return;

  hi_sup = vnet_get_hw_interface (vnm, hw_if_index);
  vec_validate (sw_if_indices,
		hash_elts (hi_sup->sub_interface_sw_if_index_by_id));
  vec_reset_length (sw_if_indices);

  vec_add1 (sw_if_indices, hi_sup->sw_if_index);
  /* clang-format off */
  hash_foreach (id, sw_if_index, hi_sup->sub_interface_sw_if_index_by_id,
  ({
    vec_add1 (sw_if_indices, sw_if_index);
  }));
  /* clang-format on */

  vlib_stats_segment_lock ();

  vec_foreach_index (id, sw_if_indices)
    {
      sw_if_index = vec_elt (sw_if_indices, id);

      si = vnet_get_sw_interface (vnm, sw_if_index);
      name = format (name, "%v", hi_sup->name);
      if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	name = format (name, ".%d", si->sub.id);

      vlib_stats_set_string_vector (&if_names, sw_if_index, "%v", name);

      for (u32 index, i = 0; i < ARRAY_LEN (if_counters); i++)
	{
	  vlib_stats_remove_entry (dir_entry_indices[sw_if_index][i]);
	  index = vlib_stats_add_symlink (
	    if_counters[i].index, sw_if_index, "/interfaces/%U/%s",
	    format_vlib_stats_symlink, name, if_counters[i].name);
	  ASSERT (index != ~0);
	  dir_entry_indices[sw_if_index][i] = index;
	}

      vec_reset_length (name);
    }

  vec_free (name);

  vlib_stats_segment_unlock ();

  vec_free (sw_if_indices);
}

void
stat_segment_update_hw_interface_link_speed (vnet_main_t *vnm, u32 hw_if_index)
{
  vnet_hw_interface_t *hi_sup;
  u32 id, sw_if_index;
  u32 *sw_if_indices = NULL;

  if (if_speed == 0)
    return;

  hi_sup = vnet_get_hw_interface (vnm, hw_if_index);
  vec_validate (sw_if_indices,
		hash_elts (hi_sup->sub_interface_sw_if_index_by_id));
  vec_reset_length (sw_if_indices);

  vec_add1 (sw_if_indices, hi_sup->sw_if_index);
  /* clang-format off */
  hash_foreach (id, sw_if_index, hi_sup->sub_interface_sw_if_index_by_id,
  ({
    vec_add1 (sw_if_indices, sw_if_index);
  }));
  /* clang-format on */

  vlib_stats_segment_lock ();

  vec_foreach_index (id, sw_if_indices)
    {
      sw_if_index = vec_elt (sw_if_indices, id);

      vlib_stats_set_counter_vector (if_speed, 0, sw_if_index,
				     hi_sup->link_speed);
    }

  vlib_stats_segment_unlock ();

  vec_free (sw_if_indices);
}

void
stat_segment_set_sw_interface_tag (u32 sw_if_index, u8 *tag)
{
  ASSERT (if_tags);
  vlib_stats_set_string_vector (&if_tags, sw_if_index, tag ? "%s" : "", tag);
}
