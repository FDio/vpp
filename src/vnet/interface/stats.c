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
static u32 **dir_entry_indices = 0;

static struct
{
  char *prefix, *name;
  u32 index;
} if_counters[] = {
#define _(e, n, p) { .prefix = #p, .name = #n },
  foreach_simple_interface_counter_name foreach_combined_interface_counter_name
#undef _
};

static clib_error_t *
statseg_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  u8 *name;

  if (if_names == 0)
    {
      if_names = vlib_stats_add_string_vector ("/if/names");

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

      for (u32 index, i = 0; i < ARRAY_LEN (if_counters); i++)
	{
	  name = format (0, "%v", hi_sup->name);
	  index = vlib_stats_add_symlink (
	    if_counters[i].index, sw_if_index, "/interfaces/%U/%s",
	    format_vlib_stats_symlink, name, if_counters[i].name);
	  if (index != ~0)
	    vec_add1 (dir_entry_indices[sw_if_index], index);
	}
    }
  else
    {
      name = format (0, "%s", "deleted");
      vlib_stats_set_string_vector (&if_names, sw_if_index, "%v", name);
      for (u32 i = 0; i < vec_len (dir_entry_indices[sw_if_index]); i++)
	vlib_stats_remove_entry (dir_entry_indices[sw_if_index][i]);
      vec_free (dir_entry_indices[sw_if_index]);
    }

  vec_free (name);

  vlib_stats_segment_unlock ();

  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (statseg_sw_interface_add_del);
