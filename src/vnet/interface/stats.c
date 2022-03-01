/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>
#include <vnet/vnet.h>
#include <vnet/devices/devices.h> /* vnet_get_aggregate_rx_packets */
#include <vnet/interface.h>

u8 **interfaces = 0;
u32 **dir_entry_indices = 0;

static struct
{
  char *prefix;
  char *name;
  u32 index;
} if_counters[] = {

#define _(e, n, p) { .prefix = #p, .name = #n },

  foreach_simple_interface_counter_name foreach_combined_interface_counter_name
#undef _
};

static clib_error_t *
statseg_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
  vnet_sw_interface_t *si_sup =
    vnet_get_sup_sw_interface (vnm, si->sw_if_index);
  vnet_hw_interface_t *hi_sup;
  void *oldheap;

  if (dir_entry_indices == 0)
    {
      for (int i = 0; i < ARRAY_LEN (if_counters); i++)
	if_counters[i].index = vlib_stats_find_directory_index (
	  "/%s/%s", if_counters[i].prefix, if_counters[i].name);
    }

  vec_validate (dir_entry_indices, sw_if_index);

  oldheap = clib_mem_set_heap (sm->heap);
  vlib_stats_segment_lock ();

  vec_validate (interfaces, sw_if_index);
  sm->directory_vector[vnm->interface_names_stats_dir_index].data = interfaces;

  ASSERT (si_sup->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
  hi_sup = vnet_get_hw_interface (vnm, si_sup->hw_if_index);

  if (is_add)
    {
      u8 *s = format (0, "%v", hi_sup->name);
      if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	s = format (s, ".%d", si->sub.id);
      s = format (s, "%c", 0);

      ASSERT (interfaces[sw_if_index] == 0);
      interfaces[sw_if_index] = s;
      clib_mem_set_heap (oldheap);
      u8 *pfx = format (0, "/interfaces/%U", format_vlib_stats_symlink, s);
      for (u32 i = 0; i < ARRAY_LEN (if_counters); i++)
	{
	  u32 index =
	    vlib_stats_register_symlink (if_counters[i].index, sw_if_index,
					 "%v/%s", pfx, if_counters[i].name);
	  ASSERT (index != ~0);
	  vec_add1 (dir_entry_indices[sw_if_index], index);
	}
      vec_free (pfx);
    }
  else
    {
      vec_free (interfaces[sw_if_index]);
      clib_mem_set_heap (oldheap);
      for (u32 i = 0; i < vec_len (dir_entry_indices[sw_if_index]); i++)
	vlib_stats_delete_counter (dir_entry_indices[sw_if_index][i]);
      vec_free (dir_entry_indices[sw_if_index]);
    }

  vlib_stats_segment_unlock ();

  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (statseg_sw_interface_add_del);
