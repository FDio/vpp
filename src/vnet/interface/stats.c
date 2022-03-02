/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>
#include <vnet/vnet.h>
#include <vnet/devices/devices.h> /* vnet_get_aggregate_rx_packets */
#include <vnet/interface.h>

static clib_error_t *
statseg_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment (0);
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
  vnet_sw_interface_t *si_sup =
    vnet_get_sup_sw_interface (vnm, si->sw_if_index);
  vnet_hw_interface_t *hi_sup;
  u8 *s;
  u8 *symlink_name = 0;
  u32 vector_index;

  void *oldheap = clib_mem_set_heap (sm->heap);
  vlib_stats_segment_lock ();

  vec_validate (sm->interfaces, sw_if_index);

  ASSERT (si_sup->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
  hi_sup = vnet_get_hw_interface (vnm, si_sup->hw_if_index);

  s = format (0, "%v", hi_sup->name);
  if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    s = format (s, ".%d", si->sub.id);
  s = format (s, "%c", 0);

  if (is_add)
    {
      sm->interfaces[sw_if_index] = s;
#define _(E, n, p)                                                            \
  clib_mem_set_heap (oldheap); /* Exit stats segment */                       \
  vector_index = vlib_stats_find_directory_index ((u8 *) "/" #p "/" #n);      \
  clib_mem_set_heap (sm->heap); /* Re-enter stat segment */                   \
  vlib_stats_register_symlink (vector_index, sw_if_index,                     \
			       "/interfaces/%U/" #n,                          \
			       format_vlib_stats_symlink, s);
      foreach_simple_interface_counter_name
	foreach_combined_interface_counter_name
#undef _
    }
  else
    {
      vec_free (sm->interfaces[sw_if_index]);
      sm->interfaces[sw_if_index] = 0;
#define _(E, n, p)                                                            \
  vec_reset_length (symlink_name);                                            \
  symlink_name = format (symlink_name, "/interfaces/%U/" #n "%c",             \
			 format_vlib_stats_symlink, s, 0);                    \
  clib_mem_set_heap (oldheap); /* Exit stats segment */                       \
  vector_index = vlib_stats_find_directory_index ((u8 *) symlink_name);       \
  clib_mem_set_heap (sm->heap); /* Re-enter stat segment */                   \
  vlib_stats_delete_counter (vector_index);
      foreach_simple_interface_counter_name
	foreach_combined_interface_counter_name
#undef _

	  vec_free (symlink_name);
      vec_free (s);
    }

  vlib_stats_directory_entry_t *ep;
  ep = &sm->directory_vector[vnm->interface_names_stats_dir_index];
  ep->data = sm->interfaces;

  vlib_stats_segment_unlock ();
  clib_mem_set_heap (oldheap);

  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (statseg_sw_interface_add_del);
