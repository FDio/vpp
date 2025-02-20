/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <click/click.h>

#include <click/vppclick.h>
#include <click/click.h>

VLIB_REGISTER_LOG_CLASS (click_log, static) = {
  .class_name = "click",
  .subclass_name = "packet",
};

void
click_pkt_free (u32 buffer_indices[], uint32_t n)
{
  vlib_main_t *vm = vlib_get_main ();

  click_elog_pkt_free (vm->thread_index, n);

  vlib_buffer_free (vm, buffer_indices, n);
}

vppclick_pkt_t
vlib_buffer_to_vppclick_pkt (vlib_main_t *vm, u32 bi, u32 buffer_size)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  u8 *current = vlib_buffer_get_current (b);
  u16 size = b->current_length;
  u16 headroom = current - b->pre_data;

  return (vppclick_pkt_t){
    .buffer_index = bi,
    .data = current,
    .size = size,
    .headroom = headroom,
    .tailroom = buffer_size + VLIB_BUFFER_PRE_DATA_SIZE - size - headroom,
  };
}

static_always_inline u32
click_pkt_alloc_one (vlib_main_t *vm, vppclick_pkt_t pkts[], u32 data_size,
		     u32 n)
{
  const u32 batch_size = CLICK_PKT_ALLOC_BATCH_SZ;
  u32 buffer_indices[batch_size], rv;

  rv = vlib_buffer_alloc (vm, buffer_indices, batch_size);
  if (rv != batch_size)
    {
      if (rv)
	vlib_buffer_free (vm, buffer_indices, rv);
      return 0;
    }

  for (u32 i = 0; i < n; i++)
    pkts[i] = (vppclick_pkt_t){
      .buffer_index = buffer_indices[i],
      .data = vlib_get_buffer (vm, buffer_indices[i])->data,
      .headroom = VLIB_BUFFER_PRE_DATA_SIZE,
      .tailroom = data_size,
    };
  return n;
}

uint32_t
click_pkt_alloc (vppclick_pkt_t pkts[], uint32_t n)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 data_size = vlib_buffer_get_default_data_size (vm);
  const u32 batch_size = CLICK_PKT_ALLOC_BATCH_SZ;
  u32 buffer_indices[batch_size];
  vppclick_pkt_t *p = pkts;

  click_elog_pkt_alloc (vm->thread_index, n);

  for (; n >= batch_size; n -= batch_size, p += batch_size)
    if (click_pkt_alloc_one (vm, p, data_size, batch_size) == 0)
      goto fail;

  if (click_pkt_alloc_one (vm, p, data_size, n) == 0)
    goto fail;

  return (p - pkts) + n;

fail:
  for (; pkts < p; pkts += batch_size)
    {
      for (u32 i = 0; i < batch_size; i++)
	buffer_indices[i] = pkts[i].buffer_index;
      vlib_buffer_free (vm, buffer_indices, batch_size);
    }
  return 0;
}
