/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/*
 *   WARNING!
 *   This driver is not intended for production use and it is unsupported.
 *   It is provided for educational use only.
 *   Please use supported DPDK driver instead.
 */

#if __x86_64__ || __i386__
#include <vppinfra/vector.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/vnet.h>
#include <ixge/ixge.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <ixge/inline.h>

#define IXGE_ALWAYS_POLL 0

#define PCI_VENDOR_ID_INTEL 0x8086

ixge_main_t ixge_main;

#define IXGE_COUNTER_IS_64_BIT (1 << 0)
#define IXGE_COUNTER_NOT_CLEAR_ON_READ (1 << 1)

static u8 ixge_counter_flags[] = {
#define _(a,f) 0,
#define _64(a,f) IXGE_COUNTER_IS_64_BIT,
  foreach_ixge_counter
#undef _
#undef _64
};

void
ixge_update_counters (ixge_device_t * xd)
{
  /* Byte offset for counter registers. */
  static u32 reg_offsets[] = {
#define _(a,f) (a) / sizeof (u32),
#define _64(a,f) _(a,f)
    foreach_ixge_counter
#undef _
#undef _64
  };
  volatile u32 *r = (volatile u32 *) xd->regs;
  int i;

  for (i = 0; i < ARRAY_LEN (xd->counters); i++)
    {
      u32 o = reg_offsets[i];
      xd->counters[i] += r[o];
      if (ixge_counter_flags[i] & IXGE_COUNTER_NOT_CLEAR_ON_READ)
	r[o] = 0;
      if (ixge_counter_flags[i] & IXGE_COUNTER_IS_64_BIT)
	xd->counters[i] += (u64) r[o + 1] << (u64) 32;
    }
}


#define IXGE_N_BYTES_IN_RX_BUFFER  (2048)	// DAW-HACK: Set Rx buffer size so all packets < ETH_MTU_SIZE fit in the buffer (i.e. sop & eop for all descriptors).

static clib_error_t *
ixge_dma_init (ixge_device_t * xd, vlib_rx_or_tx_t rt, u32 queue_index)
{
  ixge_main_t *xm = &ixge_main;
  vlib_main_t *vm = xm->vlib_main;
  ixge_dma_queue_t *dq;
  clib_error_t *error = 0;

  vec_validate (xd->dma_queues[rt], queue_index);
  dq = vec_elt_at_index (xd->dma_queues[rt], queue_index);

  if (!xm->n_descriptors_per_cache_line)
    xm->n_descriptors_per_cache_line =
      CLIB_CACHE_LINE_BYTES / sizeof (dq->descriptors[0]);

  if (!xm->n_bytes_in_rx_buffer)
    xm->n_bytes_in_rx_buffer = IXGE_N_BYTES_IN_RX_BUFFER;
  xm->n_bytes_in_rx_buffer = round_pow2 (xm->n_bytes_in_rx_buffer, 1024);

  if (!xm->n_descriptors[rt])
    xm->n_descriptors[rt] = 4 * VLIB_FRAME_SIZE;

  dq->queue_index = queue_index;
  dq->n_descriptors =
    round_pow2 (xm->n_descriptors[rt], xm->n_descriptors_per_cache_line);
  dq->head_index = dq->tail_index = 0;

  dq->descriptors =
    vlib_physmem_alloc_aligned (vm, xm->physmem_region, &error,
				dq->n_descriptors *
				sizeof (dq->descriptors[0]),
				128 /* per chip spec */ );
  if (error)
    return error;

  memset (dq->descriptors, 0,
	  dq->n_descriptors * sizeof (dq->descriptors[0]));
  vec_resize (dq->descriptor_buffer_indices, dq->n_descriptors);

  if (rt == VLIB_RX)
    {
      u32 n_alloc, i;

      n_alloc = vlib_buffer_alloc (vm, dq->descriptor_buffer_indices,
				   vec_len (dq->descriptor_buffer_indices));
      ASSERT (n_alloc == vec_len (dq->descriptor_buffer_indices));
      for (i = 0; i < n_alloc; i++)
	{
	  dq->descriptors[i].rx_to_hw.tail_address =
	    vlib_get_buffer_data_physical_address (vm,
						   dq->descriptor_buffer_indices
						   [i]);
	}
    }
  else
    {
      u32 i;

      dq->tx.head_index_write_back = vlib_physmem_alloc (vm,
							 xm->physmem_region,
							 &error,
							 CLIB_CACHE_LINE_BYTES);

      for (i = 0; i < dq->n_descriptors; i++)
	dq->descriptors[i].tx = xm->tx_descriptor_template;

      vec_validate (xm->tx_buffers_pending_free, dq->n_descriptors - 1);
    }

  {
    ixge_dma_regs_t *dr = get_dma_regs (xd, rt, queue_index);
    u64 a;

    a =
      vlib_physmem_virtual_to_physical (vm, xm->physmem_region,
					dq->descriptors);
    dr->descriptor_address[0] = a & 0xFFFFFFFF;
    dr->descriptor_address[1] = a >> (u64) 32;
    dr->n_descriptor_bytes = dq->n_descriptors * sizeof (dq->descriptors[0]);
    dq->head_index = dq->tail_index = 0;

    if (rt == VLIB_RX)
      {
	ASSERT ((xm->n_bytes_in_rx_buffer / 1024) < 32);
	dr->rx_split_control =
	  ( /* buffer size */ ((xm->n_bytes_in_rx_buffer / 1024) << 0)
	   | (			/* lo free descriptor threshold (units of 64 descriptors) */
	       (1 << 22)) | (	/* descriptor type: advanced one buffer */
			      (1 << 25)) | (	/* drop if no descriptors available */
					     (1 << 28)));

	/* Give hardware all but last 16 cache lines' worth of descriptors. */
	dq->tail_index = dq->n_descriptors -
	  16 * xm->n_descriptors_per_cache_line;
      }
    else
      {
	/* Make sure its initialized before hardware can get to it. */
	dq->tx.head_index_write_back[0] = dq->head_index;

	a = vlib_physmem_virtual_to_physical (vm, xm->physmem_region,
					      dq->tx.head_index_write_back);
	dr->tx.head_index_write_back_address[0] = /* enable bit */ 1 | a;
	dr->tx.head_index_write_back_address[1] = (u64) a >> (u64) 32;
      }

    /* DMA on 82599 does not work with [13] rx data write relaxed ordering
       and [12] undocumented set. */
    if (rt == VLIB_RX)
      dr->dca_control &= ~((1 << 13) | (1 << 12));

    CLIB_MEMORY_BARRIER ();

    if (rt == VLIB_TX)
      {
	xd->regs->tx_dma_control |= (1 << 0);
	dr->control |= ((32 << 0)	/* prefetch threshold */
			| (64 << 8)	/* host threshold */
			| (0 << 16) /* writeback threshold */ );
      }

    /* Enable this queue and wait for hardware to initialize
       before adding to tail. */
    if (rt == VLIB_TX)
      {
	dr->control |= 1 << 25;
	while (!(dr->control & (1 << 25)))
	  ;
      }

    /* Set head/tail indices and enable DMA. */
    dr->head_index = dq->head_index;
    dr->tail_index = dq->tail_index;
  }

  return error;
}

static u32
ixge_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  ixge_device_t *xd;
  ixge_regs_t *r;
  u32 old;
  ixge_main_t *xm = &ixge_main;

  xd = vec_elt_at_index (xm->devices, hw->dev_instance);
  r = xd->regs;

  old = r->filter_control;

  if (flags & ETHERNET_INTERFACE_FLAG_ACCEPT_ALL)
    r->filter_control = old | (1 << 9) /* unicast promiscuous */ ;
  else
    r->filter_control = old & ~(1 << 9);

  return old;
}

static void
ixge_device_init (ixge_main_t * xm)
{
  vnet_main_t *vnm = vnet_get_main ();
  ixge_device_t *xd;

  /* Reset chip(s). */
  vec_foreach (xd, xm->devices)
  {
    ixge_regs_t *r = xd->regs;
    const u32 reset_bit = (1 << 26) | (1 << 3);

    r->control |= reset_bit;

    /* No need to suspend.  Timed to take ~1e-6 secs */
    while (r->control & reset_bit)
      ;

    /* Software loaded. */
    r->extended_control |= (1 << 28);

    ixge_phy_init (xd);

    /* Register ethernet interface. */
    {
      u8 addr8[6];
      u32 i, addr32[2];
      clib_error_t *error;

      addr32[0] = r->rx_ethernet_address0[0][0];
      addr32[1] = r->rx_ethernet_address0[0][1];
      for (i = 0; i < 6; i++)
	addr8[i] = addr32[i / 4] >> ((i % 4) * 8);

      error = ethernet_register_interface
	(vnm, ixge_device_class.index, xd->device_index,
	 /* ethernet address */ addr8,
	 &xd->vlib_hw_if_index, ixge_flag_change);
      if (error)
	clib_error_report (error);
    }

    {
      vnet_sw_interface_t *sw =
	vnet_get_hw_sw_interface (vnm, xd->vlib_hw_if_index);
      xd->vlib_sw_if_index = sw->sw_if_index;
    }

    ixge_dma_init (xd, VLIB_RX, /* queue_index */ 0);

    xm->n_descriptors[VLIB_TX] = 20 * VLIB_FRAME_SIZE;

    ixge_dma_init (xd, VLIB_TX, /* queue_index */ 0);

    /* RX/TX queue 0 gets mapped to interrupt bits 0 & 8. */
    r->interrupt.queue_mapping[0] = (( /* valid bit */ (1 << 7) |
				      ixge_rx_queue_to_interrupt (0)) << 0);

    r->interrupt.queue_mapping[0] |= (( /* valid bit */ (1 << 7) |
				       ixge_tx_queue_to_interrupt (0)) << 8);

    /* No use in getting too many interrupts.
       Limit them to one every 3/4 ring size at line rate
       min sized packets.
       No need for this since kernel/vlib main loop provides adequate interrupt
       limiting scheme. */
    if (0)
      {
	f64 line_rate_max_pps =
	  10e9 / (8 * (64 + /* interframe padding */ 20));
	ixge_throttle_queue_interrupt (r, 0,
				       .75 * xm->n_descriptors[VLIB_RX] /
				       line_rate_max_pps);
      }

    /* Accept all multicast and broadcast packets. Should really add them
       to the dst_ethernet_address register array. */
    r->filter_control |= (1 << 10) | (1 << 8);

    /* Enable frames up to size in mac frame size register. */
    r->xge_mac.control |= 1 << 2;
    r->xge_mac.rx_max_frame_size = (9216 + 14) << 16;

    /* Enable all interrupts. */
    if (!IXGE_ALWAYS_POLL)
      r->interrupt.enable_write_1_to_set = ~0;
  }
}

static uword
ixge_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vnet_main_t *vnm = vnet_get_main ();
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd;
  uword event_type, *event_data = 0;
  f64 timeout, link_debounce_deadline;

  ixge_device_init (xm);

  /* Clear all counters. */
  vec_foreach (xd, xm->devices)
  {
    ixge_update_counters (xd);
    memset (xd->counters, 0, sizeof (xd->counters));
  }

  timeout = 30.0;
  link_debounce_deadline = 1e70;

  while (1)
    {
      /* 36 bit stat counters could overflow in ~50 secs.
         We poll every 30 secs to be conservative. */
      vlib_process_wait_for_event_or_clock (vm, timeout);

      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case EVENT_SET_FLAGS:
	  /* 1 ms */
	  link_debounce_deadline = vlib_time_now (vm) + 1e-3;
	  timeout = 1e-3;
	  break;

	case ~0:
	  /* No events found: timer expired. */
	  if (vlib_time_now (vm) > link_debounce_deadline)
	    {
	      vec_foreach (xd, xm->devices)
	      {
		ixge_regs_t *r = xd->regs;
		u32 v = r->xge_mac.link_status;
		uword is_up = (v & (1 << 30)) != 0;

		vnet_hw_interface_set_flags
		  (vnm, xd->vlib_hw_if_index,
		   is_up ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
	      }
	      link_debounce_deadline = 1e70;
	      timeout = 30.0;
	    }
	  break;

	default:
	  ASSERT (0);
	}

      if (event_data)
	_vec_len (event_data) = 0;

      /* Query stats every 30 secs. */
      {
	f64 now = vlib_time_now (vm);
	if (now - xm->time_last_stats_update > 30)
	  {
	    xm->time_last_stats_update = now;
	    vec_foreach (xd, xm->devices) ixge_update_counters (xd);
	  }
      }
    }

  return 0;
}

vlib_node_registration_t ixge_process_node = {
  .function = ixge_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ixge-process",
};

clib_error_t *
ixge_init (vlib_main_t * vm)
{
  ixge_main_t *xm = &ixge_main;
  clib_error_t *error;

  xm->vlib_main = vm;
  memset (&xm->tx_descriptor_template, 0,
	  sizeof (xm->tx_descriptor_template));
  memset (&xm->tx_descriptor_template_mask, 0,
	  sizeof (xm->tx_descriptor_template_mask));
  xm->tx_descriptor_template.status0 =
    (IXGE_TX_DESCRIPTOR_STATUS0_ADVANCED |
     IXGE_TX_DESCRIPTOR_STATUS0_IS_ADVANCED |
     IXGE_TX_DESCRIPTOR_STATUS0_INSERT_FCS);
  xm->tx_descriptor_template_mask.status0 = 0xffff;
  xm->tx_descriptor_template_mask.status1 = 0x00003fff;

  xm->tx_descriptor_template_mask.status0 &=
    ~(IXGE_TX_DESCRIPTOR_STATUS0_IS_END_OF_PACKET
      | IXGE_TX_DESCRIPTOR_STATUS0_REPORT_STATUS);
  xm->tx_descriptor_template_mask.status1 &=
    ~(IXGE_TX_DESCRIPTOR_STATUS1_DONE);

  error = vlib_call_init_function (vm, pci_bus_init);

  return error;
}

VLIB_INIT_FUNCTION (ixge_init);


static void
ixge_pci_intr_handler (vlib_pci_dev_handle_t h)
{
  ixge_main_t *xm = &ixge_main;
  vlib_main_t *vm = xm->vlib_main;
  uword private_data = vlib_pci_get_private_data (h);

  vlib_node_set_interrupt_pending (vm, ixge_input_node.index);

  /* Let node know which device is interrupting. */
  {
    vlib_node_runtime_t *rt =
      vlib_node_get_runtime (vm, ixge_input_node.index);
    rt->runtime_data[0] |= 1 << private_data;
  }
}

static clib_error_t *
ixge_pci_init (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  ixge_main_t *xm = &ixge_main;
  clib_error_t *error = 0;
  void *r;
  ixge_device_t *xd;
  vlib_pci_addr_t *addr = vlib_pci_get_addr (h);
  vlib_pci_device_info_t *d = vlib_pci_get_device_info (addr, 0);

  /* Allocate physmem region for DMA buffers */
  if (xm->physmem_region_allocated == 0)
    {
      error = vlib_physmem_region_alloc (vm, "ixge decriptors", 2 << 20, 0,
					 VLIB_PHYSMEM_F_INIT_MHEAP,
					 &xm->physmem_region);
      xm->physmem_region_allocated = 1;
    }
  if (error)
    return error;

  error = vlib_pci_map_resource (h, 0, &r);
  if (error)
    return error;

  vec_add2 (xm->devices, xd, 1);

  xd->pci_dev_handle = h;
  xd->device_id = d->device_id;
  xd->regs = r;
  xd->device_index = xd - xm->devices;
  xd->pci_function = addr->function;
  xd->per_interface_next_index = ~0;

  vlib_pci_set_private_data (h, xd->device_index);

  /* Chip found so enable node. */
  {
    vlib_node_set_state (vm, ixge_input_node.index,
			 (IXGE_ALWAYS_POLL
			  ? VLIB_NODE_STATE_POLLING
			  : VLIB_NODE_STATE_INTERRUPT));
  }

  if (vec_len (xm->devices) == 1)
    {
      vlib_register_node (vm, &ixge_process_node);
      xm->process_node_index = ixge_process_node.index;
    }

  error = vlib_pci_bus_master_enable (h);

  if (error)
    return error;

  return vlib_pci_intr_enable (h);
}

/* *INDENT-OFF* */
PCI_REGISTER_DEVICE (ixge_pci_device_registration,static) = {
  .init_function = ixge_pci_init,
  .interrupt_handler = ixge_pci_intr_handler,
  .supported_devices = {
#define _(t,i) { .vendor_id = PCI_VENDOR_ID_INTEL, .device_id = i, },
    foreach_ixge_pci_device_id
#undef _
    { 0 },
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .default_disabled = 1,
    .description = "Intel 82599 Family Native Driver (experimental)",
};
#endif

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
