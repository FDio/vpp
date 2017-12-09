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

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <cbdma/cbdma.h>

cbdma_main_t cbdma_main;

clib_error_t *
cbdma_channel_init (vlib_main_t * vm, cbdma_channel_t * cc)
{
  cbdma_desc_t *d;
  u64 pa, pa_next;

  /* reset  - CHANCMD (0x84) bit 5 */
  cbdma_set_u32 (cc->bar, 0x84, 1 << 5);

  pa = vlib_physmem_virtual_to_physical (vm, cc->physmem_region, cc->desc);
  pa_next = pa;

  d = cc->desc;

  /* initialize descriptors */
  while (d - cc->desc < cc->n_desc - 1)
    {
      pa_next += sizeof (cbdma_desc_t);
      d->ctl = 0;
      d->next_desc = pa_next;
      d++;
    }
  d->ctl = 0;
  d->next_desc = pa;

  cc->next = 0;

  /* set CHAINADDR */
  cbdma_set_u64 (cc->bar, 0x90, pa);
  return 0;
}

static clib_error_t *
cbdma_pci_init (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  cbdma_main_t *cm = &cbdma_main;
  cbdma_engine_t *ce;
  cbdma_channel_t *cc;
  void *bar;
  clib_error_t *err = 0;
  u8 numa_node, channel;
  u8 *s = 0;
  void *desc;
  u16 n_desc = 4096;

  vlib_pci_addr_t *addr = vlib_pci_get_addr (h);
  vlib_pci_device_info_t *d = vlib_pci_get_device_info (addr, 0);

  numa_node = d->numa_node;
  channel = addr->function;

  vlib_pci_free_device_info (d);

  if ((err = vlib_pci_map_resource (h, 0, (void *) &bar)))
    goto done;

  vec_validate (cm->engines, numa_node);
  ce = vec_elt_at_index (cm->engines, numa_node);

  if (!ce->channels)
    {
      s = format (s, "cbdma engine %u descriptors%c", numa_node, 0);
      err = vlib_physmem_region_alloc (vm, (char *) s, 2 << 21, numa_node,
				       VLIB_PHYSMEM_F_INIT_MHEAP,
				       &ce->physmem_region);
      if (err)
	goto done;
    }
  desc = vlib_physmem_alloc_aligned (vm, ce->physmem_region, &err,
				     sizeof (cbdma_desc_t) * n_desc,
				     CLIB_CACHE_LINE_BYTES);
  if (err)
    goto done;

  vec_validate (ce->channels, channel);
  cc = vec_elt_at_index (ce->channels, channel);
  cc->bar = bar;
  cc->pci_dev_handle = h;
  cc->engine = numa_node;
  cc->channel = channel;
  cc->n_desc = n_desc;
  cc->desc = desc;
  cc->physmem_region = ce->physmem_region;

  if ((err = vlib_pci_bus_master_enable (h)) != 0)
    goto done;

  if ((err = cbdma_channel_init (vm, cc)) != 0)
    goto done;


done:
  if (err)
    {
      if (desc)
	vlib_physmem_free (vm, ce->physmem_region, desc);
    }
  vec_free (s);
  return err;
}

/* *INDENT-OFF* */
PCI_REGISTER_DEVICE (cbdma_pci_device_registration, static) = {
  .init_function = cbdma_pci_init,
  .supported_devices = {
    { .vendor_id = 0x8086, .device_id = 0x2021, },
    { .vendor_id = 0x8086, .device_id = 0x6f20, },
    { .vendor_id = 0x8086, .device_id = 0x6f21, },
    { 0 },
  },
};

/* *INDENT-ON* */

clib_error_t *
cbdma_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (cbdma_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Intel DirectData (Crystal Beach) DMA Plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
