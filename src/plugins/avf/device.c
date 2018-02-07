/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <avf/avf.h>

#define AVF_MBOX_LEN 64

#define AVF_ARQBAH          0x00006000
#define AVF_ATQH            0x00006400
#define AVF_ATQLEN          0x00006800
#define AVF_ARQBAL          0x00006C00
#define AVF_ARQT            0x00007000
#define AVF_ARQH            0x00007400
#define AVF_ATQBAH          0x00007800
#define AVF_ATQBAL          0x00007C00
#define AVF_ARQLEN          0x00008000
#define AVF_ATQT            0x00008400
#define AVFGEN_RSTAT        0x00008800

avf_main_t avf_main;

static inline u32
avf_get_u32_bits (void *start, int offset, int first, int last)
{
  u32 value = *(u32 *) (((u8 *) start) + offset);
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

static inline void
avf_set_u32 (void *start, int offset, u32 value)
{
  (*(u32 *) (((u8 *) start) + offset)) = value;
}

static inline void
avf_set_u64 (void *start, int offset, u64 value)
{
  (*(u64 *) (((u8 *) start) + offset)) = value;
}

void
avf_create_if (avf_create_if_args_t * args)
{
}

void
avf_delete_if (avf_device_t * ad)
{
}

clib_error_t *
avf_device_init (vlib_main_t * vm, avf_device_t * ad)
{
  avf_main_t *am = &avf_main;
  u64 pa;
  vlib_pci_addr_t *addr = vlib_pci_get_addr (ad->pci_dev_handle);
  clib_warning ("init %U", format_vlib_pci_addr, addr);

  /* VF MailBox Transmit */
  memset (ad->atq, 0, sizeof (avf_aq_desc_t) * AVF_MBOX_LEN);
  pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region, ad->atq);
  avf_set_u32 (ad->bar0, AVF_ATQT, 0);	/* Tail */
  avf_set_u32 (ad->bar0, AVF_ATQH, 0);	/* Head */
  avf_set_u32 (ad->bar0, AVF_ATQBAL, (u32) pa);	/* Base Address Low */
  avf_set_u32 (ad->bar0, AVF_ATQBAH, (u32) (pa >> 32));	/* Base Address High */
  avf_set_u32 (ad->bar0, AVF_ATQLEN, AVF_MBOX_LEN | (1 << 31));	/* len & ena */

  /* VF MailBox Receive */
  memset (ad->arq, 0, sizeof (avf_aq_desc_t) * AVF_MBOX_LEN);
  pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region, ad->arq);
  avf_set_u32 (ad->bar0, AVF_ARQT, 0);	/* Tail */
  avf_set_u32 (ad->bar0, AVF_ARQH, 0);	/* Head */
  avf_set_u32 (ad->bar0, AVF_ARQBAL, (u32) pa);	/* Base Address Low */
  avf_set_u32 (ad->bar0, AVF_ARQBAH, (u32) (pa >> 32));	/* Base Address High */
  avf_set_u32 (ad->bar0, AVF_ARQLEN, AVF_MBOX_LEN | (1 << 31));	/* len & ena */

  ad->flags |= AVF_DEVICE_F_INITIALIZED;
  return 0;
}

static uword
avf_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  avf_main_t *am = &avf_main;
  avf_device_t *ad;
  clib_error_t *error;

  /* *INDENT-OFF* */
  pool_foreach (ad, am->devices,
    {
    });
  /* *INDENT-ON* */

  while (1)
    {
      vlib_process_suspend (vm, 3.0);
      /* *INDENT-OFF* */
      pool_foreach (ad, am->devices,
        {
          if (ad->flags & AVF_DEVICE_F_ERROR)
            continue;

          if ((ad->flags & AVF_DEVICE_F_INITIALIZED) == 0)
	    if ((error = avf_device_init (vm, ad)))
              clib_error_report (error);
        });
      /* *INDENT-ON* */
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (avf_process_node, static)  = {
  .function = avf_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "avf-process",
};
/* *INDENT-ON* */

static void
avf_pci_intr_handler (vlib_pci_dev_handle_t h)
{
  clib_warning ("int");
}

static clib_error_t *
avf_pci_init (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  clib_error_t *error = 0;
  avf_main_t *am = &avf_main;
  avf_device_t *ad;
  //vlib_pci_device_info_t *d = vlib_pci_get_device_info (addr, 0);

  pool_get (am->devices, ad);
  ad->pci_dev_handle = h;
  ad->dev_instance = ad - am->devices;
  ad->per_interface_next_index = ~0;

  if ((error = vlib_pci_bus_master_enable (h)))
    goto error;

  if ((error = vlib_pci_map_resource (h, 0, &ad->bar0)))
    goto error;

  ad->atq = vlib_physmem_alloc_aligned (vm, am->physmem_region, &error,
					sizeof (avf_aq_desc_t) *
					AVF_MBOX_LEN, 64);
  if (error)
    goto error;

  ad->arq = vlib_physmem_alloc_aligned (vm, am->physmem_region, &error,
					sizeof (avf_aq_desc_t) *
					AVF_MBOX_LEN, 64);
  if (error)
    goto error;

  error = vlib_pci_intr_enable (h);

  if (error == 0)
    return 0;

error:
  if (ad->atq)
    vlib_physmem_free (vm, am->physmem_region, ad->atq);
  if (ad->arq)
    vlib_physmem_free (vm, am->physmem_region, ad->arq);
  memset (ad, 0, sizeof (*ad));
  pool_put (am->devices, ad);
  return error;
}

/* *INDENT-OFF* */
PCI_REGISTER_DEVICE (avf_pci_device_registration,static) = {
  .init_function = avf_pci_init,
  .interrupt_handler = avf_pci_intr_handler,
  .supported_devices = {
    { .vendor_id = 0x8086, .device_id = 0x154c, },
    { 0 },
  },
};
  /* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (avf_device_class,) =
{
  .name = "Adaptive Virtual Function (AVF) interface",
};
/* *INDENT-ON* */

clib_error_t *
avf_init (vlib_main_t * vm)
{
  avf_main_t *am = &avf_main;
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, pci_bus_init)))
    return error;

  error = vlib_physmem_region_alloc (vm, "avf_pool", 2 << 20, 0,
				     VLIB_PHYSMEM_F_INIT_MHEAP,
				     &am->physmem_region);

  return 0;
}

VLIB_INIT_FUNCTION (avf_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
