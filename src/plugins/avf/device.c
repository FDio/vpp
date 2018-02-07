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
  vlib_pci_addr_t * addr = vlib_pci_get_addr (ad->pci_dev_handle);
  clib_warning ("init %U", format_vlib_pci_addr, addr);

  ad->flags |= AVF_DEVICE_F_INITIALIZED;
  return 0;
}

static uword
avf_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  avf_main_t *am = &avf_main;
  avf_device_t *ad;
  clib_error_t * error;

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
  void *r;

  pool_get (am->devices, ad);
  ad->pci_dev_handle = h;
  ad->dev_instance = ad - am->devices;
  ad->per_interface_next_index = ~0;

  if ((error = vlib_pci_bus_master_enable (h)))
    goto error;

  if ((error = vlib_pci_map_resource (h, 0, &r)))
    goto error;

  fformat (stderr, "\n%U\n", format_hexdump, r + 0x8800, 16);
  fformat (stderr, "\n%u\n", avf_get_u32_bits (r, 0x8800, 31, 0));
  usleep (100 * 1000);
  fformat (stderr, "\n%u\n", avf_get_u32_bits (r, 0x8800, 31, 0));

  error = vlib_pci_intr_enable (h);

  if (error == 0)
    return 0;

error:
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
