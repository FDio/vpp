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

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <vmxnet3/vmxnet3.h>

#define PCI_VENDOR_ID_VMWARE				0x15ad
#define PCI_DEVICE_ID_VMWARE_VMXNET3			0x07b0

vmxnet3_main_t vmxnet3_main;

static pci_device_id_t vmxnet3_pci_device_ids[] = {
  {
   .vendor_id = PCI_VENDOR_ID_VMWARE,
   .device_id = PCI_DEVICE_ID_VMWARE_VMXNET3},
  {0},
};


static clib_error_t *
vmxnet3_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				 u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vmxnet3_main_t *am = &vmxnet3_main;
  vmxnet3_device_t *ad = vec_elt_at_index (am->devices, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (ad->flags & VMXNET3_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      ad->flags |= VMXNET3_DEVICE_F_ADMIN_UP;
      vnet_hw_interface_assign_rx_thread (vnm, ad->hw_if_index, 0, ~0);
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ad->flags &= ~VMXNET3_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (vmxnet3_device_class,) =
{
  .name = "VMXNET3 interface",
  .tx_function = vmxnet3_interface_tx,
  .format_device = format_vmxnet3_device,
  .format_device_name = format_vmxnet3_device_name,
  .admin_up_down_function = vmxnet3_interface_admin_up_down,
};
/* *INDENT-ON* */

static inline void
vmxnet3_reg_write (vmxnet3_device_t * vd, u8 bar, u32 addr, u32 val)
{
  *(volatile u32 *) ((u8 *) vd->bar[bar] + addr) = val;
}

static inline u32
vmxnet3_reg_read (vmxnet3_device_t * vd, u8 bar, u32 addr)
{
  return *(volatile u32 *) (vd->bar[bar] + addr);
}

#define VMXNET3_REG_VRRS 0x0000
#define VMXNET3_REG_UVRS 0x0008
#define VMXNET3_REG_MACL 0x0028   /* MAC Address Low */
#define VMXNET3_REG_MACH 0x0030   /* MAC Address High */

static u32
vmxnet3_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  return 0;
}

void
vmxnet3_create_if (vlib_main_t * vm, vmxnet3_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vmxnet3_device_t *vd;
  vlib_pci_dev_handle_t h;
  clib_error_t *error = 0;
  u32 reg;

  pool_get (vmxm->devices, vd);
  vd->dev_instance = vd - vmxm->devices;
  vd->per_interface_next_index = ~0;

  if (args->enable_elog)
    vd->flags |= VMXNET3_DEVICE_F_ELOG;

  if ((error =
       vlib_pci_device_open (&args->addr, vmxnet3_pci_device_ids, &h)))
    goto error;
  vd->pci_dev_handle = h;

  vlib_pci_set_private_data (h, vd->dev_instance);

  if ((error = vlib_pci_bus_master_enable (h)))
    goto error;

  if ((error = vlib_pci_map_region (h, 1, (void **) &vd->bar[1])))
    goto error;

  reg = vmxnet3_reg_read (vd, 1, VMXNET3_REG_VRRS);
  vd->version = count_leading_zeros (reg);
  vd->version = uword_bits - vd->version;

  if (vd->version == 0 || vd->version > 3)
    {
      error = clib_error_return (0, "unsupported interface version");
      goto error;
    }

  vmxnet3_reg_write (vd, 1, VMXNET3_REG_VRRS, 1 << vd->version);

  reg = vmxnet3_reg_read (vd, 1, VMXNET3_REG_UVRS);
  //FIXME check
  vmxnet3_reg_write (vd, 1, VMXNET3_REG_UVRS, 1);
  reg = vmxnet3_reg_read (vd, 1, VMXNET3_REG_MACL);
  clib_memcpy (vd->mac_addr, &reg, 4);
  reg = vmxnet3_reg_read (vd, 1, VMXNET3_REG_MACH);
  clib_memcpy (vd->mac_addr + 4, &reg, 2);

  /* create interface */
  error = ethernet_register_interface (vnm, vmxnet3_device_class.index,
				       vd->dev_instance, vd->mac_addr,
				       &vd->hw_if_index, vmxnet3_flag_change);

  if (error)
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, vd->hw_if_index);
  vd->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_set_input_node (vnm, vd->hw_if_index,
				    vmxnet3_input_node.index);
  return;

error:
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
  args->error = error;
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "vmxnet device plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
