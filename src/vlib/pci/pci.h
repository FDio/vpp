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
 * pci.h: PCI definitions.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_vlib_pci_h
#define included_vlib_pci_h

#include <vlib/vlib.h>
#include <vlib/pci/pci_config.h>

/* *INDENT-OFF* */
typedef CLIB_PACKED (union
{
  struct
    {
      u16 domain;
      u8 bus;
      u8 slot: 5;
      u8 function:3;
    };
  u32 as_u32;
}) vlib_pci_addr_t;
/* *INDENT-ON* */

typedef struct vlib_pci_device_info
{
  u32 flags;
#define VLIB_PCI_DEVICE_INFO_F_NOIOMMU		(1 << 0);

  /* addr */
  vlib_pci_addr_t addr;

  /* Numa Node */
  int numa_node;

  /* Device data */
  u16 device_class;
  u16 vendor_id;
  u16 device_id;

  /* Vital Product Data */
  u8 *product_name;
  u8 *vpd_r;
  u8 *vpd_w;

  /* Driver name */
  u8 *driver_name;

  /* First 64 bytes of configuration space. */
  union
  {
    pci_config_type0_regs_t config0;
    pci_config_type1_regs_t config1;
    u8 config_data[256];
  };

  /* IOMMU Group */
  int iommu_group;

} vlib_pci_device_info_t;

typedef u32 vlib_pci_dev_handle_t;

vlib_pci_device_info_t *vlib_pci_get_device_info (vlib_main_t * vm,
						  vlib_pci_addr_t * addr,
						  clib_error_t ** error);
vlib_pci_addr_t *vlib_pci_get_all_dev_addrs ();
vlib_pci_addr_t *vlib_pci_get_addr (vlib_main_t * vm,
				    vlib_pci_dev_handle_t h);
u32 vlib_pci_get_numa_node (vlib_main_t * vm, vlib_pci_dev_handle_t h);
uword vlib_pci_get_private_data (vlib_main_t * vm, vlib_pci_dev_handle_t h);
void vlib_pci_set_private_data (vlib_main_t * vm, vlib_pci_dev_handle_t h,
				uword private_data);

static inline void
vlib_pci_free_device_info (vlib_pci_device_info_t * di)
{
  if (!di)
    return;
  vec_free (di->product_name);
  vec_free (di->vpd_r);
  vec_free (di->vpd_w);
  vec_free (di->driver_name);
  clib_mem_free (di);
}

typedef struct
{
  u16 vendor_id, device_id;
} pci_device_id_t;

typedef void (pci_intx_handler_function_t) (vlib_main_t * vm,
					    vlib_pci_dev_handle_t handle);
typedef void (pci_msix_handler_function_t) (vlib_main_t * vm,
					    vlib_pci_dev_handle_t handle,
					    u16 line);

typedef struct _pci_device_registration
{
  /* Driver init function. */
  clib_error_t *(*init_function) (vlib_main_t * vm,
				  vlib_pci_dev_handle_t handle);

  /* Interrupt handler */
  pci_intx_handler_function_t *interrupt_handler;

  /* List of registrations */
  struct _pci_device_registration *next_registration;

  /* Vendor/device ids supported by this driver. */
  pci_device_id_t supported_devices[];
} pci_device_registration_t;

/* Pool of PCI devices. */
typedef struct
{
  vlib_main_t *vlib_main;
  pci_device_registration_t *pci_device_registrations;
  /* logging */
  vlib_log_class_t log_default;
} vlib_pci_main_t;

extern vlib_pci_main_t pci_main;

#define PCI_REGISTER_DEVICE(x,...)                              \
    __VA_ARGS__ pci_device_registration_t x;                    \
static void __vlib_add_pci_device_registration_##x (void)       \
    __attribute__((__constructor__)) ;                          \
static void __vlib_add_pci_device_registration_##x (void)       \
{                                                               \
    vlib_pci_main_t * pm = &pci_main;                           \
    x.next_registration = pm->pci_device_registrations;         \
    pm->pci_device_registrations = &x;                          \
}                                                               \
static void __vlib_rm_pci_device_registration_##x (void)        \
    __attribute__((__destructor__)) ;                           \
static void __vlib_rm_pci_device_registration_##x (void)        \
{                                                               \
    vlib_pci_main_t * pm = &pci_main;                           \
    VLIB_REMOVE_FROM_LINKED_LIST (pm->pci_device_registrations, \
                                  &x, next_registration);       \
}                                                               \
__VA_ARGS__ pci_device_registration_t x

clib_error_t *vlib_pci_bind_to_uio (vlib_main_t * vm, vlib_pci_addr_t * addr,
				    char *uio_driver_name);

/* Configuration space read/write. */
clib_error_t *vlib_pci_read_write_config (vlib_main_t * vm,
					  vlib_pci_dev_handle_t handle,
					  vlib_read_or_write_t read_or_write,
					  uword address, void *data,
					  u32 n_bytes);

/* io space read/write. */
clib_error_t *vlib_pci_read_write_io (vlib_main_t * vm,
				      vlib_pci_dev_handle_t handle,
				      vlib_read_or_write_t read_or_write,
				      uword address, void *data, u32 n_bytes);


#define _(t, x)								\
static inline clib_error_t *						\
vlib_pci_read_##x##_##t (vlib_main_t *vm, vlib_pci_dev_handle_t h,	\
			  uword address, t * data)			\
{									\
  return vlib_pci_read_write_##x (vm, h, VLIB_READ,address, data,	\
				     sizeof (data[0]));			\
}

_(u32, config);
_(u16, config);
_(u8, config);

_(u32, io);
_(u16, io);
_(u8, io);

#undef _

#define _(t, x)								\
static inline clib_error_t *						\
vlib_pci_write_##x##_##t (vlib_main_t *vm, vlib_pci_dev_handle_t h,	\
			   uword address, t * data)			\
{									\
  return vlib_pci_read_write_##x (vm, h, VLIB_WRITE,			\
				   address, data, sizeof (data[0]));	\
}

_(u32, config);
_(u16, config);
_(u8, config);

_(u32, io);
_(u16, io);
_(u8, io);

#undef _

static inline clib_error_t *
vlib_pci_intr_enable (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  u16 command;
  clib_error_t *err;

  err = vlib_pci_read_config_u16 (vm, h, 4, &command);

  if (err)
    return err;

  command &= ~PCI_COMMAND_INTX_DISABLE;

  return vlib_pci_write_config_u16 (vm, h, 4, &command);
}

static inline clib_error_t *
vlib_pci_intr_disable (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  u16 command;
  clib_error_t *err;

  err = vlib_pci_read_config_u16 (vm, h, 4, &command);

  if (err)
    return err;

  command |= PCI_COMMAND_INTX_DISABLE;

  return vlib_pci_write_config_u16 (vm, h, 4, &command);
}

static inline clib_error_t *
vlib_pci_bus_master_enable (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  clib_error_t *err;
  u16 command;

  /* Set bus master enable (BME) */
  err = vlib_pci_read_config_u16 (vm, h, 4, &command);

  if (err)
    return err;

  if (command & PCI_COMMAND_BUS_MASTER)
    return 0;

  command |= PCI_COMMAND_BUS_MASTER;

  return vlib_pci_write_config_u16 (vm, h, 4, &command);
}

clib_error_t *vlib_pci_device_open (vlib_main_t * vm, vlib_pci_addr_t * addr,
				    pci_device_id_t ids[],
				    vlib_pci_dev_handle_t * handle);
void vlib_pci_device_close (vlib_main_t * vm, vlib_pci_dev_handle_t h);
clib_error_t *vlib_pci_map_region (vlib_main_t * vm, vlib_pci_dev_handle_t h,
				   u32 resource, void **result);
clib_error_t *vlib_pci_map_region_fixed (vlib_main_t * vm,
					 vlib_pci_dev_handle_t h,
					 u32 resource, u8 * addr,
					 void **result);
clib_error_t *vlib_pci_io_region (vlib_main_t * vm, vlib_pci_dev_handle_t h,
				  u32 resource);
clib_error_t *vlib_pci_register_intx_handler (vlib_main_t * vm,
					      vlib_pci_dev_handle_t h,
					      pci_intx_handler_function_t *
					      intx_handler);
clib_error_t *vlib_pci_register_msix_handler (vlib_main_t * vm,
					      vlib_pci_dev_handle_t h,
					      u32 start, u32 count,
					      pci_msix_handler_function_t *
					      msix_handler);
clib_error_t *vlib_pci_enable_msix_irq (vlib_main_t * vm,
					vlib_pci_dev_handle_t h, u16 start,
					u16 count);
clib_error_t *vlib_pci_disable_msix_irq (vlib_main_t * vm,
					 vlib_pci_dev_handle_t h, u16 start,
					 u16 count);
clib_error_t *vlib_pci_map_dma (vlib_main_t * vm, vlib_pci_dev_handle_t h,
				void *ptr);

int vlib_pci_supports_virtual_addr_dma (vlib_main_t * vm,
					vlib_pci_dev_handle_t h);

unformat_function_t unformat_vlib_pci_addr;
format_function_t format_vlib_pci_addr;
format_function_t format_vlib_pci_link_speed;
format_function_t format_vlib_pci_vpd;

#endif /* included_vlib_pci_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
