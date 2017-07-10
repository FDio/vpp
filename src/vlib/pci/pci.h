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

typedef CLIB_PACKED (union
		     {
		     struct
		     {
u16 domain; u8 bus; u8 slot: 5; u8 function:3;};
		     u32 as_u32;}) vlib_pci_addr_t;

typedef struct vlib_pci_device
{
  /* Operating system handle for this device. */
  uword os_handle;

  vlib_pci_addr_t bus_address;

  /* First 64 bytes of configuration space. */
  union
  {
    pci_config_type0_regs_t config0;
    pci_config_type1_regs_t config1;
    u8 config_data[256];
  };

  /* Interrupt handler */
  void (*interrupt_handler) (struct vlib_pci_device * dev);

  /* Driver name */
  u8 *driver_name;

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

  /* Private data */
  uword private_data;

} vlib_pci_device_t;

typedef struct
{
  u16 vendor_id, device_id;
} pci_device_id_t;

typedef struct _pci_device_registration
{
  /* Driver init function. */
  clib_error_t *(*init_function) (vlib_main_t * vm, vlib_pci_device_t * dev);

  /* Interrupt handler */
  void (*interrupt_handler) (vlib_pci_device_t * dev);

  /* List of registrations */
  struct _pci_device_registration *next_registration;

  /* Vendor/device ids supported by this driver. */
  pci_device_id_t supported_devices[];
} pci_device_registration_t;

/* Pool of PCI devices. */
typedef struct
{
  vlib_main_t *vlib_main;
  vlib_pci_device_t *pci_devs;
  pci_device_registration_t *pci_device_registrations;
  uword *pci_dev_index_by_pci_addr;
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
__VA_ARGS__ pci_device_registration_t x

clib_error_t *vlib_pci_bind_to_uio (vlib_pci_device_t * d,
				    char *uio_driver_name);

/* Configuration space read/write. */
clib_error_t *vlib_pci_read_write_config (vlib_pci_device_t * dev,
					  vlib_read_or_write_t read_or_write,
					  uword address,
					  void *data, u32 n_bytes);

#define _(t)								\
static inline clib_error_t *						\
vlib_pci_read_config_##t (vlib_pci_device_t * dev,			\
			  uword address, t * data)			\
{									\
  return vlib_pci_read_write_config (dev, VLIB_READ,address, data,	\
				     sizeof (data[0]));			\
}

_(u32);
_(u16);
_(u8);

#undef _

#define _(t)								\
static inline clib_error_t *						\
vlib_pci_write_config_##t (vlib_pci_device_t * dev, uword address,	\
			   t * data)					\
{									\
  return vlib_pci_read_write_config (dev, VLIB_WRITE,			\
				   address, data, sizeof (data[0]));	\
}

_(u32);
_(u16);
_(u8);

#undef _

static inline clib_error_t *
vlib_pci_intr_enable (vlib_pci_device_t * dev)
{
  u16 command;
  clib_error_t *err;

  err = vlib_pci_read_config_u16 (dev, 4, &command);

  if (err)
    return err;

  command &= ~PCI_COMMAND_INTX_DISABLE;

  return vlib_pci_write_config_u16 (dev, 4, &command);
}

static inline clib_error_t *
vlib_pci_intr_disable (vlib_pci_device_t * dev)
{
  u16 command;
  clib_error_t *err;

  err = vlib_pci_read_config_u16 (dev, 4, &command);

  if (err)
    return err;

  command |= PCI_COMMAND_INTX_DISABLE;

  return vlib_pci_write_config_u16 (dev, 4, &command);
}

static inline clib_error_t *
vlib_pci_bus_master_enable (vlib_pci_device_t * dev)
{
  clib_error_t *err;
  u16 command;

  /* Set bus master enable (BME) */
  err = vlib_pci_read_config_u16 (dev, 4, &command);

  if (err)
    return err;

  if (command & PCI_COMMAND_BUS_MASTER)
    return 0;

  command |= PCI_COMMAND_BUS_MASTER;

  return vlib_pci_write_config_u16 (dev, 4, &command);
}

clib_error_t *vlib_pci_map_resource (vlib_pci_device_t * dev, u32 resource,
				     void **result);

clib_error_t *vlib_pci_map_resource_fixed (vlib_pci_device_t * dev,
					   u32 resource, u8 * addr,
					   void **result);

vlib_pci_device_t *vlib_get_pci_device (vlib_pci_addr_t * addr);
/* Free's device. */
void vlib_pci_free_device (vlib_pci_device_t * dev);

unformat_function_t unformat_vlib_pci_addr;
format_function_t format_vlib_pci_addr;
format_function_t format_vlib_pci_handle;
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
