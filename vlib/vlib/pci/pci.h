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

typedef CLIB_PACKED (union {
  struct {
    u16 domain;
    u8 bus;
    u8 slot:5;
    u8 function:3;
   };
   u32 as_u32;
}) vlib_pci_addr_t;

typedef struct {
  /* Operating system handle for this device. */
  uword os_handle;

  vlib_pci_addr_t bus_address;

  /* First 64 bytes of configuration space. */
  union {
    pci_config_type0_regs_t config0;
    pci_config_type1_regs_t config1;
    u8 config_data[256];
  };
} vlib_pci_device_t;

typedef struct {
  u16 vendor_id, device_id;
} pci_device_id_t;

typedef struct _pci_device_registration {
  /* Driver init function. */
  clib_error_t * (* init_function) (vlib_main_t * vm, vlib_pci_device_t * dev);

  char const *kernel_driver;
  u8 kernel_driver_running;

  /* List of registrations */
  struct _pci_device_registration * next_registration;

  /* Vendor/device ids supported by this driver. */
  pci_device_id_t supported_devices[];
} pci_device_registration_t;

#define PCI_REGISTER_DEVICE(x,...)                              \
    __VA_ARGS__ pci_device_registration_t x;                    \
static void __vlib_add_pci_device_registration_##x (void)       \
    __attribute__((__constructor__)) ;                          \
static void __vlib_add_pci_device_registration_##x (void)       \
{                                                               \
    linux_pci_main_t * lpm = vlib_unix_get_main();              \
    x.next_registration = lpm->pci_device_registrations;        \
    lpm->pci_device_registrations = &x;                         \
}                                                               \
__VA_ARGS__ pci_device_registration_t x 


/* Configuration space read/write. */
clib_error_t *
os_read_write_pci_config (uword os_handle,
			  vlib_read_or_write_t read_or_write,
			  uword address,
			  void * data,
			  u32 n_bytes);

#define _(t)								\
static inline clib_error_t *						\
os_read_pci_config_##t (uword os_handle, uword address, t * data)	\
{									\
  return os_read_write_pci_config (os_handle, VLIB_READ,		\
				   address, data, sizeof (data[0]));	\
}

_ (u32);
_ (u16);
_ (u8);

#undef _

#define _(t)								\
static inline clib_error_t *						\
os_write_pci_config_##t (uword os_handle, uword address, t * data)	\
{									\
  return os_read_write_pci_config (os_handle, VLIB_WRITE,		\
				   address, data, sizeof (data[0]));	\
}

_ (u32);
_ (u16);
_ (u8);

#undef _

clib_error_t *
os_map_pci_resource (uword os_handle, u32 resource, void ** result);

clib_error_t *
os_map_pci_resource_fixed (uword os_handle, u32 resource, u8 * addr, 
                           void ** result);

/* Free's device. */
void os_free_pci_device (uword os_handle);

void os_add_pci_disable_interrupts_reg (uword os_handle, u32 resource, u32 reg_offset, u32 reg_value);

format_function_t format_os_pci_handle;

static inline uword
unformat_vlib_pci_addr (unformat_input_t * input, va_list * args)
{
  vlib_pci_addr_t * addr = va_arg (* args, vlib_pci_addr_t *);
  u32 x[4];

  if (!unformat (input, "%x:%x:%x.%x", &x[0], &x[1], &x[2], &x[3]))
    return 0;

  addr->domain   = x[0];
  addr->bus      = x[1];
  addr->slot     = x[2];
  addr->function = x[3];

  return 1;
}

static inline u8 *
format_vlib_pci_addr (u8 * s, va_list * va)
{
  vlib_pci_addr_t * addr = va_arg (* va, vlib_pci_addr_t *);
  return format (s, "%04x:%02x:%02x.%x", addr->domain, addr->bus,
		 addr->slot, addr->function);
}

#endif /* included_vlib_pci_h */
