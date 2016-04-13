/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 * unix/pci.h: Linux specific pci state
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

#ifndef included_unix_pci_h
#define included_unix_pci_h

#include <vlib/pci/pci.h>

typedef struct {
  /* /sys/bus/pci/devices/... directory name for this device. */
  u8 * dev_dir_name;

  /* Resource file descriptors. */
  int * resource_fds;

  /* File descriptor for config space read/write. */
  int config_fd;

  /* PCI bus address for this devices parsed from /sys/bus/pci/devices name. */
  vlib_pci_addr_t bus_address;

  /* File descriptor for /dev/uio%d */
  int uio_fd;

  /* Minor device for uio device. */
  u32 uio_minor;

  /* Index given by unix_file_add. */
  u32 unix_file_index;

  /* Input node to handle interrupts for this device. */ 
  u32 device_input_node_index;
  
  /* Node runtime will be a bitmap of device indices with pending interrupts. */
  u32 device_index;
} linux_pci_device_t;

/* Pool of PCI devices. */
typedef struct {
  vlib_main_t * vlib_main;
  vlib_pci_device_t * pci_devs;
  linux_pci_device_t * linux_pci_devices;
  pci_device_registration_t * pci_device_registrations;
  uword * pci_dev_index_by_pci_addr;
} linux_pci_main_t;

extern linux_pci_main_t linux_pci_main;

always_inline linux_pci_device_t *
pci_dev_for_linux (vlib_pci_device_t * dev)
{
  linux_pci_main_t * pm = &linux_pci_main;
  return pool_elt_at_index (pm->linux_pci_devices, dev->os_handle);
}

/* Call to allocate/initialize the pci subsystem.
   This is not an init function so that users can explicitly enable
   pci only when it's needed. */
clib_error_t * pci_bus_init (vlib_main_t * vm);

clib_error_t * vlib_pci_bind_to_uio (vlib_pci_device_t * d, char * uio_driver_name);

#endif /* included_unix_pci_h */
