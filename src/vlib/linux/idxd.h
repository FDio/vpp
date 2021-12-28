/*
 * Copyright (c) 2021, Microsoft Corporation.
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
 *
 * idxd.h: IDXD device definitions
 */

#ifndef included_vlib_idxd_h
#define included_vlib_idxd_h

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>

typedef CLIB_PACKED (union {
  struct
  {
    u16 device_id;
    u16 wq_id;
  };
  u32 as_u32;
}) vlib_dsa_addr_t;

format_function_t format_vlib_dsa_addr;
unformat_function_t unformat_vlib_dsa_addr;

typedef enum
{
  LINUX_DSA_DEVICE_TYPE_UNKNOWN,
  LINUX_DSA_DEVICE_TYPE_KERNEL,
  LINUX_DSA_DEVICE_TYPE_USER,
  LINUX_DSA_DEVICE_TYPE_MDEV,
} linux_dsa_device_type_t;

typedef u32 vlib_dsa_dev_handle_t;

typedef struct
{
  vlib_pci_addr_t paddr;
  vlib_dsa_addr_t daddr;
  u32 numa_node;
  /* Device File descriptor */
  int fd;

  /* work queue name */
  u8 wq_name[32];

  /* private data */
  uword private_data;

  u8 supports_va_dma;

  vlib_dsa_dev_handle_t handle;
} linux_dsa_device_t;

typedef struct vlib_dsa_device_info
{
  u32 flags;
  /* addr */
  vlib_pci_addr_t paddr;
  linux_dsa_device_type_t type;
  /* Numa Node */
  int numa_node;
  u16 size;
  /* work queue name */
  u8 *wq_name;
  /* Driver name */
  u8 *driver_name;
} vlib_dsa_device_info_t;

typedef struct
{
  vlib_main_t *vlib_main;
  linux_dsa_device_t *linux_dsa_devices;
  vlib_dsa_addr_t *addrs;
  /* logging */
  vlib_log_class_t log_default;
} vlib_dsa_main_t;

clib_error_t *vlib_dsa_device_open (vlib_main_t *vm, vlib_dsa_addr_t *addr,
				    vlib_dsa_dev_handle_t *handle);

clib_error_t *vlib_dsa_device_map (vlib_main_t *vm, vlib_dsa_dev_handle_t h,
				   void **result);

clib_error_t *vlib_dsa_device_unmap (vlib_dsa_dev_handle_t h, void *base);

extern vlib_dsa_main_t linux_dsa_main;
static inline linux_dsa_device_t *
linux_dsa_get_device (vlib_dsa_dev_handle_t h)
{
  vlib_dsa_main_t *dm = &linux_dsa_main;
  return pool_elt_at_index (dm->linux_dsa_devices, h);
}

static inline vlib_dsa_addr_t *
vlib_dsa_get_addr (vlib_main_t *vm, vlib_dsa_dev_handle_t h)
{
  linux_dsa_device_t *d = linux_dsa_get_device (h);
  return &d->daddr;
}

static inline vlib_pci_addr_t *
vlib_dsa_get_paddr (vlib_main_t *vm, vlib_dsa_dev_handle_t h)
{
  linux_dsa_device_t *d = linux_dsa_get_device (h);
  return &d->paddr;
}

#endif