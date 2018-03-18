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

#ifndef __included_vmnet_vmnet_h__
#define __included_vmnet_vmnet_h__

#define foreach_vmxnet3_device_flags \
  _(0, ERROR, "error") \
  _(1, ADMIN_UP, "admin-up") \
  _(2, ELOG, "elog")

enum
{
#define _(a, b, c) VMXNET3_DEVICE_F_##b = (1 << a),
  foreach_vmxnet3_device_flags
#undef _
};

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
  u32 per_interface_next_index;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;
  vlib_pci_dev_handle_t pci_dev_handle;
  void *bar[2];

  u8 version;
  u8 mac_addr[6];
} vmxnet3_device_t;

typedef struct
{
  vmxnet3_device_t *devices;
} vmxnet3_main_t;

extern vmxnet3_main_t vmxnet3_main;

typedef struct
{
  vlib_pci_addr_t addr;
  int enable_elog;
  /* return */
  int rv;
  clib_error_t *error;
} vmxnet3_create_if_args_t;

void vmxnet3_create_if (vlib_main_t * vm, vmxnet3_create_if_args_t * args);
void vmxnet3_delete_if (vlib_main_t * vm, vmxnet3_device_t * ad);

extern vlib_node_registration_t vmxnet3_input_node;
extern vnet_device_class_t vmxnet3_device_class;
uword vmxnet3_interface_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame);

/* format.c */
format_function_t format_vmxnet3_device;
format_function_t format_vmxnet3_device_name;
format_function_t format_vmxnet3_input_trace;

#endif /* __included_vmnet_vmnet_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
