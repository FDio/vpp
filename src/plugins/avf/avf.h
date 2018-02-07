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

#include <avf/virtchnl.h>

#define foreach_avf_device_flags \
  _(0, INITIALIZED, "initialized") \
  _(1, ERROR, "error") \
  _(2, ADMIN_UP, "admin-up") \
  _(3, INIT_START, "init-start")

enum
{
#define _(a, b, c) AVF_DEVICE_F_##b = (1 << a),
  foreach_avf_device_flags
#undef _
};

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  virtchnl_rxq_info_t info;
  void *descs;
  u32 *bufs;
} avf_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  virtchnl_txq_info_t info;
  void *descs;
  u32 *bufs;
} avf_txq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
  u32 per_interface_next_index;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;
  vlib_pci_dev_handle_t pci_dev_handle;
  void *bar0;

  /* queues */
  avf_rxq_t *rxqs;
  avf_txq_t *txqs;

  /* Admin queues */
  avf_aq_desc_t *atq;
  avf_aq_desc_t *arq;
  void *atq_bufs;
  void *arq_bufs;
  u16 atq_next_slot;
  u16 arq_next_slot;
  u16 vsi_id;

  /* error */
  clib_error_t *error;
} avf_device_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
} avf_per_thread_data_t;

typedef struct
{
  avf_device_t *devices;
  avf_per_thread_data_t *per_thread_data;
  vlib_physmem_region_index_t physmem_region;
} avf_main_t;

extern avf_main_t avf_main;

typedef struct
{
  vlib_pci_addr_t addr;
  /* return */
  int rv;
  clib_error_t *error;
} avf_create_if_args_t;

void avf_create_if (avf_create_if_args_t * args);
void avf_delete_if (avf_device_t * ad);

extern vlib_node_registration_t avf_input_node;
extern vnet_device_class_t avf_device_class;
uword avf_interface_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * frame);

/* format.c */
format_function_t format_avf_device;
format_function_t format_avf_device_name;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
