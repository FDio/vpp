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

#define foreach_avf_device_flags \
  _(0, INITIALIZED, "initialized") \
  _(1, ERROR, "error")

enum
{
#define _(a, b, c) AVF_DEVICE_F_##b = (1 << a),
  foreach_avf_device_flags
#undef _
};

typedef enum
{
  VIRTCHNL_OP_UNKNOWN = 0,
  VIRTCHNL_OP_VERSION = 1,
  VIRTCHNL_OP_RESET_VF = 2,
  VIRTCHNL_OP_GET_VF_RESOURCES = 3,
  VIRTCHNL_OP_EVENT = 17,
} virtchnl_ops_t;

typedef enum
{
  VIRTCHNL_STATUS_SUCCESS = 0,
  VIRTCHNL_ERR_PARAM = -5,
  VIRTCHNL_STATUS_ERR_OPCODE_MISMATCH = -38,
  VIRTCHNL_STATUS_ERR_CQP_COMPL_ERROR = -39,
  VIRTCHNL_STATUS_ERR_INVALID_VF_ID = -40,
  VIRTCHNL_STATUS_NOT_SUPPORTED = -64,
} virtchnl_status_code_t;

typedef enum
{
  VIRTCHNL_VSI_TYPE_INVALID = 0,
  VIRTCHNL_VSI_SRIOV = 6,
} virtchnl_vsi_type_t;

typedef struct
{
  u16 vsi_id;
  u16 num_queue_pairs;
  virtchnl_vsi_type_t vsi_type;
  u16 qset_handle;
  u8 default_mac_addr[6];
} virtchnl_vsi_resource_t;

typedef struct
{
  u16 num_vsis;
  u16 num_queue_pairs;
  u16 max_vectors;
  u16 max_mtu;
  u32 vf_offload_flags;
  u32 rss_key_size;
  u32 rss_lut_size;
  virtchnl_vsi_resource_t vsi_res[1];
} virtchnl_vf_resource_t;


typedef struct
{
  u32 major;
  u32 minor;
} virtchnl_version_info_t;

typedef struct
{
  u16 flags;
  u16 opcode;
  u16 datalen;
  u16 retval;
  union
  {
    u32 cookie_hi;
    virtchnl_ops_t v_opcode;
  };
  union
  {
    u32 cookie_lo;
    virtchnl_status_code_t v_retval;
  };
  u32 param[2];
  u32 addr_hi;
  u32 addr_lo;
} avf_aq_desc_t;

STATIC_ASSERT_SIZEOF (avf_aq_desc_t, 32);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
#define AVF_DEVICE_F_INITIALIZED (1 << 0)
#define AVF_DEVICE_F_ERROR (1 << 1)
  u32 per_interface_next_index;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;
  vlib_pci_dev_handle_t pci_dev_handle;
  void *bar0;

  /* Admin queues */
  avf_aq_desc_t *atq;
  avf_aq_desc_t *arq;
  void *atq_bufs;
  void *arq_bufs;
  u16 atq_next_slot;
  u16 arq_next_slot;
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

/* format.c */
format_function_t format_avf_input_trace;
format_function_t format_avf_interface;
format_function_t format_avf_interface_name;


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
