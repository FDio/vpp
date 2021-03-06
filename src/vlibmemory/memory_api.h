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

#ifndef SRC_VLIBMEMORY_MEMORY_API_H_
#define SRC_VLIBMEMORY_MEMORY_API_H_

#include <svm/svm.h>
#include <svm/ssvm.h>
#include <svm/queue.h>
#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/memory_shared.h>

svm_queue_t *vl_api_client_index_to_input_queue (u32 index);
int vl_mem_api_init (const char *region_name);
void vl_mem_api_dead_client_scan (api_main_t * am, vl_shmem_hdr_t * shm,
				  f64 now);
int vl_mem_api_handle_msg_main (vlib_main_t * vm, vlib_node_runtime_t * node);
int vl_mem_api_handle_msg_private (vlib_main_t * vm,
				   vlib_node_runtime_t * node, u32 reg_index);
int vl_mem_api_handle_rpc (vlib_main_t * vm, vlib_node_runtime_t * node);

vl_api_registration_t *vl_mem_api_client_index_to_registration (u32 handle);
void vl_mem_api_enable_disable (vlib_main_t * vm, int yesno);
u32 vl_api_memclnt_create_internal (char *, svm_queue_t *);

static inline u32
vl_msg_api_handle_get_epoch (u32 index)
{
  return (index & VL_API_EPOCH_MASK);
}

static inline u32
vl_msg_api_handle_get_index (u32 index)
{
  return (index >> VL_API_EPOCH_SHIFT);
}

static inline u32
vl_msg_api_handle_from_index_and_epoch (u32 index, u32 epoch)
{
  u32 handle;
  ASSERT (index < 0x00FFFFFF);

  handle = (index << VL_API_EPOCH_SHIFT) | (epoch & VL_API_EPOCH_MASK);
  return handle;
}

static inline u8
vl_msg_api_handle_is_valid (u32 handle, u32 restarts)
{
  u32 epoch = vl_msg_api_handle_get_epoch (handle);
  return ((restarts & VL_API_EPOCH_MASK) == epoch);
}

#define VL_MEM_API_LOG_Q_LEN(fmt, qlen)                                       \
  if (TRACE_VLIB_MEMORY_QUEUE)                                                \
    do                                                                        \
      {                                                                       \
	ELOG_TYPE_DECLARE (e) = {                                             \
	  .format = fmt,                                                      \
	  .format_args = "i4",                                                \
	};                                                                    \
	struct                                                                \
	{                                                                     \
	  u32 len;                                                            \
	} * ed;                                                               \
	ed = ELOG_DATA (&vlib_global_main.elog_main, e);                      \
	ed->len = qlen;                                                       \
      }                                                                       \
  while (0)

#endif /* SRC_VLIBMEMORY_MEMORY_API_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
