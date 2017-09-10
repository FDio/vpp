/*
 *------------------------------------------------------------------
 * api.h
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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

#ifndef included_vlibmemory_api_h
#define included_vlibmemory_api_h

#include <svm/svm.h>
#include <vlib/vlib.h>
#include <vlibmemory/unix_shared_memory_queue.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api_common.h>

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

void vl_enable_disable_memory_api (vlib_main_t * vm, int yesno);

#endif /* included_vlibmemory_api_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
