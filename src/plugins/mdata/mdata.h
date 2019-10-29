
/*
 * mdata.h - Buffer metadata change tracker
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#ifndef __included_mdata_h__
#define __included_mdata_h__

#include <vnet/vnet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

/** @file buffer metadata change tracker definitions
 */

typedef struct
{
  /** Node index, ~0 means no data from this run */
  u32 node_index;
  /** buffer metadata, cast to vlib_buffer_t as needed */
  u8 mdata[128];
} mdata_t;

typedef struct
{
  /** API message ID base */
  u16 msg_id_base;

  /** Per-thread buffer metadata before calling node fcn */
  mdata_t **before_per_thread;

  /** Spinlock to protect modified metadata by node */
  clib_spinlock_t modify_lock;

  /** Modified metadata by node */
  mdata_t *modifies;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} mdata_main_t;

extern mdata_main_t mdata_main;

#endif /* __included_mdata_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
