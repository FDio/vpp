/*
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

#ifndef __FILTER_BUFFER_H__
#define __FILTER_BUFFER_H__

#include <filter/filter_types.h>

#include <vnet/buffer.h>

typedef struct filter_buffer_meta_data_t_
{
  u8 fbmd_hook;
  /** the bits in the 'marked' by targets and matched */
  u32 fbmd_mark;
  /** The index of the filter object currently being used */
  index_t fbmd_index;
} filter_buffer_meta_data_t;

/**
 * We store this data at the end of the vnet_buffer_opaque_t struct
 */
always_inline filter_buffer_meta_data_t *
filter_buffer_meta_data_get (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *op;

  op = vnet_buffer (b);

  return ((filter_buffer_meta_data_t *) ((u8 *) op + sizeof (*op) -
					 sizeof (filter_buffer_meta_data_t)));
}


typedef struct filter_per_thread_data_t_
{
  // per-buffer jump stacks
  dpo_id_t **fptd_stack;
} filter_per_thread_data_t;

typedef struct filter_main_t_
{
  filter_per_thread_data_t *fbm_threads;
} filter_buffer_main_t;

extern filter_buffer_main_t filter_buffer_main;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
