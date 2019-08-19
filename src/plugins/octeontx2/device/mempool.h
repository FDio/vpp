/*
 * Copyright (c) 2019 Marvell International Ltd.
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

#ifndef include_otx2_device_mempool_h
#define include_otx2_device_mempool_h
#include <octeontx2/buffer.h>

static inline u32
otx2_mempool_deplete (vlib_main_t * vm, u32 buffer_pool_index,
		      i64 n_buffers_to_free, u32 * bi, void **buffers)
{
  struct rte_mempool *mp =
    otx2_mempool_by_buffer_pool_index[buffer_pool_index];

  if (PREDICT_FALSE (!mp))
    clib_panic ("mempool at index %u is NULL", buffer_pool_index);

  if (PREDICT_FALSE (n_buffers_to_free < 1))
    return 0;

  if (PREDICT_FALSE (rte_mempool_get_bulk (mp, buffers, n_buffers_to_free)))
    clib_panic ("rte_mempool_get_bulk failed for mp: %0xlx", mp);

  vlib_get_buffer_indices_with_offset (vm, buffers, bi, n_buffers_to_free,
				       sizeof (struct rte_mbuf));
  vlib_buffer_free (vm, bi, n_buffers_to_free);
  return n_buffers_to_free;
}

static inline u32
otx2_mempool_refill (vlib_main_t * vm,
		     u32
		     buffer_pool_index,
		     i64 n_buffers_to_free, u32 * bi, void **buffers)
{
  struct rte_mempool *mp =
    otx2_mempool_by_buffer_pool_index[buffer_pool_index];

  if (PREDICT_FALSE (!mp))
    clib_panic ("mempool at index %u is NULL", buffer_pool_index);

  if (PREDICT_FALSE (n_buffers_to_free < 1))
    return 0;

  n_buffers_to_free =
    vlib_buffer_alloc_from_pool (vm, bi,
				 n_buffers_to_free, buffer_pool_index);

  vlib_get_buffers_with_offset (vm, bi,
				buffers,
				n_buffers_to_free,
				-(i32) sizeof (struct rte_mbuf));

  rte_mempool_put_bulk (mp, buffers, n_buffers_to_free);

  return (n_buffers_to_free);
}

#endif /* include_otx2_device_mempool_h */

/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
