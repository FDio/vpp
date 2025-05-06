/*
 * gpcapng_filter_api.h - API for pluggable filter implementations
 *
 * Copyright (c) 2024 Cisco Systems, Inc.
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

#ifndef __included_gpcapng_filter_api_h__
#define __included_gpcapng_filter_api_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>

/* API version for compatibility checking */
#define GPCAPNG_FILTER_API_VERSION 1

/* Forward declarations */
typedef struct gpcapng_filter_impl_t gpcapng_filter_impl_t;

/*
 * Filter classification function prototype
 *
 * This function is called once per vector to classify packets.
 * It should set dest_indices[i] to:
 *   - ~0 if packet i should not be captured
 *   - destination index if packet i should be captured
 *
 * Parameters are passed individually to allow for API evolution
 * without breaking existing implementations.
 *
 * IMPORTANT: Implementations MUST check api_version and handle
 * unsupported versions gracefully (e.g., capture nothing).
 */
typedef void (*gpcapng_filter_classify_fn_t) (
  /* API version - implementations MUST check this */
  u32 api_version,
  /* Input: buffers to classify */
  vlib_buffer_t **bufs, u32 n_buffers,
  /* Input: frame info */
  vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
  int is_output,
  /* Input: per-interface capture status bitmap */
  uword *capture_enabled_bitmap, /* Bitmap indexed by sw_if_index */
  /* Output: destination indices for each buffer */
  u32 *dest_indices,
  /* Output: statistics (can be NULL) */
  u32 *n_matched, u32 *n_captured,
  /* Output: elapsed time; filled when tracing, can NOT be NULL */
  u64 *filtering_elapsed);

/* Filter implementation structure */
struct gpcapng_filter_impl_t
{
  /* Implementation name */
  char *name;

  /* Implementation description */
  char *description;

  /* API version this implementation was built against */
  u32 api_version;

  /* Filter classification function */
  gpcapng_filter_classify_fn_t selected_fn;

  /* Priority for registration (higher = preferred default) */
  u32 priority;
};

/* API functions for filter implementations */

/* Register a filter implementation
 * Returns: 0 on success, negative on error
 * Note: Implementations should register themselves in their plugin init
 */
int gpcapng_register_filter_impl (gpcapng_filter_impl_t *impl);

/* Unregister a filter implementation
 * Returns: 0 on success, negative on error
 */
int gpcapng_unregister_filter_impl (const char *name);

/* Get current active filter implementation
 * Returns: pointer to active implementation or NULL
 */
gpcapng_filter_impl_t *gpcapng_get_active_filter_impl (void);

/* Set active filter implementation by name
 * Returns: 0 on success, negative on error
 * Note: This switches the active filter for all workers
 */
int gpcapng_set_active_filter_impl (const char *name);

/* Get filter implementation by name
 * Returns: pointer to implementation or NULL
 */
gpcapng_filter_impl_t *gpcapng_get_filter_impl_by_name (const char *name);

/* List all registered filter implementations (for CLI "show" commands) */
void gpcapng_list_filter_impls (vlib_main_t *vm);

#endif /* __included_gpcapng_filter_api_h__ */
