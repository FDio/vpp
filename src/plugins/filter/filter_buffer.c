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

#include <filter/filter_buffer.h>

filter_buffer_main_t filter_buffer_main;

static clib_error_t *
filter_buffer_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vec_validate_aligned (filter_buffer_main.fbm_threads,
			tm->n_vlib_mains, CLIB_CACHE_LINE_BYTES);
  return (NULL);
}

VLIB_INIT_FUNCTION (filter_buffer_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
