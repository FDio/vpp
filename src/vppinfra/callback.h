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

/** @file
 * @brief Callback multiplex scheme
 * For a fully worked-out example, see .../src/vlib/main.[ch] and
 * .../src/plugins/perfmon.c
 */

#ifndef included_callback_h
#define included_callback_h
#include <vppinfra/clib.h>

/** @brief Add or remove a callback to the specified callback set
 *  @param h head of the callback vector
 *  @param f function to add or remove
 *  @param enable 1 adds f to the vector, 0 removes f from the vector
 */
#define clib_callback_enable_disable(h,f,enable)        \
do {                                                    \
  if (enable)                                           \
    vec_add1 (h,(void *)f);                             \
  else                                                  \
    {                                                   \
      int i;                                            \
      for (i = 0; i < vec_len (h); i++)                 \
        if (((void *)h[i]) == (void *)f)                \
          {                                             \
            vec_delete (h, 1, i);                       \
            break;                                      \
          }                                             \
    }                                                   \
} while(0);

/** @brief call the specified callback set
 * @param h the callback set
 * @param varargs additional callback parameters
 */

#define clib_call_callbacks(h, ... )            \
do {                                            \
  int i;                                        \
  for (i = 0; i < vec_len (h); i++)             \
    h[i] (__VA_ARGS__);                         \
 } while (0);

/** @brief predicate function says whether the specified function is enabled
 * @param h the callback set
 * @param f the function to search for
 * @return 1 if the function is enabled, 0 if not
 */
#define clib_callback_is_set(h,f)               \
({                                              \
  int i;                                        \
  int found = 0;                                \
  for (i = 0; i < vec_len (h); i++)             \
    if (((void *)h[i]) == (void *) f)           \
      {                                         \
        found=1;                                \
        break;                                  \
      }                                         \
  found;                                        \
 })

#endif /* included_callback_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
