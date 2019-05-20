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
 *  @param tmp vector to build result
 *  @param l clib_spinlock_t lock to protect the vector, may be 0
 *  @param f function to add or remove
 *  @param enable 1 adds f to the vector, 0 removes f from the vector
 *
 * Add or remove a callback from the indicated callback vector.
 * Caller must provide locking to prevent > 1 concurrent writer
 * Swaps the head of the callback vector and a tmp vector in one
 * motion, after a write barrier to ensure that the write is atomic.
 */
#define clib_callback_enable_disable(h,tmp,l,f,enable)  \
do {                                                    \
  void *tmp2;                                           \
  clib_spinlock_lock_if_init(&l);                       \
  vec_reset_length(tmp);                                \
  vec_append(tmp, h);                                   \
  if (enable)                                           \
    vec_add1 (tmp,(void *)f);                           \
  else                                                  \
    {                                                   \
      int i;                                            \
      for (i = 0; i < vec_len (tmp); i++)               \
        if (((void *)tmp[i]) == (void *)f)              \
          {                                             \
            vec_delete (tmp, 1, i);                     \
            break;                                      \
          }                                             \
    }                                                   \
  tmp2 = h;                                             \
  CLIB_MEMORY_STORE_BARRIER();                          \
  h = tmp;                                              \
  tmp = tmp2;                                           \
  clib_spinlock_unlock_if_init(&l);                     \
} while(0);

/** @brief call the specified callback set
 * @param h the callback set
 * @param varargs additional callback parameters
 */
#define clib_call_callbacks(h, ... )                    \
do {                                                    \
  /*                                                    \
   * Note: fp exists to shut up gcc-6, which            \
   * produces a warning not seen with gcc-7 or 8        \
   */                                                   \
  void (*fp)(void *a1, ...);                            \
  int i;                                                \
  for (i = 0; i < vec_len (h); i++)                     \
    {                                                   \
      fp = (void *)(h[i]);                              \
      (*fp) (__VA_ARGS__);                              \
    }                                                   \
 } while (0);

/** @brief predicate function says whether the specified function is enabled
 * @param h the callback set
 * @param l clib_spinlock_t lock to protect the vector, may be 0
 * @param f the function to search for
 * @return 1 if the function is enabled, 0 if not
 */
#define clib_callback_is_set(h,l,f)             \
({                                              \
  int _i;                                       \
  int _found = 0;                               \
  clib_spinlock_lock_if_init(&l);               \
  for (_i = 0; _i < vec_len (h); _i++)          \
    if (((void *)h[_i]) == (void *) f)          \
      {                                         \
        _found=1;                               \
        break;                                  \
      }                                         \
  clib_spinlock_unlock_if_init(&l);             \
  _found;                                       \
 })

#endif /* included_callback_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
