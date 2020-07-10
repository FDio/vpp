/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 */

#ifndef included_callback_data_h
#define included_callback_data_h
#include <vppinfra/clib.h>

/** @brief Declare and define a callback set type
 * @param set_t_ The set type to define
 * @param cb_t_ The callback type to use
 */
#define clib_callback_data_typedef(set_t_, cb_t_)   \
typedef struct set_t_                               \
{                                                   \
  cb_t_* curr;                                      \
  cb_t_* volatile next;                             \
  cb_t_* spare;                                     \
  clib_spinlock_t* lock;                            \
} set_t_

/** @brief Initialize a callback set
 * @param set_ The callback set to initialize
 * @param lock_ The lock to use, if any
 */
#define clib_callback_data_init(set_,lock_)  \
do {                                         \
  (set_)->lock = (lock_);                    \
  (set_)->curr = 0;                          \
  (set_)->next = 0;                          \
  (set_)->spare = 0;                         \
} while (0)

/** @brief Add a callback to the specified callback set
 * @param set_ The callback set
 * @param value_ The value_ to assign the callback
 *
 * Add a callback from the indicated callback set.  If the set is
 * currently being iterated, then the change will be applied after the
 * current full iteration, and prior to the next full iteration.
 */
#define clib_callback_data_add(set_,value_)          \
do {                                                 \
  clib_spinlock_lock_if_init ((set_)->lock);         \
  typeof ((set_)->next) next_ = (set_)->next;        \
  if (PREDICT_TRUE (next_ == 0))                     \
    {                                                \
      next_ = (set_)->spare;                         \
      (set_)->spare = 0;                             \
      vec_append (next_, (set_)->curr);              \
    }                                                \
  u32 sz_ = vec_len (next_);                         \
  vec_validate (next_, sz_);                         \
  next_[sz_] = (value_);                             \
  (set_)->next = next_;                              \
  clib_spinlock_unlock_if_init ((set_)->lock);       \
} while (0)

/** @brief Remove a callback from the specified callback set
 * @param set_ The callback set
 * @param fp_ The current callback function
 * @return 1 if the function was removed, 0 if not
 *
 * Remove a callback from the indicated callback set.  Idempotent.  If
 * the set is currently being iterated, then the change will be applied
 * after the current full iteration, and prior to the next full
 * iteration.
 */
#define clib_callback_data_remove(set_,fp_)          \
({                                                   \
  int found_ = 0;                                    \
  clib_spinlock_lock_if_init ((set_)->lock);         \
  typeof ((set_)->next) next_ = (set_)->next;        \
  if (PREDICT_TRUE (next_ == 0))                     \
    {                                                \
      next_ = (set_)->spare;                         \
      (set_)->spare = 0;                             \
      vec_append (next_, (set_)->curr);              \
    }                                                \
  u32 sz_ = vec_len (next_);                         \
  u32 i_;                                            \
  for (i_ = 0; i_ < sz_; i_++)                       \
    if (next_[i_].fp == (fp_))                       \
      {                                              \
        vec_delete (next_, 1, i_);                   \
        found_ = 1;                                  \
        break;                                       \
      }                                              \
  (set_)->next = next_;                              \
  clib_spinlock_unlock_if_init ((set_)->lock);       \
  found_;                                            \
})

/** @brief Swap a callback in the specified callback set
 * @param set_ The callback set
 * @param fp_ The current callback function
 * @param value_ The value_ to assign the callback
 * @return 1 if the function was swapped, 0 if not
 *
 * Swap a callback in the indicated callback set.  If the callback is
 * not found, then nothing is done.  If the set is currently being
 * iterated, then the change will be applied after the current full
 * iteration, and prior to the next full iteration.
 */
#define clib_callback_data_swap(set_,fp_,value_)     \
({                                                   \
  int found_ = 0;                                    \
  clib_spinlock_lock_if_init ((set_)->lock);         \
  typeof ((set_)->next) next_ = (set_)->next;        \
  if (PREDICT_TRUE (next_ == 0))                     \
    {                                                \
      next_ = (set_)->spare;                         \
      (set_)->spare = 0;                             \
      vec_append (next_, (set_)->curr);              \
    }                                                \
  u32 sz_ = vec_len (next_);                         \
  u32 i_;                                            \
  for (i_ = 0; i_ < sz_; i_++)                       \
    if (next_[i_].fp == (fp_))                       \
      {                                              \
        next_[i_] = (value_);                        \
        found_ = 1;                                  \
        break;                                       \
      }                                              \
  (set_)->next = next_;                              \
  clib_spinlock_unlock_if_init ((set_)->lock);       \
  found_;                                            \
})

/** @brief Ensure a callback is in the specified callback set
 * @param set_ The callback set
 * @param value_ The value_ to assign the callback
 * @return 1 if the function was swapped, 0 if not
 *
 * Add or swap a callback in the indicated callback set.  If the
 * callback is already in the set, it is replaced.  If the callback is
 * not found, then it is added.  If the set is currently being
 * iterated, then the change will be applied after the current full
 * iteration, and prior to the next full iteration.
 */
#define clib_callback_data_ensure(set_,value_)       \
do {                                                 \
  int found_ = 0;                                    \
  clib_spinlock_lock_if_init ((set_)->lock);         \
  typeof ((set_)->next) next_ = (set_)->next;        \
  if (PREDICT_TRUE (next_ == 0))                     \
    {                                                \
      next_ = (set_)->spare;                         \
      (set_)->spare = 0;                             \
      vec_append (next_, (set_)->curr);              \
    }                                                \
  u32 sz_ = vec_len (next_);                         \
  u32 i_;                                            \
  for (i_ = 0; i_ < sz_; i_++)                       \
    if (next_[i_].fp == (value_).fp)                 \
      {                                              \
        found_ = 1;                                  \
        break;                                       \
      }                                              \
  if (!found_)                                       \
    vec_validate (next_, i_);                        \
  next_[i_] = (value_);                              \
  (set_)->next = next_;                              \
  clib_spinlock_unlock_if_init ((set_)->lock);       \
} while(0)

/** @brief Enable/Disable the specified callback
 * @param set_ The callback set
 * @param fp_ The callback function
 * @param ena_ 1 to enable, 0 to disable
 *
 * Enable or disable a callback function, with no data.
 */
#define clib_callback_data_enable_disable(set_,fp_,ena_)   \
do {                                                       \
  if (ena_)                                                \
    {                                                      \
      typeof ((set_)->next[0]) data_ = { .fp = (fp_) };    \
      clib_callback_data_add ((set_), data_);              \
    }                                                      \
  else                                                     \
    clib_callback_data_remove ((set_), (fp_));             \
} while (0)

/** @brief Get the value of a callback, if set.
 * @param set_ The callback set
 * @param fp_ The callback function
 * @param v_ Set to the callback's current value
 * @return 1 if the function is in the set, 0 if not
 */
#define clib_callback_data_get_value(set_,fp_,v_)    \
({                                                   \
  int found_ = 0;                                    \
  clib_spinlock_lock_if_init ((set_)->lock);         \
  typeof ((set_)->next) search_ = (set_)->next;      \
  if (PREDICT_TRUE (search_ == 0))                   \
    search_ = (set_)->curr;                          \
  u32 sz_ = vec_len (search_);                       \
  u32 i_;                                            \
  for (i_ = 0; i_ < sz_; i_++)                       \
    if (search_[i_].fp == (fp_))                     \
      {                                              \
        (v_) = search_[i];                           \
        found_ = 1;                                  \
        break;                                       \
      }                                              \
  clib_spinlock_unlock_if_init ((set_)->lock);       \
  found_;                                            \
})

/** @brief Check if callback is set
 * @param set_ The callback set
 * @param fp_ The callback function
 * @return 1 if the function is in the set, 0 if not
 */
#define clib_callback_data_is_set(set_,fp_)          \
({                                                   \
  int found_ = 0;                                    \
  clib_spinlock_lock_if_init ((set_)->lock);         \
  typeof ((set_)->next) search_ = (set_)->next;      \
  if (PREDICT_TRUE (search_ == 0))                   \
    search_ = (set_)->curr;                          \
  u32 sz_ = vec_len (search_);                       \
  u32 i_;                                            \
  for (i_ = 0; i_ < sz_; i_++)                       \
    if (search_[i_].fp == (fp_))                     \
      {                                              \
        found_ = 1;                                  \
        break;                                       \
      }                                              \
  clib_spinlock_unlock_if_init ((set_)->lock);       \
  found_;                                            \
})

/** @brief Check for and get current callback set
 * @param set_ the callback set
 * @param varargs additional callback parameters
 */
#define clib_callback_data_check_and_get(set_)       \
({                                                   \
  typeof ((set_)->curr) curr_ = (set_)->curr;        \
  if (PREDICT_FALSE ((set_)->next != 0))             \
    {                                                \
      clib_spinlock_lock_if_init ((set_)->lock);     \
      vec_reset_length (curr_);                      \
      (set_)->spare = curr_;                         \
      curr_ = (set_)->next;                          \
      (set_)->next = 0;                              \
      if (PREDICT_FALSE (0 == vec_len (curr_)))      \
        vec_free (curr_);                            \
      (set_)->curr = curr_;                          \
      clib_spinlock_unlock_if_init ((set_)->lock);   \
    }                                                \
  curr_;                                             \
})

/** @brief Iterate and call a callback vector
 * @param vec_ the callback vector
 * @param varargs additional callback parameters
 */
#define clib_callback_data_call_vec(vec_, ...)                     \
do {                                                               \
  u32 sz_ = vec_len (vec_);                                        \
  u32 i_;                                                          \
  for (i_ = 0; i_ < sz_; i_++)                                     \
    {                                                              \
      CLIB_PREFETCH (&vec_[i_+1], CLIB_CACHE_LINE_BYTES, STORE);   \
      (vec_[i_].fp) (&vec_[i_], __VA_ARGS__);                      \
    }                                                              \
} while (0)

/** @brief Call the specified callback set
 * @param set_ the callback set
 * @param varargs additional callback parameters
 */
#define clib_callback_data_call(set_, ...)                           \
do {                                                                 \
  typeof ((set_)->curr) v_ = clib_callback_data_check_and_get(set_); \
  clib_callback_data_iterate (v_, __VA_ARGS__);                      \
} while (0)

/** @brief prefetch the callback set
 * @param set_ The callback set
 */
#define clib_callback_data_prefetch(set_)                        \
do {                                                             \
  if (PREDICT_FALSE ((set_)->curr))                              \
    CLIB_PREFETCH ((set_)->curr, CLIB_CACHE_LINE_BYTES, STORE);  \
} while (0)


#endif /* included_callback_data_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
