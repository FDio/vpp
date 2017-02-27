/*
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief BFD global declarations
 */
#ifndef __included_bfd_debug_h__
#define __included_bfd_debug_h__

/* controls debug prints */
#define BFD_DEBUG (0)

#if BFD_DEBUG
#define BFD_DEBUG_FILE_DEF            \
  static const char *__file = NULL;   \
  {                                   \
    __file = strrchr (__FILE__, '/'); \
    if (__file)                       \
      {                               \
        ++__file;                     \
      }                               \
    else                              \
      {                               \
        __file = __FILE__;            \
      }                               \
  }

#define BFD_DBG(fmt, ...)                                                \
  do                                                                     \
    {                                                                    \
      BFD_DEBUG_FILE_DEF                                                 \
      static u8 *_s = NULL;                                              \
      vlib_main_t *vm = vlib_get_main ();                                \
      _s = format (_s, "%6.02f:DBG:%s:%d:%s():" fmt, vlib_time_now (vm), \
                   __file, __LINE__, __func__, ##__VA_ARGS__);           \
      printf ("%.*s\n", vec_len (_s), _s);                               \
      vec_reset_length (_s);                                             \
    }                                                                    \
  while (0);

#define BFD_ERR(fmt, ...)                                                \
  do                                                                     \
    {                                                                    \
      BFD_DEBUG_FILE_DEF                                                 \
      static u8 *_s = NULL;                                              \
      vlib_main_t *vm = vlib_get_main ();                                \
      _s = format (_s, "%6.02f:ERR:%s:%d:%s():" fmt, vlib_time_now (vm), \
                   __file, __LINE__, __func__, ##__VA_ARGS__);           \
      printf ("%.*s\n", vec_len (_s), _s);                               \
      vec_reset_length (_s);                                             \
    }                                                                    \
  while (0);

#define BFD_CLK_FMT "%luus/%lu clocks/%.2fs"
#define BFD_CLK_PRN(clocks)                                                \
  (u64) ((((f64)clocks) / vlib_get_main ()->clib_time.clocks_per_second) * \
         USEC_PER_SECOND),                                                 \
      (clocks),                                                            \
      (((f64)clocks) / vlib_get_main ()->clib_time.clocks_per_second)

#else
#define BFD_DBG(...)
#define BFD_ERR(...)
#endif

#endif /* __included_bfd_debug_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
