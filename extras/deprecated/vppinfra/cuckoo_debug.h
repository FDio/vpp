/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 * @brief cuckoo debugs
 */
#ifndef __included_cuckoo_debug_h__
#define __included_cuckoo_debug_h__

/* controls debug counters */
#define CLIB_CUCKOO_DEBUG_COUNTERS (0)

/* controls debug prints */
#define CLIB_CUCKOO_DEBUG (0)

/* controls garbage collection related debug prints */
#define CLIB_CUCKOO_DEBUG_GC (0)

#if CLIB_CUCKOO_DEBUG
#define CLIB_CUCKOO_DEBUG_FILE_DEF    \
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

#define CLIB_CUCKOO_DBG(fmt, ...)                                         \
  do                                                                      \
    {                                                                     \
      CLIB_CUCKOO_DEBUG_FILE_DEF                                          \
      static u8 *_s = NULL;                                               \
      _s = format (_s, "DBG:%s:%d:%s():" fmt, __file, __LINE__, __func__, \
                   ##__VA_ARGS__);                                        \
      printf ("%.*s\n", vec_len (_s), _s);                                \
      vec_reset_length (_s);                                              \
    }                                                                     \
  while (0);

#define CLIB_CUCKOO_ERR(fmt, ...)                                         \
  do                                                                      \
    {                                                                     \
      CLIB_CUCKOO_DEBUG_FILE_DEF                                          \
      static u8 *_s = NULL;                                               \
      _s = format (_s, "ERR:%s:%d:%s():" fmt, __file, __LINE__, __func__, \
                   ##__VA_ARGS__);                                        \
      printf ("%.*s\n", vec_len (_s), _s);                                \
      vec_reset_length (_s);                                              \
    }                                                                     \
  while (0);

#else
#define CLIB_CUCKOO_DBG(...)
#define CLIB_CUCKOO_ERR(...)
#endif

#endif /* __included_cuckoo_debug_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
