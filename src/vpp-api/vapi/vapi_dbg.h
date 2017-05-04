/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#ifndef __included_vapi_debug_h__
#define __included_vapi_debug_h__

/* controls debug prints */
#define VAPI_DEBUG (1)
#define VAPI_DEBUG_CONNECT (0)
#define VAPI_DEBUG_ALLOC (0)

#if VAPI_DEBUG
#include <stdio.h>
#define VAPI_DEBUG_FILE_DEF           \
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

#define VAPI_DBG(fmt, ...)                                       \
  do                                                             \
    {                                                            \
      VAPI_DEBUG_FILE_DEF                                        \
      printf ("DBG:%s:%d:%s():" fmt, __file, __LINE__, __func__, \
              ##__VA_ARGS__);                                    \
      printf ("\n");                                             \
      fflush (stdout);                                           \
    }                                                            \
  while (0);

#define VAPI_ERR(fmt, ...)                                       \
  do                                                             \
    {                                                            \
      VAPI_DEBUG_FILE_DEF                                        \
      printf ("ERR:%s:%d:%s():" fmt, __file, __LINE__, __func__, \
              ##__VA_ARGS__);                                    \
      printf ("\n");                                             \
      fflush (stdout);                                           \
    }                                                            \
  while (0);
#else
#define VAPI_DBG(...)
#define VAPI_ERR(...)
#endif

#endif /* __included_vapi_debug_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
