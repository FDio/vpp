/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef __included_vapi_debug_h__
#define __included_vapi_debug_h__

/* controls debug prints */
#define VAPI_DEBUG (0)
#define VAPI_DEBUG_CONNECT (0)
#define VAPI_DEBUG_ALLOC (0)
#define VAPI_CPP_DEBUG_LEAKS (0)

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
