/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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

#define BFD_CLK_FMT "%luus/%lu nsec/%.2fs"
#define BFD_CLK_PRN(nsec) \
  (nsec * NSEC_PER_SEC), (nsec), (((f64)nsec) / NSEC_PER_SEC)

#else
#define BFD_DBG(...)
#define BFD_ERR(...)
#endif

#endif /* __included_bfd_debug_h__ */
