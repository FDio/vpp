/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#ifndef __STACK_H__
#define __STACK_H__

#include <vppinfra/clib.h>

typedef struct
{
  uword ip, sp;
  uword offset;
  char name[256];
  const char *file_name;
  u32 index;
  u8 is_signal_frame;
} clib_stack_frame_t;

int clib_stack_frame_get_raw (void **sf, int n, int skip);
clib_stack_frame_t *clib_stack_frame_get (clib_stack_frame_t *);

#define foreach_clib_stack_frame(sf)                                          \
  for (clib_stack_frame_t _sf = {}, *sf = clib_stack_frame_get (&_sf); sf;    \
       sf = clib_stack_frame_get (sf))

#endif /* __STACK_H__ */
