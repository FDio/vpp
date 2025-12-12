/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef included_clib_error_h
#define included_clib_error_h

#include <vppinfra/types.h>

typedef struct
{
  /* Error message. */
  u8 *what;

  /* Where error occurred (e.g. __func__ __LINE__) */
  const u8 *where;

  uword flags;

  /* Error code (e.g. errno for Unix errors). */
  any code;
} clib_error_t;

#endif
