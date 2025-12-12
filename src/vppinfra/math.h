/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus
 */

#ifndef included_math_h
#define included_math_h

#include <vppinfra/clib.h>

always_inline f64
sqrt (f64 x)
{
  return __builtin_sqrt (x);
}

always_inline f64
fabs (f64 x)
{
  return __builtin_fabs (x);
}

#ifndef isnan
#define isnan(x) __builtin_isnan(x)
#endif

#ifndef isinf
#define isinf(x) __builtin_isinf(x)
#endif

#endif /* included_math_h */
