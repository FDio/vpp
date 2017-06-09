/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef included_clib_error_h
#define included_clib_error_h

#include <vppinfra/types.h>

typedef struct
{
  /* Error message. */
  u8 *what;

  /* Where error occurred (e.g. __FUNCTION__ __LINE__) */
  const u8 *where;

  uword flags;

  /* Error code (e.g. errno for Unix errors). */
  any code;
} clib_error_t;

#endif
