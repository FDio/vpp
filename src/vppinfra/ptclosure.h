/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef included_clib_ptclosure_h
#define included_clib_ptclosure_h

#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>

/*
 * set r[i][j] if item i "bears the relation to" item j
 *
 */

u8 **clib_ptclosure_alloc (int n);
void clib_ptclosure_free (u8 ** ptc);
void clib_ptclosure_copy (u8 ** dst, u8 ** src);
u8 **clib_ptclosure (u8 ** orig);

#endif /* included_clib_ptclosure_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
