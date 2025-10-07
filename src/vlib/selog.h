/*
 * Copyright (c) 2025 Cisco and/or its affiliates.
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
#ifndef included_vlib_selog_h
#define included_vlib_selog_h
#include <vppinfra/elog.h>
typedef struct
{
  elog_main_t *elog_main;
} vlib_selog_main_t;

extern vlib_selog_main_t vlib_selog_main;
static_always_inline elog_main_t *
vlib_selog_get_elog_main ()
{
  return vlib_selog_main.elog_main;
}

clib_error_t *vlib_selog_update_elog_main (elog_main_t *em);

#endif /* included_vlib_selog_h */
