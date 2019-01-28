/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef _PERFMON_INTEL_H_
#define _PERFMON_INTEL_H_

#include <vppinfra/clib.h>
#include <vppinfra/format.h>

typedef struct
{
  u8 event_code[2];
  u8 umask;
  char *event_name;
} perfmon_intel_pmc_event_t;

typedef struct
{
  u8 model;
  u8 stepping;
  u8 has_stepping;
} perfmon_intel_pmc_cpu_model_t;

typedef struct
{
  perfmon_intel_pmc_event_t *events;
  perfmon_intel_pmc_cpu_model_t *models;
  u32 n_events;
  u32 n_models;
} perfmon_intel_pmc_registration_t;


void
perfmon_register_intel_pmc (perfmon_intel_pmc_cpu_model_t * m, int n_models,
			    perfmon_intel_pmc_event_t * e, int n_events);

#define PERFMON_REGISTER_INTEL_PMC(m, e) \
static void __clib_constructor \
perfmon_register_intel_pmc_constructor() \
{ \
  perfmon_register_intel_pmc (m, ARRAY_LEN(m), e, ARRAY_LEN (e)); \
}

#endif /* _PERFMON_INTEL_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
