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
#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/cpu.h>

#define foreach_x86_cpu_uarch \
 _(0x06, 0x4f, "Broadwell", "Broadwell-EP/EX") \
 _(0x06, 0x3d, "Broadwell", "Broadwell") \
 _(0x06, 0x3f, "Haswell", "Haswell-E") \
 _(0x06, 0x3c, "Haswell", "Haswell") \
 _(0x06, 0x3e, "IvyBridge", "IvyBridge-E/EN/EP") \
 _(0x06, 0x3a, "IvyBridge", "IvyBridge") \
 _(0x06, 0x2a, "SandyBridge", "SandyBridge") \
 _(0x06, 0x2d, "SandyBridge", "SandyBridge-E/EN/EP") \
 _(0x06, 0x25, "Westmere", "Arrandale,Clarksdale") \
 _(0x06, 0x2c, "Westmere", "Westmere-EP/EX,Gulftown") \
 _(0x06, 0x2f, "Westmere", "Westmere-EX") \
 _(0x06, 0x1e, "Nehalem", "Clarksfield,Lynnfield,Jasper Forest") \
 _(0x06, 0x1a, "Nehalem", "Nehalem-EP,Bloomfield)") \
 _(0x06, 0x2e, "Nehalem", "Nehalem-EX") \
 _(0x06, 0x17, "Penryn", "Yorkfield,Wolfdale,Penryn,Harpertown (DP)") \
 _(0x06, 0x1d, "Penryn", "Dunnington (MP)") \
 _(0x06, 0x37, "Atom", "Bay Trail") \
 _(0x06, 0x36, "Atom", "Cedarview") \
 _(0x06, 0x26, "Atom", "Lincroft") \
 _(0x06, 0x1c, "Atom", "Pineview/Silverthorne")

u8 *
format_cpu_uarch (u8 * s, va_list * args)
{
#if __x86_64__
  u32 __attribute__ ((unused)) eax, ebx, ecx, edx;
  u8 model, family;

  if (__get_cpuid (1, &eax, &ebx, &ecx, &edx) == 0)
    return format (s, "unknown (missing cpuid)");

  model = ((eax >> 4) & 0x0f) | ((eax >> 12) & 0xf0);
  family = (eax >> 8) & 0x0f;

#define _(f,m,a,c) if ((model == m) && (family == f)) return format(s, "%s (%s)", a, c);
  foreach_x86_cpu_uarch
#undef _
    return format (s, "unknown (family 0x%02x model 0x%02x)", family, model);

#else /* ! __x86_64__ */
  return format (s, "unknown");
#endif
}

u8 *
format_cpu_model_name (u8 * s, va_list * args)
{
#if __x86_64__
  u32 __attribute__ ((unused)) eax, ebx, ecx, edx;
  u8 *name = 0;
  u32 *name_u32;

  if (__get_cpuid (1, &eax, &ebx, &ecx, &edx) == 0)
    return format (s, "unknown (missing cpuid)");

  __get_cpuid (0x80000000, &eax, &ebx, &ecx, &edx);
  if (eax < 0x80000004)
    return format (s, "unknown (missing ext feature)");

  vec_validate (name, 48);
  name_u32 = (u32 *) name;

  __get_cpuid (0x80000002, &eax, &ebx, &ecx, &edx);
  name_u32[0] = eax;
  name_u32[1] = ebx;
  name_u32[2] = ecx;
  name_u32[3] = edx;

  __get_cpuid (0x80000003, &eax, &ebx, &ecx, &edx);
  name_u32[4] = eax;
  name_u32[5] = ebx;
  name_u32[6] = ecx;
  name_u32[7] = edx;

  __get_cpuid (0x80000004, &eax, &ebx, &ecx, &edx);
  name_u32[8] = eax;
  name_u32[9] = ebx;
  name_u32[10] = ecx;
  name_u32[11] = edx;

  s = format (s, "%s", name);
  vec_free (name);
  return s;

#elif defined(__aarch64__)
  return format (s, "armv8");
#else /* ! __x86_64__ */
  return format (s, "unknown");
#endif
}

u8 *
format_cpu_flags (u8 * s, va_list * args)
{
#if defined(__x86_64__)
#define _(flag, func, reg, bit) \
  if (clib_cpu_supports_ ## flag()) \
    s = format (s, #flag " ");
  foreach_x86_64_flags return s;
#undef _
#else /* ! __x86_64__ */
  return format (s, "unknown");
#endif
}



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
