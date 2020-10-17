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
#include <fcntl.h>
#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/cpu.h>

#define foreach_x86_cpu_uarch \
 _(0x06, 0x9e, "Kaby Lake", "Kaby Lake DT/H/S/X") \
 _(0x06, 0x8e, "Kaby Lake", "Kaby Lake Y/U") \
 _(0x06, 0x8c, "Tiger Lake", "Tiger Lake U") \
 _(0x06, 0x86, "Tremont", "Elkhart Lake") \
 _(0x06, 0x85, "Knights Mill", "Knights Mill") \
 _(0x06, 0x7e, "Ice Lake", "Ice Lake U") \
 _(0x06, 0x7d, "Ice Lake", "Ice Lake Y") \
 _(0x06, 0x7a, "Goldmont Plus", "Gemini Lake") \
 _(0x06, 0x6c, "Ice Lake", "Ice Lake SP") \
 _(0x06, 0x6a, "Ice Lake", "Ice Lake DE") \
 _(0x06, 0x66, "Cannon Lake", "Cannon Lake U") \
 _(0x06, 0x5f, "Goldmont", "Denverton") \
 _(0x06, 0x5e, "Skylake", "Skylake DT/H/S") \
 _(0x06, 0x5c, "Goldmont", "Apollo Lake") \
 _(0x06, 0x5a, "Silvermont", "Moorefield") \
 _(0x06, 0x57, "Knights Landing", "Knights Landing") \
 _(0x06, 0x56, "Broadwell", "Broadwell DE") \
 _(0x06, 0x55, "Skylake", "Skylake X/SP") \
 _(0x06, 0x4f, "Broadwell", "Broadwell EP/EX") \
 _(0x06, 0x4e, "Skylake", "Skylake Y/U") \
 _(0x06, 0x4d, "Silvermont", "Rangeley") \
 _(0x06, 0x4c, "Airmont", "Braswell") \
 _(0x06, 0x47, "Broadwell", "Broadwell H") \
 _(0x06, 0x46, "Haswell", "Crystalwell") \
 _(0x06, 0x45, "Haswell", "Haswell ULT") \
 _(0x06, 0x3f, "Haswell", "Haswell E") \
 _(0x06, 0x3e, "Ivy Bridge", "Ivy Bridge E/EN/EP") \
 _(0x06, 0x3d, "Broadwell", "Broadwell U") \
 _(0x06, 0x3c, "Haswell", "Haswell") \
 _(0x06, 0x3a, "Ivy Bridge", "IvyBridge") \
 _(0x06, 0x37, "Silvermont", "BayTrail") \
 _(0x06, 0x36, "Saltwell", "Cedarview,Centerton") \
 _(0x06, 0x35, "Saltwell", "Cloverview") \
 _(0x06, 0x2f, "Westmere", "Westmere EX") \
 _(0x06, 0x2e, "Nehalem", "Nehalem EX") \
 _(0x06, 0x2d, "Sandy Bridge", "SandyBridge E/EN/EP") \
 _(0x06, 0x2c, "Westmere", "Westmere EP/EX,Gulftown") \
 _(0x06, 0x2a, "Sandy Bridge", "Sandy Bridge") \
 _(0x06, 0x27, "Saltwell", "Medfield") \
 _(0x06, 0x26, "Bonnell", "Tunnel Creek") \
 _(0x06, 0x25, "Westmere", "Arrandale,Clarksdale") \
 _(0x06, 0x1e, "Nehalem", "Clarksfield,Lynnfield,Jasper Forest") \
 _(0x06, 0x1d, "Penryn", "Dunnington") \
 _(0x06, 0x1c, "Bonnell", "Pineview,Silverthorne") \
 _(0x06, 0x1a, "Nehalem", "Nehalem EP,Bloomfield)") \
 _(0x06, 0x17, "Penryn", "Yorkfield,Wolfdale,Penryn,Harpertown")

/* _(implementor-id, part-id, vendor-name, cpu-name, show CPU pass as string) */
#define foreach_aarch64_cpu_uarch \
 _(0x41, 0xd03, "ARM", "Cortex-A53", 0) \
 _(0x41, 0xd07, "ARM", "Cortex-A57", 0) \
 _(0x41, 0xd08, "ARM", "Cortex-A72", 0) \
 _(0x41, 0xd09, "ARM", "Cortex-A73", 0) \
 _(0x41, 0xd0a, "ARM", "Cortex-A75", 0) \
 _(0x41, 0xd0b, "ARM", "Cortex-A76", 0) \
 _(0x41, 0xd0c, "ARM", "Neoverse-N1", 0) \
 _(0x41, 0xd4a, "ARM", "Neoverse-E1", 0) \
 _(0x43, 0x0a1, "Marvell", "THUNDERX CN88XX", 0) \
 _(0x43, 0x0a2, "Marvell", "OCTEON TX CN81XX", 0) \
 _(0x43, 0x0a3, "Marvell", "OCTEON TX CN83XX", 0) \
 _(0x43, 0x0af, "Marvell", "THUNDERX2 CN99XX", 1) \
 _(0x43, 0x0b1, "Marvell", "OCTEON TX2 CN98XX", 1) \
 _(0x43, 0x0b2, "Marvell", "OCTEON TX2 CN96XX", 1)

__clib_export u8 *
format_cpu_uarch (u8 * s, va_list * args)
{
#if __x86_64__
  u32 __attribute__ ((unused)) eax, ebx, ecx, edx;
  u8 model, family, stepping;

  if (__get_cpuid (1, &eax, &ebx, &ecx, &edx) == 0)
    return format (s, "unknown (missing cpuid)");

  model = ((eax >> 4) & 0x0f) | ((eax >> 12) & 0xf0);
  family = (eax >> 8) & 0x0f;
  stepping = eax & 0x0f;

#define _(f,m,a,c) if ((model == m) && (family == f)) return \
format(s, "[0x%x] %s ([0x%02x] %s) stepping 0x%x", f, a, m, c, stepping);
  foreach_x86_cpu_uarch
#undef _
    return format (s, "unknown (family 0x%02x model 0x%02x)", family, model);

#elif __aarch64__
  int fd;
  unformat_input_t input;
  u32 implementer, primary_part_number, variant, revision;

  fd = open ("/proc/cpuinfo", 0);
  if (fd < 0)
    return format (s, "unknown");

  unformat_init_clib_file (&input, fd);
  while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&input, "CPU implementer%_: 0x%x", &implementer))
	;
      else if (unformat (&input, "CPU part%_: 0x%x", &primary_part_number))
	;
      else if (unformat (&input, "CPU variant%_: 0x%x", &variant))
	;
      else if (unformat (&input, "CPU revision%_: %u", &revision))
	;
      else
	unformat_skip_line (&input);
    }
  unformat_free (&input);
  close (fd);

#define _(i,p,a,c,_format) if ((implementer == i) && (primary_part_number == p)){ \
	if (_format)\
	 return format(s, "%s (%s PASS %c%u)", a, c, 'A'+variant, revision);\
	 else {\
  if (implementer == 0x43)\
    variant++; \
  return format (s, "%s (%s PASS %u.%u)", a, c, variant, revision);}}

  foreach_aarch64_cpu_uarch
#undef _
    return format (s, "unknown (implementer 0x%02x part 0x%03x PASS %u.%u)",
		   implementer, primary_part_number, variant, revision);

#else /* ! __x86_64__ */
  return format (s, "unknown");
#endif
}

__clib_export u8 *
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


static inline char const *
flag_skip_prefix (char const *flag, const char *pfx, int len)
{
  if (0 == strncmp (flag, pfx, len - 1))
    return flag + len - 1;
  return flag;
}

__clib_export u8 *
format_cpu_flags (u8 * s, va_list * args)
{
#if defined(__x86_64__)
#define _(flag, func, reg, bit) \
  if (clib_cpu_supports_ ## flag()) \
    s = format (s, "%s ", flag_skip_prefix(#flag, "x86_", sizeof("x86_")));
  foreach_x86_64_flags return s;
#undef _
#elif defined(__aarch64__)
#define _(flag, bit) \
  if (clib_cpu_supports_ ## flag()) \
    s = format (s, "%s ", flag_skip_prefix(#flag, "aarch64_", sizeof("aarch64_")));
  foreach_aarch64_flags return s;
#undef _
#else /* ! ! __x86_64__ && ! __aarch64__ */
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
