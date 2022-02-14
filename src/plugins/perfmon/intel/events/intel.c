/*
 * Copyright (c) 2022 Intel and/or its affiliates.
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

#include <vnet/vnet.h>
#include "intel.h"

int
is_genuine_intel_cpu ()
{
  u32 eax, ebx, ecx, edx;
  if (__get_cpuid (0, &eax, &ebx, &ecx, &edx) == 0)
    return 0;

  // GenuineIntel
  if (ebx != 0x756e6547 || ecx != 0x6c65746e || edx != 0x49656e69)
    return 0;

  return 1;
}

u8 *
format_intel_core_config (u8 *s, va_list *args)
{
  u64 config = va_arg (*args, u64);
  u8 v;

  s = format (s, "event=0x%02x, umask=0x%02x", config & 0xff,
	      (config >> 8) & 0xff);

  if ((v = (config >> 18) & 1))
    s = format (s, ", edge=%u", v);

  if ((v = (config >> 19) & 1))
    s = format (s, ", pc=%u", v);

  if ((v = (config >> 21) & 1))
    s = format (s, ", any=%u", v);

  if ((v = (config >> 23) & 1))
    s = format (s, ", inv=%u", v);

  if ((v = (config >> 24) & 0xff))
    s = format (s, ", cmask=0x%02x", v);

  /* show the raw config, for convenience sake */
  if (!((config >> 16) & 0xffff))
    s = format (s, ", raw=r%x", config & 0xffff);

  return s;
}
