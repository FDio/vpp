/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_clib_pmc_h
#define included_clib_pmc_h

#if defined (__x86_64__)

always_inline u64
clib_rdpmc (int counter_id)
{
  u32 a, d;

  asm volatile ("rdpmc":"=a" (a), "=d" (d):"c" (counter_id));
  return (u64) a + ((u64) d << (u64) 32);
}

#else
always_inline u64
clib_rdpmc (int counter_id)
{
  return 0ULL;
}
#endif /* __aarch64__ */

#endif /* included_clib_pmc_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
