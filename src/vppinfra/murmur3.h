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

#ifndef __included_murmur3_h__
#define __included_murmur3_h__

#include <vppinfra/clib.h>

/* clib_murmur3_32 is based on MurmurHash3 was written by Austin Appleby, and
   is placed in the public domain per:
         https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
   Thanks, Austin. */

static_always_inline u32
clib_murmur3_32 (u8 * s, u32 len, u32 seed)
{
  u32 h = seed;

  if (len > 3)
    {
      u32 *a = (u32 *) s;
      u32 i = len >> 2;
      do
	{
	  u32 k = *a++;
	  k *= 0xcc9e2d51;
	  k = (k << 15) | (k >> 17);
	  k *= 0x1b873593;
	  h ^= k;
	  h = (h << 13) | (h >> 19);
	  h = (h * 5) + 0xe6546b64;
	}
      while (--i);
      s = (u8 *) a;
    }

  if (len & 3)
    {
      u32 i = len & 3;
      u32 k = 0;
      s = &s[i - 1];
      do
	{
	  k <<= 8;
	  k |= *s--;
	}
      while (--i);
      k *= 0xcc9e2d51;
      k = (k << 15) | (k >> 17);
      k *= 0x1b873593;
      h ^= k;
    }
  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

#endif /* included_murmur3_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
