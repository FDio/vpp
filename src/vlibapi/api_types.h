/*
 *------------------------------------------------------------------
 * api_types.h
 *
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
 *------------------------------------------------------------------
 */

#ifndef included_api_types_h
#define included_api_types_h

#include <stdbool.h>

#include <vppinfra/types.h>
#include <arpa/inet.h>
#include <string.h>

/* VPP API string type */
typedef struct
{
  u32 length;
  u8 buf[0];
} __attribute__ ((packed)) vl_api_string_t;

static inline int
vl_api_to_api_string (u32 len, const char *buf, vl_api_string_t * str)
{
  memcpy(str->buf, buf, len);
  str->length = htonl (len);
  return len + sizeof (u32);
}

/* Return a pointer to the API string (not nul terminated) */
static inline u8 *
vl_api_from_api_string (vl_api_string_t * astr)
{
  return astr->buf;
}

static inline u32
vl_api_string_len (vl_api_string_t * astr)
{
  return ntohl (astr->length);
}

static inline char *
vl_api_from_api_string_c (vl_api_string_t *astr)
{
  return strndup((char *)astr->buf, ntohl (astr->length));
}

#endif
