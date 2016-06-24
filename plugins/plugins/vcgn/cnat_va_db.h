/*
 *------------------------------------------------------------------
 * cnat_va_db.h - definition for virtual assembly database
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#ifndef __CNAT_VA_DB_H__
#define __CNAT_VA_DB_H__

#include <clib_lite.h>

#define FRAG_DEBUG 1

/* virtual assemble hash database size ~ 16B x 64K = 1MB */ 

#define VA_TOTAL_ENTRIES    (64*1024)
#define VA_ENTRY_PER_BUCKET (8)   /* make sure size is power of 2 for circular FIFO */ 
#define VA_BUCKET_MASK      (VA_ENTRY_PER_BUCKET -1)
#define VA_BUCKETS          (VA_TOTAL_ENTRIES / VA_ENTRY_PER_BUCKET)
#define VA_KEY_SIZE         12      

typedef struct _va_entry {
   /* key: top 12 bytes */
    u32 src_ip;
    u32 dst_ip;
    u16 vrf;       /* overloaded with protocol info with top two bits */
    u16 ip_id;

    /* values */
    u16 src_port;
    u16 dst_port;
} va_entry_t;

typedef struct _va_keys {
    u64 key64;    /* src & dst IP */
    u32 key32;    /* vrf, protocol and ip_id */
} va_keys;

typedef union {
    va_entry_t e;
    va_keys    k;
} va_lookup_key;

typedef struct _va_bucket_t {
    u32 head_entry;
    u32 next_available_entry;    /* ~0 for empty bucket */
    u32 new_entry_counter;       /* for debug purpose */
    va_entry_t va_entry[VA_ENTRY_PER_BUCKET];
} va_bucket_t;

extern va_bucket_t va_bucket[];   /* hash table in cnat_va_db.c */

void va_bucket_init ();

inline void va_db_add_new_entry (u32 bucket_index, va_lookup_key * );
inline int  va_db_delete_entry (u32 bucket_index, va_lookup_key * );
inline va_entry_t * va_db_lookup (u32 bucket_index, va_lookup_key * key);

#ifdef FRAG_DEBUG

#define FRAG_DEBUG_PRINTF1(a)                                \
     if (frag_debug_flag) {                                  \
         PLATFORM_DEBUG_PRINT(a);                                          \
     }

#define FRAG_DEBUG_PRINTF2(a, b)                             \
     if (frag_debug_flag) {                                  \
         PLATFORM_DEBUG_PRINT(a, b);                                       \
     }

#define FRAG_DEBUG_PRINTF3(a, b, c)                          \
     if (frag_debug_flag) {                                  \
         PLATFORM_DEBUG_PRINT(a, b, c);                                    \
     }

#define FRAG_DEBUG_PRINTF4(a, b, c, d)                       \
    if (frag_debug_flag) {                                   \
         PLATFORM_DEBUG_PRINT(a, b, c, d);                                 \
    }

#define FRAG_DEBUG_PRINTF5(a, b, c, d, e)                    \
    if (frag_debug_flag) {                                   \
         PLATFORM_DEBUG_PRINT(a, b, c, d, e);                              \
    }

#define FRAG_DEBUG_PRINTF6(a, b, c, d, e, f)                 \
    if (frag_debug_flag) {                                   \
         PLATFORM_DEBUG_PRINT(a, b, c, d, e, f);                           \
    }
#else

#define FRAG_DEBUG_PRINTF1(a)

#define FRAG_DEBUG_PRINTF2(a, b)

#define FRAG_DEBUG_PRINTF3(a, b, c)

#define FRAG_DEBUG_PRINTF4(a, b, c, d)

#define FRAG_DEBUG_PRINTF5(a, b, c, d, e)

#define FRAG_DEBUG_PRINTF6(a, b, c, d, e, f)

#endif

#endif  /* __CNAT_VA_DB_H__ */


