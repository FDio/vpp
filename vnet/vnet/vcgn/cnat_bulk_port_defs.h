/* 
 *------------------------------------------------------------------
 * cnat_bulk_port_defs.h bulk port alloc definitions
 *
 * Copyright (c) 2011 Cisco and/or its affiliates.
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

#ifndef __CNAT_BULK_PORT_DEFS_H__
#define __CNAT_BULK_PORT_DEFS_H__


#ifndef NO_BULK_LOGGING

typedef enum {
    BULK_ALLOC_SIZE_NONE = 1,
    BULK_ALLOC_SIZE_16 = 16,
    BULK_ALLOC_SIZE_32 = 32,
    BULK_ALLOC_SIZE_64 = 64,
    BULK_ALLOC_SIZE_128 = 128,
    BULK_ALLOC_SIZE_256 = 256,
    BULK_ALLOC_SIZE_512 = 512,
    BULK_ALLOC_SIZE_1024 = 1024,
    BULK_ALLOC_SIZE_2048 = 2048,
    BULK_ALLOC_SIZE_4096 = 4096
} bulk_alloc_size_t;

/* #define DEBUG_BULK_PORT 1   TODO: remove this later */

#define CACHE_ALLOC_NO_LOG_REQUIRED     -1
#define BULK_ALLOC_NOT_ATTEMPTED        -2

#define BULK_RANGE_INVALID 0xFFFF
#define BULK_RANGE_CACHE_SIZE 4

#define BULKSIZE_FROM_VRFMAP(vrfmap)    ((vrfmap)->bulk_size)

#define INIT_BULK_CACHE(udb)    \
    {   \
        int i;  \
        for(i =0; i < BULK_RANGE_CACHE_SIZE; i++) \
            (udb)->bulk_port_range_cache[i] = (i16)BULK_RANGE_INVALID; \
    }   

#endif /* NO_BULK_LOGGING */
#endif /* __CNAT_BULK_PORT_DEFS_H__ */
