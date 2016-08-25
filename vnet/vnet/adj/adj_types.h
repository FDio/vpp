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

#ifndef __ADJ_TYPES_H__
#define __ADJ_TYPES_H__

#include <vnet/vnet.h>

/**
 * An index for adjacencies
 */
typedef u32 adj_index_t; 

/**
 * Invalid ADJ index - used when no adj is known
 */
#define ADJ_INDEX_INVALID ((u32)~0)

/**
 * The types of special adjacencies
 */
typedef enum adj_special_type_t_ {
    ADJ_SPECIAL_TYPE_DROP,
    ADJ_SPECIAL_TYPE_PUNT,
    ADJ_SPECIAL_TYPE_LOCAL,
} adj_special_type_t;

#define ADJ_SPECIAL_TYPE_NUM (ADJ_SPECIAL_TYPE_LOCAL+1)

#define ADJ_SPECIAL_TYPES {		\
    [ADJ_SPECIAL_TYPE_DROP]  = "drop",	\
    [ADJ_SPECIAL_TYPE_PUNT]  = "punt",	\
    [ADJ_SPECIAL_TYPE_LOCAL] = "local",	\
}


#endif
