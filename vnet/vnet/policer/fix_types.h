/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __included_fix_types_h__
#define __included_fix_types_h__

/* deal with various imported type choices */
#define cerrno int
#define trans_layer_rc int
#define EOK 0
#define CERR_IS_NOTOK(a) (a != EOK)
#define PACKED
#define OK_pushHW EOK
#define Not_OK (-1)

typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;

#ifdef __powerpc64__
typedef unsigned long uint64_t;
#endif

#endif /* __included_fix_types_h__ */
