/*
 *------------------------------------------------------------------
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

/**
 * QoS tyeps
 */

#ifndef __QOS_TYPES_H__
#define __QOS_TYPES_H__

#include <vnet/vnet.h>

/**
 * Sources for the QoS bits in the packet
 */
typedef enum qos_source_t_
{
  /**
   * Some external source, e.g. a plugin.
   */
  QOS_SOURCE_EXT,
  QOS_SOURCE_VLAN,
  QOS_SOURCE_MPLS,
  QOS_SOURCE_IP,
} __attribute__ ((packed)) qos_source_t;

/**
 * The maximum number of sources. defined outside the enum so switch
 * statements don't need to handle a non-value nor use a default label
 */
#define QOS_N_SOURCES (QOS_SOURCE_IP + 1)

#define QOS_SOURCE_NAMES {                   \
    [QOS_SOURCE_EXT] = "ext",                \
    [QOS_SOURCE_IP] = "IP",                  \
    [QOS_SOURCE_MPLS] = "MPLS",              \
    [QOS_SOURCE_VLAN] = "VLAN",              \
}

#define FOR_EACH_QOS_SOURCE(_src)    \
    for (_src = QOS_SOURCE_EXT;      \
         _src <= QOS_SOURCE_IP;      \
         _src++)

/**
 * format/unformat QoS source types
 */
extern u8 *format_qos_source (u8 * s, va_list * args);
extern uword unformat_qos_source (unformat_input_t * input, va_list * args);

/**
 * Type, er, safety for us water based entities
 */
typedef u8 qos_bits_t;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
