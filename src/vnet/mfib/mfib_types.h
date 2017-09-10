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

#ifndef __MFIB_TYPES_H__
#define __MFIB_TYPES_H__

#include <vnet/fib/fib_types.h>

/**
 * Aggregrate type for a prefix
 */
typedef struct mfib_prefix_t_ {
    /**
     * The mask length
     */
    u16 fp_len;

    /**
     * protocol type
     */
    fib_protocol_t fp_proto;

    /**
     * Pad to keep the address 4 byte aligned
     */
    u8 ___fp___pad;

    /**
     * The address type is not deriveable from the fp_addr member.
     * If it's v4, then the first 3 u32s of the address will be 0.
     * v6 addresses (even v4 mapped ones) have at least 2 u32s assigned
     * to non-zero values. true. but when it's all zero, one cannot decide.
     */
    ip46_address_t fp_grp_addr;
    ip46_address_t fp_src_addr;
} mfib_prefix_t;

typedef enum mfib_entry_attribute_t_
{
    MFIB_ENTRY_ATTRIBUTE_FIRST = 0,
    /**
     * The control planes needs packets mathing this entry to generate
     * a signal.
     */
    MFIB_ENTRY_SIGNAL =  MFIB_ENTRY_ATTRIBUTE_FIRST,
    /**
     * Drop all traffic to this route
     */
    MFIB_ENTRY_DROP,
    /**
     * The control plane needs to be informed of coneected sources
     */
    MFIB_ENTRY_CONNECTED,
    /**
     * Accept packets from any incpoming interface
     *        Use with extreme caution
     */
    MFIB_ENTRY_ACCEPT_ALL_ITF,
    /**
     * Exclusive - like its unicast counterpart. the source has provided
     * the forwarding DPO directly. The entry therefore does not resolve
     * paths via a path-list
     */
    MFIB_ENTRY_EXCLUSIVE,

    MFIB_ENTRY_INHERIT_ACCEPT,
    MFIB_ENTRY_ATTRIBUTE_LAST = MFIB_ENTRY_INHERIT_ACCEPT,
} mfib_entry_attribute_t;

#define FOR_EACH_MFIB_ATTRIBUTE(_item)			\
    for (_item = MFIB_ENTRY_ATTRIBUTE_FIRST;		\
	 _item <= MFIB_ENTRY_ATTRIBUTE_LAST;		\
	 _item++)

#define MFIB_ENTRY_NAMES_SHORT  {          \
    [MFIB_ENTRY_SIGNAL]         = "S",     \
    [MFIB_ENTRY_CONNECTED]      = "C",     \
    [MFIB_ENTRY_DROP]           = "D",     \
    [MFIB_ENTRY_ACCEPT_ALL_ITF] = "AA",    \
    [MFIB_ENTRY_INHERIT_ACCEPT] = "IA",    \
    [MFIB_ENTRY_EXCLUSIVE]      = "E",     \
}

#define MFIB_ENTRY_NAMES_LONG  {                    \
    [MFIB_ENTRY_SIGNAL]         = "Signal",         \
    [MFIB_ENTRY_CONNECTED]      = "Connected",      \
    [MFIB_ENTRY_DROP]           = "Drop",           \
    [MFIB_ENTRY_ACCEPT_ALL_ITF] = "Accept-all-itf", \
    [MFIB_ENTRY_INHERIT_ACCEPT] = "Inherit-Accept", \
    [MFIB_ENTRY_EXCLUSIVE]      = "Exclusive",      \
}

typedef enum mfib_entry_flags_t_
{
    MFIB_ENTRY_FLAG_NONE,
    MFIB_ENTRY_FLAG_SIGNAL = (1 << MFIB_ENTRY_SIGNAL),
    MFIB_ENTRY_FLAG_DROP = (1 << MFIB_ENTRY_DROP),
    MFIB_ENTRY_FLAG_CONNECTED = (1 << MFIB_ENTRY_CONNECTED),
    MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF = (1 << MFIB_ENTRY_ACCEPT_ALL_ITF),
    MFIB_ENTRY_FLAG_EXCLUSIVE = (1 << MFIB_ENTRY_EXCLUSIVE),
    MFIB_ENTRY_FLAG_INHERIT_ACCEPT = (1 << MFIB_ENTRY_INHERIT_ACCEPT),
} mfib_entry_flags_t;

typedef enum mfib_itf_attribute_t_
{
    MFIB_ITF_ATTRIBUTE_FIRST,
    MFIB_ITF_NEGATE_SIGNAL = MFIB_ITF_ATTRIBUTE_FIRST,
    MFIB_ITF_ACCEPT,
    MFIB_ITF_FORWARD,
    MFIB_ITF_SIGNAL_PRESENT,
    MFIB_ITF_DONT_PRESERVE,
    MFIB_ITF_ATTRIBUTE_LAST = MFIB_ITF_DONT_PRESERVE,
} mfib_itf_attribute_t;

#define FOR_EACH_MFIB_ITF_ATTRIBUTE(_item)	       	\
    for (_item = MFIB_ITF_ATTRIBUTE_FIRST;       	\
	 _item <= MFIB_ITF_ATTRIBUTE_LAST;		\
	 _item++)

#define MFIB_ITF_NAMES_SHORT  {             \
    [MFIB_ITF_NEGATE_SIGNAL] = "NS",        \
    [MFIB_ITF_ACCEPT] = "A",                \
    [MFIB_ITF_FORWARD] = "F",               \
    [MFIB_ITF_SIGNAL_PRESENT] = "SP",       \
    [MFIB_ITF_DONT_PRESERVE] = "DP",        \
}

#define MFIB_ITF_NAMES_LONG  {                    \
    [MFIB_ITF_NEGATE_SIGNAL] = "Negate-Signal",   \
    [MFIB_ITF_ACCEPT] = "Accept",                 \
    [MFIB_ITF_FORWARD] = "Forward",               \
    [MFIB_ITF_SIGNAL_PRESENT] = "Signal-Present", \
    [MFIB_ITF_DONT_PRESERVE] = "Don't-Preserve", \
}

typedef enum mfib_itf_flags_t_
{
    MFIB_ITF_FLAG_NONE,
    MFIB_ITF_FLAG_NEGATE_SIGNAL = (1 << MFIB_ITF_NEGATE_SIGNAL),
    MFIB_ITF_FLAG_ACCEPT = (1 << MFIB_ITF_ACCEPT),
    MFIB_ITF_FLAG_FORWARD = (1 << MFIB_ITF_FORWARD),
    MFIB_ITF_FLAG_SIGNAL_PRESENT = (1 << MFIB_ITF_SIGNAL_PRESENT),
    MFIB_ITF_FLAG_DONT_PRESERVE = (1 << MFIB_ITF_DONT_PRESERVE),
} mfib_itf_flags_t;

/**
 * Possible [control plane] sources of MFIB entries
 */
typedef enum mfib_source_t_
{
    MFIB_SOURCE_SPECIAL,
    MFIB_SOURCE_API,
    MFIB_SOURCE_CLI,
    MFIB_SOURCE_VXLAN,
    MFIB_SOURCE_DHCP,
    MFIB_SOURCE_SRv6,
    MFIB_SOURCE_GTPU,
    MFIB_SOURCE_VXLAN_GPE,
    MFIB_SOURCE_RR,
    MFIB_SOURCE_DEFAULT_ROUTE,
} mfib_source_t;

#define MFIB_SOURCE_NAMES {                        \
    [MFIB_SOURCE_SPECIAL] = "Special",             \
    [MFIB_SOURCE_API] = "API",                     \
    [MFIB_SOURCE_CLI] = "CLI",                     \
    [MFIB_SOURCE_DHCP] = "DHCP",                   \
    [MFIB_SOURCE_VXLAN] = "VXLAN",                 \
    [MFIB_SOURCE_SRv6] = "SRv6",                   \
    [MFIB_SOURCE_GTPU] = "GTPU",                   \
    [MFIB_SOURCE_VXLAN_GPE] = "VXLAN-GPE",         \
    [MFIB_SOURCE_RR] = "Recursive-resolution",     \
    [MFIB_SOURCE_DEFAULT_ROUTE] = "Default Route", \
}

#define MFIB_N_SOURCES (MFIB_SOURCE_DEFAULT_ROUTE)

/**
 * \brief Compare two prefixes for equality
 */
extern int mfib_prefix_cmp(const mfib_prefix_t *p1,
                           const mfib_prefix_t *p2);

extern u8 * format_mfib_prefix(u8 * s, va_list * args);

extern u8 *format_mfib_entry_flags(u8 * s, va_list * args);
extern u8 *format_mfib_itf_flags(u8 * s, va_list * args);
extern uword unformat_mfib_itf_flags(unformat_input_t * input,
                                     va_list * args);
extern uword unformat_mfib_entry_flags(unformat_input_t * input,
                                       va_list * args);

#endif
