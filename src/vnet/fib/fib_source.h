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

#ifndef __FIB_SOURCE_H__
#define __FIB_SOURCE_H__

#include <vnet/vnet.h>

/**
 * The different sources that can create a route.
 *
 * A source is a combination of two concepts; priority and behaviour.
 * Priority determines whether the source is contributing forwarding.
 * Behaviour determines how FIB entries with this source interact with
 * other elements of FIB.
 */
typedef enum fib_source_t_ {
    /**
     * An invalid source
     * This is not a real source, so don't use it to source a prefix.
     * It exists here to provide a value for inexistant/uninitialized source
     */
    FIB_SOURCE_INVALID = 0,
    /**
     * Marker. Add new values after this one.
     */
    FIB_SOURCE_FIRST,
    /**
     * Special sources. These are for entries that are added to all
     * FIBs by default, and should never be over-ridden (hence they
     * are the highest priority)
     */
    FIB_SOURCE_SPECIAL = FIB_SOURCE_FIRST,
    /**
     * Classify. A route that links directly to a classify adj
     */
    FIB_SOURCE_CLASSIFY,
    /**
     * A route the is being 'proxied' on behalf of another device
     */
    FIB_SOURCE_PROXY,
    /**
     * Route added as a result of interface configuration.
     * this will also come from the API/CLI, but the distinction is
     * that is from confiiguration on an interface, not a 'ip route' command
     */
    FIB_SOURCE_INTERFACE,
    /**
     * SRv6 and SR-MPLS
     */
    FIB_SOURCE_SR,
    /**
     * From the BIER subsystem
     */
    FIB_SOURCE_BIER,
    /**
     * From 6RD.
     */
    FIB_SOURCE_6RD,
    /**
     * From the control plane API
     */
    FIB_SOURCE_API,
    /**
     * From the CLI.
     */
    FIB_SOURCE_CLI,
    /**
     * LISP
     */
    FIB_SOURCE_LISP,
    /**
     * IPv[46] Mapping
     */
    FIB_SOURCE_MAP,
    /**
     * DHCP
     */
    FIB_SOURCE_DHCP,
    /**
     * IPv6 Proxy ND
     */
    FIB_SOURCE_IP6_ND_PROXY,
    /**
     * IPv6 ND (seen in the link-local tables)
     */
    FIB_SOURCE_IP6_ND,
    /**
     * Adjacency source.
     * routes created as a result of ARP/ND entries. This is lower priority
     * then the API/CLI. This is on purpose. trust me.
     */
    FIB_SOURCE_ADJ,
    /**
     * MPLS label. The prefix has been assigned a local label. This source
     * never provides forwarding information, instead it acts as a place-holder
     * so the association of label to prefix can be maintained
     */
    FIB_SOURCE_MPLS,
    /**
     * Attached Export source.
     * routes created as a result of attahced export. routes thus sourced
     * will be present in the export tables
     */
    FIB_SOURCE_AE,
    /**
     * Recursive resolution source.
     * Used to install an entry that is the resolution traget of another.
     */
    FIB_SOURCE_RR,
    /**
     * uRPF bypass/exemption.
     * Used to install an entry that is exempt from the loose uRPF check
     */
    FIB_SOURCE_URPF_EXEMPT,
    /**
     * The default route source.
     * The default route is always added to the FIB table (like the
     * special sources) but we need to be able to over-ride it with
     * 'ip route' sources when provided
     */
    FIB_SOURCE_DEFAULT_ROUTE,
    /**
     * The interpose source.
     * This is not a real source, so don't use it to source a prefix.
     * It exists here to provide a value against which to register to the
     * VFT for providing the interpose actions to a real source.
     */
    FIB_SOURCE_INTERPOSE,
    /**
     * Marker. add new entries before this one.
     */
    FIB_SOURCE_LAST = FIB_SOURCE_INTERPOSE,
} __attribute__ ((packed)) fib_source_t;

STATIC_ASSERT (sizeof(fib_source_t) == 1,
	       "FIB too many sources");

#define FIB_SOURCES {					\
    [FIB_SOURCE_INVALID] = "invalid",			\
    [FIB_SOURCE_SPECIAL] = "special",			\
    [FIB_SOURCE_INTERFACE] = "interface",		\
    [FIB_SOURCE_PROXY] = "proxy",                       \
    [FIB_SOURCE_BIER] = "BIER",			        \
    [FIB_SOURCE_6RD] = "6RD",			        \
    [FIB_SOURCE_API] = "API",			        \
    [FIB_SOURCE_CLI] = "CLI",			        \
    [FIB_SOURCE_ADJ] = "adjacency",			\
    [FIB_SOURCE_MAP] = "MAP",			        \
    [FIB_SOURCE_SR] = "SR",			        \
    [FIB_SOURCE_LISP] = "LISP", 			\
    [FIB_SOURCE_CLASSIFY] = "classify",			\
    [FIB_SOURCE_DHCP] = "DHCP",   			\
    [FIB_SOURCE_IP6_ND_PROXY] = "IPv6-proxy-nd",        \
    [FIB_SOURCE_IP6_ND] = "IPv6-nd",                    \
    [FIB_SOURCE_RR] = "recursive-resolution",	        \
    [FIB_SOURCE_AE] = "attached_export",	        \
    [FIB_SOURCE_MPLS] = "mpls",           	        \
    [FIB_SOURCE_URPF_EXEMPT] = "urpf-exempt",	        \
    [FIB_SOURCE_DEFAULT_ROUTE] = "default-route",	\
    [FIB_SOURCE_INTERPOSE] = "interpose",               \
}

/**
 * Each source is assigned a priority. lower priority is better.
 * the source with the best source with have its contribution added
 * to forwarding. the lesser sources will be 'remembered' by FIB and
 * added to forwarding should the best source be removed.
 */
typedef u8 fib_source_priority_t;

/**
 * source comparison
 */
typedef enum fib_source_priority_cmp_t_
{
    FIB_SOURCE_CMP_BETTER,
    FIB_SOURCE_CMP_WORSE,
    FIB_SOURCE_CMP_EQUAL,
} fib_source_priority_cmp_t;

/**
 * Each source has a defined behaviour that controls how entries
 * behave that have that source.
 * Sources with non-default behaviour may have a private data area
 * in the fib_entry_src_t union.
 */
typedef enum fib_source_behaviour_t_
{
    /**
     * If you're adding a new source from a plugin pick one of these
     */
    /** Default behaviour - always install a drop */
    FIB_SOURCE_BH_DROP,
    /** add paths with [mpls] path extensions */
    FIB_SOURCE_BH_API,
    /** add paths without path extensions */
    FIB_SOURCE_BH_SIMPLE,

    /**
     * If your adding a new source from a plugin
     * these are probably not the behaviour you're lokking for.
     */
    /** recursive resolution w/ cover tracking*/
    FIB_SOURCE_BH_RR,
    /** associated label stored in private data */
    FIB_SOURCE_BH_MPLS,
    /** cover tracking w/ glean management */
    FIB_SOURCE_BH_INTERFACE,
    /** interpose */
    FIB_SOURCE_BH_INTERPOSE,
    /**
     * simple behaviour, plus the source specific data stores the
     * FIB index that is used for subsequent lookups using the
     * packet's source address.
     * This doesn't need to be a LISP specific source, it's just
     * 'simple' behaviour with a u32 stored in the source specific data.
     */
    FIB_SOURCE_BH_LISP,
    /** adj w/ cover tracking + refinement */
    FIB_SOURCE_BH_ADJ,
} fib_source_behaviour_t;

#define FIB_SOURCE_BH_MAX (FIB_SOURCE_BH_ADJ+1)

#define FIB_SOURCE_BEHAVIOURS {                 \
    [FIB_SOURCE_BH_DROP] = "drop",		\
    [FIB_SOURCE_BH_RR] = "rr",                  \
    [FIB_SOURCE_BH_MPLS] = "mpls",              \
    [FIB_SOURCE_BH_INTERFACE] = "interface",    \
    [FIB_SOURCE_BH_INTERPOSE] = "interpose",    \
    [FIB_SOURCE_BH_LISP] = "lisp",              \
    [FIB_SOURCE_BH_ADJ] = "adjacency",          \
    [FIB_SOURCE_BH_API] = "api",                \
    [FIB_SOURCE_BH_SIMPLE] = "simple",          \
}

/**
 * The fixed source to priority mappings.
 * Declared here so those adding new sources can better determine their respective
 * priority values.
 */
#define foreach_fib_source                                      \
    /** you can't do better then the special source */         \
    _(FIB_SOURCE_SPECIAL,       0x00, FIB_SOURCE_BH_SIMPLE)    \
    _(FIB_SOURCE_CLASSIFY,      0x01, FIB_SOURCE_BH_SIMPLE)    \
    _(FIB_SOURCE_PROXY,         0x02, FIB_SOURCE_BH_SIMPLE)    \
    _(FIB_SOURCE_INTERFACE,     0x03, FIB_SOURCE_BH_INTERFACE) \
    _(FIB_SOURCE_SR,            0x10, FIB_SOURCE_BH_API)       \
    _(FIB_SOURCE_BIER,          0x20, FIB_SOURCE_BH_SIMPLE)    \
    _(FIB_SOURCE_6RD,           0x30, FIB_SOURCE_BH_API)       \
    _(FIB_SOURCE_API,           0x80, FIB_SOURCE_BH_API)       \
    _(FIB_SOURCE_CLI,           0x81, FIB_SOURCE_BH_API)       \
    _(FIB_SOURCE_LISP,          0x90, FIB_SOURCE_BH_LISP)      \
    _(FIB_SOURCE_MAP,           0xa0, FIB_SOURCE_BH_SIMPLE)    \
    _(FIB_SOURCE_DHCP,          0xb0, FIB_SOURCE_BH_API)       \
    _(FIB_SOURCE_IP6_ND_PROXY,  0xc0, FIB_SOURCE_BH_API)       \
    _(FIB_SOURCE_IP6_ND,        0xc1, FIB_SOURCE_BH_API)       \
    _(FIB_SOURCE_ADJ,           0xd0, FIB_SOURCE_BH_ADJ)       \
    _(FIB_SOURCE_MPLS,          0xe0, FIB_SOURCE_BH_MPLS)      \
    _(FIB_SOURCE_AE,            0xf0, FIB_SOURCE_BH_SIMPLE)    \
    _(FIB_SOURCE_RR,            0xfb, FIB_SOURCE_BH_RR)        \
    _(FIB_SOURCE_URPF_EXEMPT,   0xfc, FIB_SOURCE_BH_RR)        \
    _(FIB_SOURCE_DEFAULT_ROUTE, 0xfd, FIB_SOURCE_BH_DROP)      \
    _(FIB_SOURCE_INTERPOSE,     0xfe, FIB_SOURCE_BH_INTERPOSE) \
    _(FIB_SOURCE_INVALID,       0xff, FIB_SOURCE_BH_DROP)

/**
 * Some priority values that plugins might use when they are not to concerned
 * where in the list they'll go.
 */
#define FIB_SOURCE_PRIORITY_HI 0x10
#define FIB_SOURCE_PRIORITY_LOW 0xd0


extern u16 fib_source_get_prio(fib_source_t src);
extern fib_source_behaviour_t fib_source_get_behaviour(fib_source_t src);
extern fib_source_priority_cmp_t fib_source_cmp(fib_source_t s1,
                                                fib_source_t s2);

extern u8 *format_fib_source(u8 *s, va_list *a);

extern fib_source_t fib_source_allocate(const char *name,
                                        fib_source_priority_t prio,
                                        fib_source_behaviour_t bh);

extern void fib_source_register(fib_source_t src,
                                fib_source_priority_t prio,
                                fib_source_behaviour_t bh);

typedef walk_rc_t (*fib_source_walk_t)(fib_source_t id,
                                       const char *name,
                                       fib_source_priority_t prio,
                                       fib_source_behaviour_t bh,
                                       void *ctx);
extern void fib_source_walk(fib_source_walk_t fn,
                            void *ctx);

extern void fib_source_module_init(void);

#endif
