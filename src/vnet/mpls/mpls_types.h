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
#ifndef __MPLS_TYPES_H__
#define __MPLS_TYPES_H__

#define MPLS_IETF_MIN_LABEL                  0x00000
#define MPLS_IETF_MAX_LABEL                  0xfffff

#define MPLS_IETF_MIN_RESERVED_LABEL         0x00000
#define MPLS_IETF_MAX_RESERVED_LABEL         0x0000f

#define MPLS_IETF_MIN_UNRES_LABEL            0x00010
#define MPLS_IETF_MAX_UNRES_LABEL            0xfffff

#define MPLS_IETF_IPV4_EXPLICIT_NULL_LABEL   0x00000
#define MPLS_IETF_ROUTER_ALERT_LABEL         0x00001
#define MPLS_IETF_IPV6_EXPLICIT_NULL_LABEL   0x00002
#define MPLS_IETF_IMPLICIT_NULL_LABEL        0x00003
#define MPLS_IETF_ELI_LABEL                  0x00007
#define MPLS_IETF_GAL_LABEL                  0x0000D
#define MPLS_IETF_ENTROPY_LABEL              0x0000E

#define MPLS_IETF_IPV4_EXPLICIT_NULL_STRING          "ip4-explicit-null"
#define MPLS_IETF_IPV4_EXPLICIT_NULL_BRIEF_STRING    "e-nul"
#define MPLS_IETF_IMPLICIT_NULL_STRING               "implicit-null"
#define MPLS_IETF_IMPLICIT_NULL_BRIEF_STRING         "i-nul"
#define MPLS_IETF_ROUTER_ALERT_STRING                "router-alert"
#define MPLS_IETF_ROUTER_ALERT_BRIEF_STRING          "r-alt"
#define MPLS_IETF_IPV6_EXPLICIT_NULL_STRING          "ipv6-explicit-null"
#define MPLS_IETF_IPV6_EXPLICIT_NULL_BRIEF_STRING    "v6enl"
#define MPLS_IETF_ELI_STRING                         "entropy-label-indicator"
#define MPLS_IETF_ELI_BRIEF_STRING                   "eli"
#define MPLS_IETF_GAL_STRING                         "gal"
#define MPLS_IETF_GAL_BRIEF_STRING                   "gal"

#define MPLS_LABEL_INVALID (MPLS_IETF_MAX_LABEL+1)

#define MPLS_LABEL_IS_REAL(_lbl) \
    (((_lbl) > MPLS_IETF_MIN_UNRES_LABEL) &&	\
     ((_lbl) <= MPLS_IETF_MAX_UNRES_LABEL))

/**
 * The top bit of the index, which is the result of the MPLS lookup
 * is used to determine if the DPO is a load-balance or a replicate
 */
#define MPLS_IS_REPLICATE 0x80000000

#endif
