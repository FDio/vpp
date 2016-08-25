#ifndef included_vnet_mpls_packet_h
#define included_vnet_mpls_packet_h

/*
 * MPLS packet format
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

/**
 * A label value only, i.e. 20bits.
 */
typedef u32 mpls_label_t;

typedef struct {
    /* Label: top 20 bits [in network byte order] */
    /* Experimental: 3 bits ... */
    /* S (bottom of label stack): 1 bit */
    /* TTL: 8 bits */
    mpls_label_t label_exp_s_ttl;
} mpls_unicast_header_t;

typedef enum mpls_eos_bit_t_
{
    MPLS_NON_EOS = 0,
    MPLS_EOS     = 1,
} mpls_eos_bit_t;

#define MPLS_EOS_BITS {				\
    [MPLS_NON_EOS] = "neos",		      	\
    [MPLS_EOS] = "eos",				\
}

#define FOR_EACH_MPLS_EOS_BIT(_eos) \
    for (_eos = MPLS_NON_EOS; _eos <= MPLS_EOS; _eos++)

#define MPLS_ENTRY_LABEL_OFFSET        0
#define MPLS_ENTRY_LABEL_SHIFT 12
#define MPLS_ENTRY_LABEL_MASK  0x000fffff
#define MPLS_ENTRY_LABEL_BITS  \
    (MPLS_ENTRY_LABEL_MASK << MPLS_ENTRY_LABEL_SHIFT)

#define MPLS_ENTRY_EXP_OFFSET   2       /* byte offset to EXP bits */
#define MPLS_ENTRY_EXP_SHIFT   9
#define MPLS_ENTRY_EXP_MASK    0x07
#define MPLS_ENTRY_EXP(mpls)   \
    (((mpls)>>MPLS_ENTRY_EXP_SHIFT) & MPLS_ENTRY_EXP_MASK)
#define MPLS_ENTRY_EXP_BITS    \
    (MPLS_ENTRY_EXP_MASK << MPLS_ENTRY_EXP_SHIFT)

#define MPLS_ENTRY_EOS_OFFSET   2       /* byte offset to EOS bit */
#define MPLS_ENTRY_EOS_SHIFT   8
#define MPLS_ENTRY_EOS_MASK    0x01    /* EOS bit in its byte */
#define        MPLS_ENTRY_EOS(mpls)    \
    (((mpls) >> MPLS_ENTRY_EOS_SHIFT) & MPLS_ENTRY_EOS_MASK)
#define MPLS_ENTRY_EOS_BIT     (MPLS_ENTRY_EOS_MASK << MPLS_ENTRY_EOS_SHIFT)

#define MPLS_ENTRY_TTL_OFFSET  3  /* byte offset to ttl field */
#define MPLS_ENTRY_TTL_SHIFT   0
#define MPLS_ENTRY_TTL_MASK    0xff
#define MPLS_ENTRY_TTL(mpls)   \
    (((mpls) >> MPLS_ENTRY_TTL_SHIFT) & MPLS_ENTRY_TTL_MASK)
#define MPLS_ENTRY_TTL_BITS    \
    (MPLS_ENTRY_TTL_MASK << MPLS_ENTRY_TTL_SHIFT)

static inline u32 vnet_mpls_uc_get_label (mpls_label_t label_exp_s_ttl)
{
    return (label_exp_s_ttl>>MPLS_ENTRY_LABEL_SHIFT);
}

static inline u32 vnet_mpls_uc_get_exp (mpls_label_t label_exp_s_ttl)
{
    return (MPLS_ENTRY_EXP(label_exp_s_ttl));
}

static inline u32 vnet_mpls_uc_get_s (mpls_label_t label_exp_s_ttl)
{
    return (MPLS_ENTRY_EOS(label_exp_s_ttl));
}

static inline u32 vnet_mpls_uc_get_ttl (mpls_label_t label_exp_s_ttl)
{
    return (MPLS_ENTRY_TTL(label_exp_s_ttl));
}

static inline void vnet_mpls_uc_set_label (mpls_label_t *label_exp_s_ttl,
                                           u32 value)
{
    *label_exp_s_ttl = (((*label_exp_s_ttl) & ~(MPLS_ENTRY_LABEL_BITS)) |
                        ((value  & MPLS_ENTRY_LABEL_MASK) << MPLS_ENTRY_LABEL_SHIFT));
}

static inline void vnet_mpls_uc_set_exp (mpls_label_t *label_exp_s_ttl,
                                         u32 exp)
{
    *label_exp_s_ttl = (((*label_exp_s_ttl) & ~(MPLS_ENTRY_EXP_BITS)) |
                        ((exp & MPLS_ENTRY_EXP_MASK) << MPLS_ENTRY_EXP_SHIFT));
}
 
static inline void vnet_mpls_uc_set_s (mpls_label_t *label_exp_s_ttl,
                                       u32 eos)
{
    *label_exp_s_ttl = (((*label_exp_s_ttl) & ~(MPLS_ENTRY_EOS_BIT)) |
                        ((eos & MPLS_ENTRY_EOS_MASK) << MPLS_ENTRY_EOS_SHIFT));
}
 
static inline void vnet_mpls_uc_set_ttl (mpls_label_t *label_exp_s_ttl,
                                         u32 ttl)
{
    *label_exp_s_ttl = (((*label_exp_s_ttl) & ~(MPLS_ENTRY_TTL_BITS)) |
                        ((ttl & MPLS_ENTRY_TTL_MASK)));
}

#endif /* included_vnet_mpls_packet_h */
